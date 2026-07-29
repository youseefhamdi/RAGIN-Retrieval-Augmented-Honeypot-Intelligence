"""Role-based access control and multi-tenant isolation."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Permission(str, Enum):
    READ_SESSIONS = "read:sessions"
    WRITE_SESSIONS = "write:sessions"
    DELETE_SESSIONS = "delete:sessions"
    READ_DECEPTION = "read:deception"
    WRITE_DECEPTION = "write:deception"
    READ_CTI = "read:cti"
    WRITE_CTI = "write:cti"
    READ_HONEYTOKENS = "read:honeytokens"
    WRITE_HONEYTOKENS = "write:honeytokens"
    MANAGE_USERS = "manage:users"
    MANAGE_TENANTS = "manage:tenants"
    READ_SIEM = "read:siem"
    WRITE_SIEM = "write:siem"
    READ_BENCHMARKS = "read:benchmarks"
    WRITE_BENCHMARKS = "write:benchmarks"
    ADMIN = "admin"


ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    "viewer": {
        Permission.READ_SESSIONS,
        Permission.READ_DECEPTION,
        Permission.READ_CTI,
        Permission.READ_HONEYTOKENS,
        Permission.READ_BENCHMARKS,
    },
    "operator": {
        Permission.READ_SESSIONS,
        Permission.WRITE_SESSIONS,
        Permission.READ_DECEPTION,
        Permission.WRITE_DECEPTION,
        Permission.READ_CTI,
        Permission.READ_HONEYTOKENS,
        Permission.WRITE_HONEYTOKENS,
        Permission.READ_BENCHMARKS,
    },
    "analyst": {
        Permission.READ_SESSIONS,
        Permission.WRITE_SESSIONS,
        Permission.READ_DECEPTION,
        Permission.WRITE_DECEPTION,
        Permission.READ_CTI,
        Permission.WRITE_CTI,
        Permission.READ_HONEYTOKENS,
        Permission.WRITE_HONEYTOKENS,
        Permission.READ_SIEM,
        Permission.READ_BENCHMARKS,
    },
    "admin": {p for p in Permission},
}


@dataclass
class Role:
    name: str
    permissions: set[Permission]
    description: str = ""

    @classmethod
    def from_preset(cls, name: str, description: str = "") -> Role:
        perms = ROLE_PERMISSIONS.get(name, set())
        return cls(name=name, permissions=perms, description=description)

    def has_permission(self, perm: Permission) -> bool:
        return Permission.ADMIN in self.permissions or perm in self.permissions

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "permissions": sorted([p.value for p in self.permissions]),
            "description": self.description,
        }


@dataclass
class Tenant:
    tenant_id: str
    name: str
    created_at: float = field(default_factory=time.time)
    is_active: bool = True
    config: dict[str, Any] = field(default_factory=dict)
    session_ids: set[str] = field(default_factory=set)
    _api_key: str = field(default_factory=lambda: secrets.token_urlsafe(32))

    @property
    def api_key(self) -> str:
        return self._api_key

    def owns_session(self, session_id: str) -> bool:
        return session_id in self.session_ids

    def register_session(self, session_id: str) -> None:
        self.session_ids.add(session_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "name": self.name,
            "created_at": self.created_at,
            "is_active": self.is_active,
            "session_count": len(self.session_ids),
        }


@dataclass
class User:
    user_id: str
    username: str
    tenant_id: str
    roles: list[Role] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    is_active: bool = True
    last_login: float = 0.0

    @property
    def all_permissions(self) -> set[Permission]:
        perms: set[Permission] = set()
        for role in self.roles:
            perms |= role.permissions
        return perms

    def has_permission(self, perm: Permission) -> bool:
        if not self.is_active:
            return False
        return Permission.ADMIN in self.all_permissions or perm in self.all_permissions

    def has_role(self, role_name: str) -> bool:
        return any(r.name == role_name for r in self.roles)

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "tenant_id": self.tenant_id,
            "roles": [r.name for r in self.roles],
            "is_active": self.is_active,
            "permissions": sorted([p.value for p in self.all_permissions]),
        }


class RoleBasedAccessControl:
    def __init__(self) -> None:
        self._tenants: dict[str, Tenant] = {}
        self._users: dict[str, User] = {}
        self._api_key_tenant: dict[str, str] = {}
        self._audit_log: list[dict[str, Any]] = []

    def create_tenant(self, tenant_id: str, name: str, config: dict[str, Any] | None = None) -> Tenant:
        if tenant_id in self._tenants:
            raise ValueError(f"Tenant '{tenant_id}' already exists")
        tenant = Tenant(tenant_id=tenant_id, name=name, config=config or {})
        self._tenants[tenant_id] = tenant
        self._api_key_tenant[tenant.api_key] = tenant_id
        self._log("tenant_create", tenant_id=tenant_id, name=name)
        return tenant

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        return self._tenants.get(tenant_id)

    def list_tenants(self) -> list[Tenant]:
        return list(self._tenants.values())

    def create_user(
        self,
        user_id: str,
        username: str,
        tenant_id: str,
        role_names: list[str] | None = None,
    ) -> User:
        if user_id in self._users:
            raise ValueError(f"User '{user_id}' already exists")
        if tenant_id not in self._tenants:
            raise KeyError(f"Tenant '{tenant_id}' not found")
        roles = [Role.from_preset(rn) for rn in (role_names or ["viewer"])]
        user = User(user_id=user_id, username=username, tenant_id=tenant_id, roles=roles)
        self._users[user_id] = user
        self._log("user_create", user_id=user_id, username=username, tenant_id=tenant_id)
        return user

    def get_user(self, user_id: str) -> User | None:
        return self._users.get(user_id)

    def authenticate_api_key(self, api_key: str) -> Tenant | None:
        tenant_id = self._api_key_tenant.get(api_key)
        if tenant_id is None:
            return None
        tenant = self._tenants.get(tenant_id)
        if tenant and tenant.is_active:
            return tenant
        return None

    def authorize(self, user: User, permission: Permission, resource_tenant_id: str = "") -> bool:
        if not user.is_active:
            self._log("authz_denied", user_id=user.user_id, permission=permission.value, reason="inactive")
            return False
        if resource_tenant_id and user.tenant_id != resource_tenant_id:
            self._log(
                "authz_denied",
                user_id=user.user_id,
                permission=permission.value,
                reason="tenant_mismatch",
                resource_tenant=resource_tenant_id,
            )
            return False
        allowed = user.has_permission(permission)
        if not allowed:
            self._log("authz_denied", user_id=user.user_id, permission=permission.value, reason="insufficient_role")
        return allowed

    def validate_session_access(self, user: User, session_id: str) -> bool:
        tenant = self._tenants.get(user.tenant_id)
        if tenant is None:
            return False
        return tenant.owns_session(session_id)

    def _log(self, action: str, **kwargs: Any) -> None:
        self._audit_log.append({"action": action, "timestamp": time.time(), **kwargs})

    def get_audit_log(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._audit_log[-limit:]

    def get_stats(self) -> dict[str, Any]:
        return {
            "tenants": len(self._tenants),
            "active_tenants": sum(1 for t in self._tenants.values() if t.is_active),
            "users": len(self._users),
            "active_users": sum(1 for u in self._users.values() if u.is_active),
            "audit_events": len(self._audit_log),
        }
