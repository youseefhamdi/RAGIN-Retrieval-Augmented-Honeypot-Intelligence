"""
Honeytoken injection for Hisoka deception responses.

Infects every deceptive response with canary tokens — fake credentials,
decoy URLs, synthetic database references, and fingerprinted files.
When attackers use or access these tokens, alerts fire immediately.

Supports: credential tokens, URL tokens, API key tokens, file path tokens,
          database record tokens, and SSH key tokens.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────


@dataclass
class HoneytokenConfig:
    """Configuration for honeytoken generation and injection."""

    session_id: str = ""
    attacker_id: str = ""
    domain: str = "corp.local"
    network_range: str = "10.0.0.0/8"
    db_prefix: str = "DB_"
    cloud_project: str = "corp-prod-001"
    enabled_types: list[str] = field(
        default_factory=lambda: [
            "credential",
            "url",
            "api_key",
            "file_path",
            "database_record",
            "ssh_key",
        ]
    )
    # Custom honeyseed — use deterministic generation for reproducibility
    # across sessions with the same attacker (for correlation)
    honeyseed: str = ""


@dataclass
class HoneytokenAlert:
    """An alert fired when a honeytoken is triggered."""

    token_type: str
    token_value: str
    session_id: str
    attacker_id: str
    triggered_at: str
    context: str = ""
    severity: str = "critical"

    def to_dict(self) -> dict[str, Any]:
        return {
            "token_type": self.token_type,
            "token_value": self.token_value,
            "session_id": self.session_id,
            "attacker_id": self.attacker_id,
            "triggered_at": self.triggered_at,
            "context": self.context,
            "severity": self.severity,
        }


class HoneytokenEngine:
    """Generates, injects, and tracks honeytokens for deception responses.

    Usage::

        engine = HoneytokenEngine(HoneytokenConfig(
            session_id="sess_abc",
            attacker_id="192.168.1.100",
            domain="corp.local",
        ))

        # Inject honeytokens into a deceptive response
        enriched = engine.inject(response_text, context="lateral_movement")

        # Check if any tokens were triggered
        alerts = engine.check_triggers(logs_or_request_data)
    """

    def __init__(self, config: HoneytokenConfig | None = None) -> None:
        self._config = config or HoneytokenConfig()
        self._deployed_tokens: dict[str, dict[str, Any]] = {}
        self._alerts: list[HoneytokenAlert] = []
        self._token_counter = 0

    @property
    def config(self) -> HoneytokenConfig:
        return self._config

    @property
    def deployed_count(self) -> int:
        return len(self._deployed_tokens)

    @property
    def alerts(self) -> list[HoneytokenAlert]:
        return list(self._alerts)

    # ── Token Generation ──────────────────────────────────────────────────

    def _honeyseed(self, extra: str = "") -> str:
        """Generate a deterministic seed for reproducible token generation."""
        base = f"{self._config.honeyseed or self._config.session_id}:{self._config.attacker_id}:{extra}"
        return hashlib.sha256(base.encode()).hexdigest()[:16]

    def generate_credential_token(
        self,
        context: str = "",
        username: str = "",
    ) -> dict[str, str]:
        """Generate a fake credential pair — username + password canary."""
        seed = self._honeyseed("cred")
        if not username:
            # Pick a plausible username from a curated list
            names = ["svc_backup", "svc_sql", "admin_dev", "devops_bot", "monitoring", "jmartinez", "rchen"]
            idx = int(seed[:4], 16) % len(names)
            username = names[idx]

        # Generate a realistic-looking password
        word_hash = hashlib.sha256(seed.encode()).hexdigest()
        password = f"{username.replace('_', ' ').split()[0].title()}!{word_hash[:8].upper()}#{word_hash[-4:]}"

        token_id = self._register_token(
            token_type="credential",
            token_value=f"{username}:{password}",
            context=context,
        )

        return {
            "type": "credential",
            "username": username,
            "password": password,
            "token_id": token_id,
            "description": f"Canary credential for {username} — triggers alert if used",
        }

    def generate_url_token(
        self,
        context: str = "",
        path: str = "",
    ) -> dict[str, str]:
        """Generate a canary URL that phones home when accessed."""
        seed = self._honeyseed("url")
        token_id = seed[:12]
        fake_host = f"internal-{seed[:6]}.{self._config.domain}"

        if not path:
            paths = ["/api/admin", "/internal/backup", "/debug/config", "/metrics/secret", "/health/db-status"]
            idx = int(seed[4:8], 16) % len(paths)
            path = paths[idx]

        url = f"https://{fake_host}{path}"

        self._register_token(
            token_type="url",
            token_value=url,
            context=context,
        )

        return {
            "type": "url",
            "url": url,
            "token_id": token_id,
            "description": "Canary URL — triggers alert if HTTP request is made to this endpoint",
        }

    def generate_api_key_token(self, context: str = "") -> dict[str, str]:
        """Generate a fake API key that triggers if used against real APIs."""
        seed = self._honeyseed("apikey")
        prefixes = ["sk-proj-", "ghp_", "AKIA", "xoxb-", "AIza"]
        idx = int(seed[:4], 16) % len(prefixes)
        prefix = prefixes[idx]
        key_body = seed[4:20].upper()
        key = f"{prefix}{key_body}{''.join(seed[i:i+2] for i in range(20, 32, 2))}"

        self._register_token(
            token_type="api_key",
            token_value=key,
            context=context,
        )

        return {
            "type": "api_key",
            "key": key,
            "token_id": seed[:12],
            "description": f"Canary API key (prefix: {prefix}) — triggers if used in any API call",
        }

    def generate_file_path_token(
        self,
        context: str = "",
        filename: str = "",
    ) -> dict[str, str]:
        """Generate a fake sensitive file path with a canary marker."""
        seed = self._honeyseed("file")

        if not filename:
            filenames = [
                "backup_credentials.csv",
                "admin_notes.txt",
                "db_passwords.conf",
                "ssl_private_key.pem",
                "api_tokens.json",
                "network_diagram.vsdx",
                "incident_report_draft.docx",
                "server_access_matrix.xlsx",
            ]
            idx = int(seed[:4], 16) % len(filenames)
            filename = filenames[idx]

        # Randomize path across common locations
        dirs = ["/opt/backups", "/var/lib/secret", "/home/shared", "/tmp/deploy", "/etc/corp"]
        dir_idx = int(seed[4:8], 16) % len(dirs)
        path = f"{dirs[dir_idx]}/{filename}"

        self._register_token(
            token_type="file_path",
            token_value=path,
            context=context,
        )

        return {
            "type": "file_path",
            "path": path,
            "filename": filename,
            "token_id": seed[:12],
            "description": "Canary file — exists only as a marker; triggers alert if accessed",
        }

    def generate_database_record_token(
        self,
        context: str = "",
        table: str = "",
    ) -> dict[str, str]:
        """Generate a fake database record (row) that triggers if queried."""
        seed = self._honeyseed("db")

        if not table:
            tables = ["employees", "customers", "admin_users", "api_keys", "vpn_tokens", "server_creds"]
            idx = int(seed[:4], 16) % len(tables)
            table = tables[idx]

        fake_email = f"canary_{seed[:8]}@{self._config.domain}"
        fake_name = f"Honey User {seed[:4].upper()}"
        fake_id = f"{self._config.db_prefix}{int(seed[:8], 16) % 999999:06d}"

        record = {
            "table": table,
            "columns": {
                "id": fake_id,
                "name": fake_name,
                "email": fake_email,
                "role": "super_admin",
                "api_token": f"honey_{seed[8:24]}",
                "password_hash": f"$2b$12${seed[:22]}",
                "last_login": "2025-01-15T03:42:00Z",
                "is_active": True,
            },
        }

        self._register_token(
            token_type="database_record",
            token_value=f"{table}:{fake_id}:{fake_email}",
            context=context,
        )

        return {
            "type": "database_record",
            "table": table,
            "record": record["columns"],
            "token_id": seed[:12],
            "description": f"Canary DB record in '{table}' table — triggers if row is queried or accessed",
        }

    def generate_ssh_key_token(
        self,
        context: str = "",
        username: str = "",
    ) -> dict[str, str]:
        """Generate a fake SSH private key that triggers if used to authenticate."""
        seed = self._honeyseed("ssh")
        if not username:
            usernames = ["root", "deploy", "admin", "jenkins", "ansible"]
            idx = int(seed[:4], 16) % len(usernames)
            username = usernames[idx]

        # Fake but realistic-looking SSH key header
        fake_pub = f"ssh-rsa AAAA{seed[:40].upper()}...honeytoken_canary_{seed[:8]}"
        key_path = f"/home/{username}/.ssh/id_rsa"

        self._register_token(
            token_type="ssh_key",
            token_value=key_path,
            context=context,
        )

        return {
            "type": "ssh_key",
            "path": key_path,
            "username": username,
            "public_key": fake_pub,
            "token_id": seed[:12],
            "description": f"Canary SSH key for {username} — triggers if key is used for authentication",
        }

    # ── Injection ─────────────────────────────────────────────────────────

    def inject(self, text: str, context: str = "") -> str:
        """Inject honeytokens into a deceptive response text.

        Selects appropriate token types based on context and appends
        them naturally into the response.
        """
        tokens_to_inject: list[dict[str, str]] = []

        if context in ("lateral_movement", "credential_access", "initial_access", ""):
            tokens_to_inject.append(self.generate_credential_token(context))
        if context in ("discovery", "recon", "lateral_movement", ""):
            tokens_to_inject.append(self.generate_database_record_token(context))
        if context in ("exfiltration", "c2", "credential_access", ""):
            tokens_to_inject.append(self.generate_url_token(context))
        if context in ("persistence", "defense_evasion", "execution", ""):
            tokens_to_inject.append(self.generate_file_path_token(context))

        # Build natural-looking injection
        injections: list[str] = []
        for token in tokens_to_inject:
            ttype = token["type"]
            if ttype == "credential":
                injections.append(
                    f"\n\nBTW — the DB credentials are in the config: " f"{token['username']} / {token['password']}"
                )
            elif ttype == "url":
                injections.append(f"\n\nInternal API docs are at: {token['url']}")
            elif ttype == "api_key":
                injections.append(f"\n\nThe API key is: {token['key']}")
            elif ttype == "file_path":
                injections.append(f"\n\nAdmin notes are at: {token['path']}")
            elif ttype == "database_record":
                rec = token["record"]
                injections.append(
                    f"\n\nDB query shows user {rec['name']} ({rec['email']}) "
                    f"with role={rec['role']} and token={rec['api_token']}"
                )
            elif ttype == "ssh_key":
                injections.append(f"\n\nSSH key for {token['username']} is at: {token['path']}")

        enriched = text + "".join(injections)
        return enriched

    # ── Trigger Checking ──────────────────────────────────────────────────

    def check_triggers(
        self,
        request_or_log_data: dict[str, Any],
    ) -> list[HoneytokenAlert]:
        """Check if any deployed honeytokens were triggered by attacker activity.

        Args:
            request_or_log_data: Dict containing request headers, body, URL,
                                 or log data to check against deployed tokens.

        Returns:
            List of alerts for any triggered tokens.
        """
        alerts: list[HoneytokenAlert] = []

        # Flatten request data for searching
        search_text = self._flatten_data(request_or_log_data)

        for _token_id, token_info in self._deployed_tokens.items():
            token_value = token_info["value"]
            if token_value in search_text:
                alert = HoneytokenAlert(
                    token_type=token_info["type"],
                    token_value=token_value,
                    session_id=self._config.session_id,
                    attacker_id=self._config.attacker_id,
                    triggered_at=datetime.now(timezone.utc).isoformat(),
                    context=token_info.get("context", ""),
                )
                alerts.append(alert)
                self._alerts.append(alert)
                logger.critical(
                    "HONEYTOKEN TRIGGERED: type=%s value=%s session=%s attacker=%s",
                    alert.token_type,
                    alert.token_value[:50],
                    alert.session_id,
                    alert.attacker_id,
                )

        return alerts

    def check_credential_use(
        self,
        username: str,
        password: str,
    ) -> HoneytokenAlert | None:
        """Check if a login attempt uses a honeytoken credential pair."""
        for _token_id, token_info in self._deployed_tokens.items():
            if token_info["type"] != "credential":
                continue
            stored_user, stored_pass = token_info["value"].split(":", 1)
            if username == stored_user or password == stored_pass:
                alert = HoneytokenAlert(
                    token_type="credential_use",
                    token_value=f"{username}:{password[:4]}...",
                    session_id=self._config.session_id,
                    attacker_id=self._config.attacker_id,
                    triggered_at=datetime.now(timezone.utc).isoformat(),
                    context=f"Login attempt with honeytoken credential for {stored_user}",
                    severity="critical",
                )
                self._alerts.append(alert)
                logger.critical(
                    "HONEYTOKEN CREDENTIAL USED: user=%s session=%s",
                    username,
                    self._config.session_id,
                )
                return alert
        return None

    def check_url_access(self, url: str) -> HoneytokenAlert | None:
        """Check if a URL access hits a honeytoken endpoint."""
        for _token_id, token_info in self._deployed_tokens.items():
            if token_info["type"] != "url":
                continue
            if token_info["value"] in url:
                alert = HoneytokenAlert(
                    token_type="url_access",
                    token_value=url,
                    session_id=self._config.session_id,
                    attacker_id=self._config.attacker_id,
                    triggered_at=datetime.now(timezone.utc).isoformat(),
                    context=f"URL access to honeytoken endpoint: {url}",
                    severity="critical",
                )
                self._alerts.append(alert)
                logger.critical(
                    "HONEYTOKEN URL ACCESSED: url=%s session=%s",
                    url,
                    self._config.session_id,
                )
                return alert
        return None

    # ── Bulk Deployment ───────────────────────────────────────────────────

    def deploy_full_set(self, context: str = "") -> list[dict[str, str]]:
        """Deploy one of each token type. Returns list of all generated tokens."""
        tokens: list[dict[str, str]] = []
        for token_type in self._config.enabled_types:
            generator = getattr(self, f"generate_{token_type}_token", None)
            if generator:
                tokens.append(generator(context=context))
        return tokens

    # ── Internal Helpers ──────────────────────────────────────────────────

    def _register_token(
        self,
        token_type: str,
        token_value: str,
        context: str = "",
    ) -> str:
        """Register a token for tracking and trigger detection."""
        self._token_counter += 1
        token_id = f"{token_type}_{self._token_counter:04d}"

        self._deployed_tokens[token_id] = {
            "type": token_type,
            "value": token_value,
            "context": context,
            "deployed_at": time.time(),
            "session_id": self._config.session_id,
            "attacker_id": self._config.attacker_id,
        }

        logger.info(
            "Honeytoken deployed: type=%s id=%s session=%s",
            token_type,
            token_id,
            self._config.session_id,
        )
        return token_id

    @staticmethod
    def _flatten_data(data: Any, depth: int = 0) -> str:
        """Recursively flatten a dict/list into a searchable string."""
        if depth > 10:
            return ""
        parts: list[str] = []
        if isinstance(data, dict):
            for k, v in data.items():
                parts.append(str(k))
                parts.append(HoneytokenEngine._flatten_data(v, depth + 1))
        elif isinstance(data, (list, tuple)):
            for item in data:
                parts.append(HoneytokenEngine._flatten_data(item, depth + 1))
        elif data is not None:
            parts.append(str(data))
        return " ".join(parts)

    def get_all_tokens(self) -> dict[str, dict[str, Any]]:
        """Return all deployed tokens (for debugging/testing)."""
        return dict(self._deployed_tokens)

    def get_alerts_summary(self) -> dict[str, Any]:
        """Get summary of all triggered alerts."""
        by_type: dict[str, int] = {}
        for alert in self._alerts:
            by_type[alert.token_type] = by_type.get(alert.token_type, 0) + 1
        return {
            "total_alerts": len(self._alerts),
            "by_type": by_type,
            "alerts": [a.to_dict() for a in self._alerts],
        }

    def clear(self) -> None:
        """Clear all deployed tokens and alerts."""
        self._deployed_tokens.clear()
        self._alerts.clear()
        self._token_counter = 0
