"""Pydantic models for Chrollo inter-component communication."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from ragin.utils import hash_ip

# ── Enums ────────────────────────────────────────────────────────────────────


class SkillLevel(str, Enum):
    NOVICE = "novice"
    INTERMEDIATE = "intermediate"
    EXPERT = "expert"
    APT = "apt"


# ── Session log primitives ───────────────────────────────────────────────────


class CommandEntry(BaseModel):
    timestamp: datetime
    command: str
    working_directory: str = ""
    user: str = ""
    exit_code: int | None = None
    output_length: int = 0

    @field_validator("command")
    @classmethod
    def sanitize_command(cls, v: str) -> str:
        v = v.strip()
        if len(v) > 4096:
            raise ValueError("Command exceeds maximum allowed length")
        return v


class FileOperation(BaseModel):
    timestamp: datetime
    operation: str  # create, modify, delete, read
    path: str
    size: int = 0

    @field_validator("path")
    @classmethod
    def sanitize_path(cls, v: str) -> str:
        if len(v) > 1024:
            raise ValueError("Path exceeds maximum allowed length")
        return v.strip()


class NetworkActivity(BaseModel):
    timestamp: datetime
    protocol: str
    source_ip: str = ""
    destination_ip: str = ""
    destination_port: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0


# ── Raw session log ──────────────────────────────────────────────────────────


class SessionLog(BaseModel):
    session_id: str
    source_ip: str = ""
    start_time: datetime
    end_time: datetime | None = None
    commands: list[CommandEntry] = Field(default_factory=list)
    file_operations: list[FileOperation] = Field(default_factory=list)
    network_activity: list[NetworkActivity] = Field(default_factory=list)
    raw_log: str = ""
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 256:
            raise ValueError("Invalid session_id")
        return hashlib.sha256(v.encode()).hexdigest()[:64]

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        v = v.strip()
        if v and not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-f:]+$", v):
            raise ValueError(f"Invalid IP address: {v}")
        return hash_ip(v)

    @field_validator("raw_log")
    @classmethod
    def sanitize_raw_log(cls, v: str) -> str:
        if len(v) > 1_000_000:
            raise ValueError("Raw log exceeds 1MB limit")
        return v


# ── Inter-component request/response models ──────────────────────────────────


class ClassificationRequest(BaseModel):
    session_log: SessionLog
    request_id: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EscalationPayload(BaseModel):
    session_id: str
    skill_level: SkillLevel
    confidence: float = Field(ge=0.0, le=1.0)
    features_used: list[str] = Field(default_factory=list)
    session_log: SessionLog
    request_id: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EscalationResponse(BaseModel):
    request_id: str
    status: str = "accepted"
    message: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Training data ────────────────────────────────────────────────────────────


class TrainingSample(BaseModel):
    session_log: SessionLog
    skill_level: SkillLevel
    features: dict[str, float] = Field(default_factory=dict)
