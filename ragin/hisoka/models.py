"""Pydantic models for Hisoka — Adaptive Deception Layer."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Persona(BaseModel):
    """Deception persona matched to attacker skill level."""

    skill_level: str
    tone: str = "neutral"
    complexity: float = Field(0.5, ge=0.0, le=1.0)
    knowledge_scope: list[str] = Field(default_factory=list)
    system_prompt: str = ""
    description: str = ""

    @field_validator("skill_level")
    @classmethod
    def validate_skill_level(cls, v: str) -> str:
        valid = {"novice", "intermediate", "expert", "apt", "advanced"}
        if v not in valid:
            raise ValueError(f"Invalid skill level: {v!r}. Must be one of {valid}")
        return v


class SessionState(BaseModel):
    """State of an active deception session."""

    session_id: str
    source_ip: str = ""
    persona: Persona | None = None
    command_count: int = 0
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_interaction: datetime | None = None
    history: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    closed: bool = False

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 256:
            raise ValueError("Invalid session_id")
        return v


class DeceptionResponse(BaseModel):
    """Response from Hisoka to an attacker interaction."""

    session_id: str
    response_text: str
    persona_used: str = ""
    artifacts_injected: list[str] = Field(default_factory=list)
    engagement_score: float = Field(0.0, ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)
    honeytoken_triggered: bool = False


class SessionSummary(BaseModel):
    """Summary of a completed deception session."""

    session_id: str
    source_ip: str = ""
    persona_used: str = ""
    total_interactions: int = 0
    dwell_time_seconds: float = 0.0
    engagement_score: float = Field(0.0, ge=0.0, le=1.0)
    start_time: datetime | None = None
    end_time: datetime | None = None
    artifacts_injected: list[str] = Field(default_factory=list)


class DwellMetrics(BaseModel):
    """Aggregated dwell time metrics."""

    total_sessions: int = 0
    active_sessions: int = 0
    avg_dwell_time: float = 0.0
    max_dwell_time: float = 0.0
    min_dwell_time: float = 0.0
    target_multiplier: float = 4.1
    current_multiplier: float = 0.0
    baseline_dwell_time: float = 0.0


class DonAnalysis(BaseModel):
    """Incoming analysis from Don component."""

    session_id: str
    skill_level: str = "novice"
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    threat_summary: str = ""
    recommendations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
