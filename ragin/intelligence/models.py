"""Pydantic models for the Intelligence Layer."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from ragin.chrollo.models import SkillLevel


class ResponseStrategy(str, Enum):
    NOVICE = "novice"
    INTERMEDIATE = "intermediate"
    EXPERT = "expert"
    APT = "apt"


class EvasionIndicatorType(str, Enum):
    FINGERPRINTING = "fingerprinting"
    TIMING_ANALYSIS = "timing_analysis"
    TOOL_SIGNATURE = "tool_signature"
    SANDBOX_DETECTION = "sandbox_detection"
    DECEPTION_AWARE = "deception_aware"


class TimeWindow(str, Enum):
    BUSINESS_HOURS = "business_hours"
    AFTER_HOURS = "after_hours"
    WEEKEND = "weekend"


class DeceptionLayer(BaseModel):
    """A single layer of indirection in a deception response."""

    layer_index: int = Field(ge=0)
    description: str = ""
    fake_artifacts: list[str] = Field(default_factory=list)
    credential_seeds: list[str] = Field(default_factory=list)
    breadcrumb_trail: list[str] = Field(default_factory=list)


class AdaptedResponse(BaseModel):
    """Output of AdaptiveResponseEngine — a tuned deception response."""

    response_id: str = ""
    session_id: str = ""
    strategy: ResponseStrategy
    response_text: str = ""
    deception_layers: list[DeceptionLayer] = Field(default_factory=list)
    complexity_score: int = Field(default=1, ge=1, le=10)
    tone: str = "neutral"
    artifacts_injected: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvasionIndicator(BaseModel):
    """A single detection indicator found in session activity."""

    indicator_type: EvasionIndicatorType
    evidence: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvasionResult(BaseModel):
    """Result of evasion detection analysis."""

    session_id: str = ""
    detected: bool = False
    indicators: list[EvasionIndicator] = Field(default_factory=list)
    detection_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    recommendation: AdjustmentRecommendation | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AdjustmentRecommendation(BaseModel):
    """Recommended response adjustment when evasion is detected."""

    increase_deception: bool = False
    reduce_artifacts: bool = False
    slow_response_timing: bool = False
    inject_false_flags: bool = False
    persona_rotation: bool = False
    reason: str = ""

    @field_validator("reason")
    @classmethod
    def sanitize_reason(cls, v: str) -> str:
        if len(v) > 2048:
            raise ValueError("Reason exceeds maximum length")
        return v


class StrategyProfile(BaseModel):
    """Complete strategy profile for a session."""

    session_id: str
    skill_level: SkillLevel = SkillLevel.NOVICE
    response_strategy: ResponseStrategy = ResponseStrategy.NOVICE
    engagement_score: float = Field(default=0.0, ge=0.0, le=1.0)
    interaction_count: int = Field(default=0, ge=0)
    deception_depth: int = Field(default=1, ge=1, le=5)
    information_leakage_rate: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_trail: list[str] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EngagementParams(BaseModel):
    """Runtime engagement parameters derived from a strategy."""

    response_delay_ms: int = Field(default=100, ge=0, le=30000)
    artifact_density: float = Field(default=0.5, ge=0.0, le=1.0)
    persona_complexity: int = Field(default=1, ge=1, le=10)
    deception_depth: int = Field(default=1, ge=1, le=5)
    information_leakage_rate: float = Field(default=0.5, ge=0.0, le=1.0)
    time_window: TimeWindow = TimeWindow.BUSINESS_HOURS


class AdjustedResponseParams(BaseModel):
    """Parameters adjusted by evasion detection."""

    original_delay_ms: int = 100
    adjusted_delay_ms: int = 100
    original_artifact_density: float = 0.5
    adjusted_artifact_density: float = 0.5
    inject_false_flags: bool = False
    rotate_persona: bool = False


def _sanitize_input(text: str, max_length: int = 4096) -> str:
    """Sanitize free-text input for LLM safety."""
    text = text.strip()
    if len(text) > max_length:
        text = text[:max_length]
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"javascript:", "", text, flags=re.IGNORECASE)
    return text
