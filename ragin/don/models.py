"""Pydantic models for Don component — inter-component communication and threat intel."""

from __future__ import annotations

import logging
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


# --- Enums ---


class MITRETacticID(str, Enum):
    """MITRE ATT&CK Enterprise tactic IDs."""

    RECONNAISSANCE = "TA0043"
    RESOURCE_DEV = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIV_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CIDR = "cidr"
    FILE_PATH = "file_path"
    REGISTRY = "registry"
    USER_AGENT = "user_agent"
    JA3 = "ja3"


class ClassificationLabel(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


# --- Core Models ---


class IOC(BaseModel):
    """Indicator of Compromise."""

    type: IOCType
    value: str = Field(..., max_length=2048)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source: str = "chrollo"
    tags: list[str] = Field(default_factory=list)

    @field_validator("value")
    @classmethod
    def sanitize_value(cls, v: str) -> str:
        """Strip control characters to prevent injection via IOC payloads."""
        return "".join(c for c in v if c.isprintable()).strip()


class MITRETactic(BaseModel):
    """MITRE ATT&CK tactic mapping."""

    tactic_id: str = Field(..., pattern=r"^TA\d{4}$")
    tactic_name: str
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    techniques: list[str] = Field(default_factory=list)
    sub_techniques: list[str] = Field(default_factory=list)


class ThreatActor(BaseModel):
    """Identified threat actor."""

    name: str
    aliases: list[str] = Field(default_factory=list)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    country: str | None = None
    motivation: str | None = None
    sophistication: str | None = None
    known_ttps: list[str] = Field(default_factory=list)


class IntelDocument(BaseModel):
    """Document from the threat intelligence corpus."""

    doc_id: str
    title: str
    content: str
    source: str = ""
    published_date: datetime | None = None
    tags: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    score: float = Field(0.0, ge=0.0, le=1.0)

    @field_validator("content")
    @classmethod
    def sanitize_content(cls, v: str) -> str:
        """Sanitize intel doc content before LLM context injection."""
        return _sanitize_for_llm(v)


class ThreatAnalysis(BaseModel):
    """Complete threat analysis result from Don."""

    analysis_id: str
    session_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    classification: ClassificationLabel
    severity: SeverityLevel = SeverityLevel.INFO
    confidence: float = Field(0.0, ge=0.0, le=1.0)

    tactics: list[MITRETactic] = Field(default_factory=list)
    threat_actors: list[ThreatActor] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    sophistication_score: float = Field(0.0, ge=0.0, le=1.0)
    intel_documents: list[IntelDocument] = Field(default_factory=list)

    narrative: str = ""
    recommendations: list[str] = Field(default_factory=list)
    raw_features: dict[str, Any] = Field(default_factory=dict)


# --- Request / Response Models ---


class AnalysisRequest(BaseModel):
    """Request from Chrollo to Don."""

    session_id: str = Field(..., max_length=128)
    classification: ClassificationLabel
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    features: dict[str, Any] = Field(default_factory=dict)
    session_log: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, v: str) -> str:
        if not v or not v.isalnum():
            raise ValueError("session_id must be alphanumeric")
        return v


class AnalysisResponse(BaseModel):
    """Response from Don back to Chrollo or Hisoka."""

    analysis_id: str
    session_id: str
    threat_analysis: ThreatAnalysis
    report: str = ""
    success: bool = True
    error: str | None = None


class GatewayMessage(BaseModel):
    """Message format for LLM Gateway calls."""

    role: str
    content: str


class GatewayRequest(BaseModel):
    """Request to the LLM Gateway /v1/chat/completions."""

    model: str = "inclusionai/ling-3.0-flash:free"
    messages: list[GatewayMessage]
    temperature: float = Field(0.3, ge=0.0, le=2.0)
    max_tokens: int = Field(2048, ge=1, le=8192)
    stream: bool = False


class GatewayResponse(BaseModel):
    """Response from the LLM Gateway."""

    id: str
    choices: list[dict[str, Any]]
    usage: dict[str, int] = Field(default_factory=dict)
    model: str = ""


# --- Security Helpers ---


_PROMPT_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous",
    "disregard prior",
    "forget everything",
    "new instructions:",
    "system prompt:",
    "you are now",
    "pretend you are",
    "act as if",
    "override",
    "<|system|>",
    "<|assistant|>",
    "```system",
    "<<SYS>>",
]


def _sanitize_for_llm(text: str) -> str:
    """Remove prompt-injection patterns from intel content before LLM context."""
    lower = text.lower()
    for pattern in _PROMPT_INJECTION_PATTERNS:
        if pattern in lower:
            logger.warning("Prompt injection pattern detected in intel doc, stripping")
            idx = lower.index(pattern)
            text = text[:idx] + "[REDACTED]"
            lower = text.lower()
    return text


def validate_from_chrollo(data: dict[str, Any]) -> AnalysisRequest:
    """Validate and construct an AnalysisRequest from raw Chrollo output."""
    return AnalysisRequest(**data)
