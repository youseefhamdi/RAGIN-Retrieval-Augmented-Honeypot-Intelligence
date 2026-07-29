"""Threat Modeling & Verification — Phase 4 of the Harness/Loop integration.

Provides:
- STRIDE threat modeling for deception sessions
- Structured findings with MITRE ATT&CK mappings + confidence scores
- Response verification against threat model consistency
- Attack chain construction from observed TTPs
- MTTA (Mean Time to Act) tracking

Design references:
- VISA VVAH Harness: threat modeling BEFORE analysis, structured SARIF output
- Loop Engineering: stateless pipeline stages, event-driven
- Anthropic Managed Agents: session log as source of truth
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# STRIDE Threat Model
# ──────────────────────────────────────────────


class StrideCategory(str, Enum):
    """STRIDE threat categories mapped to honeypot/deception context."""

    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFO_DISCLOSURE = "info_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


@dataclass
class StrideThreat:
    """A single STRIDE threat assessment."""

    category: StrideCategory
    risk_level: str  # "low", "medium", "high", "critical"
    confidence: float  # 0.0–1.0
    evidence: list[str] = field(default_factory=list)
    description: str = ""
    mitigation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "description": self.description,
            "mitigation": self.mitigation,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> StrideThreat:
        return cls(
            category=StrideCategory(d["category"]),
            risk_level=d["risk_level"],
            confidence=d["confidence"],
            evidence=d.get("evidence", []),
            description=d.get("description", ""),
            mitigation=d.get("mitigation", ""),
        )


@dataclass
class ThreatModel:
    """Complete STRIDE threat model for a session or interaction."""

    session_id: str
    threats: list[StrideThreat] = field(default_factory=list)
    overall_risk: str = "low"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    attacker_input: str = ""
    context: dict[str, Any] = field(default_factory=dict)

    @property
    def threat_count(self) -> int:
        return len(self.threats)

    @property
    def high_risk_threats(self) -> list[StrideThreat]:
        return [t for t in self.threats if t.risk_level in ("high", "critical")]

    @property
    def max_confidence(self) -> float:
        if not self.threats:
            return 0.0
        return max(t.confidence for t in self.threats)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "threats": [t.to_dict() for t in self.threats],
            "overall_risk": self.overall_risk,
            "timestamp": self.timestamp.isoformat(),
            "attacker_input": self.attacker_input,
            "threat_count": self.threat_count,
            "high_risk_count": len(self.high_risk_threats),
        }


# ──────────────────────────────────────────────
# Structured Findings (MITRE ATT&CK + Confidence)
# ──────────────────────────────────────────────


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    FALSE_POSITIVE = "false_positive"


@dataclass
class MitreMapping:
    """MITRE ATT&CK mapping for a finding."""

    technique_id: str  # e.g. "T1059.001"
    technique_name: str  # e.g. "Command and Scripting Interpreter: PowerShell"
    tactic: str  # e.g. "execution"
    sub_technique: str = ""
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "sub_technique": self.sub_technique,
            "url": self.url,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MitreMapping:
        return cls(
            technique_id=d["technique_id"],
            technique_name=d["technique_name"],
            tactic=d["tactic"],
            sub_technique=d.get("sub_technique", ""),
            url=d.get("url", ""),
        )


@dataclass
class StructuredFinding:
    """A structured finding with MITRE mapping and confidence scoring.

    Inspired by VVAH Harness SARIF output — each finding is machine-readable
    and includes provenance, confidence, and actionable recommendations.
    """

    finding_id: str
    title: str
    severity: FindingSeverity
    confidence: float  # 0.0–1.0
    status: FindingStatus = FindingStatus.CONFIRMED
    description: str = ""
    mitre_mappings: list[MitreMapping] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    session_id: str = ""
    source_ip: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def mitre_technique_ids(self) -> list[str]:
        return [m.technique_id for m in self.mitre_mappings]

    @property
    def mitre_tactics(self) -> list[str]:
        return sorted({m.tactic for m in self.mitre_mappings})

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "status": self.status.value,
            "description": self.description,
            "mitre_mappings": [m.to_dict() for m in self.mitre_mappings],
            "evidence": self.evidence,
            "recommendations": self.recommendations,
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> StructuredFinding:
        return cls(
            finding_id=d["finding_id"],
            title=d["title"],
            severity=FindingSeverity(d["severity"]),
            confidence=d["confidence"],
            status=FindingStatus(d.get("status", "confirmed")),
            description=d.get("description", ""),
            mitre_mappings=[MitreMapping.from_dict(m) for m in d.get("mitre_mappings", [])],
            evidence=d.get("evidence", []),
            recommendations=d.get("recommendations", []),
            session_id=d.get("session_id", ""),
            source_ip=d.get("source_ip", ""),
            timestamp=datetime.fromisoformat(d["timestamp"]) if "timestamp" in d else datetime.now(timezone.utc),
            metadata=d.get("metadata", {}),
        )


# ──────────────────────────────────────────────
# MITRE ATT&CK Technique Database
# ──────────────────────────────────────────────

# Known technique patterns mapped to ATT&CK entries
_TECHNIQUE_PATTERNS: list[tuple[str, MitreMapping]] = [
    # Discovery
    (r"whoami", MitreMapping("T1033", "System Owner/User Discovery", "discovery")),
    (r"uname\s+-a", MitreMapping("T1082", "System Information Discovery", "discovery")),
    (r"hostname", MitreMapping("T1082", "System Information Discovery", "discovery")),
    (r"ip\s+addr|ifconfig|ipconfig", MitreMapping("T1049", "System Network Connections Discovery", "discovery")),
    (r"netstat", MitreMapping("T1049", "System Network Connections Discovery", "discovery")),
    (r"ps\s+aux|tasklist|tasklist", MitreMapping("T1057", "Process Discovery", "discovery")),
    (r"cat\s+/etc/passwd", MitreMapping("T1087", "Account Discovery", "discovery")),
    (r"id\s", MitreMapping("T1033", "System Owner/User Discovery", "discovery")),
    (r"ls\s+/", MitreMapping("T1083", "File and Directory Discovery", "discovery")),
    (r"find\s+/", MitreMapping("T1083", "File and Directory Discovery", "discovery")),
    (r"df\s+-h", MitreMapping("T1082", "System Information Discovery", "discovery")),
    (r"w", MitreMapping("T1033", "System Owner/User Discovery", "discovery")),
    (r"who", MitreMapping("T1033", "System Owner/User Discovery", "discovery")),
    (r"last", MitreMapping("T1033", "System Owner/User Discovery", "discovery")),
    # Credential Access
    (r"cat\s+/etc/shadow", MitreMapping("T1003", "OS Credential Dumping", "credential_access")),
    (r"hashdump|mimikatz|sekurlsa", MitreMapping("T1003", "OS Credential Dumping", "credential_access")),
    (r"/etc/shadow", MitreMapping("T1003.008", "OS Credential Dumping: /etc/shadow", "credential_access")),
    (r"john\s|hashcat\s", MitreMapping("T1110", "Brute Force", "credential_access")),
    # Execution
    (r"bash\s+-i|/bin/sh\s+-i", MitreMapping("T1059.004", "Unix Shell", "execution")),
    (r"python\s+-c|perl\s+-e|ruby\s+-e", MitreMapping("T1059", "Command and Scripting Interpreter", "execution")),
    (r"curl\s+.*\|\s*bash|wget\s+.*\|\s*bash", MitreMapping("T1059.004", "Unix Shell", "execution")),
    (r"eval\s*\(", MitreMapping("T1059", "Command and Scripting Interpreter", "execution")),
    (r"systemctl\s+start|systemctl\s+stop|systemctl\s+enable", MitreMapping("T1569", "System Services", "execution")),
    # Persistence
    (r"crontab\s+-e|crontab\s+-l", MitreMapping("T1053", "Scheduled Task/Job", "persistence")),
    (r"authorized_keys", MitreMapping("T1098", "Account Manipulation", "persistence")),
    (r"ssh-keygen", MitreMapping("T1098", "Account Manipulation", "persistence")),
    (r"/etc/rc\.local|/etc/init\.d/", MitreMapping("T1037", "Boot or Logon Initialization Scripts", "persistence")),
    (r"useradd\s|adduser\s", MitreMapping("T1136", "Create Account", "persistence")),
    # Privilege Escalation
    (r"sudo\s+-l", MitreMapping("T1548", "Abuse Elevation Control Mechanism", "privilege_escalation")),
    (r"chmod\s+[47]|chmod\s+u\+s", MitreMapping("T1548.001", "Setuid and Setgid", "privilege_escalation")),
    (r"su\s+root|su\s+-", MitreMapping("T1548", "Abuse Elevation Control Mechanism", "privilege_escalation")),
    # Lateral Movement
    (r"ssh\s+.*@", MitreMapping("T1021.004", "Remote Services: SSH", "lateral_movement")),
    (r"scp\s+", MitreMapping("T1021.004", "Remote Services: SSH", "lateral_movement")),
    (r"rsync\s+", MitreMapping("T1021.004", "Remote Services: SSH", "lateral_movement")),
    # Collection
    (r"tcpdump|wireshark|tshark", MitreMapping("T1040", "Network Sniffing", "collection")),
    (r"scp\s+.*:", MitreMapping("T1048", "Exfiltration Over Alternative Protocol", "exfiltration")),
    (r"nc\s+-l|ncat\s+-l", MitreMapping("T1571", "Non-Standard Port", "command_and_control")),
    # Evasion
    (r"nmap\s+.*-s[sSvO]", MitreMapping("T1046", "Network Service Scanning", "discovery")),
    (r"masscan\s+", MitreMapping("T1046", "Network Service Scanning", "discovery")),
    (r"nikto\s+", MitreMapping("T1595", "Active Scanning", "reconnaissance")),
    (r"gobuster\s+|dirb\s+|wfuzz\s+", MitreMapping("T1595.003", "Wordlist Scanning", "reconnaissance")),
    (r"sqlmap\s+", MitreMapping("T1190", "Exploit Public-Facing Application", "initial_access")),
    # C2
    (r"reverse.*shell|revshell", MitreMapping("T1059", "Command and Scripting Interpreter", "execution")),
    (r"msfvenom|meterpreter", MitreMapping("T1059", "Command and Scripting Interpreter", "execution")),
    (r"beacon|cobalt", MitreMapping("T1071", "Application Layer Protocol", "command_and_control")),
]

# STRIDE evidence patterns
_STRIDE_PATTERNS: dict[StrideCategory, list[tuple[str, float]]] = {
    StrideCategory.SPOOFING: [
        (r"curl.*localhost|wget.*127\.0\.0\.1", 0.6),
        (r"(ssh|telnet)\s+.*-l\s+root", 0.5),
    ],
    StrideCategory.TAMPERING: [
        (r"echo\s+.*>\s*/etc/", 0.7),
        (r"sed\s+-i\s+.*/etc/", 0.7),
        (r"chmod\s+.*777", 0.5),
    ],
    StrideCategory.REPUDIATION: [
        (r"rm\s+.*\.log|shred\s+", 0.6),
        (r"history\s+-c|\.bash_history", 0.5),
    ],
    StrideCategory.INFO_DISCLOSURE: [
        (r"cat\s+/etc/(passwd|shadow|issue)", 0.8),
        (r"(env|printenv|set)\s*$", 0.6),
        (r"cat\s+/proc/.*/(environ|cmdline)", 0.7),
        (r"uname\s+-a", 0.5),
        (r"is\s+this\s+(real|fake|honeypot|trap)", 0.8),
        (r"(detect|check)\s+(honeypot|vm|sandbox)", 0.9),
        (r"lsb_release|hostnamectl", 0.5),
        (r"^whoami\s*$", 0.7),
        (r"nmap\s+", 0.6),
    ],
    StrideCategory.DENIAL_OF_SERVICE: [
        (r":\(\)\{ :\|:& \};:", 0.95),  # fork bomb
        (r"dd\s+if=/dev/(zero|random)", 0.7),
        (r"stress\s+--cpu", 0.6),
        (r"forkbomb|fork_bomb", 0.8),
        (r"while\s+true.*curl", 0.6),
    ],
    StrideCategory.ELEVATION_OF_PRIVILEGE: [
        (r"sudo\s+-l", 0.6),
        (r"chmod\s+[u+s4]", 0.7),
        (r"useradd|adduser", 0.6),
        (r"visudo", 0.5),
        (r"crontab\s+", 0.6),
    ],
}


# ──────────────────────────────────────────────
# ThreatModeler — STRIDE analysis engine
# ──────────────────────────────────────────────

_RISK_SCORES = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _compute_overall_risk(threats: list[StrideThreat]) -> str:
    """Compute overall risk from individual STRIDE threats."""
    if not threats:
        return "low"
    max_score = max(_RISK_SCORES.get(t.risk_level, 1) for t in threats)
    # If any critical threat, overall is critical
    # Otherwise, use weighted average
    weighted = sum(_RISK_SCORES.get(t.risk_level, 1) * t.confidence for t in threats)
    avg = weighted / len(threats) if threats else 0

    if max_score >= 4 or avg >= 3.5:
        return "critical"
    elif max_score >= 3 or avg >= 2.5:
        return "high"
    elif avg >= 1.5:
        return "medium"
    return "low"


class ThreatModeler:
    """STRIDE threat modeling engine.

    Analyzes attacker input and session context to produce a structured
    threat model with per-category risk assessments.

    Usage::

        modeler = ThreatModeler()
        threat_model = modeler.analyze(
            attacker_input="cat /etc/shadow",
            session_context={"session_id": "ses-123", "skill_level": "expert"},
        )
        print(threat_model.overall_risk)  # "high"
        for threat in threat_model.threats:
            print(f"{threat.category}: {threat.risk_level}")
    """

    def analyze(
        self,
        attacker_input: str,
        session_context: dict[str, Any],
    ) -> ThreatModel:
        """Run STRIDE analysis on attacker input + context."""
        session_id = session_context.get("session_id", "")
        threats: list[StrideThreat] = []

        for category, patterns in _STRIDE_PATTERNS.items():
            threat = self._assess_category(category, patterns, attacker_input, session_context)
            if threat:
                threats.append(threat)

        # Check for TTP-extracted techniques from CTI
        observed_ttps = session_context.get("observed_ttps", [])
        if observed_ttps:
            for ttp in observed_ttps:
                mapped = self._map_ttp_to_stride(ttp)
                if mapped:
                    # Add as evidence to existing or new threat
                    existing = next((t for t in threats if t.category == mapped), None)
                    if existing:
                        existing.evidence.append(f"TTP: {ttp}")
                        existing.confidence = min(1.0, existing.confidence + 0.1)
                    else:
                        threats.append(
                            StrideThreat(
                                category=mapped,
                                risk_level="medium",
                                confidence=0.6,
                                evidence=[f"TTP: {ttp}"],
                                description=f"Observed technique {ttp} suggests {mapped.value} risk",
                            )
                        )

        overall_risk = _compute_overall_risk(threats)

        return ThreatModel(
            session_id=session_id,
            threats=threats,
            overall_risk=overall_risk,
            attacker_input=attacker_input,
            context=session_context,
        )

    def _assess_category(
        self,
        category: StrideCategory,
        patterns: list[tuple[str, float]],
        attacker_input: str,
        context: dict[str, Any],
    ) -> StrideThreat | None:
        """Assess a single STRIDE category against input."""
        import re

        matched_evidence: list[str] = []
        max_confidence = 0.0

        for pattern, base_confidence in patterns:
            if re.search(pattern, attacker_input, re.IGNORECASE):
                matched_evidence.append(attacker_input[:256])
                max_confidence = max(max_confidence, base_confidence)

        if not matched_evidence:
            return None

        # Boost confidence based on skill level
        skill = context.get("skill_level", "novice")
        skill_boost = {"novice": 0.0, "intermediate": 0.05, "expert": 0.1, "apt": 0.15}
        confidence = min(1.0, max_confidence + skill_boost.get(skill, 0.0))

        # Determine risk level from confidence
        if confidence >= 0.8:
            risk = "critical"
        elif confidence >= 0.6:
            risk = "high"
        elif confidence >= 0.4:
            risk = "medium"
        else:
            risk = "low"

        return StrideThreat(
            category=category,
            risk_level=risk,
            confidence=round(confidence, 4),
            evidence=matched_evidence,
            description=f"Attacker input matches {category.value} patterns",
            mitigation=self._get_mitigation(category),
        )

    def _map_ttp_to_stride(self, ttp: str) -> StrideCategory | None:
        """Map a MITRE technique ID to a STRIDE category."""
        mapping = {
            "T1033": StrideCategory.INFO_DISCLOSURE,
            "T1082": StrideCategory.INFO_DISCLOSURE,
            "T1083": StrideCategory.INFO_DISCLOSURE,
            "T1087": StrideCategory.INFO_DISCLOSURE,
            "T1049": StrideCategory.INFO_DISCLOSURE,
            "T1057": StrideCategory.INFO_DISCLOSURE,
            "T1003": StrideCategory.ELEVATION_OF_PRIVILEGE,
            "T1003.008": StrideCategory.ELEVATION_OF_PRIVILEGE,
            "T1110": StrideCategory.SPOOFING,
            "T1059": StrideCategory.ELEVATION_OF_PRIVILEGE,
            "T1059.004": StrideCategory.ELEVATION_OF_PRIVILEGE,
            "T1053": StrideCategory.ELEVATION_OF_PRIVILEGE,
            "T1098": StrideCategory.ELEVATION_OF_PRIVILEGE,
            "T1037": StrideCategory.ELEVATION_OF_PRIVILEGE,
            "T1136": StrideCategory.ELEVATION_OF_PRIVILEGE,
            "T1548": StrideCategory.ELEVATION_OF_PRIVILEGE,
            "T1548.001": StrideCategory.ELEVATION_OF_PRIVILEGE,
            "T1021.004": StrideCategory.SPOOFING,
            "T1040": StrideCategory.INFO_DISCLOSURE,
            "T1046": StrideCategory.INFO_DISCLOSURE,
            "T1048": StrideCategory.INFO_DISCLOSURE,
            "T1190": StrideCategory.ELEVATION_OF_PRIVILEGE,
            "T1071": StrideCategory.SPOOFING,
            "T1595": StrideCategory.INFO_DISCLOSURE,
            "T1595.003": StrideCategory.INFO_DISCLOSURE,
            "T1571": StrideCategory.SPOOFING,
            "T1569": StrideCategory.TAMPERING,
        }
        return mapping.get(ttp)

    def _get_mitigation(self, category: StrideCategory) -> str:
        """Return mitigation advice for a STRIDE category."""
        mitigations = {
            StrideCategory.SPOOFING: "Enforce multi-factor authentication; validate identity at each stage",
            StrideCategory.TAMPERING: "Use integrity checks; log all state changes; isolate critical data",
            StrideCategory.REPUDIATION: "Maintain append-only audit logs; timestamp all events",
            StrideCategory.INFO_DISCLOSURE: "Minimize information leakage; use deceptive responses; vary behavior",
            StrideCategory.DENIAL_OF_SERVICE: "Rate-limit commands; detect fork bombs; resource isolation",
            StrideCategory.ELEVATION_OF_PRIVILEGE: "Least privilege; monitor sudo/su usage; alert on escalation",
        }
        return mitigations.get(category, "Monitor and log activity")


# ──────────────────────────────────────────────
# Response Verification (threat-model-aware)
# ──────────────────────────────────────────────


@dataclass
class VerificationResult:
    """Result of response verification against threat model."""

    passed: bool
    confidence: float  # 0.0–1.0
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "confidence": self.confidence,
            "issues": self.issues,
            "recommendations": self.recommendations,
            "metadata": self.metadata,
        }


class ThreatModelResponseVerifier:
    """Verifies deception responses against the threat model.

    Checks:
    1. Response doesn't leak honeypot indicators when threat level is high
    2. Response complexity matches attacker skill level
    3. Response doesn't contradict the assigned persona
    4. Response doesn't reveal information that would help evasion

    This is a threat-model-aware version of the basic ResponseVerifier protocol.
    It integrates with ThreatModeler output to make context-sensitive decisions.

    Usage::

        verifier = ThreatModelResponseVerifier()
        result = verifier.verify(
            response={"response_text": "Welcome to...", "persona_used": "linux_admin"},
            session_context={"threat_model": threat_model.to_dict()},
        )
        print(result.passed, result.issues)
    """

    def verify(
        self,
        response: dict[str, Any],
        session_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Verify a response against threat model and context.

        Returns dict compatible with Harness's ResponseVerifier protocol.
        """
        issues: list[str] = []
        recommendations: list[str] = []
        confidence = 1.0

        response_text = response.get("response_text", "")
        persona = response.get("persona_used", "")
        threat_model_data = session_context.get("threat_model", {})
        skill_level = session_context.get("skill_level", "novice")

        # Check 1: Response length appropriateness
        if response_text and len(response_text) > 2000:
            issues.append("Response excessively long — may reveal too much information")
            confidence -= 0.15

        # Check 2: Honeypot indicator leakage
        honeypot_indicators = [
            "honeypot",
            "this is a trap",
            "you are being monitored",
            "deception system",
            "fake server",
            "canary",
        ]
        for indicator in honeypot_indicators:
            if indicator.lower() in response_text.lower():
                issues.append(f"Response contains honeypot indicator: '{indicator}'")
                confidence -= 0.3

        # Check 3: Skill level matching
        if skill_level == "expert" and len(response_text) < 20:
            recommendations.append("Expert-level attacker may expect detailed responses")
            confidence -= 0.05

        # Check 4: Threat model consistency
        overall_risk = threat_model_data.get("overall_risk", "low")
        if (
            overall_risk in ("high", "critical")
            and "error" in response_text.lower()
            and "not found" in response_text.lower()
        ):
            recommendations.append("Consider more deceptive error messages for high-risk sessions")

        # Check 5: Empty response
        if not response_text or not response_text.strip():
            issues.append("Empty response — may break engagement")
            confidence -= 0.2

        # Check 6: Persona consistency
        if persona and response_text:
            # If persona is set but response doesn't match any known persona
            valid_personas = {"linux_admin", "windows_admin", "db_admin", "novice_user", "security_analyst", "generic"}
            if persona not in valid_personas:
                recommendations.append(f"Unknown persona '{persona}' — verify persona routing")

        passed = confidence >= 0.5 and len(issues) == 0

        return {
            "passed": passed,
            "confidence": max(0.0, confidence),
            "issues": issues,
            "recommendations": recommendations,
        }


# ──────────────────────────────────────────────
# Attack Chain Builder
# ──────────────────────────────────────────────


@dataclass
class AttackChainStep:
    """A single step in a reconstructed attack chain."""

    step_index: int
    technique_id: str
    technique_name: str
    tactic: str
    evidence: str = ""
    timestamp: str = ""
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_index": self.step_index,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
        }


@dataclass
class AttackChain:
    """A reconstructed attack chain from observed TTPs."""

    session_id: str
    steps: list[AttackChainStep] = field(default_factory=list)
    kill_chain_phases: list[str] = field(default_factory=list)
    confidence: float = 0.0
    attacker_sophistication: str = "unknown"

    @property
    def step_count(self) -> int:
        return len(self.steps)

    @property
    def tactics_covered(self) -> list[str]:
        return sorted({s.tactic for s in self.steps})

    @property
    def duration_estimate(self) -> str:
        """Rough estimate of attack duration based on step count."""
        if self.step_count <= 3:
            return "quick_probe"
        elif self.step_count <= 8:
            return "focused_attack"
        elif self.step_count <= 15:
            return "extended_campaign"
        return "persistent_presence"

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "steps": [s.to_dict() for s in self.steps],
            "kill_chain_phases": self.kill_chain_phases,
            "confidence": self.confidence,
            "attacker_sophistication": self.attacker_sophistication,
            "step_count": self.step_count,
            "tactics_covered": self.tactics_covered,
            "duration_estimate": self.duration_estimate,
        }


# Kill chain phase ordering
_KILL_CHAIN_ORDER = [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]


def _estimate_sophistication(steps: list[AttackChainStep]) -> str:
    """Estimate attacker sophistication from the attack chain."""
    if not steps:
        return "unknown"

    tactics = {s.tactic for s in steps}
    technique_count = len(steps)

    # APT indicators
    apt_tactics = {"defense_evasion", "credential_access", "lateral_movement", "exfiltration"}
    apt_overlap = tactics & apt_tactics

    if len(apt_overlap) >= 3 and technique_count >= 10:
        return "apt"
    elif len(apt_overlap) >= 2 or technique_count >= 7:
        return "expert"
    elif technique_count >= 3:
        return "intermediate"
    elif technique_count >= 1:
        return "novice"
    return "unknown"


class AttackChainBuilder:
    """Constructs attack chains from observed TTPs in a session.

    Usage::

        builder = AttackChainBuilder()
        chain = builder.build(
            session_id="ses-123",
            ttps=[
                {"technique_id": "T1033", "technique_name": "System Owner/User Discovery",
                 "tactic": "discovery", "evidence": "whoami"},
                {"technique_id": "T1082", "technique_name": "System Information Discovery",
                 "tactic": "discovery", "evidence": "uname -a"},
                {"technique_id": "T1003", "technique_name": "OS Credential Dumping",
                 "tactic": "credential_access", "evidence": "cat /etc/shadow"},
            ],
        )
        print(chain.attacker_sophistication)  # "intermediate"
    """

    def build(
        self,
        session_id: str,
        ttps: list[dict[str, Any]],
    ) -> AttackChain:
        """Build an attack chain from a list of observed TTPs."""
        steps: list[AttackChainStep] = []

        for i, ttp in enumerate(ttps):
            step = AttackChainStep(
                step_index=i + 1,
                technique_id=ttp.get("technique_id", "T0000"),
                technique_name=ttp.get("technique_name", "Unknown"),
                tactic=ttp.get("tactic", "unknown"),
                evidence=ttp.get("evidence", ""),
                timestamp=ttp.get("timestamp", ""),
                confidence=ttp.get("confidence", 0.5),
            )
            steps.append(step)

        # Sort by tactic in kill chain order
        tactic_order = {t: i for i, t in enumerate(_KILL_CHAIN_ORDER)}
        steps.sort(key=lambda s: tactic_order.get(s.tactic, 99))

        # Re-index after sorting
        for i, step in enumerate(steps):
            step.step_index = i + 1

        # Determine kill chain phases covered
        kill_chain_phases = sorted({s.tactic for s in steps if s.tactic in tactic_order})

        # Estimate confidence
        confidence = sum(s.confidence for s in steps) / len(steps) if steps else 0.0

        sophistication = _estimate_sophistication(steps)

        return AttackChain(
            session_id=session_id,
            steps=steps,
            kill_chain_phases=kill_chain_phases,
            confidence=round(confidence, 4),
            attacker_sophistication=sophistication,
        )

    def build_from_session_context(
        self,
        session_id: str,
        session_context: dict[str, Any],
    ) -> AttackChain:
        """Build attack chain from session context (TTPs, classifications, etc.)."""
        ttps = []

        # Extract from observed_ttps
        for ttp_id in session_context.get("observed_ttps", []):
            mapped = _map_ttp_to_mitre(ttp_id)
            if mapped:
                ttps.append(
                    {
                        "technique_id": mapped.technique_id,
                        "technique_name": mapped.technique_name,
                        "tactic": mapped.tactic,
                    }
                )

        # Extract from TTP history events
        for ttp_event in session_context.get("ttp_history", []):
            if isinstance(ttp_event, dict):
                ttps.append(ttp_event)

        return self.build(session_id, ttps)


def _map_ttp_to_mitre(technique_id: str) -> MitreMapping | None:
    """Map a technique ID to a full MITRE mapping."""
    for _, mapping in _TECHNIQUE_PATTERNS:
        if mapping.technique_id == technique_id:
            return mapping
    return None
