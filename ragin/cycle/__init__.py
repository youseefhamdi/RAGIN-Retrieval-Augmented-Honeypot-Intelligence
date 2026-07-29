"""
Intelligence Cycle — closed feedback loop between Don (CTI analysis) and Hisoka (deception).

When Hisoka learns attacker TTPs from interactions, Don uses that intelligence
to dynamically adjust persona selection, CTI-informed responses, and deception
strategy. This creates a self-improving deception environment.

Architecture (HARNESS_LOOP_PLAN.md):
    Harness (stateless loop) → Session (append-only event log) → Sandbox (attacker I/O)

Flow:
    Attacker → Hisoka (interaction) → TTP Extraction → Don (CTI enrichment)
         ↑                                                          ↓
         ←── Refined Persona + Context + Artifacts ←── Strategy Update ←──

Components:
    Session  — append-only crash-safe JSONL event log
    Harness  — stateless orchestration loop (Chrollo → Don → Hisoka)
    Sandbox  — isolated execution environment for attacker interactions
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ragin.cycle.adapters import ChrolloAdapter, DonAdapter, HisokaAdapter
from ragin.cycle.harness import Harness, PipelineResult
from ragin.cycle.sandbox import Sandbox, SandboxConfig, SandboxResponse

# Re-export new cycle components
from ragin.cycle.session import Event, EventType, Session
from ragin.hisoka.models import DeceptionResponse

# Re-export coordination patterns
with contextlib.suppress(ImportError):
    from ragin.cycle.coordination import (
        DeceptionReviewer,
        DelegationChain,
        DelegationResult,
        DelegationStatus,
        EnhancedProducerReviewer,
        ExpertPool,
        ExpertResult,
        PersonaRoute,
        QualityReviewer,
        RiskLevel,
        RoutingDecision,
        SecurityReviewer,
        Supervisor,
        VoteOutcome,
        VoteResult,
        VotingSystem,
    )

# Re-export Phase 4: Threat Modeling & Verification
try:
    from ragin.cycle.metrics import (
        InteractionMetrics,
        MTTATracker,
        SessionMetrics,
        StageTimer,
        StageTiming,
    )
    from ragin.cycle.threat_modeling import (
        AttackChain,
        AttackChainBuilder,
        AttackChainStep,
        FindingSeverity,
        FindingStatus,
        MitreMapping,
        StrideCategory,
        StrideThreat,
        StructuredFinding,
        ThreatModel,
        ThreatModeler,
        ThreatModelResponseVerifier,
        VerificationResult,
    )
except ImportError:
    pass

logger = logging.getLogger(__name__)

# ── MITRE ATT&CK TTP extraction patterns ─────────────────────────────────────

_TTP_KEYWORDS: dict[str, list[str]] = {
    # Initial Access
    "T1566": ["phishing", "spearphish", "email attachment", "malicious link"],
    "T1190": ["exploit public", "web application", "rce", "remote code execution"],
    "T1133": ["external remote", "brute force", "rdp", "vpn"],
    # Execution
    "T1059": ["powershell", "cmd.exe", "command line", "script", "wscript"],
    "T1053": ["scheduled task", "cron", "at.exe", "schtasks"],
    "T1047": ["wmic", "wmi", "remote execution"],
    # Persistence
    "T1547": ["registry run", "startup", "autostart", "boot"],
    "T1543": ["systemd", "launchd", "service", "daemon"],
    # Privilege Escalation
    "T1068": ["exploit", "privilege escalation", "escalate"],
    "T1055": ["process injection", "dll injection", "inject"],
    # Defense Evasion
    "T1027": ["obfuscate", "encode", "encrypt", "pack"],
    "T1070": ["clear log", "timestomp", "delete event", "clean"],
    "T1562": ["disable", "tamper", "defender", "firewall", "security tool"],
    # Credential Access
    "T1003": ["credential dump", "mimikatz", "lsass", "sam", "ntds"],
    "T1110": ["brute force", "password spray", "credential stuffing"],
    # Discovery
    "T1087": ["whoami", "net user", "net group", "domain", "enum"],
    "T1018": ["net view", "ping", "scan", "port scan", "nmap"],
    # Lateral Movement
    "T1021": ["smb", "psexec", "wmi remote", "rdp", "ssh"],
    "T1570": ["lateral tool", "file transfer"],
    # Exfiltration
    "T1041": ["exfiltration", "c2 channel", "data upload"],
    "T1567": ["exfiltration over web", "paste site", "cloud storage"],
    # Impact
    "T1486": ["ransomware", "encrypt", "ransom", "decrypt"],
    "T1489": ["service stop", "kill process"],
}


@dataclass
class TTPExtraction:
    """Extracted TTPs from a single interaction."""

    technique_ids: list[str] = field(default_factory=list)
    tactic_ids: list[str] = field(default_factory=list)
    confidence: float = 0.0
    indicators: list[str] = field(default_factory=list)


@dataclass
class DeceptionStrategy:
    """Strategy updates derived from the intelligence cycle."""

    recommended_persona: str = ""
    persona_reason: str = ""
    context_enrichments: list[str] = field(default_factory=list)
    artifact_suggestions: list[str] = field(default_factory=list)
    ttp_focus: list[str] = field(default_factory=list)
    attacker_profile: str = ""
    risk_level: str = "low"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "recommended_persona": self.recommended_persona,
            "persona_reason": self.persona_reason,
            "context_enrichments": self.context_enrichments,
            "artifact_suggestions": self.artifact_suggestions,
            "ttp_focus": self.ttp_focus,
            "attacker_profile": self.attacker_profile,
            "risk_level": self.risk_level,
            "timestamp": self.timestamp,
        }


def extract_ttps(text: str) -> TTPExtraction:
    """Extract MITRE ATT&CK TTPs from interaction text using keyword matching.

    This is a lightweight extraction that doesn't require an LLM — suitable
    for real-time enrichment during active sessions.
    """
    text_lower = text.lower()
    found_techniques: set[str] = set()
    found_indicators: list[str] = []

    for technique_id, keywords in _TTP_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in text_lower:
                found_techniques.add(technique_id)
                found_indicators.append(kw)
                break

    # Map technique IDs to tactic IDs
    tactic_map = {
        "T1566": "TA0001",
        "T1190": "TA0001",
        "T1133": "TA0001",
        "T1059": "TA0002",
        "T1053": "TA0003",
        "T1047": "TA0002",
        "T1547": "TA0003",
        "T1543": "TA0003",
        "T1068": "TA0004",
        "T1055": "TA0005",
        "T1027": "TA0005",
        "T1070": "TA0005",
        "T1562": "TA0005",
        "T1003": "TA0006",
        "T1110": "TA0006",
        "T1087": "TA0007",
        "T1018": "TA0007",
        "T1021": "TA0008",
        "T1570": "TA0008",
        "T1041": "TA0010",
        "T1567": "TA0010",
        "T1486": "TA0040",
        "T1489": "TA0040",
    }
    found_tactics = {tactic_map[tid] for tid in found_techniques if tid in tactic_map}

    # Confidence based on number of matching indicators
    confidence = min(len(found_indicators) / 5, 1.0) if found_indicators else 0.0

    return TTPExtraction(
        technique_ids=sorted(found_techniques),
        tactic_ids=sorted(found_tactics),
        confidence=confidence,
        indicators=found_indicators,
    )


def _determine_risk_level(ttps: TTPExtraction, interaction_count: int) -> str:
    """Determine attacker risk level from extracted TTPs and engagement."""
    if "T1486" in ttps.technique_ids or "T1003" in ttps.technique_ids:
        return "critical"
    if len(ttps.technique_ids) >= 5 or interaction_count >= 20:
        return "high"
    if len(ttps.technique_ids) >= 3 or interaction_count >= 10:
        return "medium"
    return "low"


def _suggest_persona(ttps: TTPExtraction) -> tuple[str, str]:
    """Suggest persona based on observed TTPs."""
    techniques = set(ttps.technique_ids)

    # APT-level indicators
    apt_techniques = {"T1562", "T1027", "T1070", "T1068", "T1570"}
    if techniques & apt_techniques:
        return "apt", "Observed advanced defense evasion and persistence techniques"

    # Expert indicators
    expert_techniques = {"T1003", "T1055", "T1021", "T1047"}
    if techniques & expert_techniques:
        return "expert", "Observed credential dumping and lateral movement"

    # Intermediate indicators
    intermediate_techniques = {"T1059", "T1053", "T1087", "T1018"}
    if techniques & intermediate_techniques:
        return "intermediate", "Observed discovery and execution techniques"

    return "novice", "Limited TTP indicators — maintaining baseline engagement"


def _suggest_artifacts(ttps: TTPExtraction) -> list[str]:
    """Suggest honeytoken artifacts based on observed TTPs."""
    suggestions: list[str] = []
    techniques = set(ttps.technique_ids)

    if "T1003" in techniques:
        suggestions.extend(
            [
                "fake_lsass_dump.txt",
                "fake_sam_registry.hive",
                "credential_file Documents/backup_credentials.txt",
            ]
        )
    if "T1087" in techniques or "T1018" in techniques:
        suggestions.extend(
            [
                "fake_network_diagram.pdf",
                "fake_asset_inventory.xlsx",
                "fake_ad_enumeration_notes.txt",
            ]
        )
    if "T1547" in techniques or "T1053" in techniques:
        suggestions.extend(
            [
                "fake_autorun_script.ps1",
                "fake_scheduled_task_config.xml",
            ]
        )
    if "T1486" in techniques:
        suggestions.extend(
            [
                "fake_ransom_note.txt",
                "fake_decryption_instructions.html",
            ]
        )
    if "T1041" in techniques or "T1567" in techniques:
        suggestions.extend(
            [
                "fake_exfiltration_server_config.json",
                "fake_data_dump_sample.csv",
            ]
        )

    return suggestions


class IntelligenceCycle:
    """Orchestrates the closed feedback loop between Don and Hisoka.

    Usage::

        cycle = IntelligenceCycle()

        # After each attacker interaction:
        ttps = cycle.extract_ttps_from_interaction(attacker_input + response_text)
        strategy = cycle.compute_strategy(ttps, session_history)

        # Feed strategy back into Hisoka's context
        hisoka_context["strategy"] = strategy
    """

    def __init__(self) -> None:
        self._interaction_ttps: dict[str, list[TTPExtraction]] = {}
        self._strategies: dict[str, list[DeceptionStrategy]] = {}

    def extract_ttps_from_interaction(
        self,
        text: str,
        session_id: str = "",
    ) -> TTPExtraction:
        """Extract TTPs from attacker interaction text.

        Optionally accumulates per-session TTP history.
        """
        ttps = extract_ttps(text)

        if session_id:
            self._interaction_ttps.setdefault(session_id, []).append(ttps)

        return ttps

    def get_session_ttps(self, session_id: str) -> list[TTPExtraction]:
        """Get all TTPs observed in a session."""
        return self._interaction_ttps.get(session_id, [])

    def get_unique_techniques(self, session_id: str) -> list[str]:
        """Get unique technique IDs observed across all interactions in a session."""
        all_techniques: set[str] = set()
        for ttps in self._interaction_ttps.get(session_id, []):
            all_techniques.update(ttps.technique_ids)
        return sorted(all_techniques)

    def compute_strategy(
        self,
        ttps: TTPExtraction,
        session_id: str = "",
        interaction_count: int = 1,
    ) -> DeceptionStrategy:
        """Compute a deception strategy update based on observed TTPs.

        Returns a DeceptionStrategy with recommended persona, context
        enrichments, and artifact suggestions.
        """
        persona, reason = _suggest_persona(ttps)
        risk_level = _determine_risk_level(ttps, interaction_count)
        artifacts = _suggest_artifacts(ttps)

        # Context enrichments — what to tell the deceiver
        enrichments: list[str] = []
        if ttps.technique_ids:
            enrichments.append(f"Attacker has demonstrated: {', '.join(ttps.technique_ids[:5])}")
        if ttps.tactic_ids:
            enrichments.append(f"Active tactic phases: {', '.join(ttps.tactic_ids)}")
        if risk_level in ("high", "critical"):
            enrichments.append(
                f"Risk level elevated to {risk_level} — increase engagement, " "deploy additional artifacts"
            )

        # Build attacker profile from accumulated session TTPs
        if session_id:
            unique_techs = self.get_unique_techniques(session_id)
            profile_parts = [f"Techniques observed: {', '.join(unique_techs)}"]
            profile_parts.append(f"Risk level: {risk_level}")
            attacker_profile = "; ".join(profile_parts)
        else:
            attacker_profile = f"Techniques: {', '.join(ttps.technique_ids)}; Risk: {risk_level}"

        strategy = DeceptionStrategy(
            recommended_persona=persona,
            persona_reason=reason,
            context_enrichments=enrichments,
            artifact_suggestions=artifacts,
            ttp_focus=ttps.technique_ids,
            attacker_profile=attacker_profile,
            risk_level=risk_level,
        )

        if session_id:
            self._strategies.setdefault(session_id, []).append(strategy)

        return strategy

    def get_strategy_history(self, session_id: str) -> list[DeceptionStrategy]:
        """Get all strategy updates for a session."""
        return self._strategies.get(session_id, [])

    def clear_session(self, session_id: str) -> None:
        """Clear accumulated data for a completed session."""
        self._interaction_ttps.pop(session_id, None)
        self._strategies.pop(session_id, None)
