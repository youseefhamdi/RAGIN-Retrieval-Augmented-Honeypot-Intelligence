"""Multi-turn TTP tracking — session-level TTP accumulation, evolution, and escalation metrics.

Extends per-turn TTP extraction with cross-turn analytics:
- TTP diversity (unique TTPs vs total turns)
- TTP persistence (how many turns a TTP stays active)
- Escalation detection (TTP severity progression across turns)
- Session-level TTP summary for benchmark aggregation
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TurnTTPSnapshot:
    """TTP state at a single turn."""

    turn_number: int
    ttps: set[str] = field(default_factory=set)
    severity: str = "info"
    attacker_input: str = ""
    artifacts_accessed: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "turn": self.turn_number,
            "ttps": sorted(self.ttps),
            "severity": self.severity,
            "attacker_input_preview": self.attacker_input[:128],
            "artifacts_accessed": self.artifacts_accessed,
        }


@dataclass
class TTPEvolution:
    """Tracks how a single TTP evolves across turns."""

    ttp_id: str
    first_seen_turn: int
    last_seen_turn: int = 0
    appearances: int = 0
    peak_severity: str = "info"
    consecutive: int = 0  # max consecutive turns this TTP was seen
    _current_streak: int = 0

    def record_turn(self, turn: int, severity: str = "info") -> None:
        self.appearances += 1
        self.last_seen_turn = turn
        if self._severity_rank(severity) > self._severity_rank(self.peak_severity):
            self.peak_severity = severity
        self._current_streak += 1
        if self._current_streak > self.consecutive:
            self.consecutive = self._current_streak

    def break_streak(self) -> None:
        self._current_streak = 0

    @staticmethod
    def _severity_rank(sev: str) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ttp_id": self.ttp_id,
            "first_seen_turn": self.first_seen_turn,
            "last_seen_turn": self.last_seen_turn,
            "appearances": self.appearances,
            "peak_severity": self.peak_severity,
            "max_consecutive": self.consecutive,
        }


@dataclass
class SessionTTPSummary:
    """Aggregated TTP metrics for an entire multi-turn session."""

    session_id: str = ""
    total_turns: int = 0
    unique_ttps: set[str] = field(default_factory=set)
    total_ttp_detections: int = 0
    ttp_diversity_ratio: float = 0.0  # unique_ttps / total_turns
    escalation_detected: bool = False
    escalation_turn: int | None = None
    escalation_from: str = ""
    escalation_to: str = ""
    persistent_ttps: list[str] = field(default_factory=list)  # TTPs seen in >1 turn
    new_ttps_per_turn: list[int] = field(default_factory=list)
    ttp_evolutions: list[TTPEvolution] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "total_turns": self.total_turns,
            "unique_ttps": sorted(self.unique_ttps),
            "total_ttp_detections": self.total_ttp_detections,
            "ttp_diversity_ratio": round(self.ttp_diversity_ratio, 3),
            "escalation_detected": self.escalation_detected,
            "escalation_turn": self.escalation_turn,
            "escalation_from": self.escalation_from,
            "escalation_to": self.escalation_to,
            "persistent_ttps": self.persistent_ttps,
            "new_ttps_per_turn": self.new_ttps_per_turn,
            "ttp_evolutions": [e.to_dict() for e in self.ttp_evolutions],
        }


class MultiTurnTracker:
    """Track TTP accumulation and evolution across turns in a session.

    Usage::

        tracker = MultiTurnTracker("session-123")

        # After each turn, feed TTPs
        tracker.record_turn(
            turn=1,
            ttps={"T1059", "T1071"},
            severity="medium",
            attacker_input="whoami",
        )

        tracker.record_turn(
            turn=2,
            ttps={"T1059", "T1021"},
            severity="high",
            attacker_input="psexec",
        )

        summary = tracker.get_summary()
        # summary.escalation_detected == True (medium -> high)
        # summary.unique_ttps == {"T1059", "T1071", "T1021"}
        # summary.persistent_ttps == ["T1059"]
    """

    def __init__(self, session_id: str = "") -> None:
        self.session_id = session_id
        self._turns: list[TurnTTPSnapshot] = []
        self._ttp_evolutions: dict[str, TTPEvolution] = {}
        self._prev_severity: str = "info"
        logger.debug("MultiTurnTracker initialized for session %s", session_id)

    def record_turn(
        self,
        turn: int,
        ttps: set[str] | None = None,
        severity: str = "info",
        attacker_input: str = "",
        artifacts_accessed: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> TurnTTPSnapshot:
        """Record TTP state for a single turn."""
        ttp_set = ttps or set()
        snapshot = TurnTTPSnapshot(
            turn_number=turn,
            ttps=ttp_set,
            severity=severity,
            attacker_input=attacker_input,
            artifacts_accessed=artifacts_accessed,
            metadata=metadata or {},
        )
        self._turns.append(snapshot)

        # Update per-TTP evolution
        for ttp_id in ttp_set:
            if ttp_id not in self._ttp_evolutions:
                self._ttp_evolutions[ttp_id] = TTPEvolution(
                    ttp_id=ttp_id,
                    first_seen_turn=turn,
                    last_seen_turn=turn,
                )
            self._ttp_evolutions[ttp_id].record_turn(turn, severity)

        # Break streak for TTPs not seen this turn
        for ttp_id, evo in self._ttp_evolutions.items():
            if ttp_id not in ttp_set:
                evo.break_streak()

        self._prev_severity = severity
        return snapshot

    def get_summary(self) -> SessionTTPSummary:
        """Compute session-level TTP summary."""
        if not self._turns:
            return SessionTTPSummary(session_id=self.session_id)

        all_ttps: set[str] = set()
        for snap in self._turns:
            all_ttps.update(snap.ttps)

        total_detections = sum(len(snap.ttps) for snap in self._turns)
        diversity = len(all_ttps) / max(len(self._turns), 1)

        # Escalation detection: severity increased across consecutive turns
        escalation_detected = False
        escalation_turn = None
        escalation_from = ""
        escalation_to = ""
        prev_rank = -1
        seen_first = False
        sev_order = ["info", "low", "medium", "high", "critical"]
        for snap in self._turns:
            cur_rank = sev_order.index(snap.severity) if snap.severity in sev_order else 0
            if seen_first and cur_rank > prev_rank and not escalation_detected:
                escalation_detected = True
                escalation_turn = snap.turn_number
                escalation_from = sev_order[prev_rank]
                escalation_to = snap.severity
            prev_rank = cur_rank
            seen_first = True

        # Persistent TTPs: seen in >1 turn
        ttp_turn_counts: dict[str, int] = defaultdict(int)
        for snap in self._turns:
            for ttp in snap.ttps:
                ttp_turn_counts[ttp] += 1
        persistent = sorted(ttp for ttp, count in ttp_turn_counts.items() if count > 1)

        # New TTPs per turn
        seen_so_far: set[str] = set()
        new_per_turn: list[int] = []
        for snap in self._turns:
            new = snap.ttps - seen_so_far
            new_per_turn.append(len(new))
            seen_so_far.update(snap.ttps)

        return SessionTTPSummary(
            session_id=self.session_id,
            total_turns=len(self._turns),
            unique_ttps=all_ttps,
            total_ttp_detections=total_detections,
            ttp_diversity_ratio=diversity,
            escalation_detected=escalation_detected,
            escalation_turn=escalation_turn,
            escalation_from=escalation_from,
            escalation_to=escalation_to,
            persistent_ttps=persistent,
            new_ttps_per_turn=new_per_turn,
            ttp_evolutions=list(self._ttp_evolutions.values()),
        )

    def get_ttp_evolution(self, ttp_id: str) -> TTPEvolution | None:
        return self._ttp_evolutions.get(ttp_id)

    def reset(self) -> None:
        self._turns.clear()
        self._ttp_evolutions.clear()
        self._prev_severity = "info"


logger = logging.getLogger(__name__)
