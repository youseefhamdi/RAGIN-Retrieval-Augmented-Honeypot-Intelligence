"""Session — append-only, crash-safe event log for attacker interactions.

Design principles from Anthropic Managed Agents:
- Session = append-only log (durable, interrogatable, survives crashes)
- State lives OUTSIDE the context window (in files, not memory)
- Pets → Cattle: honeypot instances can die, sessions survive
- wake(sessionId) resumes from durable log, not from in-memory state
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_SESSION_DIR = os.environ.get("RAGIN_SESSION_DIR", "data/sessions")


class EventType(str, Enum):
    """All event types that can occur in a session."""

    # Lifecycle
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    SESSION_RESUME = "session_resume"

    # Attacker interaction
    ATTACKER_INPUT = "attacker_input"
    SYSTEM_RESPONSE = "system_response"

    # Pipeline stages
    CLASSIFICATION = "classification"
    CTI_LOOKUP = "cti_lookup"
    PERSONA_SELECT = "persona_select"
    RESPONSE_GENERATE = "response_generate"
    RESPONSE_VERIFY = "response_verify"

    # Deception
    ARTIFACT_INJECT = "artifact_inject"
    HONEYTOKEN_PLANT = "honeytoken_plant"

    # Intelligence cycle
    TTP_EXTRACT = "ttp_extract"
    STRATEGY_UPDATE = "strategy_update"

    # Phase 4: Threat Modeling & Verification
    THREAT_MODEL = "threat_model"
    FINDING = "finding"
    ATTACK_CHAIN = "attack_chain"
    VERIFICATION = "verification"

    # System
    HEARTBEAT = "heartbeat"
    ERROR = "error"
    METRIC = "metric"


@dataclass
class Event:
    """A single immutable event in the session log."""

    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    event_type: EventType = EventType.HEARTBEAT
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    data: dict[str, Any] = field(default_factory=dict)
    source: str = ""  # which component emitted this

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Event:
        return cls(
            event_id=d["event_id"],
            event_type=EventType(d["event_type"]),
            timestamp=datetime.fromisoformat(d["timestamp"]),
            data=d.get("data", {}),
            source=d.get("source", ""),
        )


class Session:
    """Append-only, crash-safe session log.

    Events are written to a JSONL file on disk immediately (fsync after each
    write). Reading reconstructs state from the log — no in-memory state is
    trusted after a crash.

    Usage::

        session = Session.create(source_ip="10.0.0.1")
        session.emit(EventType.ATTACKER_INPUT, {"command": "whoami"}, source="sandbox")
        session.emit(EventType.SYSTEM_RESPONSE, {"text": "root"}, source="hisoka")

        # Later (even after crash):
        recovered = Session.wake(session.session_id)
        history = recovered.replay()
    """

    def __init__(
        self,
        session_id: str,
        session_dir: str | Path | None = None,
    ) -> None:
        self.session_id = session_id
        self._dir = Path(session_dir or _DEFAULT_SESSION_DIR)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self._dir / f"{session_id}.jsonl"
        self._meta_path = self._dir / f"{session_id}.meta.json"
        self._event_count = 0
        self._closed = False

        # Load existing event count if log exists
        if self._log_path.exists():
            self._event_count = sum(1 for _ in self._log_path.open())

    # ── Factory methods ──────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        source_ip: str = "",
        session_dir: str | Path | None = None,
    ) -> Session:
        """Create a new session with a unique ID."""
        session_id = f"ses-{uuid.uuid4().hex[:16]}"
        session = cls(session_id, session_dir=session_dir)
        session.emit(
            EventType.SESSION_START,
            {"source_ip": source_ip, "session_id": session_id},
            source="harness",
        )
        return session

    @classmethod
    def wake(
        cls,
        session_id: str,
        session_dir: str | Path | None = None,
    ) -> Session:
        """Resume a session from its durable log on disk.

        Raises FileNotFoundError if the session doesn't exist.
        """
        session = cls(session_id, session_dir=session_dir)
        if not session._log_path.exists():
            raise FileNotFoundError(f"Session {session_id} not found at {session._log_path}")
        session.emit(
            EventType.SESSION_RESUME,
            {"session_id": session_id, "resumed_events": session._event_count},
            source="harness",
        )
        logger.info(
            "Session %s resumed from %d existing events",
            session_id,
            session._event_count,
        )
        return session

    # ── Append-only event writing ────────────────────────────────────────

    def emit(
        self,
        event_type: EventType,
        data: dict[str, Any] | None = None,
        source: str = "",
    ) -> Event:
        """Append an event to the session log. Always succeeds or raises."""
        if self._closed:
            raise RuntimeError(f"Session {self.session_id} is closed")

        event = Event(
            event_type=event_type,
            data=data or {},
            source=source,
        )
        line = json.dumps(event.to_dict(), default=str) + "\n"

        with open(self._log_path, "a") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

        self._event_count += 1
        return event

    # ── Replay / read ────────────────────────────────────────────────────

    def replay(self) -> list[Event]:
        """Read all events from the log, in order."""
        events: list[Event] = []
        if not self._log_path.exists():
            return events
        with open(self._log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                events.append(Event.from_dict(json.loads(line)))
        return events

    def replay_since(self, after_event_id: str) -> list[Event]:
        """Read events after a specific event_id (for incremental replay)."""
        found = False
        events: list[Event] = []
        for event in self.replay():
            if found:
                events.append(event)
            if event.event_id == after_event_id:
                found = True
        return events

    def get_events_by_type(self, event_type: EventType) -> list[Event]:
        """Filter events by type."""
        return [e for e in self.replay() if e.event_type == event_type]

    def get_last_event(self) -> Event | None:
        """Get the most recent event."""
        events = self.replay()
        return events[-1] if events else None

    # ── Session lifecycle ────────────────────────────────────────────────

    def close(self, reason: str = "normal") -> None:
        """Close the session — no more events can be emitted."""
        self.emit(
            EventType.SESSION_END,
            {"reason": reason, "total_events": self._event_count},
            source="harness",
        )
        self._closed = True

        # Write metadata summary
        meta = {
            "session_id": self.session_id,
            "total_events": self._event_count,
            "closed": True,
            "closed_reason": reason,
        }
        with open(self._meta_path, "w") as f:
            json.dump(meta, f, indent=2)

    @property
    def event_count(self) -> int:
        return self._event_count

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def event_log(self) -> list[dict[str, Any]]:
        """Return all events as a list of dicts for easy inspection."""
        return [e.to_dict() for e in self.replay()]

    # ── Convenience: build context dict from replay ──────────────────────

    def build_context(self) -> dict[str, Any]:
        """Reconstruct session context from the event log.

        This replaces in-memory state reconstruction — the single source of
        truth is always the event log.
        """
        events = self.replay()
        if not events:
            return {"session_id": self.session_id, "events": []}

        # Extract key state from events
        attacker_inputs = []
        system_responses = []
        classifications = []
        ttps = set()
        artifacts = []
        persona = ""

        for event in events:
            if event.event_type == EventType.ATTACKER_INPUT:
                attacker_inputs.append(event.data)
            elif event.event_type == EventType.SYSTEM_RESPONSE:
                system_responses.append(event.data)
            elif event.event_type == EventType.CLASSIFICATION:
                classifications.append(event.data)
            elif event.event_type == EventType.TTP_EXTRACT:
                ttps.update(event.data.get("technique_ids", []))
            elif event.event_type == EventType.ARTIFACT_INJECT:
                artifacts.append(event.data.get("artifact", ""))
            elif event.event_type == EventType.PERSONA_SELECT:
                persona = event.data.get("persona", persona)
            elif event.event_type == EventType.METRIC:
                ttps.update(event.data.get("observed_ttps", []))

        start_event = next((e for e in events if e.event_type == EventType.SESSION_START), None)
        source_ip = start_event.data.get("source_ip", "") if start_event else ""

        return {
            "session_id": self.session_id,
            "source_ip": source_ip,
            "persona": persona,
            "interaction_count": len(attacker_inputs),
            "attacker_inputs": attacker_inputs,
            "system_responses": system_responses,
            "classifications": classifications,
            "ttps_seen": sorted(ttps),
            "observed_ttps": sorted(ttps),
            "artifacts_injected": artifacts,
            "total_events": len(events),
        }

    def __repr__(self) -> str:
        return f"Session(id={self.session_id!r}, events={self._event_count}, " f"closed={self._closed})"
