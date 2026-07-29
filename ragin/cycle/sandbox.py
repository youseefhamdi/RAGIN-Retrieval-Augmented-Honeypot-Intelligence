"""Sandbox — isolated execution environment for attacker interactions.

Design principles from Anthropic Managed Agents:
- Sandbox = execution env (credentials never reach the sandbox)
- The sandbox is where attacker commands are "executed" (simulated)
- CTI corpus is the "hands" — the sandbox feeds data to the LLM brains
- Pets → Cattle: sandbox instances can be provisioned/destroyed freely

The sandbox manages:
- Command reception from attacker
- Routing through the pipeline (Harness)
- Response delivery back to attacker
- Artifact injection (honeytokens)
- Session lifecycle (create/resume/close)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from ragin.cycle.harness import Harness
from ragin.cycle.session import EventType, Session

logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    """Configuration for a sandbox instance."""

    source_ip: str = "_"
    max_commands: int = 1000
    timeout_s: float = 30.0
    enable_artifacts: bool = True
    enable_verification: bool = True
    session_dir: str | None = None


@dataclass
class SandboxResponse:
    """Response from the sandbox to the attacker."""

    session_id: str
    response_text: str
    command_count: int
    status: str = "ok"
    persona_used: str = ""
    artifacts_injected: list[str] = field(default_factory=list)
    engagement_score: float = 0.0
    processing_time_ms: float = 0.0
    event_count: int = 0
    error: str | None = None


class Sandbox:
    """Isolated execution environment for attacker interactions.

    The sandbox is the "hands" of RAGIN — it receives attacker commands,
    routes them through the pipeline (Harness), and returns deceptive
    responses. The LLM brains (Chrollo, Don, Hisoka) never touch the
    attacker directly — all interaction goes through the sandbox.

    Usage::

        sandbox = Sandbox(
            harness=Harness(classifier=..., cti_engine=..., deceiver=...),
        )
        # New session
        response = sandbox.handle_command("10.0.0.1", "whoami")
        # Continue session
        response = sandbox.handle_command(
            "10.0.0.1", "cat /etc/passwd", session_id=response.session_id
        )
    """

    def __init__(
        self,
        harness: Harness,
        config: SandboxConfig | None = None,
    ) -> None:
        self._harness = harness
        self._config = config or SandboxConfig()
        self._sessions: dict[str, Session] = {}  # session_id → Session

    # ── Session creation ──────────────────────────────────────────────────

    def create_session(self, config: SandboxConfig | None = None) -> SandboxResponse:
        """Create a new session and return its ID."""
        cfg = config or self._config
        session = Session.create(
            source_ip=cfg.source_ip if hasattr(cfg, "source_ip") else "_",
            session_dir=cfg.session_dir,
        )
        self._sessions[session.session_id] = session
        return SandboxResponse(
            session_id=session.session_id,
            response_text="",
            command_count=0,
            persona_used="",
        )

    # ── Command handling ──────────────────────────────────────────────────

    def handle_command(
        self,
        source_ip: str,
        command: str,
        session_id: str | None = None,
    ) -> SandboxResponse:
        """Handle a single attacker command.

        If session_id is provided, resumes that session. Otherwise creates
        a new one.
        """
        # Get or create session
        if session_id and session_id in self._sessions:
            session = self._sessions[session_id]
        elif session_id:
            # Try to wake from disk
            try:
                session = Session.wake(session_id, session_dir=self._config.session_dir)
                self._sessions[session_id] = session
                # Restore _command_count from existing log
                if not hasattr(session, "_command_count") or session._command_count == 0:
                    session._command_count = len(session.get_events_by_type(EventType.ATTACKER_INPUT))
            except FileNotFoundError:
                session = Session.create(source_ip=source_ip, session_dir=self._config.session_dir)
                self._sessions[session.session_id] = session
        else:
            session = Session.create(source_ip=source_ip, session_dir=self._config.session_dir)
            self._sessions[session.session_id] = session

        # Check command limit (use _command_count which tracks actual commands,
        # not event_count which includes SESSION_START/END lifecycle events)
        if not hasattr(session, "_command_count"):
            session._command_count = 0
        session._command_count += 1

        if session._command_count > self._config.max_commands:
            session.close(reason="max_commands_reached")
            return SandboxResponse(
                session_id=session.session_id,
                response_text="Session limit reached.",
                command_count=session._command_count,
                error="max_commands_reached",
            )

        # Run through harness pipeline
        start = time.monotonic()
        result = self._harness.process(session, command)
        elapsed_ms = (time.monotonic() - start) * 1000

        # Extract artifacts from response
        artifacts = result.deception_response.get("artifacts_injected", [])

        # Record metric
        session.emit(
            EventType.METRIC,
            {
                "command": command[:100],  # truncate for storage
                "processing_time_ms": elapsed_ms,
                "persona_used": result.deception_response.get("persona_used", ""),
                "artifacts_count": len(artifacts),
            },
            source="sandbox",
        )

        return SandboxResponse(
            session_id=session.session_id,
            response_text=result.response_text,
            command_count=session._command_count if hasattr(session, "_command_count") else 0,
            persona_used=result.deception_response.get("persona_used", ""),
            artifacts_injected=artifacts,
            engagement_score=result.deception_response.get("engagement_score", 0.0),
            processing_time_ms=elapsed_ms,
            event_count=session.event_count,
            error=result.error,
        )

    # ── Session management ───────────────────────────────────────────────

    def get_session_context(self, session_id: str) -> dict[str, Any] | None:
        """Get reconstructed context for a session."""
        if session_id in self._sessions:
            return self._sessions[session_id].build_context()
        try:
            session = Session.wake(session_id, session_dir=self._config.session_dir)
            return session.build_context()
        except FileNotFoundError:
            return None

    def close_session(self, session_id: str, reason: str = "normal") -> bool:
        """Close a session."""
        if session_id in self._sessions:
            self._sessions[session_id].close(reason=reason)
            return True
        return False

    def get_active_sessions(self) -> list[str]:
        """List active (non-closed) session IDs."""
        return [sid for sid, session in self._sessions.items() if not session.is_closed]

    # ── Batch operations ─────────────────────────────────────────────────

    def handle_commands(
        self,
        source_ip: str,
        commands: list[str],
        session_id: str | None = None,
    ) -> list[SandboxResponse]:
        """Handle multiple commands in sequence (same session)."""
        responses = []
        current_session_id = session_id
        for cmd in commands:
            resp = self.handle_command(source_ip, cmd, session_id=current_session_id)
            current_session_id = resp.session_id
            responses.append(resp)
        return responses

    # ── Metrics ──────────────────────────────────────────────────────────

    def get_metrics(self) -> dict[str, Any]:
        """Get aggregate metrics across all sessions."""
        total_sessions = len(self._sessions)
        active_sessions = sum(1 for s in self._sessions.values() if not s.is_closed)
        total_events = sum(s.event_count for s in self._sessions.values())
        return {
            "total_sessions": total_sessions,
            "active_sessions": active_sessions,
            "total_events": total_events,
        }
