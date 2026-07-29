"""Hisoka pipeline — orchestrates deception flow from Don analysis to response."""

from __future__ import annotations

import logging
from typing import Any

from ragin.hisoka.deceiver import AdaptiveDeceiver
from ragin.hisoka.memory import HisokaMemory
from ragin.hisoka.models import DeceptionResponse, DonAnalysis, SessionSummary
from ragin.hisoka.session_manager import SessionManagerExtended

logger = logging.getLogger(__name__)


class HisokaPipeline:
    """End-to-end deception pipeline.

    Receives attacker input and Don analysis, coordinates the deceiver
    and session manager to produce adaptive deception responses.

    Optionally integrates with :class:`HisokaMemory` (Mem0-backed)
    for cross-session recall and attacker profiling.
    """

    def __init__(
        self,
        deceiver: AdaptiveDeceiver | None = None,
        session_manager: SessionManagerExtended | None = None,
        memory: HisokaMemory | None = None,
        gateway_url: str | None = None,
    ) -> None:
        self._deceiver = deceiver or AdaptiveDeceiver(gateway_url=gateway_url)
        self._session_manager = session_manager or SessionManagerExtended()
        self._memory = memory

    def handle_attacker_input(
        self,
        attacker_input: str,
        session_id: str,
        attacker_ip: str = "",
    ) -> DeceptionResponse:
        """Process attacker input and return a deception response.

        Creates the session if it doesn't exist yet.  If a
        :class:`HisokaMemory` instance is configured, enriches the
        session context with cross-session behavioral history and
        persists the interaction.
        """
        session = self._session_manager.get_session(session_id)
        if session is None:
            session = self._session_manager.create_session(
                session_id=session_id,
                source_ip=attacker_ip,
            )

        skill_level = session.persona.skill_level if session.persona else "novice"

        self._session_manager.update_session(
            session_id,
            {
                "command": attacker_input,
                "type": "attacker_input",
            },
        )

        # ------------------------------------------------------------------
        # Memory enrichment — pull cross-session history before generating
        # ------------------------------------------------------------------
        history_memories: list[dict[str, Any]] = []
        if self._memory and attacker_ip:
            history_memories = self._memory.search_attacker_history(
                attacker_ip,
                attacker_input,
                limit=5,
            )

        context: dict[str, Any] = {
            "session_id": session_id,
            "skill_level": skill_level,
            "command_count": session.command_count,
        }
        if history_memories:
            context["attacker_history"] = [m.get("memory", "") for m in history_memories]

        response = self._deceiver.generate_response(attacker_input, context)

        # ------------------------------------------------------------------
        # Memory persistence — store the interaction
        # ------------------------------------------------------------------
        if self._memory and attacker_ip:
            self._memory.add_interaction(
                attacker_ip=attacker_ip,
                session_id=session_id,
                attacker_input=attacker_input,
                response=response,
                metadata={
                    "skill_level": skill_level,
                    "persona_used": skill_level,
                    "engagement_score": response.engagement_score,
                    "artifacts": response.artifacts_injected,
                },
            )

        return response

    def process_don_analysis(self, analysis: DonAnalysis) -> None:
        """Receive and apply Don's threat analysis to adapt the session.

        May upgrade the persona if Don identifies higher skill level.
        """
        session = self._session_manager.get_session(analysis.session_id)
        if session is None:
            logger.warning("Received analysis for unknown session %s", analysis.session_id[:8])
            return

        # Adapt persona if Don's assessment differs
        if session.persona and session.persona.skill_level != analysis.skill_level:
            logger.info(
                "Adapting persona for session %s: %s -> %s",
                analysis.session_id[:8],
                session.persona.skill_level,
                analysis.skill_level,
            )
            new_persona = self._deceiver.adapt_persona(analysis.skill_level)
            self._session_manager.update_session(
                analysis.session_id,
                {
                    "persona": new_persona,
                },
            )

        self._session_manager.update_session(
            analysis.session_id,
            {
                "metadata": {"don_analysis": analysis.model_dump()},
            },
        )

    def end_session(self, session_id: str) -> SessionSummary:
        """Close a session and return its summary.

        If memory is enabled, persists the session summary as an
        attacker profile update.
        """
        session = self._session_manager.get_session(session_id)
        if session is None:
            return SessionSummary(session_id=session_id)

        dwell_time = self._session_manager.get_dwell_time(session_id)
        self._session_manager.close_session(session_id)

        summary = SessionSummary(
            session_id=session_id,
            source_ip=session.source_ip,
            persona_used=session.persona.skill_level if session.persona else "unknown",
            total_interactions=session.command_count,
            dwell_time_seconds=dwell_time,
            start_time=session.start_time,
            artifacts_injected=session.metadata.get("artifacts", []),
        )

        # Persist session summary to memory
        if self._memory and session.source_ip:
            profile_text = (
                f"Session {session_id[:8]} closed: "
                f"{session.command_count} interactions, "
                f"dwell {dwell_time:.0f}s, "
                f"persona={summary.persona_used}"
            )
            self._memory.add_attacker_profile(
                attacker_ip=session.source_ip,
                profile_summary=profile_text,
                metadata={
                    "session_id": session_id,
                    "total_interactions": session.command_count,
                    "dwell_time": dwell_time,
                    "persona": summary.persona_used,
                },
            )

        return summary
