"""Hisoka Memory — persistent attacker memory layer backed by Mem0.

Provides cross-session recall, attacker profiling, and behavioral
pattern detection for the Hisoka deception pipeline.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from ragin.hisoka.models import DeceptionResponse

logger = logging.getLogger(__name__)

_DEFAULT_GATEWAY_URL = os.environ.get("RAGIN_GATEWAY_URL", "http://localhost:8080")
_DEFAULT_QDRANT_PATH = os.environ.get("RAGIN_QDRANT_PATH", "data/hisoka_memory/qdrant")


class HisokaMemory:
    """Persistent memory layer for Hisoka using Mem0 local mode.

    Organizes memories by ``agent_id`` (= attacker IP) and ``run_id``
    (= session ID) so that each attacker's behavioral history is
    isolated but queryable across sessions.

    Public API:
      - add_interaction(attacker_ip, session_id, attacker_input, response, ...)
      - search_attacker_history(attacker_ip, query, limit=5)
      - get_attacker_profile(attacker_ip)
      - get_session_memories(session_id, attacker_ip)
      - get_all_attackers()
    """

    def __init__(
        self,
        gateway_url: str | None = None,
        qdrant_path: str | None = None,
        llm_model: str | None = None,
        embedder_model: str | None = None,
        embedding_dims: int = 384,
        custom_instructions: str | None = None,
    ) -> None:
        self._gateway_url = (gateway_url or _DEFAULT_GATEWAY_URL).rstrip("/")
        self._qdrant_path = qdrant_path or _DEFAULT_QDRANT_PATH
        self._llm_model = llm_model or os.environ.get("RAGIN_HISOKA_MODEL", "inclusionai/ling-3.0-flash:free")
        self._embedder_model = embedder_model or "all-MiniLM-L6-v2"
        self._embedding_dims = embedding_dims
        self._custom_instructions = custom_instructions
        self._memory: Any | None = None  # lazy init

    # ------------------------------------------------------------------
    # Lazy initialization
    # ------------------------------------------------------------------

    def _ensure_initialized(self) -> None:
        if self._memory is not None:
            return

        try:
            from mem0 import Memory

            # Point OpenAI-compatible provider at our LLM Gateway
            os.environ.setdefault("OPENAI_API_BASE", f"{self._gateway_url}/v1")
            os.environ.setdefault("OPENAI_API_KEY", "dummy")

            config: dict[str, Any] = {
                "llm": {
                    "provider": "litellm",
                    "config": {
                        "model": self._llm_model,
                        "api_key": os.environ.get("OPENAI_API_KEY", "dummy"),
                    },
                },
                "embedder": {
                    "provider": "huggingface",
                    "config": {
                        "model": self._embedder_model,
                    },
                },
                "vector_store": {
                    "provider": "qdrant",
                    "config": {
                        "collection_name": "hisoka_memory",
                        "embedding_model_dims": self._embedding_dims,
                        "path": self._qdrant_path,
                    },
                },
                "version": "v1.1",
            }

            if self._custom_instructions:
                config["custom_instructions"] = self._custom_instructions

            self._memory = Memory.from_config(config)
            logger.info(
                "HisokaMemory initialized (qdrant=%s, embedder=%s)",
                self._qdrant_path,
                self._embedder_model,
            )
        except Exception as exc:
            logger.error("Failed to initialize HisokaMemory: %s", exc)
            self._memory = None

    @property
    def is_available(self) -> bool:
        """Whether Mem0 backend is initialized and usable."""
        self._ensure_initialized()
        return self._memory is not None

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def add_interaction(
        self,
        attacker_ip: str,
        session_id: str,
        attacker_input: str,
        response: str | DeceptionResponse | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Store a single attacker interaction in Mem0.

        Args:
            attacker_ip: Source IP — used as ``agent_id`` for per-attacker isolation.
            session_id: Session ID — used as ``run_id`` for per-session grouping.
            attacker_input: The raw attacker command/query (PII-safe).
            response: The deception response text or DeceptionResponse object.
            metadata: Optional extra metadata attached to this memory.

        Returns:
            Mem0 result dict or ``None`` on failure.
        """
        self._ensure_initialized()
        if self._memory is None:
            return None

        # Build the text to store — Mem0 will extract facts from this
        response_text = ""
        if isinstance(response, DeceptionResponse):
            response_text = response.response_text
        elif isinstance(response, str):
            response_text = response

        interaction_text = f"Attacker command: {attacker_input}\n" f"Hisoka response: {response_text}"

        # Enrich with metadata for better fact extraction
        if metadata:
            parts = [interaction_text]
            if metadata.get("skill_level"):
                parts.append(f"Assessed skill level: {metadata['skill_level']}")
            if metadata.get("persona_used"):
                parts.append(f"Persona used: {metadata['persona_used']}")
            if metadata.get("engagement_score") is not None:
                parts.append(f"Engagement score: {metadata['engagement_score']}")
            if metadata.get("artifacts"):
                parts.append(f"Artifacts injected: {', '.join(metadata['artifacts'])}")
            interaction_text = "\n".join(parts)

        try:
            result = self._memory.add(
                interaction_text,
                agent_id=attacker_ip,
                run_id=session_id,
                metadata=metadata,
            )
            logger.debug(
                "Stored interaction for %s/%s: %s",
                attacker_ip,
                session_id,
                attacker_input[:50],
            )
            return result
        except Exception as exc:
            logger.error("Failed to store interaction: %s", exc)
            return None

    def add_attacker_profile(
        self,
        attacker_ip: str,
        profile_summary: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Store an aggregated attacker profile (behavioral summary).

        Uses a special ``run_id`` of ``"profile"`` to separate
        aggregate profiles from per-session interactions.
        """
        self._ensure_initialized()
        if self._memory is None:
            return None

        try:
            result = self._memory.add(
                f"Attacker behavioral profile: {profile_summary}",
                agent_id=attacker_ip,
                run_id="profile",
                metadata={**(metadata or {}), "type": "attacker_profile"},
            )
            return result
        except Exception as exc:
            logger.error("Failed to store attacker profile: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def search_attacker_history(
        self,
        attacker_ip: str,
        query: str,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Search memories for a specific attacker.

        Returns a list of memory entries ranked by relevance.

        Each entry contains at minimum:
          - ``id``: memory ID
          - ``memory``: extracted fact text
          - ``score``: relevance score
          - ``metadata``: optional metadata dict
        """
        self._ensure_initialized()
        if self._memory is None:
            return []

        try:
            result = self._memory.search(
                query,
                agent_id=attacker_ip,
                limit=limit,
            )
            memories = result.get("results", []) if isinstance(result, dict) else []
            return memories
        except Exception as exc:
            logger.error("Failed to search attacker history: %s", exc)
            return []

    def get_session_memories(
        self,
        session_id: str,
        attacker_ip: str,
    ) -> list[dict[str, Any]]:
        """Retrieve all memories stored for a specific session.

        Uses search with the session_id as a query term to find
        session-scoped entries.
        """
        self._ensure_initialized()
        if self._memory is None:
            return []

        try:
            result = self._memory.search(
                f"session {session_id}",
                agent_id=attacker_ip,
                limit=50,
            )
            memories = result.get("results", []) if isinstance(result, dict) else []
            return memories
        except Exception as exc:
            logger.error("Failed to get session memories: %s", exc)
            return []

    def get_attacker_profile(
        self,
        attacker_ip: str,
    ) -> dict[str, Any]:
        """Build a behavioral profile for an attacker from accumulated memories.

        Returns a dict with:
          - ``attacker_ip``: the IP
          - ``total_memories``: number of stored facts
          - ``memories``: the raw memory entries
          - ``summary``: concatenated profile text (or empty string)
        """
        self._ensure_initialized()
        if self._memory is None:
            return {
                "attacker_ip": attacker_ip,
                "total_memories": 0,
                "memories": [],
                "summary": "",
            }

        try:
            # Fetch all memories for this attacker
            result = self._memory.search(
                "attacker behavior patterns commands techniques",
                agent_id=attacker_ip,
                limit=50,
            )
            memories = result.get("results", []) if isinstance(result, dict) else []

            # Also get profile-specific memories
            profile_result = self._memory.search(
                "profile behavioral summary",
                agent_id=attacker_ip,
                limit=10,
            )
            profile_memories = profile_result.get("results", []) if isinstance(profile_result, dict) else []

            all_memories = memories + [p for p in profile_memories if p not in memories]

            summary_parts = [m.get("memory", "") for m in all_memories if m.get("memory")]

            return {
                "attacker_ip": attacker_ip,
                "total_memories": len(all_memories),
                "memories": all_memories,
                "summary": "\n".join(summary_parts),
            }
        except Exception as exc:
            logger.error("Failed to get attacker profile: %s", exc)
            return {
                "attacker_ip": attacker_ip,
                "total_memories": 0,
                "memories": [],
                "summary": "",
            }

    def get_all_attackers(self) -> list[dict[str, Any]]:
        """List all attackers (agent_ids) that have stored memories.

        Returns a list of dicts with ``agent_id`` keys.  The actual
        list depends on the Mem0 backend — may be empty if the
        backend doesn't support enumeration.
        """
        self._ensure_initialized()
        if self._memory is None:
            return []

        try:
            result = self._memory.get_all()
            memories = result.get("results", []) if isinstance(result, dict) else []
            # Extract unique agent_ids
            agents: dict[str, dict[str, Any]] = {}
            for m in memories:
                aid = m.get("agent_id", "")
                if aid and aid not in agents:
                    agents[aid] = {
                        "agent_id": aid,
                        "memory_count": 0,
                        "sample_memories": [],
                    }
                if aid:
                    agents[aid]["memory_count"] += 1
                    if len(agents[aid]["sample_memories"]) < 3:
                        agents[aid]["sample_memories"].append(m.get("memory", ""))
            return list(agents.values())
        except Exception as exc:
            logger.error("Failed to list attackers: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Update / Delete
    # ------------------------------------------------------------------

    def update_memory(self, memory_id: str, text: str, metadata: dict[str, Any] | None = None) -> dict[str, Any] | None:
        """Update an existing memory entry by ID."""
        self._ensure_initialized()
        if self._memory is None:
            return None

        try:
            result = self._memory.update(memory_id, text, metadata=metadata)
            return result
        except Exception as exc:
            logger.error("Failed to update memory %s: %s", memory_id, exc)
            return None

    def delete_memory(self, memory_id: str) -> bool:
        """Delete a single memory entry by ID."""
        self._ensure_initialized()
        if self._memory is None:
            return False

        try:
            self._memory.delete(memory_id)
            return True
        except Exception as exc:
            logger.error("Failed to delete memory %s: %s", memory_id, exc)
            return False

    def delete_attacker(self, attacker_ip: str) -> int:
        """Delete all memories for a given attacker IP.

        Returns the number of memories deleted (may be approximate).
        """
        self._ensure_initialized()
        if self._memory is None:
            return 0

        try:
            # Get all memories for this attacker
            result = self._memory.get_all(agent_id=attacker_ip)
            memories = result.get("results", []) if isinstance(result, dict) else []
            count = 0
            for m in memories:
                mid = m.get("id")
                if mid:
                    self._memory.delete(mid)
                    count += 1
            logger.info("Deleted %d memories for attacker %s", count, attacker_ip)
            return count
        except Exception as exc:
            logger.error("Failed to delete attacker memories: %s", exc)
            return 0
