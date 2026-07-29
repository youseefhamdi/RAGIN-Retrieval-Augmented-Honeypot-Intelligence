"""Unit tests for HisokaMemory — Mem0-backed persistent memory layer.

These tests mock the Mem0 backend so they run without any external services.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

try:
    from ragin.hisoka.memory import HisokaMemory

    HAS_HISOKA_MEMORY = True
except ImportError:
    HAS_HISOKA_MEMORY = False

pytestmark = pytest.mark.unit


def _make_memory_mock() -> MagicMock:
    """Create a mock Mem0 Memory instance with standard responses."""
    mock = MagicMock()
    mock.add.return_value = {
        "results": [
            {"id": "mem-1", "memory": "Test memory", "event": "ADD"},
        ]
    }
    mock.search.return_value = {
        "results": [
            {
                "id": "mem-1",
                "memory": "Attacker ran ls -la",
                "event": "ADD",
                "score": 0.95,
                "metadata": {"session_id": "sess-1"},
            },
        ]
    }
    all_results = [
        {
            "id": "mem-1",
            "memory": "Attacker ran ls -la",
            "event": "ADD",
            "agent_id": "192.168.1.100",
        },
        {
            "id": "mem-2",
            "memory": "Attacker used sudo",
            "event": "ADD",
            "agent_id": "192.168.1.100",
        },
        {
            "id": "mem-3",
            "memory": "Other attacker activity",
            "event": "ADD",
            "agent_id": "10.0.0.5",
        },
    ]

    def _get_all_side_effect(**kwargs):
        aid = kwargs.get("agent_id")
        filtered = [r for r in all_results if not aid or r["agent_id"] == aid]
        return {"results": filtered}

    mock.get_all.side_effect = _get_all_side_effect
    mock.update.return_value = {"id": "mem-1", "memory": "updated", "event": "UPDATE"}
    return mock


def _init_memory() -> HisokaMemory:
    """Helper: create HisokaMemory with mocked Mem0 backend."""
    with patch("mem0.Memory") as mock_cls:
        mock_cls.from_config.return_value = _make_memory_mock()
        mem = HisokaMemory()
        mem._ensure_initialized()
    return mem


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA_MEMORY, reason="ragin.hisoka.memory not importable")
class TestHisokaMemoryInit:
    def test_default_config(self):
        mem = HisokaMemory()
        assert mem._gateway_url == "http://localhost:8080"
        assert mem._embedder_model == "all-MiniLM-L6-v2"
        assert mem._embedding_dims == 384
        assert mem._memory is None  # lazy init

    def test_custom_config(self):
        mem = HisokaMemory(
            gateway_url="http://custom:9090",
            qdrant_path="/tmp/test_qdrant",
            llm_model="openai/gpt-4o",
            embedder_model="BAAI/bge-small-en",
            embedding_dims=384,
        )
        assert mem._gateway_url == "http://custom:9090"
        assert mem._qdrant_path == "/tmp/test_qdrant"
        assert mem._llm_model == "openai/gpt-4o"
        assert mem._embedder_model == "BAAI/bge-small-en"

    def test_trailing_slash_stripped(self):
        mem = HisokaMemory(gateway_url="http://localhost:8080/")
        assert mem._gateway_url == "http://localhost:8080"


# ---------------------------------------------------------------------------
# Lazy initialization
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA_MEMORY, reason="ragin.hisoka.memory not importable")
class TestHisokaMemoryLazyInit:
    def test_ensure_initialized_calls_from_config(self):
        with patch("mem0.Memory") as mock_cls:
            mock_cls.from_config.return_value = _make_memory_mock()
            mem = HisokaMemory()
            assert not mem._memory
            mem._ensure_initialized()
            assert mem._memory is not None
            mock_cls.from_config.assert_called_once()

    def test_is_available_false_on_init_failure(self):
        with patch("mem0.Memory") as mock_cls:
            mock_cls.from_config.side_effect = RuntimeError("backend unavailable")
            mem = HisokaMemory()
            # is_available calls _ensure_initialized internally
            assert not mem.is_available

    def test_no_double_init(self):
        with patch("mem0.Memory") as mock_cls:
            mock_instance = _make_memory_mock()
            mock_cls.from_config.return_value = mock_instance
            mem = HisokaMemory()
            mem._ensure_initialized()
            mem._ensure_initialized()
            assert mock_cls.from_config.call_count == 1


# ---------------------------------------------------------------------------
# add_interaction
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA_MEMORY, reason="ragin.hisoka.memory not importable")
class TestAddInteraction:
    def test_add_basic_interaction(self):
        mem = _init_memory()
        result = mem.add_interaction(
            attacker_ip="192.168.1.100",
            session_id="sess-001",
            attacker_input="ls -la /etc",
        )
        assert result is not None
        mem._memory.add.assert_called_once()
        call_args = mem._memory.add.call_args
        assert call_args[1]["agent_id"] == "192.168.1.100"
        assert call_args[1]["run_id"] == "sess-001"
        assert "ls -la /etc" in call_args[0][0]

    def test_add_with_response_text(self):
        mem = _init_memory()
        mem.add_interaction(
            attacker_ip="10.0.0.1",
            session_id="sess-002",
            attacker_input="whoami",
            response="www-data",
        )
        call_args = mem._memory.add.call_args
        assert "Hisoka response: www-data" in call_args[0][0]

    def test_add_with_deception_response(self):
        from ragin.hisoka.models import DeceptionResponse

        mem = _init_memory()
        resp = DeceptionResponse(
            session_id="sess-002",
            response_text="Permission denied",
            persona_used="novice",
            artifacts_injected=["fake_passwd"],
            engagement_score=0.5,
        )
        mem.add_interaction(
            attacker_ip="10.0.0.1",
            session_id="sess-002",
            attacker_input="cat /etc/shadow",
            response=resp,
            metadata={"skill_level": "novice"},
        )
        call_args = mem._memory.add.call_args
        text = call_args[0][0]
        assert "cat /etc/shadow" in text
        assert "Permission denied" in text
        assert "novice" in text

    def test_add_returns_none_on_failure(self):
        with patch("mem0.Memory") as mock_cls:
            mock_inst = _make_memory_mock()
            mock_inst.add.side_effect = RuntimeError("backend down")
            mock_cls.from_config.return_value = mock_inst
            mem = HisokaMemory()
            mem._ensure_initialized()
            result = mem.add_interaction(
                attacker_ip="10.0.0.1",
                session_id="sess-fail",
                attacker_input="test",
            )
            assert result is None


# ---------------------------------------------------------------------------
# add_attacker_profile
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA_MEMORY, reason="ragin.hisoka.memory not importable")
class TestAddAttackerProfile:
    def test_add_profile_uses_profile_run_id(self):
        mem = _init_memory()
        mem.add_attacker_profile(
            attacker_ip="10.0.0.5",
            profile_summary="Persistent attacker with root access",
        )
        call_args = mem._memory.add.call_args
        assert call_args[1]["agent_id"] == "10.0.0.5"
        assert call_args[1]["run_id"] == "profile"
        assert "Persistent attacker with root access" in call_args[0][0]


# ---------------------------------------------------------------------------
# search_attacker_history
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA_MEMORY, reason="ragin.hisoka.memory not importable")
class TestSearchAttackerHistory:
    def test_search_returns_memories(self):
        mem = _init_memory()
        results = mem.search_attacker_history("192.168.1.100", "recon commands")
        assert len(results) > 0
        assert results[0]["id"] == "mem-1"
        mem._memory.search.assert_called_with("recon commands", agent_id="192.168.1.100", limit=5)

    def test_search_respects_limit(self):
        mem = _init_memory()
        mem.search_attacker_history("10.0.0.1", "test", limit=10)
        call_args = mem._memory.search.call_args
        assert call_args[1]["limit"] == 10

    def test_search_returns_empty_on_failure(self):
        with patch("mem0.Memory") as mock_cls:
            mock_inst = _make_memory_mock()
            mock_inst.search.side_effect = RuntimeError("backend error")
            mock_cls.from_config.return_value = mock_inst
            mem = HisokaMemory()
            mem._ensure_initialized()
            results = mem.search_attacker_history("10.0.0.1", "test")
            assert results == []


# ---------------------------------------------------------------------------
# get_session_memories
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA_MEMORY, reason="ragin.hisoka.memory not importable")
class TestGetSessionMemories:
    def test_get_session_memories(self):
        mem = _init_memory()
        results = mem.get_session_memories("sess-001", "192.168.1.100")
        assert isinstance(results, list)
        call_args = mem._memory.search.call_args
        assert "sess-001" in call_args[0][0]


# ---------------------------------------------------------------------------
# get_attacker_profile
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA_MEMORY, reason="ragin.hisoka.memory not importable")
class TestGetAttackerProfile:
    def test_profile_combines_searches(self):
        mem = _init_memory()
        profile = mem.get_attacker_profile("192.168.1.100")
        assert profile["attacker_ip"] == "192.168.1.100"
        assert profile["total_memories"] > 0
        assert len(profile["memories"]) > 0

    def test_profile_empty_when_unavailable(self):
        with patch("mem0.Memory") as mock_cls:
            mock_cls.from_config.side_effect = RuntimeError("no backend")
            mem = HisokaMemory()
            profile = mem.get_attacker_profile("10.0.0.1")
            assert profile["total_memories"] == 0
            assert profile["summary"] == ""


# ---------------------------------------------------------------------------
# get_all_attackers
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA_MEMORY, reason="ragin.hisoka.memory not importable")
class TestGetAllAttackers:
    def test_get_all_attackers(self):
        mem = _init_memory()
        attackers = mem.get_all_attackers()
        assert isinstance(attackers, list)
        agent_ids = [a["agent_id"] for a in attackers]
        assert "192.168.1.100" in agent_ids
        assert "10.0.0.5" in agent_ids


# ---------------------------------------------------------------------------
# Update / Delete
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA_MEMORY, reason="ragin.hisoka.memory not importable")
class TestUpdateDelete:
    def test_update_memory(self):
        mem = _init_memory()
        result = mem.update_memory("mem-1", "updated text")
        assert result is not None
        mem._memory.update.assert_called_with("mem-1", "updated text", metadata=None)

    def test_delete_memory(self):
        mem = _init_memory()
        result = mem.delete_memory("mem-1")
        assert result is True
        mem._memory.delete.assert_called_with("mem-1")

    def test_delete_attacker(self):
        mem = _init_memory()
        count = mem.delete_attacker("192.168.1.100")
        assert count == 2  # two entries for this IP in mock data
        assert mem._memory.delete.call_count == 2


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HISOKA_MEMORY, reason="ragin.hisoka.memory not importable")
class TestPipelineIntegration:
    """Test that HisokaPipeline integrates with HisokaMemory correctly."""

    def test_pipeline_handle_stores_to_memory(self):
        with patch("mem0.Memory") as mock_cls:
            mock_cls.from_config.return_value = _make_memory_mock()
            mem = HisokaMemory()
            mem._ensure_initialized()

        from ragin.hisoka.pipeline import HisokaPipeline

        pipeline = HisokaPipeline(memory=mem)
        response = pipeline.handle_attacker_input(
            attacker_input="ls -la",
            session_id="test-sess",
            attacker_ip="10.0.0.99",
        )
        assert response.response_text
        assert mem._memory.add.called

    def test_pipeline_searches_history(self):
        with patch("mem0.Memory") as mock_cls:
            mock_cls.from_config.return_value = _make_memory_mock()
            mem = HisokaMemory()
            mem._ensure_initialized()

        from ragin.hisoka.pipeline import HisokaPipeline

        pipeline = HisokaPipeline(memory=mem)
        pipeline.handle_attacker_input(
            attacker_input="whoami",
            session_id="test-sess-2",
            attacker_ip="10.0.0.99",
        )
        mem._memory.search.assert_called()

    def test_pipeline_works_without_memory(self):
        from ragin.hisoka.pipeline import HisokaPipeline

        pipeline = HisokaPipeline(memory=None)
        response = pipeline.handle_attacker_input(
            attacker_input="help",
            session_id="test-no-mem",
        )
        assert response.response_text
