"""Tests for ragin/server_v2.py — pipeline and standalone endpoints."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from aiohttp.test_utils import TestClient, TestServer

from ragin.cycle.sandbox import SandboxResponse
from ragin.cycle.session import Session

# ── Helpers ───────────────────────────────────────────────────────────────────


def _mock_sandbox() -> MagicMock:
    sb = MagicMock()
    sb.create_session.return_value = SandboxResponse(session_id="abc123", response_text="", command_count=0)
    sb.handle_command.return_value = SandboxResponse(
        session_id="abc123",
        response_text="root@honeypot:~$ ",
        command_count=1,
        event_count=3,
    )
    sb.get_session_context.return_value = {
        "session_id": "abc123",
        "attacker_inputs": ["whoami"],
        "system_responses": ["root"],
        "total_events": 3,
        "interaction_count": 1,
        "source_ip": "10.0.0.1",
    }
    sb.get_active_sessions.return_value = {"abc123": {}}
    return sb


def _mock_harness() -> MagicMock:
    h = MagicMock()
    h._classifier = MagicMock()
    h._cti_engine = MagicMock()
    h._deceiver = MagicMock()
    return h


@pytest.fixture()
async def client():
    """Create test client with mocked server_v2 globals.

    Suppresses _init_pipeline so it doesn't overwrite our mocks.
    """
    import ragin.server_v2 as sv2

    orig_harness = sv2._harness
    orig_sandbox = sv2._sandbox
    orig_component = sv2._component
    orig_comp_name = sv2._COMPONENT_NAME
    orig_api_key = sv2.API_KEY

    # Force API_KEY empty so auth middleware never blocks test requests.
    # When pytest loads .env via dotenv, the module-level API_KEY becomes
    # non-empty and the middleware returns 401 on every non-health route.
    sv2.API_KEY = ""

    # Patch _init_pipeline to prevent it from creating real components
    with patch.object(sv2, "_init_pipeline"):
        app = sv2.create_app(mode="pipeline")

    # Now set our mocks AFTER create_app (so routes are registered but
    # handlers will see our mocks at request time)
    sv2._harness = _mock_harness()
    sv2._sandbox = _mock_sandbox()
    sv2._component = None
    sv2._COMPONENT_NAME = "pipeline"

    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()

    sv2._harness = orig_harness
    sv2._sandbox = orig_sandbox
    sv2._component = orig_component
    sv2._COMPONENT_NAME = orig_comp_name
    sv2.API_KEY = orig_api_key


# ── Health / Readiness ────────────────────────────────────────────────────────


@pytest.mark.asyncio()
async def test_health(client: TestClient) -> None:
    resp = await client.get("/health")
    assert resp.status == 200
    data = await resp.json()
    assert data["component"] == "pipeline"
    assert data["status"] == "healthy"


@pytest.mark.asyncio()
async def test_ready(client: TestClient) -> None:
    resp = await client.get("/ready")
    assert resp.status == 200
    data = await resp.json()
    assert data["ready"] is True


@pytest.mark.asyncio()
async def test_metrics(client: TestClient) -> None:
    resp = await client.get("/metrics")
    assert resp.status == 200


# ── Session endpoints ─────────────────────────────────────────────────────────


@pytest.mark.asyncio()
async def test_session_create(client: TestClient) -> None:
    resp = await client.post(
        "/api/session/create",
        json={"source_ip": "10.0.0.5", "max_commands": 500},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["session_id"] == "abc123"
    assert data["status"] == "ok"


@pytest.mark.asyncio()
async def test_session_create_default(client: TestClient) -> None:
    resp = await client.post("/api/session/create", json={})
    assert resp.status == 200
    data = await resp.json()
    assert data["session_id"] == "abc123"


@pytest.mark.asyncio()
async def test_session_command(client: TestClient) -> None:
    resp = await client.post(
        "/api/session/command",
        json={"session_id": "abc123", "command": "whoami"},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["session_id"] == "abc123"
    assert data["response_text"] == "root@honeypot:~$ "
    assert data["command_count"] == 1
    assert data["event_count"] == 3


@pytest.mark.asyncio()
async def test_session_command_missing_session_id(client: TestClient) -> None:
    resp = await client.post(
        "/api/session/command",
        json={"command": "whoami"},
    )
    assert resp.status == 400
    data = await resp.json()
    assert "session_id required" in data["error"]


@pytest.mark.asyncio()
async def test_session_command_missing_command(client: TestClient) -> None:
    resp = await client.post(
        "/api/session/command",
        json={"session_id": "abc123"},
    )
    assert resp.status == 400
    data = await resp.json()
    assert "command required" in data["error"]


@pytest.mark.asyncio()
async def test_session_command_invalid_json(client: TestClient) -> None:
    resp = await client.post(
        "/api/session/command",
        data="not json",
        headers={"Content-Type": "text/plain"},
    )
    assert resp.status == 400


@pytest.mark.asyncio()
async def test_session_context(client: TestClient) -> None:
    resp = await client.get("/api/session/abc123/context")
    assert resp.status == 200
    data = await resp.json()
    assert data["session_id"] == "abc123"
    assert "attacker_inputs" in data


@pytest.mark.asyncio()
async def test_session_context_not_found(client: TestClient) -> None:
    import ragin.server_v2 as sv2

    sv2._sandbox.get_session_context.return_value = None
    resp = await client.get("/api/session/unknown/context")
    assert resp.status == 404


@pytest.mark.asyncio()
async def test_session_replay(client: TestClient) -> None:
    mock_session = MagicMock()
    mock_session.session_id = "abc123"
    mock_event = MagicMock()
    mock_event.to_dict.return_value = {
        "event_id": "aabbccdd1122",
        "timestamp": "2026-01-01T00:00:00",
        "event_type": "attacker_input",
        "data": {"command": "whoami"},
    }
    mock_session.replay.return_value = [mock_event]

    with patch.object(Session, "wake", return_value=mock_session):
        resp = await client.post(
            "/api/session/replay",
            json={"session_id": "abc123"},
        )
    assert resp.status == 200
    data = await resp.json()
    assert data["session_id"] == "abc123"
    assert isinstance(data["events"], list)
    assert data["count"] == 1


@pytest.mark.asyncio()
async def test_session_replay_missing_session_id(client: TestClient) -> None:
    resp = await client.post(
        "/api/session/replay",
        json={},
    )
    assert resp.status == 400


@pytest.mark.asyncio()
async def test_session_wake(client: TestClient) -> None:
    import ragin.server_v2 as sv2

    mock_session = MagicMock()
    mock_session.session_id = "abc123"
    mock_context = {
        "total_events": 5,
        "interaction_count": 2,
    }

    with patch.object(sv2.Harness, "wake", return_value=(mock_session, mock_context), create=True):
        resp = await client.post(
            "/api/session/wake",
            json={"session_id": "abc123"},
        )
    assert resp.status == 200
    data = await resp.json()
    assert data["session_id"] == "abc123"
    assert data["status"] == "resumed"


@pytest.mark.asyncio()
async def test_session_wake_missing_session_id(client: TestClient) -> None:
    resp = await client.post(
        "/api/session/wake",
        json={},
    )
    assert resp.status == 400


@pytest.mark.asyncio()
async def test_session_command_uses_attacker_input_alias(client: TestClient) -> None:
    resp = await client.post(
        "/api/session/command",
        json={"session_id": "abc123", "attacker_input": "id"},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["session_id"] == "abc123"
