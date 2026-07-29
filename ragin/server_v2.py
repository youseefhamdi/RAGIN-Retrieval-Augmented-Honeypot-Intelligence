"""RAGIN v2 HTTP server — Harness + Session + Sandbox architecture.

Phase 2 of the harness/loop integration:
- Harness: stateless orchestration (Chrollo→Don→Hisoka pipeline)
- Session: append-only crash-safe event log
- Sandbox: attacker interaction isolation

Backward compatible: individual component endpoints still work.
New: /api/session/* endpoints use the full harness pipeline.

Usage:
    python -m ragin.server_v2                          # full pipeline
    python -m ragin.server_v2 --component chrollo      # individual component
"""

from __future__ import annotations

import argparse
import logging
import os
import time
from typing import Any

import yaml
from aiohttp import web

from ragin.cycle.adapters import ChrolloAdapter, DonAdapter, HisokaAdapter
from ragin.cycle.harness import Harness
from ragin.cycle.sandbox import Sandbox, SandboxConfig
from ragin.cycle.session import Session

logger = logging.getLogger("ragin.server_v2")

API_KEY = os.environ.get("API_KEY", "")
LOG_LEVEL = os.environ.get("RAGIN_LOG_LEVEL", "INFO")


def _load_config() -> dict[str, Any]:
    config_path = os.path.join(os.path.dirname(__file__), "config", "settings.yaml")
    if os.path.exists(config_path):
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    return {}


# ── Shared state ─────────────────────────────────────────────────────────────

_harness: Harness | None = None
_sandbox: Sandbox | None = None
_component: Any = None
_COMPONENT_NAME: str = "pipeline"


# ── Middleware ────────────────────────────────────────────────────────────────


@web.middleware
async def auth_middleware(request: web.Request, handler: Any) -> web.Response:
    if request.path in ("/health", "/metrics", "/ready"):
        return await handler(request)
    key = request.headers.get("X-API-Key", "")
    if API_KEY and key != API_KEY:
        return web.json_response({"error": "unauthorized"}, status=401)
    return await handler(request)


@web.middleware
async def timing_middleware(request: web.Request, handler: Any) -> web.Response:
    start = time.monotonic()
    response = await handler(request)
    elapsed = time.monotonic() - start
    response.headers["X-Response-Time"] = f"{elapsed:.3f}s"
    return response


# ── Pipeline endpoints (full harness flow) ───────────────────────────────────


async def session_create(request: web.Request) -> web.Response:
    """Create a new attacker session via Sandbox."""
    try:
        data = await request.json()
    except Exception:
        data = {}

    source_ip = data.get("source_ip", request.remote or "unknown")
    max_commands = data.get("max_commands", 1000)

    config = SandboxConfig(source_ip=source_ip, max_commands=max_commands)
    resp = _sandbox.create_session(config)

    return web.json_response(
        {
            "session_id": resp.session_id,
            "status": resp.status,
        }
    )


async def session_command(request: web.Request) -> web.Response:
    """Process an attacker command through the full Harness pipeline."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)

    session_id = data.get("session_id")
    command = data.get("command", data.get("attacker_input", ""))

    if not session_id:
        return web.json_response({"error": "session_id required"}, status=400)
    if not command:
        return web.json_response({"error": "command required"}, status=400)

    resp = _sandbox.handle_command(
        source_ip="_",
        command=command,
        session_id=session_id,
    )

    return web.json_response(
        {
            "session_id": resp.session_id,
            "response_text": resp.response_text,
            "command_count": resp.command_count,
            "event_count": resp.event_count,
            "error": resp.error,
        }
    )


async def session_wake(request: web.Request) -> web.Response:
    """Wake a crashed session and resume processing."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)

    session_id = data.get("session_id")
    if not session_id:
        return web.json_response({"error": "session_id required"}, status=400)

    session, context = Harness.wake(
        session_id,
        classifier=_harness._classifier if _harness else None,
        cti_engine=_harness._cti_engine if _harness else None,
        deceiver=_harness._deceiver if _harness else None,
    )

    return web.json_response(
        {
            "session_id": session.session_id,
            "events_replayed": context["total_events"],
            "interaction_count": context["interaction_count"],
            "status": "resumed",
        }
    )


async def session_context(request: web.Request) -> web.Response:
    """Get current session context (build_context)."""
    session_id = request.match_info.get("session_id")
    if not session_id:
        return web.json_response({"error": "session_id required"}, status=400)

    context = _sandbox.get_session_context(session_id)
    if context is None:
        return web.json_response({"error": "session not found"}, status=404)

    return web.json_response(context)


async def session_replay(request: web.Request) -> web.Response:
    """Replay session events since a given event ID."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)

    session_id = data.get("session_id")
    after_event_id = data.get("after_event_id")

    if not session_id:
        return web.json_response({"error": "session_id required"}, status=400)

    session = Session.wake(session_id)
    events = session.replay_since(after_event_id) if after_event_id else list(session.replay())

    return web.json_response(
        {
            "session_id": session_id,
            "events": [e.to_dict() for e in events],
            "count": len(events),
        }
    )


# ── Legacy component endpoints (backward compatible) ─────────────────────────


async def classify(request: web.Request) -> web.Response:
    """Individual classify endpoint — backward compatible with server.py."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)

    if _component is None or not hasattr(_component, "classify"):
        return web.json_response({"error": "chrollo not available in pipeline mode"}, status=400)

    try:
        from datetime import datetime

        from ragin.chrollo.models import SessionLog

        session_log = SessionLog(
            session_id=data.get("session_id", "unknown"),
            start_time=data.get("start_time", datetime.utcnow().isoformat()),
            commands=data.get("commands", []),
            duration_seconds=data.get("duration_seconds", 0),
            features=data.get("features", {}),
        )
        result = _component.classify(session_log)
        return web.json_response(
            {
                "skill_level": result.skill_level.value,
                "confidence": result.confidence,
                "session_id": result.session_id,
            }
        )
    except Exception as e:
        logger.exception("classify error")
        return web.json_response({"error": str(e)}, status=500)


async def analyze(request: web.Request) -> web.Response:
    """Individual analyze endpoint — backward compatible with server.py."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)

    if _component is None or not hasattr(_component, "analyze"):
        return web.json_response({"error": "don not available in pipeline mode"}, status=400)

    try:
        from ragin.don.models import AnalysisRequest, ClassificationLabel

        classification_str = data.get("classification", "unknown")
        classification_map = {
            "benign": ClassificationLabel.BENIGN,
            "suspicious": ClassificationLabel.SUSPICIOUS,
            "malicious": ClassificationLabel.MALICIOUS,
        }
        req = AnalysisRequest(
            session_id=data.get("session_id", "unknown"),
            classification=classification_map.get(classification_str, ClassificationLabel.SUSPICIOUS),
            confidence=data.get("confidence", 0.5),
            features=data.get("features", {}),
        )
        session_log = data.get("session_log", [])
        result = _component.analyze(req, session_log)
        return web.json_response(
            {
                "analysis_id": result.analysis_id,
                "severity": result.severity.value,
                "classification": result.classification.value,
                "confidence": result.confidence,
            }
        )
    except Exception as e:
        logger.exception("analyze error")
        return web.json_response({"error": str(e)}, status=500)


async def deceive(request: web.Request) -> web.Response:
    """Individual deceive endpoint — backward compatible with server.py."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)

    if _component is None or not hasattr(_component, "generate_response"):
        return web.json_response({"error": "hisoka not available in pipeline mode"}, status=400)

    try:
        attacker_input = data.get("attacker_input", data.get("command", "ls"))
        session_context = {
            "session_id": data.get("session_id", "unknown"),
            "skill_level": data.get("skill_level", "novice"),
            "context": data.get("context", ""),
        }
        result = _component.generate_response(attacker_input, session_context)
        return web.json_response(
            {
                "session_id": result.session_id,
                "response_text": result.response_text,
                "persona_used": result.persona_used,
                "engagement_score": result.engagement_score,
            }
        )
    except Exception as e:
        logger.exception("deceive error")
        return web.json_response({"error": str(e)}, status=500)


# ── Health / Metrics ─────────────────────────────────────────────────────────


async def health(request: web.Request) -> web.Response:
    report: dict[str, Any] = {
        "component": _COMPONENT_NAME,
        "status": "healthy",
        "timestamp": time.time(),
    }
    if _harness:
        report["harness"] = "active"
        report["pipeline"] = ["chrollo", "don", "hisoka"]
    if _sandbox:
        report["active_sessions"] = len(_sandbox.get_active_sessions())
    return web.json_response(report)


async def ready(request: web.Request) -> web.Response:
    return web.json_response({"ready": True, "component": _COMPONENT_NAME})


async def metrics(request: web.Request) -> web.Response:
    return web.json_response({"status": "metrics placeholder"})


# ── App factory ──────────────────────────────────────────────────────────────


def _init_pipeline(gateway_url: str | None = None, api_key: str | None = None) -> None:
    """Initialize the full Harness pipeline with adapter-wrapped components."""
    global _harness, _sandbox

    cfg = _load_config()
    g_url = gateway_url or cfg.get("ragin", {}).get("cloud", {}).get(
        "gateway_url", os.environ.get("GATEWAY_URL", "http://localhost:8080")
    )
    a_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")

    classifier = ChrolloAdapter()
    cti_engine = DonAdapter(gateway_url=g_url, api_key=a_key)
    deceiver = HisokaAdapter(gateway_url=g_url)

    _harness = Harness(
        classifier=classifier,
        cti_engine=cti_engine,
        deceiver=deceiver,
    )

    # Sandbox uses the harness's internal _process_one for command handling
    # We override handle_command to go through the harness pipeline
    _sandbox = Sandbox(harness=_harness)

    logger.info("Pipeline initialized: Chrollo → Don → Hisoka")


def _init_component(name: str) -> None:
    """Initialize a single component (backward compatible mode)."""
    global _component
    cfg = _load_config()
    g_url = (
        cfg.get("ragin", {}).get("cloud", {}).get("gateway_url", os.environ.get("GATEWAY_URL", "http://localhost:8080"))
    )
    a_key = os.environ.get("OPENROUTER_API_KEY", "")

    if name == "chrollo":
        from ragin.chrollo.classifier import ChrolloClassifier

        _component = ChrolloClassifier()
    elif name == "don":
        from ragin.don.rag_engine import ThreatRAGEngine

        _component = ThreatRAGEngine(gateway_url=g_url, api_key=a_key)
    elif name == "hisoka":
        from ragin.hisoka.deceiver import AdaptiveDeceiver

        _component = AdaptiveDeceiver(gateway_url=g_url)
    else:
        raise ValueError(f"Unknown component: {name}")

    logger.info("Component %s initialized (standalone mode)", name)


def create_app(mode: str = "pipeline", component: str | None = None) -> web.Application:
    """Create the aiohttp application.

    mode:
        "pipeline" — full Harness + Session + Sandbox (default)
        "standalone" — single component (backward compatible with server.py)
    """
    global _COMPONENT_NAME

    app = web.Application(middlewares=[auth_middleware, timing_middleware])

    # Health / readiness (always available)
    app.router.add_get("/health", health)
    app.router.add_get("/ready", ready)
    app.router.add_get("/metrics", metrics)

    if mode == "pipeline":
        _COMPONENT_NAME = "pipeline"
        _init_pipeline()
        # Session management endpoints
        app.router.add_post("/api/session/create", session_create)
        app.router.add_post("/api/session/command", session_command)
        app.router.add_post("/api/session/wake", session_wake)
        app.router.add_post("/api/session/replay", session_replay)
        app.router.add_get("/api/session/{session_id}/context", session_context)
    else:
        _COMPONENT_NAME = component or "unknown"
        _init_component(component or "chrollo")
        # Legacy individual endpoints
        route_map = {
            "chrollo": ("/api/classify", classify),
            "don": ("/api/analyze", analyze),
            "hisoka": ("/api/deceive", deceive),
        }
        path, handler = route_map[component]
        app.router.add_post(path, handler)

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="RAGIN v2 HTTP server")
    parser.add_argument(
        "--mode",
        choices=["pipeline", "standalone"],
        default="pipeline",
        help="pipeline = full harness (default), standalone = single component",
    )
    parser.add_argument(
        "--component",
        choices=["chrollo", "don", "hisoka"],
        default=os.environ.get("COMPONENT", "chrollo"),
        help="Component to run in standalone mode",
    )
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    args = parser.parse_args()

    logging.basicConfig(
        level=LOG_LEVEL,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    app = create_app(mode=args.mode, component=args.component)
    logger.info("Starting RAGIN v2 server (mode=%s) on port %d", args.mode, args.port)
    web.run_app(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
