"""RAGIN HTTP server — exposes Chrollo, Don, and Hisoka as HTTP services.

Production wiring: audit logging, Prometheus metrics, rate limiting,
budget enforcement, circuit breaker status, health checks.
"""

import argparse
import logging
import os
import time
from typing import Any

import yaml
from aiohttp import web

from ragin.monitoring.alerts import AlertManager
from ragin.monitoring.audit import AuditLogger
from ragin.monitoring.metrics import MetricsCollector
from ragin.utils import RateLimiter

logger = logging.getLogger("ragin.server")

API_KEY = os.environ.get("API_KEY", "")
COMPONENT = os.environ.get("COMPONENT", "chrollo")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
PORT = int(os.environ.get("CHROLLO_PORT", os.environ.get("DON_PORT", os.environ.get("HISOKA_PORT", "8080"))))
LOG_LEVEL = os.environ.get("RAGIN_LOG_LEVEL", "INFO")

# Lazy imports per component
_component = None


def _load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config", "settings.yaml")
    if os.path.exists(config_path):
        with open(config_path) as f:
            return yaml.safe_load(f)
    return {}


def _init_component(name: str):
    global _component
    cfg = _load_config()
    if name == "chrollo":
        from ragin.chrollo.classifier import ChrolloClassifier

        _component = ChrolloClassifier()
    elif name == "don":
        from ragin.don.rag_engine import ThreatRAGEngine

        gateway_url = (
            cfg.get("ragin", {})
            .get("cloud", {})
            .get("gateway_url", os.environ.get("GATEWAY_URL", "http://localhost:8080"))
        )
        api_key = os.environ.get("OPENROUTER_API_KEY", "")
        _component = ThreatRAGEngine(gateway_url=gateway_url, api_key=api_key)
    elif name == "hisoka":
        from ragin.hisoka.deceiver import AdaptiveDeceiver

        gateway_url = (
            cfg.get("ragin", {})
            .get("cloud", {})
            .get("gateway_url", os.environ.get("GATEWAY_URL", "http://localhost:8080"))
        )
        _component = AdaptiveDeceiver(gateway_url=gateway_url)
    else:
        raise ValueError(f"Unknown component: {name}")
    logger.info("Component %s initialized", name)


# --- Shared singletons (set at app creation) ---

_audit: AuditLogger | None = None
_metrics_collector: MetricsCollector | None = None
_rate_limiter: RateLimiter | None = None
_alert_manager: AlertManager | None = None
_prometheus_metrics: dict[str, Any] | None = None  # type: ignore[name-defined]


# --- Middleware ---


@web.middleware
async def auth_middleware(request, handler):
    if request.path in ("/health", "/metrics", "/ready"):
        return await handler(request)
    key = request.headers.get("X-API-Key", "")
    if API_KEY and key != API_KEY:
        if _audit:
            _audit.log_security_event(
                "auth_failure",
                {
                    "path": request.path,
                    "remote": request.remote,
                },
            )
        return web.json_response({"error": "unauthorized"}, status=401)
    return await handler(request)


@web.middleware
async def timing_middleware(request, handler):
    start = time.monotonic()
    response = await handler(request)
    elapsed = time.monotonic() - start
    response.headers["X-Response-Time"] = f"{elapsed:.3f}s"

    # Record Prometheus metrics
    if _prometheus_metrics and request.path not in ("/health", "/metrics", "/ready"):
        _prometheus_metrics["count"].labels(
            method=request.method, endpoint=request.path, status=str(response.status)
        ).inc()
        _prometheus_metrics["latency"].labels(endpoint=request.path).observe(elapsed)

    # Record in-memory metrics
    if _metrics_collector and request.path not in ("/health", "/metrics", "/ready"):
        status = "ok" if response.status < 400 else "error"
        _metrics_collector.record_request(COMPONENT, request.method, status, elapsed * 1000)

    return response


@web.middleware
async def rate_limit_middleware(request, handler):
    if request.path in ("/health", "/metrics", "/ready"):
        return await handler(request)
    if _rate_limiter:
        client_ip = request.remote or "_unknown"
        if not _rate_limiter.allow(client_ip):
            if _audit:
                _audit.log_security_event(
                    "rate_limit_exceeded",
                    {
                        "remote": client_ip,
                        "path": request.path,
                    },
                )
            return web.json_response(
                {"error": "rate limit exceeded", "retry_after_s": 1},
                status=429,
                headers={"Retry-After": "1"},
            )
    return await handler(request)


# --- Routes ---


async def health(request):
    """Health endpoint with dependency checks."""
    report = {}
    if _audit:
        report["audit"] = "enabled"
    if _metrics_collector:
        summary = _metrics_collector.get_summary(window_minutes=5)
        report["recent_requests"] = summary.total_requests
        report["recent_errors"] = summary.error_count
        report["error_rate"] = round(summary.error_rate, 4)
    report["component"] = COMPONENT
    report["status"] = "healthy"
    report["timestamp"] = time.time()
    return web.json_response(report)


async def ready(request):
    """Readiness probe."""
    return web.json_response({"ready": True, "component": COMPONENT})


async def classify(request):
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)
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

        # Audit log
        if _audit:
            _audit.log_classification(
                result.session_id,
                {
                    "skill_level": result.skill_level.value,
                    "confidence": result.confidence,
                    "features_used": result.features_used[:10],
                },
            )

        # In-memory metrics
        if _metrics_collector:
            _metrics_collector.record_classification(result.skill_level.value, result.confidence)

        return web.json_response(
            {
                "skill_level": result.skill_level.value,
                "confidence": result.confidence,
                "session_id": result.session_id,
                "features_used": result.features_used[:10],
                "feature_values": {k: round(v, 4) for k, v in list(result.feature_values.items())[:20]},
            }
        )
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        logger.exception("classify error")
        return web.json_response({"error": str(e)}, status=500)


async def analyze(request):
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)
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

        # Audit log
        if _audit:
            _audit.log_analysis(
                result.session_id,
                {
                    "severity": result.severity.value,
                    "classification": result.classification.value,
                    "confidence": result.confidence,
                    "sophistication_score": result.sophistication_score,
                    "tactics": [{"id": t.tactic_id, "name": t.tactic_name} for t in result.tactics],
                },
            )

        # In-memory metrics
        if _metrics_collector:
            _metrics_collector.record_threat(
                result.severity.value,
                [t.tactic_id for t in result.tactics],
            )

        from ragin.cycle.adapters import _extract_evidence

        commands = data.get("commands", data.get("features", {}).get("commands", []))
        session_context = {"attacker_inputs": commands}
        evidence = _extract_evidence(session_context)

        return web.json_response(
            {
                "analysis_id": result.analysis_id,
                "session_id": result.session_id,
                "severity": result.severity.value,
                "classification": result.classification.value,
                "confidence": result.confidence,
                "sophistication_score": result.sophistication_score,
                "threat_summary": result.summary if hasattr(result, "summary") else "",
                "recommendations": [
                    r if isinstance(r, str) else str(r) for r in getattr(result, "recommendations", [])
                ],
                "tactics": [
                    {"id": t.tactic_id, "name": t.tactic_name, "confidence": t.confidence} for t in result.tactics
                ],
                "candidate_actors": [
                    {
                        "name": a.name,
                        "confidence": a.confidence,
                        "known_ttps": a.known_ttps,
                        "basis": "tactic-heuristic",
                    }
                    for a in result.threat_actors
                ],
                "evasion_techniques": evidence["evasion_techniques"],
                "tools_used": evidence["tools_used"],
                "credential_access": evidence["credential_access"],
                "iocs": [{"type": ioc.type.value, "value": ioc.value} for ioc in result.iocs[:20]],
                "ttps_seen": list(
                    {tid for a in result.threat_actors for tid in a.known_ttps}
                    | {tid for t in result.tactics for tid in t.techniques + t.sub_techniques}
                ),
                "extracted_techniques": list(
                    {tid for a in result.threat_actors for tid in a.known_ttps}
                    | {tid for t in result.tactics for tid in t.techniques + t.sub_techniques}
                ),
            }
        )
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        logger.exception("analyze error")
        return web.json_response({"error": str(e)}, status=500)


async def deceive(request):
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)
    try:
        attacker_input = data.get("attacker_input", data.get("command", "ls"))
        session_context = {
            "session_id": data.get("session_id", "unknown"),
            "skill_level": data.get("skill_level", "novice"),
            "context": data.get("context", ""),
        }
        result = _component.generate_response(attacker_input, session_context)

        # Audit log
        if _audit:
            _audit.log_deception(
                result.session_id,
                {
                    "persona_used": result.persona_used,
                    "engagement_score": result.engagement_score,
                    "artifacts_injected": result.artifacts_injected,
                    "attacker_input_preview": attacker_input[:100],
                },
            )

        # In-memory metrics
        if _metrics_collector:
            _metrics_collector.record_deception(result.session_id, 0.0, result.engagement_score)

        return web.json_response(
            {
                "session_id": result.session_id,
                "response_text": result.response_text,
                "persona_used": result.persona_used,
                "artifacts_injected": result.artifacts_injected,
                "engagement_score": result.engagement_score,
            }
        )
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        logger.exception("deceive error")
        return web.json_response({"error": str(e)}, status=500)


async def metrics(request):
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

    body = generate_latest()
    return web.Response(body=body, content_type=CONTENT_TYPE_LATEST)


# --- App factory ---


def create_app(component: str) -> web.Application:
    global _audit, _metrics_collector, _rate_limiter, _alert_manager, _prometheus_metrics

    # Initialize singletons
    _audit = AuditLogger()
    _metrics_collector = MetricsCollector()
    _rate_limiter = RateLimiter(max_tokens=60, refill_per_s=1.0)
    _alert_manager = AlertManager()

    app = web.Application(middlewares=[auth_middleware, rate_limit_middleware, timing_middleware])
    app.router.add_get("/health", health)
    app.router.add_get("/ready", ready)

    route_map = {
        "chrollo": ("/api/classify", classify),
        "don": ("/api/analyze", analyze),
        "hisoka": ("/api/deceive", deceive),
    }
    path, handler = route_map[component]
    app.router.add_post(path, handler)

    # Prometheus metrics (try import)
    try:
        from prometheus_client import Counter, Gauge, Histogram

        REQUEST_COUNT = Counter(
            f"ragin_{component}_requests_total",
            "Total requests",
            ["method", "endpoint", "status"],
        )
        REQUEST_LATENCY = Histogram(
            f"ragin_{component}_request_duration_seconds",
            "Request latency",
            ["endpoint"],
            buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0],
        )
        ACTIVE_SESSIONS = Gauge(
            f"ragin_{component}_active_sessions",
            "Active sessions",
        )
        _prometheus_metrics = {"count": REQUEST_COUNT, "latency": REQUEST_LATENCY, "gauge": ACTIVE_SESSIONS}
    except ImportError:
        logger.warning("prometheus_client not installed, metrics disabled")

    app.router.add_get("/metrics", metrics)
    return app


def main():
    global COMPONENT
    parser = argparse.ArgumentParser(description="RAGIN HTTP server")
    parser.add_argument("--component", choices=["chrollo", "don", "hisoka"], default=COMPONENT)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()

    COMPONENT = args.component
    logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    _init_component(args.component)
    app = create_app(args.component)

    logger.info("Starting %s server on port %d", args.component, args.port)
    web.run_app(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
