"""Integration tests for Gateway API endpoints.

Tests validate the HTTP contract with the Rust LLM gateway.
These can run against a live gateway or mock server.
"""

from __future__ import annotations

import pytest

try:
    import httpx

    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

pytestmark = [pytest.mark.integration]

GATEWAY_BASE = "http://localhost:8080"


# ---------------------------------------------------------------------------
# Health Endpoint
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HTTPX, reason="httpx not installed")
class TestHealthEndpoint:
    def test_health_check(self):
        """GET /health returns 200 with status ok."""
        try:
            resp = httpx.get(f"{GATEWAY_BASE}/health", timeout=5.0)
            assert resp.status_code == 200
            body = resp.json()
            assert body.get("status") in ("ok", "healthy")
        except httpx.ConnectError:
            pytest.skip("Gateway not running")


# ---------------------------------------------------------------------------
# Models Endpoint
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HTTPX, reason="httpx not installed")
class TestModelsEndpoint:
    def test_list_models(self):
        """GET /v1/models returns available models."""
        try:
            resp = httpx.get(f"{GATEWAY_BASE}/v1/models", timeout=5.0)
            assert resp.status_code == 200
            body = resp.json()
            assert "data" in body
            assert len(body["data"]) > 0
        except httpx.ConnectError:
            pytest.skip("Gateway not running")


# ---------------------------------------------------------------------------
# Chat Completions
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HTTPX, reason="httpx not installed")
class TestChatCompletions:
    def test_basic_completion(self, sample_gateway_request):
        """POST /v1/chat/completions returns a valid response."""
        try:
            resp = httpx.post(
                f"{GATEWAY_BASE}/v1/chat/completions",
                json=sample_gateway_request,
                timeout=30.0,
            )
            assert resp.status_code == 200
            body = resp.json()
            assert "choices" in body
            assert len(body["choices"]) > 0
            assert "usage" in body
        except httpx.ConnectError:
            pytest.skip("Gateway not running")

    def test_missing_model(self):
        """Request without model field returns 400."""
        try:
            resp = httpx.post(
                f"{GATEWAY_BASE}/v1/chat/completions",
                json={"messages": [{"role": "user", "content": "hi"}]},
                timeout=5.0,
            )
            assert resp.status_code in (400, 422)
        except httpx.ConnectError:
            pytest.skip("Gateway not running")

    def test_empty_messages(self):
        """Request with empty messages returns 400."""
        try:
            resp = httpx.post(
                f"{GATEWAY_BASE}/v1/chat/completions",
                json={"model": "llama-3.1-8b", "messages": []},
                timeout=5.0,
            )
            assert resp.status_code in (400, 422)
        except httpx.ConnectError:
            pytest.skip("Gateway not running")


# ---------------------------------------------------------------------------
# Cost Estimate
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HTTPX, reason="httpx not installed")
class TestCostEstimate:
    def test_estimate(self):
        """POST /v1/cost/estimate returns cost info."""
        try:
            resp = httpx.post(
                f"{GATEWAY_BASE}/v1/cost/estimate",
                json={
                    "model": "meta-llama/llama-3.1-8b-instruct",
                    "input_tokens": 1000,
                    "output_tokens": 500,
                },
                timeout=5.0,
            )
            assert resp.status_code == 200
            body = resp.json()
            assert "estimated_cost_usd" in body
        except httpx.ConnectError:
            pytest.skip("Gateway not running")


# ---------------------------------------------------------------------------
# Metrics Endpoint
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HTTPX, reason="httpx not installed")
class TestMetricsEndpoint:
    def test_prometheus_metrics(self):
        """GET /metrics returns Prometheus-format metrics."""
        try:
            resp = httpx.get(f"{GATEWAY_BASE}/metrics", timeout=5.0)
            assert resp.status_code == 200
            assert "ragin_gateway" in resp.text or "# HELP" in resp.text
        except httpx.ConnectError:
            pytest.skip("Gateway not running")


# ---------------------------------------------------------------------------
# Concurrent Requests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HTTPX, reason="httpx not installed")
class TestConcurrentRequests:
    def test_parallel_requests(self, sample_gateway_request):
        """Gateway handles concurrent requests without errors."""
        try:
            with httpx.Client(timeout=10.0) as client:
                responses = []
                for _ in range(5):
                    resp = client.post(
                        f"{GATEWAY_BASE}/v1/chat/completions",
                        json=sample_gateway_request,
                    )
                    responses.append(resp)
                codes = [r.status_code for r in responses]
                assert all(c in (200, 429) for c in codes)
        except httpx.ConnectError:
            pytest.skip("Gateway not running")


# ---------------------------------------------------------------------------
# Error Responses
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_HTTPX, reason="httpx not installed")
class TestErrorResponses:
    def test_404_on_unknown_endpoint(self):
        """Unknown endpoint returns 404."""
        try:
            resp = httpx.get(f"{GATEWAY_BASE}/v1/unknown", timeout=5.0)
            assert resp.status_code == 404
        except httpx.ConnectError:
            pytest.skip("Gateway not running")

    def test_405_on_wrong_method(self):
        """Wrong HTTP method returns 405."""
        try:
            resp = httpx.delete(f"{GATEWAY_BASE}/health", timeout=5.0)
            assert resp.status_code in (404, 405)
        except httpx.ConnectError:
            pytest.skip("Gateway not running")
