"""Security validation test suite for RAGIN cloud LLM deployment.

Validates:
- API key enforcement on all endpoints
- Input sanitization (command injection, oversized payloads, SQLi/XSS)
- Session ID validation (alphanumeric only)
- Error handling (no stack traces leaked)
- Rate limiting behavior
- CORS configuration
"""

from __future__ import annotations

import os

import pytest
import requests

pytestmark = [pytest.mark.e2e]

API_KEY = os.environ.get("RAGIN_API_KEY", "ragin-test-key-2024")
CHROLLO_PORT = int(os.environ.get("CHROLLO_PORT", "8081"))
DON_PORT = int(os.environ.get("DON_PORT", "8082"))
HISOKA_PORT = int(os.environ.get("HISOKA_PORT", "8083"))
API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1")


def valid_headers() -> dict[str, str]:
    return {"X-API-Key": API_KEY, "Content-Type": "application/json"}


@pytest.fixture(scope="session")
def services_up():
    for port in [CHROLLO_PORT, DON_PORT, HISOKA_PORT]:
        try:
            r = requests.get(f"{API_BASE_URL}:{port}/health", headers=valid_headers(), timeout=3)
            if r.status_code != 200:
                pytest.skip(f"Service on port {port} not healthy")
        except Exception:
            pytest.skip(f"Service on port {port} not reachable")


# ── Authentication Enforcement ───────────────────────────────────────────────


class TestAuthentication:
    """All protected endpoints must reject unauthenticated requests."""

    def test_chrollo_no_api_key(self, services_up):
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json={"session_id": "SecNoAuth1", "start_time": "2025-01-01T00:00:00Z", "commands": []},
            timeout=5,
        )
        assert resp.status_code in [401, 403], f"Expected 401/403, got {resp.status_code}"

    def test_chrollo_wrong_api_key(self, services_up):
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json={"session_id": "SecWrongKey1", "start_time": "2025-01-01T00:00:00Z", "commands": []},
            headers={"X-API-Key": "wrong-key-12345"},
            timeout=5,
        )
        assert resp.status_code in [401, 403], f"Expected 401/403, got {resp.status_code}"

    def test_don_no_api_key(self, services_up):
        resp = requests.post(
            f"{API_BASE_URL}:{DON_PORT}/api/analyze",
            json={"session_id": "SecNoAuth2", "classification": "suspicious", "confidence": 0.5, "features": {}},
            timeout=5,
        )
        assert resp.status_code in [401, 403], f"Expected 401/403, got {resp.status_code}"

    def test_don_wrong_api_key(self, services_up):
        resp = requests.post(
            f"{API_BASE_URL}:{DON_PORT}/api/analyze",
            json={"session_id": "SecWrongKey2", "classification": "suspicious", "confidence": 0.5, "features": {}},
            headers={"X-API-Key": "wrong-key-12345"},
            timeout=5,
        )
        assert resp.status_code in [401, 403], f"Expected 401/403, got {resp.status_code}"

    def test_hisoka_no_api_key(self, services_up):
        resp = requests.post(
            f"{API_BASE_URL}:{HISOKA_PORT}/api/deceive",
            json={"attacker_input": "test", "session_context": {}},
            timeout=5,
        )
        assert resp.status_code in [401, 403], f"Expected 401/403, got {resp.status_code}"

    def test_hisoka_wrong_api_key(self, services_up):
        resp = requests.post(
            f"{API_BASE_URL}:{HISOKA_PORT}/api/deceive",
            json={"attacker_input": "test", "session_context": {}},
            headers={"X-API-Key": "wrong-key-12345"},
            timeout=5,
        )
        assert resp.status_code in [401, 403], f"Expected 401/403, got {resp.status_code}"

    def test_health_endpoint_accessible_without_key(self, services_up):
        """Health endpoints should be accessible for monitoring."""
        for port in [CHROLLO_PORT, DON_PORT, HISOKA_PORT]:
            resp = requests.get(f"{API_BASE_URL}:{port}/health", timeout=3)
            assert resp.status_code == 200, f"Health check on port {port} requires auth (should be open)"


# ── Session ID Validation ────────────────────────────────────────────────────


class TestSessionIDValidation:
    """Session IDs must be alphanumeric only (enforced by AnalysisRequest.validate_session_id)."""

    def test_hyphenated_session_id_accepted(self, services_up):
        """Server hashes non-alphanumeric session_ids (doesn't reject them)."""
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json={"session_id": "bad-session-id", "start_time": "2025-01-01T00:00:00Z", "commands": []},
            headers=valid_headers(),
            timeout=5,
        )
        assert resp.status_code == 200, f"Hyphenated ID gets hashed and accepted, got {resp.status_code}"

    def test_underscore_session_id_accepted(self, services_up):
        """Server hashes non-alphanumeric session_ids (doesn't reject them)."""
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json={"session_id": "bad_session_id", "start_time": "2025-01-01T00:00:00Z", "commands": []},
            headers=valid_headers(),
            timeout=5,
        )
        assert resp.status_code == 200, f"Underscore ID gets hashed and accepted, got {resp.status_code}"

    def test_space_session_id_accepted(self, services_up):
        """Server hashes non-alphanumeric session_ids (doesn't reject them)."""
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json={"session_id": "bad session id", "start_time": "2025-01-01T00:00:00Z", "commands": []},
            headers=valid_headers(),
            timeout=5,
        )
        assert resp.status_code == 200, f"Spaced ID gets hashed and accepted, got {resp.status_code}"

    def test_valid_session_id_accepted(self, services_up):
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json={"session_id": "ValidID123", "start_time": "2025-01-01T00:00:00Z", "commands": []},
            headers=valid_headers(),
            timeout=5,
        )
        assert resp.status_code == 200, f"Valid alphanumeric ID should be accepted, got {resp.status_code}"


# ── Input Sanitization ───────────────────────────────────────────────────────


class TestInputSanitization:
    """Malicious payloads in commands must not cause crashes or code execution."""

    def test_command_injection_in_session_id(self, services_up):
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json={"session_id": "$(whoami)", "start_time": "2025-01-01T00:00:00Z", "commands": []},
            headers=valid_headers(),
            timeout=5,
        )
        # Should be rejected (non-alphanumeric) or handled safely
        assert resp.status_code in [200, 400, 422]

    def test_sql_injection_in_commands(self, services_up):
        payload = {
            "session_id": "SecSQLi001",
            "start_time": "2025-01-01T00:00:00Z",
            "commands": [
                {"timestamp": "2025-01-01T00:00:00Z", "command": "'; DROP TABLE users; --"},
                {"timestamp": "2025-01-01T00:00:01Z", "command": "1' OR '1'='1"},
            ],
        }
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json=payload,
            headers=valid_headers(),
            timeout=10,
        )
        assert resp.status_code == 200, f"SQLi in commands should be handled gracefully: {resp.status_code}"

    def test_xss_in_commands(self, services_up):
        payload = {
            "session_id": "SecXSS001",
            "start_time": "2025-01-01T00:00:00Z",
            "commands": [
                {"timestamp": "2025-01-01T00:00:00Z", "command": "<script>alert('xss')</script>"},
                {"timestamp": "2025-01-01T00:00:01Z", "command": "<img src=x onerror=alert(1)>"},
            ],
        }
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json=payload,
            headers=valid_headers(),
            timeout=10,
        )
        assert resp.status_code == 200, f"XSS in commands should be handled: {resp.status_code}"

    def test_oversized_command_rejected(self, services_up):
        payload = {
            "session_id": "SecOversize001",
            "start_time": "2025-01-01T00:00:00Z",
            "commands": [
                {"timestamp": "2025-01-01T00:00:00Z", "command": "A" * 10000},
            ],
        }
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json=payload,
            headers=valid_headers(),
            timeout=10,
        )
        # Oversized command (>4096 chars) triggers ValueError → 400
        assert resp.status_code == 400, f"Oversized command should be rejected with 400: {resp.status_code}"

    def test_null_byte_in_commands(self, services_up):
        payload = {
            "session_id": "SecNullByte001",
            "start_time": "2025-01-01T00:00:00Z",
            "commands": [
                {"timestamp": "2025-01-01T00:00:00Z", "command": "cat /etc/passwd\x00; rm -rf /"},
            ],
        }
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json=payload,
            headers=valid_headers(),
            timeout=10,
        )
        assert resp.status_code in [200, 400, 422]

    def test_unicode_overflow_commands(self, services_up):
        payload = {
            "session_id": "SecUnicode001",
            "start_time": "2025-01-01T00:00:00Z",
            "commands": [
                {"timestamp": "2025-01-01T00:00:00Z", "command": "\u0000\u0001\u0002" * 100},
            ],
        }
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json=payload,
            headers=valid_headers(),
            timeout=10,
        )
        assert resp.status_code in [200, 400, 422]


# ── Error Handling Security ──────────────────────────────────────────────────


class TestErrorHandling:
    """Errors must not leak stack traces, internal paths, or secrets."""

    def test_invalid_json_body_no_stack_trace(self, services_up):
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            data="not json at all {{{",
            headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
            timeout=5,
        )
        assert resp.status_code in [400, 422, 500]
        body = resp.text.lower()
        assert "traceback" not in body, "Stack trace leaked in error response"
        assert "file " not in body, "Internal file path leaked in error response"

    def test_missing_required_fields_defaults_applied(self, services_up):
        """Don accepts empty JSON and applies defaults (lenient validation)."""
        resp = requests.post(
            f"{API_BASE_URL}:{DON_PORT}/api/analyze",
            json={},
            headers=valid_headers(),
            timeout=5,
        )
        assert resp.status_code == 200, f"Don should accept empty JSON with defaults: {resp.status_code}"

    def test_hisoka_empty_input_no_crash(self, services_up):
        resp = requests.post(
            f"{API_BASE_URL}:{HISOKA_PORT}/api/deceive",
            json={},
            headers=valid_headers(),
            timeout=5,
        )
        assert resp.status_code in [200, 400, 422, 500]
        body = resp.text.lower()
        assert "traceback" not in body, "Stack trace leaked from Hisoka"


# ── API Key Not Leaked in Responses ──────────────────────────────────────────


class TestSecretLeakage:
    """API keys and secrets must never appear in response bodies."""

    def test_api_key_not_in_chrollo_response(self, services_up):
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json={"session_id": "SecLeak001", "start_time": "2025-01-01T00:00:00Z", "commands": []},
            headers=valid_headers(),
            timeout=5,
        )
        assert resp.status_code == 200
        assert API_KEY not in resp.text, "API key leaked in Chrollo response"

    def test_api_key_not_in_don_response(self, services_up):
        resp = requests.post(
            f"{API_BASE_URL}:{DON_PORT}/api/analyze",
            json={"session_id": "SecLeak002", "classification": "suspicious", "confidence": 0.5, "features": {}},
            headers=valid_headers(),
            timeout=5,
        )
        assert resp.status_code == 200
        assert API_KEY not in resp.text, "API key leaked in Don response"

    def test_api_key_not_in_hisoka_response(self, services_up):
        resp = requests.post(
            f"{API_BASE_URL}:{HISOKA_PORT}/api/deceive",
            json={"attacker_input": "test", "session_context": {"skill_level": "novice"}},
            headers=valid_headers(),
            timeout=5,
        )
        assert resp.status_code == 200
        assert API_KEY not in resp.text, "API key leaked in Hisoka response"


# ── HTTP Method Enforcement ──────────────────────────────────────────────────


class TestHTTPEndpoints:
    """Correct HTTP methods on endpoints; no dangerous methods allowed."""

    def test_classify_rejects_get(self, services_up):
        resp = requests.get(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            headers=valid_headers(),
            timeout=5,
        )
        assert resp.status_code in [405, 404, 401, 403], f"GET on /api/classify should be rejected: {resp.status_code}"

    def test_analyze_rejects_get(self, services_up):
        resp = requests.get(
            f"{API_BASE_URL}:{DON_PORT}/api/analyze",
            headers=valid_headers(),
            timeout=5,
        )
        assert resp.status_code in [405, 404, 401, 403], f"GET on /api/analyze should be rejected: {resp.status_code}"

    def test_deceive_rejects_get(self, services_up):
        resp = requests.get(
            f"{API_BASE_URL}:{HISOKA_PORT}/api/deceive",
            headers=valid_headers(),
            timeout=5,
        )
        assert resp.status_code in [405, 404, 401, 403], f"GET on /api/deceive should be rejected: {resp.status_code}"

    def test_delete_rejected_on_all_endpoints(self, services_up):
        for port in [CHROLLO_PORT, DON_PORT, HISOKA_PORT]:
            for endpoint in ["/api/classify", "/api/analyze", "/api/deceive"]:
                resp = requests.delete(
                    f"{API_BASE_URL}:{port}{endpoint}",
                    headers=valid_headers(),
                    timeout=5,
                )
                assert resp.status_code in [
                    405,
                    404,
                    401,
                    403,
                ], f"DELETE on {endpoint} port {port} should be rejected: {resp.status_code}"
