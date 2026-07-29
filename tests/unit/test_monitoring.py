"""Unit tests for ragin.monitoring module."""

from __future__ import annotations

import json
import threading
from unittest.mock import MagicMock, patch

import pytest

from ragin.monitoring.alerts import Alert, AlertManager, AlertSeverity
from ragin.monitoring.audit import AuditLogger, _redact_pii
from ragin.monitoring.health import HealthChecker, HealthState
from ragin.monitoring.metrics import MetricsCollector, MetricsSummary

# ── MetricsCollector ──────────────────────────────────────────────────────────


class TestMetricsCollector:
    def test_record_and_summary(self) -> None:
        mc = MetricsCollector()
        mc.record_request("chrollo", "classify", "ok", 15.0)
        mc.record_request("chrollo", "classify", "error", 150.0)
        mc.record_classification("intermediate", 0.85)
        mc.record_threat("high", ["TA0001"])
        mc.record_deception("sess_1", 120.0, 0.7)
        mc.record_evasion_detection("prompt_injection", 0.9)
        mc.record_cost("don", "llama-3.1-8b", 500, 0.002)

        s = mc.get_summary(window_minutes=60)
        assert s.total_requests == 2
        assert s.error_count == 1
        assert s.error_rate == pytest.approx(0.5)
        assert s.total_classifications == 1
        assert s.skill_level_distribution == {"intermediate": 1}
        assert s.total_threats == 1
        assert s.total_deceptions == 1
        assert s.avg_dwell_time_s == pytest.approx(120.0)
        assert s.avg_engagement_score == pytest.approx(0.7)
        assert s.evasion_detections == 1
        assert s.total_cost_usd == pytest.approx(0.002)
        assert "don" in s.cost_by_component

    def test_empty_summary(self) -> None:
        mc = MetricsCollector()
        s = mc.get_summary()
        assert s.total_requests == 0
        assert s.error_rate == 0.0
        assert s.latency_p50_ms == 0.0

    def test_thread_safety(self) -> None:
        mc = MetricsCollector()
        errors: list[Exception] = []

        def worker(thread_id: int) -> None:
            try:
                for i in range(100):
                    mc.record_request(f"comp_{thread_id}", "test", "ok", float(i))
                    mc.record_classification("novice", 0.5)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        s = mc.get_summary()
        assert s.total_requests == 1000
        assert s.total_classifications == 1000


# ── AlertManager ──────────────────────────────────────────────────────────────


class TestAlertManager:
    def _make_summary(self, **overrides: float) -> MetricsSummary:
        s = MetricsSummary(window_minutes=5)
        for k, v in overrides.items():
            setattr(s, k, v)
        return s

    def test_alert_error_rate(self) -> None:
        am = AlertManager()
        summary = self._make_summary(total_requests=100, error_count=6, error_rate=0.06)
        alerts = am.check_alerts(summary)
        assert any(a.rule_name == "error_rate" and a.severity == AlertSeverity.CRITICAL for a in alerts)

    def test_alert_latency(self) -> None:
        am = AlertManager()
        summary = self._make_summary(total_requests=10, latency_p99_ms=3000)
        alerts = am.check_alerts(summary)
        assert any(a.rule_name == "latency_p99" and a.severity == AlertSeverity.WARNING for a in alerts)

    def test_alert_cost_warning(self) -> None:
        am = AlertManager()
        summary = self._make_summary(total_cost_usd=25.0)
        alerts = am.check_alerts(summary)
        assert any(a.rule_name == "cost_daily_warning" for a in alerts)
        assert not any(a.rule_name == "cost_daily_critical" for a in alerts)

    def test_alert_cost_critical(self) -> None:
        am = AlertManager()
        summary = self._make_summary(total_cost_usd=60.0)
        alerts = am.check_alerts(summary)
        assert any(a.rule_name == "cost_daily_critical" and a.severity == AlertSeverity.CRITICAL for a in alerts)

    def test_alert_evasion_rate(self) -> None:
        am = AlertManager()
        summary = self._make_summary(evasion_detections=15)
        alerts = am.check_alerts(summary)
        assert any(a.rule_name == "evasion_rate" and a.severity == AlertSeverity.INFO for a in alerts)

    def test_alert_no_false_positives(self) -> None:
        am = AlertManager()
        summary = self._make_summary(
            total_requests=100,
            error_count=1,
            error_rate=0.01,
            latency_p99_ms=500,
            total_cost_usd=5.0,
            evasion_detections=3,
            active_sessions=50,
        )
        alerts = am.check_alerts(summary)
        assert alerts == []

    def test_handler_called(self) -> None:
        am = AlertManager()
        received: list[Alert] = []
        am.add_handler(received.append)
        summary = self._make_summary(total_cost_usd=55.0)
        am.check_alerts(summary)
        assert len(received) >= 1

    def test_disabled_rule_not_triggered(self) -> None:
        am = AlertManager()
        for rule in am._rules:
            if rule.name == "error_rate":
                rule.enabled = False
        summary = self._make_summary(total_requests=100, error_count=10, error_rate=0.1)
        alerts = am.check_alerts(summary)
        assert not any(a.rule_name == "error_rate" for a in alerts)


# ── AuditLogger ───────────────────────────────────────────────────────────────


class TestAuditLogger:
    def test_log_classification(self) -> None:
        al = AuditLogger()
        al.log_classification("sess_123", {"skill_level": "intermediate", "confidence": 0.85})
        assert len(al._events) == 1
        event = al._events[0]
        assert event["event_type"] == "classification"
        assert event["session_id"] == "sess_123"

    def test_pii_redaction(self) -> None:
        al = AuditLogger()
        al.log_classification(
            "sess_1",
            {"email": "test@example.com", "ssn": "123-45-6789", "phone": "555-123-4567"},
        )
        event = al._events[0]
        assert "example.com" not in json.dumps(event)
        assert "123-45-6789" not in json.dumps(event)
        assert "555-123-4567" not in json.dumps(event)

    def test_pii_redaction_function(self) -> None:
        assert "test@example.com" not in _redact_pii("email: test@example.com")
        assert "123-45-6789" not in _redact_pii("SSN: 123-45-6789")
        assert "REDACTED" in _redact_pii("email: test@example.com")

    def test_log_security_event(self) -> None:
        al = AuditLogger()
        al.log_security_event("prompt_injection", {"payload": "ignore previous", "source": "10.0.0.1"})
        event = al._events[0]
        assert event["event_type"] == "prompt_injection"
        assert "10.0.0.1" not in json.dumps(event)

    def test_log_to_file(self, tmp_path) -> None:
        log_file = tmp_path / "audit.jsonl"
        al = AuditLogger(log_path=str(log_file))
        al.log_cost_event("don", "llama-3.1-8b", 0.05)
        assert log_file.exists()

    def test_log_deception(self) -> None:
        al = AuditLogger()
        al.log_deception("sess_1", {"persona": "sysadmin", "response": "Here is /etc/passwd content"})
        assert al._events[0]["event_type"] == "deception"


# ── HealthChecker ─────────────────────────────────────────────────────────────


class TestHealthChecker:
    @patch("ragin.monitoring.health.httpx")
    def test_check_all_healthy(self, mock_httpx) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_httpx.get.return_value = mock_resp

        hc = HealthChecker()
        report = hc.check_all()
        assert report.state == HealthState.HEALTHY
        assert "monitoring" in report.components
        assert report.components["monitoring"].state == HealthState.HEALTHY

    @patch("ragin.monitoring.health.httpx")
    def test_check_all_degraded(self, mock_httpx) -> None:
        def side_effect(url, timeout=5.0):
            mock_resp = MagicMock()
            mock_resp.status_code = 503
            return mock_resp

        mock_httpx.get.side_effect = side_effect
        hc = HealthChecker()
        report = hc.check_all()
        assert report.state == HealthState.DEGRADED

    @patch("ragin.monitoring.health.httpx")
    def test_check_component_healthy(self, mock_httpx) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_httpx.get.return_value = mock_resp
        hc = HealthChecker()
        result = hc.check_component("test", "http://localhost:9999/health")
        assert result.state == HealthState.HEALTHY

    @patch("ragin.monitoring.health.httpx")
    def test_check_component_unhealthy(self, mock_httpx) -> None:
        mock_httpx.get.side_effect = ConnectionError("refused")
        hc = HealthChecker()
        result = hc.check_component("test", "http://localhost:9999/health")
        assert result.state == HealthState.UNHEALTHY
        assert "refused" in result.message

    def test_register_custom_component(self) -> None:
        hc = HealthChecker()
        hc.register_component("custom", "http://localhost:1234/health")
        assert "custom" in hc._components
