"""Splunk HTTP Event Collector (HEC) connector."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any

from ragin.siem.connector import SIEMConnector, SIEMEvent

logger = logging.getLogger(__name__)


@dataclass
class SplunkConfig:
    host: str = "localhost"
    port: int = 8088
    hec_token: str = ""
    index: str = "ragin"
    source: str = "ragin_honeypot"
    sourcetype: str = "ragin:alert"
    verify_ssl: bool = True
    timeout: int = 10
    max_retries: int = 3
    batch_size: int = 50
    flush_interval_s: float = 5.0


class SplunkHECConnector(SIEMConnector):
    def __init__(self, config: SplunkConfig | None = None) -> None:
        super().__init__(name="splunk_hec")
        self._config = config or SplunkConfig()
        self._url = f"https://{self._config.host}:{self._config.port}/services/collector/event"
        self._buffer: list[dict[str, Any]] = []
        self._last_flush = time.time()

    def _format_event(self, event: SIEMEvent) -> dict[str, Any]:
        return {
            "time": event.timestamp,
            "host": event.source_ip or "ragin",
            "source": self._config.source,
            "sourcetype": self._config.sourcetype,
            "index": self._config.index,
            "event": {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "severity": event.severity.value,
                "source_ip": event.source_ip,
                "session_id": event.session_id,
                "tenant_id": event.tenant_id,
                "message": event.message,
                "details": event.details,
                "mitre_tactics": event.mitre_tactics,
                "mitre_techniques": event.mitre_techniques,
                "honeytoken_triggered": event.honeytoken_triggered,
                "component": event.component,
            },
        }

    def send(self, event: SIEMEvent) -> bool:
        if not self.enabled:
            return False
        payload = self._format_event(event)
        self._buffer.append(payload)
        if len(self._buffer) >= self._config.batch_size:
            return self.flush()
        elapsed = time.time() - self._last_flush
        if elapsed >= self._config.flush_interval_s:
            return self.flush()
        return True

    def flush(self) -> bool:
        if not self._buffer:
            return True
        import httpx

        payload = {"batch": self._buffer}
        headers = {
            "Authorization": f"Splunk {self._config.hec_token}",
            "Content-Type": "application/json",
        }
        for attempt in range(self._config.max_retries):
            try:
                resp = httpx.post(
                    self._url,
                    content=json.dumps(payload),
                    headers=headers,
                    timeout=self._config.timeout,
                    verify=self._config.verify_ssl,
                )
                if resp.status_code == 200:
                    self._sent_count += len(self._buffer)
                    self._buffer.clear()
                    self._last_flush = time.time()
                    return True
                logger.warning("Splunk HEC returned %d: %s", resp.status_code, resp.text[:200])
            except Exception as exc:
                logger.error("Splunk HEC attempt %d failed: %s", attempt + 1, exc)
                time.sleep(0.5 * (attempt + 1))
        self._error_count += len(self._buffer)
        self._buffer.clear()
        self._last_flush = time.time()
        return False

    def test_connection(self) -> bool:
        import httpx

        url = f"https://{self._config.host}:{self._config.port}/services/collector/health"
        try:
            resp = httpx.get(url, timeout=5, verify=self._config.verify_ssl)
            return resp.status_code == 200
        except Exception:
            return False
