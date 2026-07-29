"""Elasticsearch connector using Common Event Format (CEF)."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from ragin.siem.connector import SIEMConnector, SIEMEvent

logger = logging.getLogger(__name__)


@dataclass
class ElasticsearchConfig:
    hosts: list[str] = field(default_factory=lambda: ["http://localhost:9200"])
    index_prefix: str = "ragin-alerts"
    api_key: str = ""
    username: str = ""
    password: str = ""
    verify_ssl: bool = True
    timeout: int = 10
    max_retries: int = 3
    batch_size: int = 100
    flush_interval_s: float = 5.0


class ElasticsearchCEFConnector(SIEMConnector):
    def __init__(self, config: ElasticsearchConfig | None = None) -> None:
        super().__init__(name="elasticsearch")
        self._config = config or ElasticsearchConfig()
        self._buffer: list[dict[str, Any]] = []
        self._last_flush = time.time()

    def _build_cef(self, event: SIEMEvent) -> str:
        severity = event.severity.to_cef_severity()
        extensions = (
            f"src={event.source_ip} "
            f"sessionid={event.session_id} "
            f"tenant={event.tenant_id} "
            f"msg={event.message} "
            f"rt={time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(event.timestamp))}Z "
            f"cs1={','.join(event.mitre_tactics)} cs1Label=MITRE_Tactics "
            f"cs2={','.join(event.mitre_techniques)} cs2Label=MITRE_Techniques "
            f"cs3={event.event_type} cs3Label=Event_Type "
            f"cs4={event.component} cs4Label=Component "
            f"cn1={1 if event.honeytoken_triggered else 0} cn1Label=Honeytoken_Triggered"
        )
        return f"CEF:0|RAGIN|RAGIN|1.0|{event.event_id}|{event.event_type}|{severity}|{extensions}"

    def _to_doc(self, event: SIEMEvent) -> dict[str, Any]:
        return {
            "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(event.timestamp)) + "Z",
            "event_id": event.event_id,
            "event_type": event.event_type,
            "severity": event.severity.value,
            "severity_cef": event.severity.to_cef_severity(),
            "source_ip": event.source_ip,
            "session_id": event.session_id,
            "tenant_id": event.tenant_id,
            "message": event.message,
            "details": event.details,
            "mitre_tactics": event.mitre_tactics,
            "mitre_techniques": event.mitre_techniques,
            "honeytoken_triggered": event.honeytoken_triggered,
            "component": event.component,
            "cef": self._build_cef(event),
            "labels": {"service": "ragin", "environment": "production"},
        }

    def send(self, event: SIEMEvent) -> bool:
        if not self.enabled:
            return False
        doc = self._to_doc(event)
        self._buffer.append({"index": {"_index": self._index_name()}, "_source": doc})
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

        bulk_body = "\n".join(json.dumps(action) for action in self._buffer) + "\n"
        headers: dict[str, str] = {"Content-Type": "application/x-ndjson"}
        if self._config.api_key:
            headers["Authorization"] = f"ApiKey {self._config.api_key}"
        elif self._config.username:
            import base64

            cred = base64.b64encode(f"{self._config.username}:{self._config.password}".encode()).decode()
            headers["Authorization"] = f"Basic {cred}"

        url = f"{self._config.hosts[0]}/_bulk"
        for attempt in range(self._config.max_retries):
            try:
                resp = httpx.post(
                    url,
                    content=bulk_body,
                    headers=headers,
                    timeout=self._config.timeout,
                    verify=self._config.verify_ssl,
                )
                result = resp.json()
                if resp.status_code == 200 and not result.get("errors"):
                    self._sent_count += len(self._buffer)
                    self._buffer.clear()
                    self._last_flush = time.time()
                    return True
                logger.warning("ES bulk returned errors: %s", result.get("items", [])[:3])
            except Exception as exc:
                logger.error("ES bulk attempt %d failed: %s", attempt + 1, exc)
                time.sleep(0.5 * (attempt + 1))
        self._error_count += len(self._buffer)
        self._buffer.clear()
        self._last_flush = time.time()
        return False

    def _index_name(self) -> str:
        suffix = time.strftime("%Y.%m.%d", time.gmtime())
        return f"{self._config.index_prefix}-{suffix}"

    def test_connection(self) -> bool:
        import httpx

        try:
            resp = httpx.get(f"{self._config.hosts[0]}/_cluster/health", timeout=5, verify=self._config.verify_ssl)
            return resp.status_code == 200
        except Exception:
            return False
