"""Syslog connector using CEF (Common Event Format) for generic SIEM integration."""

from __future__ import annotations

import contextlib
import logging
import socket
import time
from dataclasses import dataclass

from ragin.siem.connector import SIEMConnector, SIEMEvent, SIEMSeverity

logger = logging.getLogger(__name__)


@dataclass
class SyslogConfig:
    host: str = "localhost"
    port: int = 514
    protocol: str = "udp"
    facility: int = 16
    hostname: str = "ragin"
    timeout: int = 5
    tls_enabled: bool = False
    tls_cert_path: str = ""


class SyslogCEFConnector(SIEMConnector):
    def __init__(self, config: SyslogConfig | None = None) -> None:
        super().__init__(name="syslog")
        self._config = config or SyslogConfig()
        self._sock: socket.socket | None = None

    def _connect(self) -> socket.socket:
        if self._sock is not None:
            return self._sock
        if self._config.protocol == "tcp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self._config.timeout)
            self._sock.connect((self._config.host, self._config.port))
        else:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._sock

    def _build_cef(self, event: SIEMEvent) -> str:
        severity = event.severity.to_cef_severity()
        pri = (self._config.facility << 3) | min(severity, 7)
        timestamp = time.strftime("%b %d %H:%M:%S", time.gmtime(event.timestamp))
        extensions = (
            f"src={event.source_ip} "
            f"sessionid={event.session_id} "
            f"tenant={event.tenant_id} "
            f"msg={event.message} "
            f"cs1={','.join(event.mitre_tactics)} cs1Label=MITRE_Tactics "
            f"cs2={','.join(event.mitre_techniques)} cs2Label=MITRE_Techniques "
            f"cs3={event.event_type} cs3Label=Event_Type "
            f"cn1={1 if event.honeytoken_triggered else 0} cn1Label=Honeytoken_Triggered"
        )
        return (
            f"<{pri}>{timestamp} {self._config.hostname} "
            f"RAGIN: CEF:0|RAGIN|RAGIN|1.0|{event.event_id}|{event.event_type}|{severity}|{extensions}"
        )

    def send(self, event: SIEMEvent) -> bool:
        if not self.enabled:
            return False
        try:
            sock = self._connect()
            cef_msg = self._build_cef(event)
            data = cef_msg.encode("utf-8")
            if self._config.protocol == "tcp":
                sock.sendall(data)
            else:
                sock.sendto(data, (self._config.host, self._config.port))
            self._sent_count += 1
            return True
        except Exception as exc:
            logger.error("Syslog send failed: %s", exc)
            self._error_count += 1
            self._sock = None
            return False

    def test_connection(self) -> bool:
        try:
            sock = self._connect()
            test_msg = self._build_cef(
                SIEMEvent(
                    event_id="test",
                    event_type="connectivity_test",
                    severity=SIEMSeverity.INFO,
                    message="RAGIN SIEM connectivity test",
                )
            )
            data = test_msg.encode("utf-8")
            if self._config.protocol == "tcp":
                sock.sendall(data)
            else:
                sock.sendto(data, (self._config.host, self._config.port))
            return True
        except Exception:
            return False

    def close(self) -> None:
        if self._sock is not None:
            with contextlib.suppress(Exception):
                self._sock.close()
            self._sock = None
