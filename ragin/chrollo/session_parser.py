"""Parse and normalize raw honeypot session logs into structured SessionLog objects."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from ragin.chrollo.models import (
    CommandEntry,
    FileOperation,
    NetworkActivity,
    SessionLog,
)

# Maximum allowed field lengths (injection prevention)
_MAX_CMD_LEN = 4096
_MAX_PATH_LEN = 1024
_MAX_RAW_LOG_LEN = 1_000_000

# Timestamp format patterns commonly seen in honeypot logs
_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%Y-%m-%dT%H:%M:%S%z",
]


def _safe_parse_ts(raw: str | datetime) -> datetime:
    """Best-effort timestamp parsing; returns UTC now on failure."""
    if isinstance(raw, datetime):
        return raw
    raw = str(raw).strip()
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def _redact_pii(text: str) -> str:
    """Strip common PII patterns from log text."""
    # Email addresses
    text = re.sub(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]+", "[REDACTED_EMAIL]", text)
    # Phone numbers (simple US pattern)
    text = re.sub(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "[REDACTED_PHONE]", text)
    # SSN-like patterns
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", text)
    return text


class SessionLogParser:
    """Parse raw honeypot session logs into normalized SessionLog objects."""

    def parse(self, raw_log: str) -> SessionLog:
        """Parse a raw text-format honeypot session log.

        Expects line-based format with common honeypot output patterns:
            2024-01-15T10:30:00Z COMMAND user@host $ <cmd>
            2024-01-15T10:30:01Z FILE_CREATE /tmp/malware.sh
            2024-01-15T10:30:02Z NET_OUT 192.168.1.100:4444 1024 bytes
        """
        if not raw_log or not raw_log.strip():
            raise ValueError("Empty session log")

        if len(raw_log) > _MAX_RAW_LOG_LEN:
            raise ValueError(f"Raw log exceeds {_MAX_RAW_LOG_LEN} byte limit")

        raw_log = _redact_pii(raw_log)
        lines = raw_log.strip().splitlines()

        session_id = ""
        source_ip = ""
        commands: list[CommandEntry] = []
        file_ops: list[FileOperation] = []
        net_activities: list[NetworkActivity] = []
        start_time: datetime | None = None
        end_time: datetime | None = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Extract session metadata
            if line.upper().startswith("SESSION_ID:"):
                session_id = line.split(":", 1)[1].strip()[:256]
            elif line.upper().startswith("SOURCE_IP:"):
                source_ip = line.split(":", 1)[1].strip()[:45]

            # Try to parse structured entries
            parsed = self._parse_line(line)
            if parsed is None:
                continue

            kind, data = parsed
            if kind == "command":
                commands.append(data)
                ts = data.timestamp
                if start_time is None or ts < start_time:
                    start_time = ts
                if end_time is None or ts > end_time:
                    end_time = ts
            elif kind == "file_op":
                file_ops.append(data)
            elif kind == "network":
                net_activities.append(data)

        if not session_id:
            session_id = hashlib_id(raw_log[:512])

        return SessionLog(
            session_id=session_id,
            source_ip=source_ip,
            start_time=start_time or datetime.now(timezone.utc),
            end_time=end_time,
            commands=commands,
            file_operations=file_ops,
            network_activity=net_activities,
            raw_log=raw_log[:_MAX_RAW_LOG_LEN],
        )

    def parse_json(self, json_log: str | dict) -> SessionLog:
        """Parse a JSON-format session log into a SessionLog object."""
        if isinstance(json_log, str):
            if len(json_log) > _MAX_RAW_LOG_LEN:
                raise ValueError("JSON log exceeds size limit")
            data = json.loads(_redact_pii(json_log))
        else:
            data = json_log

        # Delegate to pydantic model validation
        return SessionLog(**data)

    def normalize(self, session_data: dict) -> dict:
        """Normalize heterogeneous log formats into the standard SessionLog schema."""
        normalized: dict = {}

        # session_id
        normalized["session_id"] = str(
            session_data.get("session_id") or session_data.get("sid") or session_data.get("id") or ""
        ).strip()[:256]

        # source_ip
        normalized["source_ip"] = str(
            session_data.get("source_ip")
            or session_data.get("src_ip")
            or session_data.get("src")
            or session_data.get("remote_addr")
            or ""
        ).strip()[:45]

        # timestamps
        raw_start = session_data.get("start_time") or session_data.get("started_at") or session_data.get("ts_start")
        raw_end = session_data.get("end_time") or session_data.get("ended_at") or session_data.get("ts_end")
        normalized["start_time"] = _safe_parse_ts(raw_start) if raw_start else datetime.now(timezone.utc)
        normalized["end_time"] = _safe_parse_ts(raw_end) if raw_end else None

        # commands
        raw_cmds = session_data.get("commands") or session_data.get("cmd_log") or []
        normalized["commands"] = self._normalize_commands(raw_cmds)

        # file operations
        raw_files = (
            session_data.get("file_operations") or session_data.get("file_ops") or session_data.get("filesystem") or []
        )
        normalized["file_operations"] = self._normalize_file_ops(raw_files)

        # network activity
        raw_net = (
            session_data.get("network_activity") or session_data.get("net_log") or session_data.get("connections") or []
        )
        normalized["network_activity"] = self._normalize_network(raw_net)

        # raw_log passthrough (truncated)
        raw_log = str(session_data.get("raw_log") or session_data.get("raw") or "")
        normalized["raw_log"] = raw_log[:_MAX_RAW_LOG_LEN]

        return normalized

    # ── Private helpers ──────────────────────────────────────────────────

    def _parse_line(self, line: str) -> tuple[str, Any] | None:
        """Attempt to parse a single log line into a typed entry."""
        # Timestamp prefix pattern: YYYY-MM-DDTHH:MM:SS... <TYPE> ...
        m = re.match(
            r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)\s+"
            r"(COMMAND|FILE_CREATE|FILE_MODIFY|FILE_DELETE|FILE_READ|NET_OUT|NET_IN)\s+(.*)",
            line,
        )
        if not m:
            return None

        ts = _safe_parse_ts(m.group(1))
        entry_type = m.group(2)
        payload = m.group(3).strip()

        if entry_type == "COMMAND":
            cmd = payload[:_MAX_CMD_LEN]
            return ("command", CommandEntry(timestamp=ts, command=cmd))
        elif entry_type.startswith("FILE_"):
            op = entry_type.replace("FILE_", "").lower()
            path = payload.split()[0] if payload else ""
            return (
                "file_op",
                FileOperation(timestamp=ts, operation=op, path=path[:_MAX_PATH_LEN]),
            )
        elif entry_type.startswith("NET_"):
            entry_type.replace("NET_", "").lower()
            parts = payload.split()
            dest = parts[0] if parts else ""
            return (
                "network",
                NetworkActivity(
                    timestamp=ts,
                    protocol="tcp",
                    destination_ip=dest.split(":")[0] if ":" in dest else dest,
                    destination_port=(int(dest.split(":")[1]) if ":" in dest else 0),
                ),
            )
        return None

    def _normalize_commands(self, raw_cmds: list) -> list[CommandEntry]:
        entries: list[CommandEntry] = []
        for item in raw_cmds:
            if isinstance(item, str):
                entries.append(
                    CommandEntry(
                        timestamp=datetime.now(timezone.utc),
                        command=item[:_MAX_CMD_LEN],
                    )
                )
            elif isinstance(item, dict):
                entries.append(
                    CommandEntry(
                        timestamp=_safe_parse_ts(item.get("timestamp", "")),
                        command=str(item.get("command", item.get("cmd", "")))[:_MAX_CMD_LEN],
                        working_directory=str(item.get("working_directory", item.get("cwd", "")))[:_MAX_PATH_LEN],
                        user=str(item.get("user", ""))[:128],
                        exit_code=item.get("exit_code"),
                        output_length=int(item.get("output_length", 0)),
                    )
                )
        return entries

    def _normalize_file_ops(self, raw_ops: list) -> list[FileOperation]:
        entries: list[FileOperation] = []
        for item in raw_ops:
            if isinstance(item, dict):
                entries.append(
                    FileOperation(
                        timestamp=_safe_parse_ts(item.get("timestamp", "")),
                        operation=str(item.get("operation", item.get("op", "unknown"))),
                        path=str(item.get("path", item.get("file", "")))[:_MAX_PATH_LEN],
                        size=int(item.get("size", 0)),
                    )
                )
        return entries

    def _normalize_network(self, raw_net: list) -> list[NetworkActivity]:
        entries: list[NetworkActivity] = []
        for item in raw_net:
            if isinstance(item, dict):
                entries.append(
                    NetworkActivity(
                        timestamp=_safe_parse_ts(item.get("timestamp", "")),
                        protocol=str(item.get("protocol", "tcp")),
                        source_ip=str(item.get("source_ip", item.get("src_ip", "")))[:45],
                        destination_ip=str(item.get("destination_ip", item.get("dst_ip", "")))[:45],
                        destination_port=int(item.get("destination_port", item.get("dst_port", 0))),
                        bytes_sent=int(item.get("bytes_sent", 0)),
                        bytes_received=int(item.get("bytes_received", 0)),
                    )
                )
        return entries


def hashlib_id(seed: str) -> str:
    """Deterministic session ID from arbitrary seed text."""
    import hashlib

    return hashlib.sha256(seed.encode()).hexdigest()[:64]
