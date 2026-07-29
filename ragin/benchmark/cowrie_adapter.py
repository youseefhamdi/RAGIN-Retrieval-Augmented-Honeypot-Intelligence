"""Cowrie log adapter — parse Cowrie JSON logs into RAGIN EffectivenessMetrics.

Cowrie (https://github.com/cowrie/cowrie) is a medium-to-high interaction
SSH/Telnet honeypot. This adapter parses its JSON log format and computes
equivalent EffectivenessMetrics for apples-to-apples comparison with RAGIN.

Cowrie JSON log format (one JSON object per line):
    {"eventid": "cowrie.login.success", "session": "abc123",
     "src_ip": "1.2.3.4", "username": "root", "password": "toor",
     "timestamp": "2024-01-01T00:00:00Z"}

Key event IDs:
    cowrie.login.success / cowrie.login.failed   — auth attempts
    cowrie.command.input                          — commands executed
    cowrie.session.file_download                  — file downloads (artifacts accessed)
    cowrie.session.file_upload                    — file uploads
    cowrie.session.closed                        — session end
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ragin.benchmark.effectiveness import EffectivenessMetrics
from ragin.utils import hash_ip

logger = logging.getLogger(__name__)

# ── Known Cowrie event categories ──────────────────────────────────────

COWRIE_LOGIN_EVENTS = {"cowrie.login.success", "cowrie.login.failed"}
COWRIE_COMMAND_EVENTS = {"cowrie.command.input"}
COWRIE_FILE_EVENTS = {"cowrie.session.file_download", "cowrie.session.file_upload"}
COWRIE_SESSION_EVENTS = {"cowrie.session.closed"}

# MITRE ATT&CK mappings for common Cowrie-captured commands
COMMAND_TTP_MAP: dict[str, list[str]] = {
    "whoami": ["T1033"],
    "id": ["T1033"],
    "uname": ["T1082"],
    "uname -a": ["T1082"],
    "cat /etc/passwd": ["T1003.008"],
    "cat /etc/shadow": ["T1003.008"],
    "ifconfig": ["T1049"],
    "ip addr": ["T1049"],
    "netstat": ["T1049"],
    "ps aux": ["T1057"],
    "top": ["T1057"],
    "ls": ["T1083"],
    "ls -la": ["T1083"],
    "pwd": ["T1082"],
    "wget": ["T1105"],
    "curl": ["T1105"],
    "ssh": ["T1021.004"],
    "scp": ["T1021.004"],
    "tar": ["T1005"],
    "find": ["T1083"],
    "grep": ["T1083"],
    "chmod": ["T1222"],
    "chown": ["T1222"],
    "rm -rf /": ["T1485"],
    "dd if=/dev/zero": ["T1485"],
    "python -c": ["T1059.006"],
    "perl -e": ["T1059.003"],
    "nc -e": ["T1219"],
    "ncat": ["T1219"],
    "msfconsole": ["T1219"],
    "exploit": ["T1219"],
}


@dataclass
class CowrieSession:
    """Aggregated state for a single Cowrie session."""

    session_id: str = ""
    src_ip: str = ""
    login_attempts: int = 0
    successful_logins: int = 0
    commands: list[str] = field(default_factory=list)
    files_downloaded: int = 0
    files_uploaded: int = 0
    start_time: str = ""
    end_time: str = ""
    duration_s: float = 0.0
    username: str = ""
    password: str = ""

    @property
    def is_engaged(self) -> bool:
        return len(self.commands) > 0

    @property
    def unique_commands(self) -> list[str]:
        return list(dict.fromkeys(self.commands))

    @property
    def ttps_from_commands(self) -> set[str]:
        ttps: set[str] = set()
        for cmd in self.commands:
            cmd_lower = cmd.lower().strip()
            for pattern, mapped_ttps in COMMAND_TTP_MAP.items():
                if pattern in cmd_lower:
                    ttps.update(mapped_ttps)
        return ttps


@dataclass
class CowrieLogParseResult:
    """Parsed result from Cowrie JSON logs."""

    sessions: dict[str, CowrieSession] = field(default_factory=dict)
    total_events: int = 0
    parse_errors: int = 0

    @property
    def session_count(self) -> int:
        return len(self.sessions)

    @property
    def engaged_sessions(self) -> int:
        return sum(1 for s in self.sessions.values() if s.is_engaged)

    @property
    def all_commands(self) -> list[str]:
        cmds: list[str] = []
        for s in self.sessions.values():
            cmds.extend(s.commands)
        return cmds

    @property
    def all_ttps(self) -> set[str]:
        ttps: set[str] = set()
        for s in self.sessions.values():
            ttps.update(s.ttps_from_commands)
        return ttps


class CowrieAdapter:
    """Parse Cowrie JSON logs and produce EffectivenessMetrics.

    Usage::

        adapter = CowrieAdapter()
        result = adapter.parse_file("cowrie.json")
        # or from a list of parsed log lines:
        result = adapter.parse_lines(log_lines)
        metrics = adapter.to_metrics(result)
    """

    def parse_file(self, path: str | Path) -> CowrieLogParseResult:
        """Parse a Cowrie JSON log file (one JSON object per line)."""
        lines: list[str] = []
        try:
            with open(path) as f:
                lines = f.readlines()
        except (FileNotFoundError, PermissionError) as e:
            logger.error("Failed to read Cowrie log: %s", e)
            return CowrieLogParseResult()
        return self.parse_lines(lines)

    def parse_lines(self, lines: list[str]) -> CowrieLogParseResult:
        """Parse Cowrie log lines (each line is a JSON object)."""
        result = CowrieLogParseResult()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            result.total_events += 1
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                result.parse_errors += 1
                continue
            self._process_event(event, result)
        return result

    def _process_event(self, event: dict[str, Any], result: CowrieLogParseResult) -> None:
        event_id = event.get("eventid", "")
        session_id = event.get("session", "unknown")

        if session_id not in result.sessions:
            result.sessions[session_id] = CowrieSession(session_id=session_id)
        session = result.sessions[session_id]

        if not session.src_ip:
            session.src_ip = hash_ip(event.get("src_ip", ""))

        if event_id in COWRIE_LOGIN_EVENTS:
            session.login_attempts += 1
            if event_id == "cowrie.login.success":
                session.successful_logins += 1
                session.username = event.get("username", "")
                session.password = event.get("password", "")
            if not session.start_time:
                session.start_time = event.get("timestamp", "")

        elif event_id in COWRIE_COMMAND_EVENTS:
            cmd = event.get("input", "")
            if cmd:
                session.commands.append(cmd)

        elif event_id in COWRIE_FILE_EVENTS:
            if event_id == "cowrie.session.file_download":
                session.files_downloaded += 1
            elif event_id == "cowrie.session.file_upload":
                session.files_uploaded += 1

        elif event_id in COWRIE_SESSION_EVENTS:
            session.end_time = event.get("timestamp", "")

    def to_metrics(self, result: CowrieLogParseResult) -> EffectivenessMetrics:
        """Convert parsed Cowrie data into EffectivenessMetrics."""
        total = result.session_count
        engaged = result.engaged_sessions
        all_ttps = result.all_ttps

        # Honeytokens: Cowrie doesn't have native honeytokens.
        # File downloads/uploads are the closest analog (attacker accessed something).
        artifacts_deployed = max(total, 1)
        artifacts_accessed = sum(1 for s in result.sessions.values() if s.files_downloaded > 0 or s.files_uploaded > 0)

        # TTPs detected from command analysis
        ttps_detected = sum(1 for s in result.sessions.values() if s.ttps_from_commands)

        # Persona: Cowrie has no persona system
        persona_correct = 0
        persona_total = 0

        # Duration
        durations = [s.duration_s for s in result.sessions.values() if s.duration_s > 0]
        avg_duration = sum(durations) / len(durations) if durations else 0.0

        # Retention: avg commands per session
        cmd_counts = [len(s.commands) for s in result.sessions.values()]
        avg_retention = sum(cmd_counts) / len(cmd_counts) if cmd_counts else 0.0

        return EffectivenessMetrics(
            honeytoken_triggers=artifacts_accessed,
            honeytokens_deployed=artifacts_deployed,
            total_sessions=total,
            sessions_with_engagement=engaged,
            persona_correct_assignments=persona_correct,
            persona_total_assignments=persona_total,
            ttps_detected=ttps_detected,
            ttps_detected_unique=len(all_ttps),
            cti_alerts_generated=ttps_detected,
            false_positives=0,
            true_positives=ttps_detected,
            attacker_retention_turns=avg_retention,
            max_retention_turns=max(cmd_counts) if cmd_counts else 0,
            mean_session_duration_s=avg_duration,
            deception_artifacts_deployed=artifacts_deployed,
            deception_artifacts_accessed=artifacts_accessed,
            strategy_adaptations=0,  # Cowrie has no adaptive strategy
            avg_response_time_ms=0.0,  # Cowrie doesn't track response time
        )
