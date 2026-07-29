"""Feature extraction from parsed honeypot session logs for Chrollo classification."""

from __future__ import annotations

import math
import re

import pandas as pd

from ragin.chrollo.models import SessionLog

# ── Persistence / privilege-escalation keyword sets ───────────────────────────
_PERSISTENCE_PATTERNS = re.compile(
    r"crontab\s+-[er]|systemctl\s+enable|update-rc\.d|chkconfig|"
    r"/etc/rc\.local|\.bashrc|\.profile|authorized_keys|"
    r"iptables\s+-A|nc\s+-[el]|msfconsole|meterpreter",
    re.IGNORECASE,
)
_PRIV_ESC_PATTERNS = re.compile(
    r"sudo\s+-s|sudo\s+-i|chmod\s+[47]00|chown\s+root|"
    r"setuid|setgid|capabilities|capsh|getcap|"
    r"find\s+.*-perm.*-4000|pkexec|polkit",
    re.IGNORECASE,
)
_CREDENTIAL_PATTERNS = re.compile(
    r"john\s+|hashcat|hydra|medusa|"
    r"/etc/shadow|/etc/passwd|mimikatz|"
    r"kerbrute|secretsdump|impacket|"
    r"sshpass|CredentialDump|password\s*=",
    re.IGNORECASE,
)
_NETWORK_SCAN_PATTERNS = re.compile(
    r"nmap|masscan|zmap|rustscan|" r"masscan\s+-p|nikto|dirb|dirbuster|gobuster|" r"fuff|ffuf|wfuzz|httpx\s+-sc",
    re.IGNORECASE,
)
_CUSTOM_TOOL_INDICATORS = re.compile(
    r"\./[a-zA-Z0-9_-]+\.(sh|py|pl|rb|elf)|"
    r"python3?\s+-c\s|bash\s+-i\s*>|"
    r"wget\s+.*\|\s*(ba)?sh|curl\s+.*\|\s*(ba)?sh",
    re.IGNORECASE,
)

# Feature names in canonical order
FEATURE_NAMES: list[str] = [
    "command_complexity",
    "tool_usage_diversity",
    "persistence_techniques",
    "lateral_movement_indicators",
    "time_between_commands",
    "unique_commands_ratio",
    "privilege_escalation_attempts",
    "network_scan_detected",
    "credential_access_attempts",
    "custom_tool_usage",
]


class FeatureExtractor:
    """Extract a fixed-dimensional feature vector from a SessionLog."""

    def extract(self, session: SessionLog) -> dict[str, float]:
        """Extract features from a single parsed session log."""
        cmds = [c.command for c in session.commands]
        cmd_count = len(cmds)
        all_text = " ".join(cmds)

        # 1. command_complexity — average token count per command (clamped)
        if cmd_count > 0:
            avg_tokens = sum(len(c.split()) for c in cmds) / cmd_count
            command_complexity = min(avg_tokens / 20.0, 1.0)
        else:
            command_complexity = 0.0

        # 2. tool_usage_diversity — unique binaries / total commands
        binaries = set()
        for cmd in cmds:
            parts = cmd.split()
            if parts:
                # strip path prefix
                binary = parts[0].rsplit("/", 1)[-1]
                binaries.add(binary)
        tool_diversity = min(len(binaries) / max(cmd_count, 1), 1.0)

        # 3. persistence_techniques — count of persistence pattern matches
        persist_matches = _PERSISTENCE_PATTERNS.findall(all_text)
        persistence_techniques = min(len(persist_matches) / 10.0, 1.0)

        # 4. lateral_movement_indicators — SSH hops, PsExec-style, WinRM
        lateral_patterns = re.findall(
            r"ssh\s+-J|ssh\s+-N|psexec|winrm|wmiexec|" r"smbclient|smbexec|crackmapexec|evil-winrm",
            all_text,
            re.IGNORECASE,
        )
        lateral_movement = min(len(lateral_patterns) / 5.0, 1.0)

        # 5. time_between_commands — coefficient of variation of inter-command deltas
        time_cv = self._compute_time_cv(session)

        # 6. unique_commands_ratio — ratio of distinct commands to total
        if cmd_count > 0:
            unique_cmds = set(cmds)
            unique_ratio = len(unique_cmds) / cmd_count
        else:
            unique_ratio = 0.0

        # 7. privilege_escalation_attempts
        priv_matches = _PRIV_ESC_PATTERNS.findall(all_text)
        priv_esc = min(len(priv_matches) / 10.0, 1.0)

        # 8. network_scan_detected — boolean-ish
        net_scan = 1.0 if _NETWORK_SCAN_PATTERNS.search(all_text) else 0.0

        # 9. credential_access_attempts
        cred_matches = _CREDENTIAL_PATTERNS.findall(all_text)
        cred_access = min(len(cred_matches) / 10.0, 1.0)

        # 10. custom_tool_usage
        custom_matches = _CUSTOM_TOOL_INDICATORS.findall(all_text)
        custom_tool = min(len(custom_matches) / 5.0, 1.0)

        return {
            "command_complexity": round(command_complexity, 6),
            "tool_usage_diversity": round(tool_diversity, 6),
            "persistence_techniques": round(persistence_techniques, 6),
            "lateral_movement_indicators": round(lateral_movement, 6),
            "time_between_commands": round(time_cv, 6),
            "unique_commands_ratio": round(unique_ratio, 6),
            "privilege_escalation_attempts": round(priv_esc, 6),
            "network_scan_detected": net_scan,
            "credential_access_attempts": round(cred_access, 6),
            "custom_tool_usage": round(custom_tool, 6),
        }

    def extract_batch(self, sessions: list[SessionLog]) -> pd.DataFrame:
        """Extract features for multiple sessions, returning a DataFrame."""
        rows = [self.extract(s) for s in sessions]
        return pd.DataFrame(rows, columns=FEATURE_NAMES)

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _compute_time_cv(session: SessionLog) -> float:
        """Coefficient of variation of inter-command time deltas."""
        timestamps = sorted(c.timestamp for c in session.commands)
        if len(timestamps) < 2:
            return 0.0

        deltas: list[float] = []
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i - 1]).total_seconds()
            deltas.append(delta)

        if not deltas:
            return 0.0

        mean = sum(deltas) / len(deltas)
        if mean == 0:
            return 0.0

        variance = sum((d - mean) ** 2 for d in deltas) / len(deltas)
        std = math.sqrt(variance)
        cv = std / mean
        return min(cv / 5.0, 1.0)  # normalize to [0, 1]
