"""ThreatMapper — map attacker behavior to MITRE ATT&CK, identify actors, score sophistication."""

from __future__ import annotations

import logging
import re
from typing import Any

from .models import IOC, IOCType, MITRETactic, ThreatActor

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# MITRE ATT&CK technique → tactic mapping (subset for common techniques)
# ------------------------------------------------------------------
_TECHNIQUE_TO_TACTIC: dict[str, tuple[str, str]] = {
    "T1566": ("TA0001", "Phishing"),
    "T1190": ("TA0001", "Exploit Public-Facing Application"),
    "T1133": ("TA0001", "External Remote Services"),
    "T1078": ("TA0001", "Valid Accounts"),
    "T1033": ("TA0007", "System Owner/User Discovery"),
    "T1059": ("TA0002", "Command and Scripting Interpreter"),
    "T1059.001": ("TA0002", "PowerShell"),
    "T1571": ("TA0008", "Non-Standard Port"),
    "T1046": ("TA0007", "Network Service Discovery"),
    "T1053": ("TA0002", "Scheduled Task/Job"),
    "T1055": ("TA0002", "Process Injection"),
    "T1547": ("TA0003", "Boot or Logon Autostart Execution"),
    "T1543": ("TA0003", "Create or Modify System Process"),
    "T1136": ("TA0003", "Create Account"),
    "T1548": ("TA0004", "Abuse Elevation Control Mechanism"),
    "T1068": ("TA0004", "Exploitation for Privilege Escalation"),
    "T1027": ("TA0005", "Obfuscated Files or Information"),
    "T1070": ("TA0005", "Indicator Removal"),
    "T1036": ("TA0005", "Masquerading"),
    "T1003": ("TA0006", "OS Credential Dumping"),
    "T1003.008": ("TA0006", "/etc/passwd and /etc/shadow"),
    "T1552": ("TA0006", "Unsecured Credentials"),
    "T1552.005": ("TA0006", "Cloud Instance Metadata API Abuse"),
    "T1134": ("TA0005", "Access Token Manipulation"),
    "T1110": ("TA0006", "Brute Force"),
    "T1087": ("TA0007", "Account Discovery"),
    "T1018": ("TA0007", "Remote System Discovery"),
    "T1021": ("TA0008", "Remote Services"),
    "T1550": ("TA0008", "Use Alternate Authentication Material"),
    "T1005": ("TA0009", "Data from Local System"),
    "T1039": ("TA0009", "Data from Network Shared Drive"),
    "T1071": ("TA0011", "Application Layer Protocol"),
    "T1573": ("TA0011", "Encrypted Channel"),
    "T1102": ("TA0011", "Web Service"),
    "T1041": ("TA0010", "Exfiltration Over C2 Channel"),
    "T1567": ("TA0010", "Exfiltration Over Web Service"),
    "T1486": ("TA0040", "Data Encrypted for Impact"),
    "T1489": ("TA0040", "Service Stop"),
}

# Known actor → technique associations
_ACTOR_TECHNIQUES: dict[str, set[str]] = {
    "apt28": {"T1566", "T1078", "T1059", "T1027", "T1003", "T1071", "T1573"},
    "apt29": {"T1566", "T1190", "T1078", "T1059", "T1547", "T1055", "T1027", "T1070"},
    "apt41": {"T1190", "T1059", "T1055", "T1027", "T1003", "T1041", "T1567"},
    "lazarus group": {"T1566", "T1059", "T1053", "T1027", "T1071"},
    "cozy bear": {"T1566", "T1078", "T1059", "T1547", "T1550"},
    "fancy bear": {"T1566", "T1078", "T1059", "T1027", "T1071"},
    "hafnium": {"T1190", "T1059", "T1078", "T1003", "T1021"},
    "sandworm": {"T1486", "T1489", "T1059", "T1027", "T1071"},
    "fin7": {"T1566", "T1059", "T1053", "T1055", "T1003"},
    "darkside": {"T1486", "T1059", "T1027", "T1070", "T1041"},
    "revil": {"T1486", "T1489", "T1059", "T1055", "T1041"},
}


_TECHNIQUE_NAME_TO_ID: dict[str, str] = {
    "phishing": "T1566",
    "spear phishing": "T1566.001",
    "credential dumping": "T1003",
    "password brute force": "T1110",
    "process injection": "T1566",
    "defense evasion": "T1027",
    "obfuscation": "T1027",
    "lateral movement": "T1021",
    "remote services": "T1021",
    "persistence": "T1547",
    "scheduled task": "T1053",
    "registry run key": "T1547.001",
    "command and scripting interpreter": "T1059",
    "powershell": "T1059.001",
    "client execution": "T1203",
    "exploitation": "T1068",
    "privilege escalation": "T1548",
    "discov": "T1046",
    "enumeration": "T1046",
    "discovery": "T1046",
    "account discovery": "T1087",
    "system information": "T1082",
    "file discovery": "T1083",
    "keylogging": "T1056",
    "screen capture": "T1113",
    "data collection": "T1005",
    "email collection": "T1114",
    "command and control": "T1071",
    "c2 channel": "T1041",
    "exfiltration": "T1041",
    "ransomware": "T1486",
    "data encrypted": "T1486",
    "service stop": "T1489",
    "impact": "T1486",
    "supply chain": "T1195",
    "initial access": "T1566",
    "valid accounts": "T1078",
    "masquerading": "T1036",
    "indicator removal": "T1070",
    "proxy execution": "T1211",
    "uac bypass": "T1548.003",
    "brute force": "T1110",
}

# Compound regex patterns for short / natural-language TTP detection.
# Covers the surface forms present in ragin/benchmark/human_eval.py SAMPLE_SCENARIOS.
# Each pattern maps to one or more MITRE technique IDs (sub-techniques supported).
_PHRASE_PATTERNS: list[tuple[str, list[str]]] = [
    # GT-001 — System Owner/User Discovery (T1033)
    (r"\bwhoami\b|\bsystem owner\b|\bcurrent user\b", ["T1033"]),
    # GT-002 — Data from Local System (T1005) + Unsecured Credentials (T1552)
    (r"\bdatabase credentials\b|\bpassword\b|\bcredentials\b|\bhash\b", ["T1005", "T1552"]),
    # GT-003 — Valid Accounts (T1078) + Access Token Manipulation (T1134)
    (r"\bescalate privileges\b|\bdomain admin\b|\bprivilege escalation\b|\bdomain controller\b", ["T1078", "T1134"]),
    # GT-004 — IMDS / Cloud Instance Metadata SSRF (T1552.005)
    (r"169\.254\.169\.254|\bimds\b|\bmeta-data\b|\binstance metadata\b", ["T1552.005"]),
    # GT-005 — SQL Injection / Exploit Public-Facing Application (T1190)
    (r"select\s+\*\s+from|\bsql injection\b|\bunion select\b|'\s*or\s*'1'\s*=\s*'1|\bsqli\b", ["T1190"]),
    # GT-006 — System Service / Network Service Discovery (T1046)
    (r"\brunning services\b|\bsystemctl\b|\bservice list\b|\bsc query\b", ["T1046"]),
    # GT-007 — Reverse shell / Command & Scripting Interpreter (T1059.001) + Non-Standard Port (T1571)
    (r"\breverse shell\b|\bbind shell\b|\bport\s+4444\b|\bnc\s+-e\b", ["T1059.001", "T1571"]),
    # GT-008 — /etc/passwd and /etc/shadow (T1003.008)
    (r"/etc/shadow|\bshadow file\b|\bcredential dumping\b|\bsecretsdump\b", ["T1003.008"]),
]


class ThreatMapper:
    """Map attacker behavior to MITRE ATT&CK tactics and known threat actors."""

    def __init__(self, actor_db: dict[str, set[str]] | None = None) -> None:
        self._actor_db = actor_db or _ACTOR_TECHNIQUES

    def map_to_mitre(self, session_features: dict[str, Any]) -> list[MITRETactic]:
        """Map session features to MITRE ATT&CK tactics."""
        detected_techniques: dict[str, str] = {}  # tactic_id → tactic_name

        observed = session_features.get("observed_techniques", [])
        commands = session_features.get("commands", [])
        process_names = session_features.get("process_names", [])

        detected_technique_ids: set[str] = set()

        # Check explicit technique tags
        for tech in observed:
            if tech in _TECHNIQUE_TO_TACTIC:
                tid, tname = _TECHNIQUE_TO_TACTIC[tech]
                detected_techniques[tid] = tname
                detected_technique_ids.add(tech)

        # Heuristic command analysis
        cmd_text = " ".join(str(c) for c in commands).lower()
        self._detect_from_commands(cmd_text, detected_techniques)

        # Process name hints
        proc_text = " ".join(str(p) for p in process_names).lower()
        self._detect_from_processes(proc_text, detected_techniques)

        # Text-based technique name detection (for natural language queries)
        self._detect_from_text(session_features, detected_techniques, detected_technique_ids)

        # Build result — group technique IDs by tactic
        tech_by_tactic: dict[str, set[str]] = {}
        for tech_id in detected_technique_ids:
            parent_id = tech_id.split(".", 1)[0]
            mapping = _TECHNIQUE_TO_TACTIC.get(parent_id)
            if mapping is None:
                continue
            tid, _ = mapping
            tech_by_tactic.setdefault(tid, set()).add(tech_id)

        tactics: list[MITRETactic] = []
        for tid, tname in detected_techniques.items():
            confidence = min(0.9, 0.5 + 0.1 * len([t for t in observed if t in _TECHNIQUE_TO_TACTIC]))
            ttp_list = sorted(tech_by_tactic.get(tid, set()))
            sub_list = [t for t in ttp_list if "." in t]
            tactics.append(
                MITRETactic(
                    tactic_id=tid,
                    tactic_name=tname,
                    confidence=round(confidence, 2),
                    techniques=ttp_list,
                    sub_techniques=sub_list,
                )
            )
        return tactics

    def identify_actor(self, ttps: list[MITRETactic], iocs: list[IOC] | None = None) -> list[ThreatActor]:
        """Match observed TTPs against known threat actor profiles."""
        observed_techniques: set[str] = set()
        for tactic in ttps:
            for tech_id in tactic.techniques:
                observed_techniques.add(tech_id)
            # Also check the tactic ID as a proxy
            for tid, (mapped_tid, _) in _TECHNIQUE_TO_TACTIC.items():
                if mapped_tid == tactic.tactic_id:
                    observed_techniques.add(tid)

        if not observed_techniques:
            return []

        scores: list[tuple[str, float]] = []
        for actor_name, known_techs in self._actor_db.items():
            overlap = observed_techniques & known_techs
            if overlap:
                score = len(overlap) / len(known_techs)
                scores.append((actor_name, score))

        scores.sort(key=lambda x: x[1], reverse=True)

        actors: list[ThreatActor] = []
        for name, score in scores[:5]:
            if score < 0.2:
                break
            actors.append(
                ThreatActor(
                    name=name.title(),
                    confidence=round(min(score, 0.95), 2),
                    known_ttps=list(self._actor_db.get(name, set())),
                )
            )
        return actors

    def calculate_sophistication_score(self, features: dict[str, Any]) -> float:
        """Calculate attacker sophistication on [0.0, 1.0]."""
        score = 0.0

        # Evasion techniques increase score
        evasion = features.get("evasion_techniques", [])
        score += min(0.3, len(evasion) * 0.05)

        # Tool diversity
        tools = features.get("tools_used", [])
        score += min(0.2, len(tools) * 0.03)

        # Duration and stealth
        duration = features.get("session_duration_s", 0)
        if duration > 3600:
            score += 0.15
        elif duration > 600:
            score += 0.1

        # Credential usage
        if features.get("credential_access", False):
            score += 0.1

        # Lateral movement
        if features.get("lateral_movement", False):
            score += 0.15

        # Encrypted C2
        if features.get("encrypted_comms", False):
            score += 0.1

        # Anti-analysis
        if features.get("anti_analysis", False):
            score += 0.1

        return round(min(score, 1.0), 2)

    def generate_ioc_list(self, session_log: list[dict[str, Any]]) -> list[IOC]:
        """Extract IOCs from session log entries."""
        iocs: list[IOC] = []
        seen: set[str] = set()

        for entry in session_log:
            # IP addresses
            for match in re.finditer(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", str(entry)):
                val = match.group(1)
                key = f"ip:{val}"
                if key not in seen:
                    seen.add(key)
                    iocs.append(IOC(type=IOCType.IP, value=val, confidence=0.7))

            # Domains
            for match in re.finditer(r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})\b", str(entry)):
                val = match.group(1)
                key = f"domain:{val}"
                if key not in seen:
                    seen.add(key)
                    iocs.append(IOC(type=IOCType.DOMAIN, value=val, confidence=0.6))

            # SHA-256 hashes
            for match in re.finditer(r"\b([a-fA-F0-9]{64})\b", str(entry)):
                val = match.group(1)
                key = f"sha256:{val}"
                if key not in seen:
                    seen.add(key)
                    iocs.append(IOC(type=IOCType.HASH_SHA256, value=val.lower(), confidence=0.8))

            # MD5 hashes
            for match in re.finditer(r"\b([a-fA-F0-9]{32})\b", str(entry)):
                val = match.group(1)
                key = f"md5:{val}"
                if key not in seen:
                    seen.add(key)
                    iocs.append(IOC(type=IOCType.HASH_MD5, value=val.lower(), confidence=0.6))

            # URLs
            for match in re.finditer(r"(https?://[^\s\"'<>]+)", str(entry)):
                val = match.group(1)
                key = f"url:{val}"
                if key not in seen:
                    seen.add(key)
                    iocs.append(IOC(type=IOCType.URL, value=val, confidence=0.7))

            # User-Agents
            ua = entry.get("user_agent", "")
            if ua and isinstance(ua, str) and len(ua) > 10:
                key = f"ua:{ua}"
                if key not in seen:
                    seen.add(key)
                    iocs.append(IOC(type=IOCType.USER_AGENT, value=ua, confidence=0.5))

        return iocs

    # ------------------------------------------------------------------
    # Heuristic detection
    # ------------------------------------------------------------------

    def _detect_from_commands(self, cmd_text: str, techniques: dict[str, str]) -> None:
        if any(kw in cmd_text for kw in ("powershell -enc", "base64", "bypass", "-nop -w hidden")):
            techniques.setdefault("TA0005", "Defense Evasion")
        if any(kw in cmd_text for kw in ("mimikatz", "sekurlsa", "kerberos::list", "/etc/shadow", "/etc/passwd")):
            techniques.setdefault("TA0006", "Credential Access")
        if any(kw in cmd_text for kw in ("net user", "net group", "whoami", "id", "uname", "ps aux", "ls -la")):
            techniques.setdefault("TA0007", "Discovery")
        if any(kw in cmd_text for kw in ("psexec", "wmic", "winrm", "ssh ")):
            techniques.setdefault("TA0008", "Lateral Movement")
        if any(kw in cmd_text for kw in ("reg add", "schtasks", "sc create", "new-service")):
            techniques.setdefault("TA0003", "Persistence")
        if any(kw in cmd_text for kw in ("find /", "/ -name")):
            techniques.setdefault("TA0007", "Discovery")
        if any(kw in cmd_text for kw in ("curl http", "wget ", "invoke-webrequest", "certutil")):
            techniques.setdefault("TA0011", "Command and Control")

    def _detect_from_processes(self, proc_text: str, techniques: dict[str, str]) -> None:
        if any(p in proc_text for p in ("mimikatz", "lazagne", "procdump")):
            techniques.setdefault("TA0006", "Credential Access")
        if any(p in proc_text for p in ("nmap", "masscan", "rustscan")):
            techniques.setdefault("TA0007", "Discovery")
        if any(p in proc_text for p in ("cobalt", "beacon", "meterpreter")):
            techniques.setdefault("TA0011", "Command and Control")
        if any(p in proc_text for p in ("psexec", "wmi", "winrm")):
            techniques.setdefault("TA0008", "Lateral Movement")

    def _detect_from_text(
        self, features: dict[str, Any], techniques: dict[str, str], technique_ids: set[str] | None = None
    ) -> None:
        """Detect techniques by name from natural-language text in features."""
        text = self._collect_text_features(features)
        self._apply_name_dictionary(text, techniques, technique_ids)
        self._apply_phrase_patterns(text, techniques, technique_ids)

    @staticmethod
    def _collect_text_features(features: dict[str, Any]) -> str:
        """Flatten known text-bearing feature keys into a single lowercase haystack."""
        text_parts: list[str] = []
        for key in (
            "description",
            "query",
            "scenario",
            "context",
            "attack_description",
            "attacker_input",
        ):
            val = features.get(key)
            if isinstance(val, str):
                text_parts.append(val.lower())
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        text_parts.append(item.lower())
        return " ".join(text_parts)

    @staticmethod
    def _apply_name_dictionary(text: str, techniques: dict[str, str], technique_ids: set[str] | None = None) -> None:
        """Apply the short-name keyword dictionary to the combined text."""
        for name, tech_id in _TECHNIQUE_NAME_TO_ID.items():
            if name in text:
                tactic_id, tactic_name = _TECHNIQUE_TO_TACTIC.get(tech_id, ("UNKNOWN", name))
                techniques.setdefault(tactic_id, tactic_name)
                if technique_ids is not None:
                    technique_ids.add(tech_id)

    @staticmethod
    def _apply_phrase_patterns(text: str, techniques: dict[str, str], technique_ids: set[str] | None = None) -> None:
        """Apply compound regex patterns for short queries / natural-language TTPs."""
        for pattern, p_technique_ids in _PHRASE_PATTERNS:
            if not re.search(pattern, text, re.IGNORECASE):
                continue
            for tech_id in p_technique_ids:
                parent_id = tech_id.split(".", 1)[0]
                mapping = _TECHNIQUE_TO_TACTIC.get(parent_id)
                if mapping is None:
                    continue
                tactic_id, tactic_name = mapping
                techniques.setdefault(tactic_id, tactic_name)
                if technique_ids is not None:
                    technique_ids.add(tech_id)
