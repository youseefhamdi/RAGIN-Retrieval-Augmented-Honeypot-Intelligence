"""Core benchmark harness — scoring, suites, and report generation."""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

# ── Benchmark Suites ──────────────────────────────────────────────────────────


class BenchmarkSuite(str, Enum):
    CTI = "cti"
    DECEPTION = "deception"
    MEMORY = "memory"
    ALL = "all"


# ── Benchmark Data ────────────────────────────────────────────────────────────

CTI_TECHNIQUE_QUERIES: list[dict[str, str]] = [
    # ── Initial Access ──
    {
        "query": "Explain T1566.001 in detail",
        "expected_technique": "T1566.001",
        "expected_tactic": "initial-access",
        "category": "phishing",
    },
    {
        "query": "How does spear phishing work?",
        "expected_technique": "T1566.001",
        "expected_tactic": "initial-access",
        "category": "phishing",
    },
    {
        "query": "What is T1190 Exploit Public-Facing Application?",
        "expected_technique": "T1190",
        "expected_tactic": "initial-access",
        "category": "exploitation",
    },
    {
        "query": "How do attackers use external remote services to gain access?",
        "expected_technique": "T1133",
        "expected_tactic": "initial-access",
        "category": "remote-access",
    },
    {
        "query": "Explain valid accounts as an initial access technique",
        "expected_technique": "T1078",
        "expected_tactic": "initial-access",
        "category": "credential",
    },
    {
        "query": "What is T1078 Valid Accounts technique?",
        "expected_technique": "T1078",
        "expected_tactic": "initial-access",
        "category": "credential",
    },
    {
        "query": "Explain T1566.002 spear phishing via link",
        "expected_technique": "T1566.002",
        "expected_tactic": "initial-access",
        "category": "phishing",
    },
    {
        "query": "What is T1566.001 phishing attack?",
        "expected_technique": "T1566.001",
        "expected_tactic": "initial-access",
        "category": "phishing",
    },
    {
        "query": "How does supply chain compromise work T1195.002?",
        "expected_technique": "T1195.002",
        "expected_tactic": "initial-access",
        "category": "supply-chain",
    },
    {
        "query": "Explain T1195.002 supply chain compromise targeting software supply chain",
        "expected_technique": "T1195.002",
        "expected_tactic": "initial-access",
        "category": "supply-chain",
    },
    # ── Execution ──
    {
        "query": "Describe how attackers run malicious commands via command-line interface",
        "expected_technique": "T1059",
        "expected_tactic": "execution",
        "category": "command-injection",
    },
    {
        "query": "What is T1059 Command and Scripting Interpreter?",
        "expected_technique": "T1059",
        "expected_tactic": "execution",
        "category": "scripting",
    },
    {
        "query": "How does power shell execution work for attackers?",
        "expected_technique": "T1059",
        "expected_tactic": "execution",
        "category": "powershell",
    },
    {
        "query": "Explain T1059.001 PowerShell command execution",
        "expected_technique": "T1059.001",
        "expected_tactic": "execution",
        "category": "powershell",
    },
    {
        "query": "What is T1203 Exploitation for Client Execution?",
        "expected_technique": "T1203",
        "expected_tactic": "execution",
        "category": "client-execution",
    },
    {
        "query": "How do attackers achieve execution via scheduled tasks T1053.005?",
        "expected_technique": "T1053.005",
        "expected_tactic": "execution",
        "category": "scheduled-task",
    },
    # ── Persistence ──
    {
        "query": "How does persistence via scheduled tasks work?",
        "expected_technique": "T1053.005",
        "expected_tactic": "persistence",
        "category": "persistence",
    },
    {
        "query": "Explain T1547 Boot or Logon Autostart Execution",
        "expected_technique": "T1547",
        "expected_tactic": "persistence",
        "category": "autostart",
    },
    {
        "query": "How do attackers create system processes for persistence?",
        "expected_technique": "T1543",
        "expected_tactic": "persistence",
        "category": "persistence",
    },
    {
        "query": "What is account creation as a persistence mechanism?",
        "expected_technique": "T1136",
        "expected_tactic": "persistence",
        "category": "persistence",
    },
    {
        "query": "Explain T1547.001 Registry Run Keys persistence",
        "expected_technique": "T1547.001",
        "expected_tactic": "persistence",
        "category": "registry",
    },
    {
        "query": "What is T1053.005 Scheduled Task persistence?",
        "expected_technique": "T1053.005",
        "expected_tactic": "persistence",
        "category": "scheduled-task",
    },
    {
        "query": "Explain service manipulation T1543 for persistence",
        "expected_technique": "T1543",
        "expected_tactic": "persistence",
        "category": "service",
    },
    # ── Privilege Escalation ──
    {
        "query": "Explain privilege escalation with sudo abuse",
        "expected_technique": "T1548.003",
        "expected_tactic": "privilege-escalation",
        "category": "escalation",
    },
    {
        "query": "How does exploitation for privilege escalation work?",
        "expected_technique": "T1068",
        "expected_tactic": "privilege-escalation",
        "category": "exploitation",
    },
    {
        "query": "What is T1548 Abuse Elevation Control Mechanism?",
        "expected_technique": "T1548",
        "expected_tactic": "privilege-escalation",
        "category": "escalation",
    },
    {
        "query": "Explain T1068 Exploitation for Privilege Escalation",
        "expected_technique": "T1068",
        "expected_tactic": "privilege-escalation",
        "category": "exploitation",
    },
    {
        "query": "What is T1548.003 Bypass User Account Control?",
        "expected_technique": "T1548.003",
        "expected_tactic": "privilege-escalation",
        "category": "uac-bypass",
    },
    # ── Defense Evasion ──
    {
        "query": "What is defense evasion via process injection?",
        "expected_technique": "T1055",
        "expected_tactic": "defense-evasion",
        "category": "process-injection",
    },
    {
        "query": "How does obfuscation help attackers avoid detection?",
        "expected_technique": "T1027",
        "expected_tactic": "defense-evasion",
        "category": "obfuscation",
    },
    {
        "query": "What is indicator removal in the context of defense evasion?",
        "expected_technique": "T1070",
        "expected_tactic": "defense-evasion",
        "category": "defense-evasion",
    },
    {
        "query": "Explain masquerading as a defense evasion technique",
        "expected_technique": "T1036",
        "expected_tactic": "defense-evasion",
        "category": "masquerading",
    },
    {
        "query": "Describe T1140 Deobfuscate Decode Data for defense evasion",
        "expected_technique": "T1140",
        "expected_tactic": "defense-evasion",
        "category": "deobfuscation",
    },
    {
        "query": "How does T1211 Signed Binary Proxy Execution enable defense evasion?",
        "expected_technique": "T1211",
        "expected_tactic": "defense-evasion",
        "category": "signed-binary",
    },
    {
        "query": "Explain indicator blocking as defense evasion T1562",
        "expected_technique": "T1562",
        "expected_tactic": "defense-evasion",
        "category": "evasion",
    },
    # ── Credential Access ──
    {
        "query": "How does credential dumping work?",
        "expected_technique": "T1003.001",
        "expected_tactic": "credential-access",
        "category": "credentials",
    },
    {
        "query": "What is brute forcing in credential access?",
        "expected_technique": "T1110",
        "expected_tactic": "credential-access",
        "category": "bruteforce",
    },
    {
        "query": "Explain OS Credential Dumping T1003",
        "expected_technique": "T1003",
        "expected_tactic": "credential-access",
        "category": "credentials",
    },
    {
        "query": "Describe T1003.001 OS Credential Dumping LSASS memory",
        "expected_technique": "T1003.001",
        "expected_tactic": "credential-access",
        "category": "lsass",
    },
    {
        "query": "How does password brute forcing T1110 work?",
        "expected_technique": "T1110",
        "expected_tactic": "credential-access",
        "category": "password-spraying",
    },
    {
        "query": "Explain T1552.004 Unsecured Credentials for credential access",
        "expected_technique": "T1552.004",
        "expected_tactic": "credential-access",
        "category": "credentials",
    },
    # ── Discovery ──
    {
        "query": "What is discovery via network service scanning?",
        "expected_technique": "T1046",
        "expected_tactic": "discovery",
        "category": "discovery",
    },
    {
        "query": "How does account discovery work on a compromised system?",
        "expected_technique": "T1087",
        "expected_tactic": "discovery",
        "category": "discovery",
    },
    {
        "query": "What is remote system discovery in the attack chain?",
        "expected_technique": "T1018",
        "expected_tactic": "discovery",
        "category": "discovery",
    },
    {
        "query": "Explain T1083 File and Directory Discovery",
        "expected_technique": "T1083",
        "expected_tactic": "discovery",
        "category": "file-discovery",
    },
    {
        "query": "What is system information discovery T1082?",
        "expected_technique": "T1082",
        "expected_tactic": "discovery",
        "category": "system-info",
    },
    {
        "query": "Describe T1046 Network Service Discovery scanning",
        "expected_technique": "T1046",
        "expected_tactic": "discovery",
        "category": "nmap",
    },
    # ── Lateral Movement ──
    {
        "query": "Describe the lateral movement technique T1021",
        "expected_technique": "T1021",
        "expected_tactic": "lateral-movement",
        "category": "lateral-movement",
    },
    {
        "query": "How does remote services facilitate lateral movement?",
        "expected_technique": "T1021",
        "expected_tactic": "lateral-movement",
        "category": "remote-services",
    },
    {
        "query": "Explain use of alternate authentication material for lateral movement",
        "expected_technique": "T1550",
        "expected_tactic": "lateral-movement",
        "category": "authentication",
    },
    {
        "query": "What is T1021 Remote Services lateral movement?",
        "expected_technique": "T1021",
        "expected_tactic": "lateral-movement",
        "category": "remote-services",
    },
    {
        "query": "Explain pass the hash T1550.002 lateral movement",
        "expected_technique": "T1550.002",
        "expected_tactic": "lateral-movement",
        "category": "pass-the-hash",
    },
    {
        "query": "How does T1021.002 SMB/Windows Admin Share lateral movement work?",
        "expected_technique": "T1021.002",
        "expected_tactic": "lateral-movement",
        "category": "smb",
    },
    # ── Collection ──
    {
        "query": "Describe collection via screen capture",
        "expected_technique": "T1113",
        "expected_tactic": "collection",
        "category": "screen-capture",
    },
    {
        "query": "What is data from local system collection?",
        "expected_technique": "T1005",
        "expected_tactic": "collection",
        "category": "local-data",
    },
    {
        "query": "Explain T1114 Email Collection technique",
        "expected_technique": "T1114",
        "expected_tactic": "collection",
        "category": "email",
    },
    {
        "query": "What is T1005 Data from Local System collection?",
        "expected_technique": "T1005",
        "expected_tactic": "collection",
        "category": "local",
    },
    # ── Command and Control ──
    {
        "query": "What is command and control via DNS?",
        "expected_technique": "T1071.004",
        "expected_tactic": "command-and-control",
        "category": "c2",
    },
    {
        "query": "How does application layer protocol communication enable C2?",
        "expected_technique": "T1071",
        "expected_tactic": "command-and-control",
        "category": "c2",
    },
    {
        "query": "What is encrypted channel for command and control?",
        "expected_technique": "T1573",
        "expected_tactic": "command-and-control",
        "category": "encryption",
    },
    {
        "query": "Describe T1071.004 Application Layer Protocol C2 via DNS",
        "expected_technique": "T1071.004",
        "expected_tactic": "command-and-control",
        "category": "dns-c2",
    },
    {
        "query": "Explain T1102 Web Service C2 for command and control",
        "expected_technique": "T1102",
        "expected_tactic": "command-and-control",
        "category": "web-service",
    },
    {
        "query": "How does T1573 Encrypted Channel C2 work?",
        "expected_technique": "T1573",
        "expected_tactic": "command-and-control",
        "category": "encrypted-c2",
    },
    # ── Exfiltration ──
    {
        "query": "How does exfiltration over HTTPS work?",
        "expected_technique": "T1041",
        "expected_tactic": "exfiltration",
        "category": "https",
    },
    {
        "query": "What is exfiltration over web service?",
        "expected_technique": "T1567",
        "expected_tactic": "exfiltration",
        "category": "web",
    },
    {
        "query": "Explain T1041 Exfiltration Over C2 Channel",
        "expected_technique": "T1041",
        "expected_tactic": "exfiltration",
        "category": "c2-channel",
    },
    {
        "query": "What is T1567 Web Service Exfiltration technique?",
        "expected_technique": "T1567",
        "expected_tactic": "exfiltration",
        "category": "web-exfil",
    },
    # ── Impact ──
    {
        "query": "How does impact via data encryption work?",
        "expected_technique": "T1486",
        "expected_tactic": "impact",
        "category": "ransomware",
    },
    {
        "query": "What is service stop as an impact technique?",
        "expected_technique": "T1489",
        "expected_tactic": "impact",
        "category": "denial",
    },
    {
        "query": "Describe T1490 Inhibit System Recovery impact technique",
        "expected_technique": "T1490",
        "expected_tactic": "impact",
        "category": "recovery",
    },
    {
        "query": "Explain T1486 Data Encrypted for Impact ransomware technique",
        "expected_technique": "T1486",
        "expected_tactic": "impact",
        "category": "ransomware",
    },
    # ── Resource Development ──
    {
        "query": "Explain resource development using compromised accounts",
        "expected_technique": "T1586.001",
        "expected_tactic": "resource-development",
        "category": "resource-dev",
    },
    {
        "query": "What is T1586 Compromise Accounts resource development technique?",
        "expected_technique": "T1586",
        "expected_tactic": "resource-development",
        "category": "accounts",
    },
    {
        "query": "Explain T1583 Acquire Infrastructure resource development",
        "expected_technique": "T1583",
        "expected_tactic": "resource-development",
        "category": "infrastructure",
    },
    {
        "query": "What is T1588 Obtain Capabilities resource development?",
        "expected_technique": "T1588",
        "expected_tactic": "resource-development",
        "category": "capabilities",
    },
    # ── Initial Access (Supply Chain) ──
    {
        "query": "How does initial access via supply chain compromise work?",
        "expected_technique": "T1195.002",
        "expected_tactic": "initial-access",
        "category": "supply-chain",
    },
    {
        "query": "Explain T1195.002 Supply Chain Compromise software supply chain",
        "expected_technique": "T1195.002",
        "expected_tactic": "initial-access",
        "category": "supply-chain",
    },
    {
        "query": "Exploit public-facing application T1190 unpatched web server",
        "expected_technique": "T1190",
        "expected_tactic": "initial-access",
        "category": "web-exploit",
    },
    {
        "query": "Use compromised SSH keys T1133 for external remote access",
        "expected_technique": "T1133",
        "expected_tactic": "initial-access",
        "category": "ssh-key",
    },
    {
        "query": "Leverage default credentials T1078.001 for initial access",
        "expected_technique": "T1078.001",
        "expected_tactic": "initial-access",
        "category": "default-cred",
    },
    {
        "query": "Access target via trusted relationship T1199 initial access",
        "expected_technique": "T1199",
        "expected_tactic": "initial-access",
        "category": "trust",
    },
    {
        "query": "Exploit client app for execution via browser T1203",
        "expected_technique": "T1203",
        "expected_tactic": "execution",
        "category": "browser-exploit",
    },
    {
        "query": "Execute malicious macro T1204.002 user execution",
        "expected_technique": "T1204",
        "expected_tactic": "execution",
        "category": "macro",
    },
    {
        "query": "Run Perl script T1059 for command injection attack",
        "expected_technique": "T1059",
        "expected_tactic": "execution",
        "category": "perl-exec",
    },
    {
        "query": "Execute Python script T1059 for command and scripting",
        "expected_technique": "T1059",
        "expected_tactic": "execution",
        "category": "python-exec",
    },
    {
        "query": "Use RDP execution T1021.001 for remote command execution",
        "expected_technique": "T1021.001",
        "expected_tactic": "execution",
        "category": "rdp-exec",
    },
    {
        "query": "Achieve execution via WMI T1047 on remote endpoint",
        "expected_technique": "T1047",
        "expected_tactic": "execution",
        "category": "wmi-exec",
    },
    {
        "query": "Persistence registry Run Keys T1547.001 Windows startup",
        "expected_technique": "T1547.001",
        "expected_tactic": "persistence",
        "category": "registry-persist",
    },
    {
        "query": "Create local account T1136.001 persistence on Windows",
        "expected_technique": "T1136.001",
        "expected_tactic": "persistence",
        "category": "local-account-persist",
    },
    {
        "query": "Create domain account T1136.002 AD persistence",
        "expected_technique": "T1136.002",
        "expected_tactic": "persistence",
        "category": "domain-account-persist",
    },
    {
        "query": "Modify system process via service creation T1543.001",
        "expected_technique": "T1543.001",
        "expected_tactic": "persistence",
        "category": "service-persist",
    },
    {
        "query": "Persistence via T1574 Hijack Execution Flow DLL side-load",
        "expected_technique": "T1574",
        "expected_tactic": "persistence",
        "category": "dll-persist",
    },
    {
        "query": "Elevate privilege T1548.001 Elevated Execution with Prompt",
        "expected_technique": "T1548.001",
        "expected_tactic": "privilege-escalation",
        "category": "elevation-prompt",
    },
    {
        "query": "Bypass UAC via T1548.003 for privilege escalation",
        "expected_technique": "T1548.003",
        "expected_tactic": "privilege-escalation",
        "category": "uac-bypass2",
    },
    {
        "query": "Exploit vulnerable driver T1210 escalation vector",
        "expected_technique": "T1210",
        "expected_tactic": "privilege-escalation",
        "category": "vuln-driver",
    },
    {
        "query": "Use T1068 Exploitation Privilege Escalation bypass",
        "expected_technique": "T1068",
        "expected_tactic": "privilege-escalation",
        "category": "patch-guard",
    },
    {
        "query": "Disable Windows Defender T1562.001 defense evasion",
        "expected_technique": "T1562.001",
        "expected_tactic": "defense-evasion",
        "category": "defender-disable",
    },
    {
        "query": "Modify security tool T1562.002 disable MpEngine",
        "expected_technique": "T1562.002",
        "expected_tactic": "defense-evasion",
        "category": "defender-mod",
    },
    {
        "query": "Hide artifact NTFS ADS T1564.004 alternate data stream",
        "expected_technique": "T1564",
        "expected_tactic": "defense-evasion",
        "category": "ads-hide",
    },
    {
        "query": "Obfuscate via software packing T1027.002 defense evasion",
        "expected_technique": "T1027.002",
        "expected_tactic": "defense-evasion",
        "category": "packing",
    },
    {
        "query": "Compile HTML file T1204.001 client-side execution",
        "expected_technique": "T1204.001",
        "expected_tactic": "execution",
        "category": "html-exec",
    },
    {
        "query": "Dump SAM credentials T1003.002 registry hive access",
        "expected_technique": "T1003.002",
        "expected_tactic": "credential-access",
        "category": "sam-registry",
    },
    {
        "query": "Dump NTDS.dit T1003.003 domain credential extraction",
        "expected_technique": "T1003.003",
        "expected_tactic": "credential-access",
        "category": "ntds-dump",
    },
    {
        "query": "Extract LSA secrets T1003.004 registry credential access",
        "expected_technique": "T1003.004",
        "expected_tactic": "credential-access",
        "category": "lsa-secrets2",
    },
    {
        "query": "DCSync dump T1003.006 domain credential access",
        "expected_technique": "T1003.006",
        "expected_tactic": "credential-access",
        "category": "dcsync2",
    },
    {
        "query": "Extract hashes from stores T1003.007 password stores",
        "expected_technique": "T1003.007",
        "expected_tactic": "credential-access",
        "category": "pass-stores",
    },
    {
        "query": "Enumerate domain trusts T1482 attack surface mapping",
        "expected_technique": "T1482",
        "expected_tactic": "discovery",
        "category": "trust-enum",
    },
    {
        "query": "Find system owner T1080 discovery information",
        "expected_technique": "T1080",
        "expected_tactic": "discovery",
        "category": "owner-find",
    },
    {
        "query": "Harvest browser credentials T1539 stealing session data",
        "expected_technique": "T1539",
        "expected_tactic": "credential-access",
        "category": "browser-creds",
    },
    {
        "query": "Keylogging T1056 for credential capture on endpoint",
        "expected_technique": "T1056",
        "expected_tactic": "credential-access",
        "category": "keylog-capture",
    },
    {
        "query": "Steal web session cookie T1539 via network sniffing",
        "expected_technique": "T1539",
        "expected_tactic": "credential-access",
        "category": "cookie-sniff",
    },
    {
        "query": "Forge Kerberos TGT T1558 golden ticket attack",
        "expected_technique": "T1558",
        "expected_tactic": "credential-access",
        "category": "golden-ticket",
    },
    {
        "query": "Extract credentials from password manager T1555",
        "expected_technique": "T1555",
        "expected_tactic": "credential-access",
        "category": "pwd-manager",
    },
    {
        "query": "Access VPN T1133 external remote services initial access",
        "expected_technique": "T1133",
        "expected_tactic": "initial-access",
        "category": "vpn-access",
    },
    {
        "query": "Compromise software supply chain T1195 build system",
        "expected_technique": "T1195",
        "expected_tactic": "initial-access",
        "category": "build-chain",
    },
    {
        "query": "Steal session cookie T1539.001 via network sniffing",
        "expected_technique": "T1539",
        "expected_tactic": "credential-access",
        "category": "session-stealing",
    },
    {
        "query": "Forge silver ticket T1558.003 Kerberos attack",
        "expected_technique": "T1558.003",
        "expected_tactic": "credential-access",
        "category": "silver-ticket",
    },
    {
        "query": "Target managed service provider T1199 initial access",
        "expected_technique": "T1199",
        "expected_tactic": "initial-access",
        "category": "msp",
    },
    {
        "query": "Embedded content macro T1203 client execution",
        "expected_technique": "T1203",
        "expected_tactic": "execution",
        "category": "embedded-content",
    },
    {
        "query": "WMI persistence T1546 event subscription endpoint",
        "expected_technique": "T1546",
        "expected_tactic": "persistence",
        "category": "wmi-persist",
    },
    {
        "query": "Disable Defender registry T1562.001 defense evasion",
        "expected_technique": "T1562.001",
        "expected_tactic": "defense-evasion",
        "category": "defender-reg",
    },
    {
        "query": "Cached domain creds T1003.005 access without DCSync",
        "expected_technique": "T1003.005",
        "expected_tactic": "credential-access",
        "category": "cached-creds",
    },
    {
        "query": "Hide data in NTFS ADS T1564 alternate data stream",
        "expected_technique": "T1564",
        "expected_tactic": "defense-evasion",
        "category": "ads-hide2",
    },
]

CTI_ACTOR_QUERIES: list[dict[str, str]] = [
    {
        "query": "Describe Salt Typhoon's targeting of telecommunications",
        "expected_actor": "salt typhoon",
        "sector": "telecommunications",
    },
    {
        "query": "What techniques does APT28 use against government targets?",
        "expected_actor": "apt28",
        "sector": "government",
    },
    {
        "query": "How does Lazarus Group target financial institutions?",
        "expected_actor": "lazarus group",
        "sector": "financial",
    },
    {
        "query": "What is Volt Typhoon's approach to critical infrastructure?",
        "expected_actor": "volt typhoon",
        "sector": "critical-infrastructure",
    },
    {"query": "Describe FIN7's attack patterns against retail", "expected_actor": "fin7", "sector": "retail"},
    {
        "query": "What is APT29's preferred method for initial access?",
        "expected_actor": "apt29",
        "sector": "government",
    },
    {"query": "How does APT41 operate against enterprise networks?", "expected_actor": "apt41", "sector": "technology"},
    {
        "query": "Describe Cozy Bear's targeting of diplomatic organizations",
        "expected_actor": "cozy bear",
        "sector": "government",
    },
    {
        "query": "What is Fancy Bear's approach to military networks?",
        "expected_actor": "fancy bear",
        "sector": "military",
    },
    {
        "query": "How does Hafnium target on-premises Exchange servers?",
        "expected_actor": "hafnium",
        "sector": "technology",
    },
    {"query": "Describe Sandworm's destructive attack patterns", "expected_actor": "sandworm", "sector": "energy"},
    {
        "query": "What is the Darkside ransomware group's approach?",
        "expected_actor": "darkside",
        "sector": "healthcare",
    },
    {"query": "How does Revil deploy its ransomware payload?", "expected_actor": "revil", "sector": "manufacturing"},
    {
        "query": "Describe APT37's targeting of South Korean organizations",
        "expected_actor": "apt37",
        "sector": "government",
    },
    {
        "query": "What is APT27's method for targeting telecom operators?",
        "expected_actor": "apt27",
        "sector": "telecommunications",
    },
    {
        "query": "Describe UNC2452 SolarWinds supply chain attack",
        "expected_actor": "solarwinds",
        "sector": "technology",
    },
    {"query": "How does UNC3886 target VMware infrastructure?", "expected_actor": "unc3886", "sector": "technology"},
    {
        "query": "What is DarkHotel group targeting travelers and hotels?",
        "expected_actor": "darkhotel",
        "sector": "hospitality",
    },
    {"query": "Explain APT32 OceanLotus targeting Vietnam", "expected_actor": "oceanlotus", "sector": "southeast-asia"},
    {
        "query": "Describe APT38 Lazarus Group financial theft from banks",
        "expected_actor": "lazarus group",
        "sector": "financial",
    },
    {"query": "What is Carbanak group ATM heist technique?", "expected_actor": "carbanak", "sector": "financial"},
    {
        "query": "How does Transparent Tribe APT36 target Indian defense?",
        "expected_actor": "apt36",
        "sector": "defense",
    },
    {
        "query": "Describe GhostEmperor APT targeting government networks",
        "expected_actor": "ghostemperor",
        "sector": "government",
    },
    {
        "query": "What is Earth Lusca targeting APAC telecoms?",
        "expected_actor": "earth lusca",
        "sector": "telecommunications",
    },
    {"query": "Explain APT50 targeting South Asian governments", "expected_actor": "apt50", "sector": "government"},
    {"query": "Describe LuckyMouse APT41 cyber espionage operations", "expected_actor": "apt41", "sector": "espionage"},
    {"query": "What is APT37 Reaper targeting South Korean media?", "expected_actor": "apt37", "sector": "media"},
    {
        "query": "How does APT27 target European telecom operators?",
        "expected_actor": "apt27",
        "sector": "telecommunications",
    },
    {"query": "Describe Turla group satellite-based covert C2", "expected_actor": "turla", "sector": "government"},
    {
        "query": "What is Seedworm targeting energy sector infrastructure?",
        "expected_actor": "seedworm",
        "sector": "energy",
    },
    {
        "query": "Explain APT20 targeting government and aviation sectors",
        "expected_actor": "apt20",
        "sector": "aviation",
    },
    {
        "query": "Describe APT43 state-sponsored cybercrime operations",
        "expected_actor": "apt43",
        "sector": "cybercrime",
    },
    {
        "query": "What is Charming Kitten targeting diplomats and activists?",
        "expected_actor": "charming kitten",
        "sector": "diplomacy",
    },
    {
        "query": "Explain Dragonfly/Energetic Bear targeting energy ICS",
        "expected_actor": "dragonfly",
        "sector": "energy",
    },
    {
        "query": "Describe Cobalt Group financial cybercrime ATM attacks",
        "expected_actor": "cobalt",
        "sector": "financial",
    },
]

PERSONA_REALISM_QUERIES: list[dict[str, Any]] = [
    {"query": "What web server are you running?", "expected_traits": ["specific version", "server details"]},
    {"query": "Tell me about your network configuration", "expected_traits": ["network topology", "subnet details"]},
    {"query": "What security tools do you have deployed?", "expected_traits": ["specific products", "version numbers"]},
    {"query": "Do you have any databases accessible?", "expected_traits": ["database type", "connection details"]},
    {"query": "What OS is installed on the servers?", "expected_traits": ["operating system", "kernel version"]},
    {"query": "Can you tell me about your firewall rules?", "expected_traits": ["rule details", "specific ports"]},
    {"query": "What patches have been applied recently?", "expected_traits": ["patch versions", "specific CVEs"]},
    {
        "query": "Show me the running processes on this machine",
        "expected_traits": ["process list", "specific binaries"],
    },
    {"query": "What users are currently logged in?", "expected_traits": ["user accounts", "login details"]},
    {"query": "What cron jobs are configured on this system?", "expected_traits": ["scheduled tasks", "cron details"]},
    {
        "query": "Show me the network interfaces and their configurations",
        "expected_traits": ["interface details", "IP addresses"],
    },
    {"query": "What disk space is available on the system?", "expected_traits": ["disk usage", "mount points"]},
    {"query": "Check the system logs for any recent activity", "expected_traits": ["log entries", "system events"]},
    {"query": "What services are currently running?", "expected_traits": ["service names", "listen ports"]},
    {"query": "Show me the SSH configuration", "expected_traits": ["SSH config", "key details"]},
    {
        "query": "Can you check if there are any suspicious scheduled tasks on this server?",
        "expected_traits": ["scheduled tasks", "suspicious", "specific binaries"],
    },
    {
        "query": "I need to find all files modified in the last 24 hours on this system",
        "expected_traits": ["file modification", "timestamp", "ls command"],
    },
    {
        "query": "Show me the crontab for all users on this system",
        "expected_traits": ["crontab", "user entries", "scheduled jobs"],
    },
    {
        "query": "What are the current network connections and which processes own them?",
        "expected_traits": ["network connections", "process names", "owner"],
    },
    {
        "query": "Check the syslog for any authentication error patterns from the last day",
        "expected_traits": ["syslog", "authentication errors", "time range"],
    },
    {
        "query": "List all Docker containers currently running and their resource usage",
        "expected_traits": ["Docker containers", "resource usage", "container names"],
    },
    {
        "query": "How do I generate a packet capture for the last 5 minutes on interface eth0?",
        "expected_traits": ["packet capture", "tcpdump", "interface"],
    },
    {
        "query": "Show me the current iptables rules with packet and byte counters",
        "expected_traits": ["iptables", "counters", "rule details"],
    },
    {
        "query": "What is the disk I/O wait percentage and which process is using the most I/O?",
        "expected_traits": ["disk I/O", "iowait", "process"],
    },
    {
        "query": "Check if there are any kernel modules that were loaded recently",
        "expected_traits": ["kernel modules", "loaded", "lsmod"],
    },
    {
        "query": "Show me all environment variables that contain API keys or tokens",
        "expected_traits": ["environment variables", "API keys", "tokens"],
    },
    {
        "query": "What is the current SELinux context of the web server process?",
        "expected_traits": ["SELinux", "context", "web server"],
    },
    {
        "query": "Check if there are any unrecognized cron jobs in /etc/cron.d/ directories",
        "expected_traits": ["cron jobs", "/etc/cron.d", "unrecognized"],
    },
    {
        "query": "Show me the top 5 processes by memory usage sorted by RSS",
        "expected_traits": ["top processes", "memory", "RSS", "ps command"],
    },
    {
        "query": "What are the current TCP connections in TIME_WAIT state and how many?",
        "expected_traits": ["TCP connections", "TIME_WAIT", "count", "netstat"],
    },
    {
        "query": "Can you check the /var/log/auth.log for failed SSH login attempts from external IPs?",
        "expected_traits": ["auth.log", "SSH", "failed logins", "external IPs"],
    },
    {
        "query": "Show me the nginx access log filtered for 5xx error codes in the last hour",
        "expected_traits": ["nginx", "access log", "5xx errors", "time range"],
    },
    {
        "query": "What is the current ulimit setting for open file descriptors on this system?",
        "expected_traits": ["ulimit", "file descriptors", "system limit"],
    },
    {
        "query": "Check if any process has capabilities set beyond the default",
        "expected_traits": ["capabilities", "setcap", "getcap"],
    },
    {
        "query": "Show me the auditd rules currently configured on this system",
        "expected_traits": ["auditd", "rules", "audit configuration"],
    },
    {
        "query": "What processes are listening on privileged ports below 1024?",
        "expected_traits": ["privileged ports", "listening", "processes", "netstat"],
    },
    {
        "query": "Can you verify the integrity of the passwd and shadow files using md5sum?",
        "expected_traits": ["passwd", "shadow", "integrity", "md5sum"],
    },
    {
        "query": "Show all established connections to port 3306 MySQL from which source IPs?",
        "expected_traits": ["MySQL", "port 3306", "established", "source IPs"],
    },
    {
        "query": "What is the current swap usage and which processes are contributing most?",
        "expected_traits": ["swap usage", "process contribution", "memory"],
    },
    {
        "query": "Check whether any cron job has been modified in the last 7 days across all users",
        "expected_traits": ["cron modification", "7 days", "all users", "audit"],
    },
    {
        "query": "Show me the last 10 lines of /var/log/syslog filtered for kernel errors",
        "expected_traits": ["syslog", "kernel errors", "last 10 lines"],
    },
    {
        "query": "List all cron jobs that run as root across system crontab and cron.d/",
        "expected_traits": ["root cron", "system crontab", "cron.d"],
    },
    {
        "query": "What is the current TCP congestion control algorithm and queue discipline?",
        "expected_traits": ["TCP", "congestion control", "queue discipline", "sysctl"],
    },
    {
        "query": "Has the root password been changed in the last 30 days? Check /etc/shadow",
        "expected_traits": ["root password", "/etc/shadow", "change date", "30 days"],
    },
    {
        "query": "Show me zombie processes and their parent process IDs on this system",
        "expected_traits": ["zombie processes", "parent PID", "process state"],
    },
    {
        "query": "List all active firewall rules with hit counts",
        "expected_traits": ["firewall rules", "hit counts", "iptables -v"],
    },
    {
        "query": "Check for unauthorized SSH keys in authorized_keys files",
        "expected_traits": ["SSH keys", "authorized_keys", "security check"],
    },
    {
        "query": "What is the current load average compared to baseline?",
        "expected_traits": ["load average", "baseline", "uptime"],
    },
    {
        "query": "Show all running Docker containers with resource limits",
        "expected_traits": ["Docker", "resource limits", "containers"],
    },
    {
        "query": "Check if any cron jobs were added in last 48 hours",
        "expected_traits": ["cron jobs", "48 hours", "audit trail"],
    },
    {
        "query": "What third-party packages are installed and their versions?",
        "expected_traits": ["third-party packages", "versions", "package manager"],
    },
    {
        "query": "Show all listening ports and their bound processes",
        "expected_traits": ["listening ports", "process binding", "netstat -tlnp"],
    },
    {
        "query": "Is SELinux enforcing and what contexts do web files have?",
        "expected_traits": ["SELinux", "enforcing", "context", "web server"],
    },
    {
        "query": "What is the DNS resolver config and exfiltration indicators?",
        "expected_traits": ["DNS configuration", "resolver", "exfiltration indicators"],
    },
    {
        "query": "Show audit log entries for privilege escalation attempts last week",
        "expected_traits": ["audit log", "privilege escalation", "last week"],
    },
    {
        "query": "Check last password changes for all users in /etc/shadow",
        "expected_traits": ["password changes", "/etc/shadow", "user accounts"],
    },
    {
        "query": "What is the current system uptime and last reboot time?",
        "expected_traits": ["uptime", "reboot time", "last boot"],
    },
    {
        "query": "Show kernel ring buffer for driver and hardware errors",
        "expected_traits": ["kernel ring buffer", "dmesg", "hardware errors"],
    },
    {
        "query": "Which users have sudo access and their last sudo timestamps?",
        "expected_traits": ["sudo access", "users", "timestamps", "sudo log"],
    },
    {
        "query": "Are there any known vulnerable packages needing immediate patches?",
        "expected_traits": ["vulnerable packages", "patching", "CVE"],
    },
]


# ── Scoring Functions ─────────────────────────────────────────────────────────


def _score_technique_match(response: str, expected_technique: str) -> float:
    """Score how well a response matches an expected MITRE ATT&CK technique."""
    if not response:
        return 0.0

    score = 0.0
    response_lower = response.lower()
    expected_lower = expected_technique.lower()

    # Exact technique ID match (e.g., T1566.001)
    if expected_lower in response_lower:
        score += 0.8

    # Parent technique match (e.g., T1566 from T1566.001)
    parent = expected_technique.split(".")[0]
    if parent.lower() in response_lower:
        score += 0.3

    # MITRE keyword bonus
    mitre_keywords = ["mitre", "att&ck", "attack technique", "tactic"]
    if any(kw in response_lower for kw in mitre_keywords):
        score += 0.1

    # Technique name match for natural-language queries (no explicit ID)
    if expected_lower not in response_lower and parent.lower() not in response_lower:
        technique_names = _get_technique_name_variants(expected_technique)
        for name in technique_names:
            if name.lower() in response_lower:
                score += 0.4
                break

    return min(score, 1.0)


def _get_technique_name_variants(technique_id: str) -> list[str]:
    """Return natural-language technique names for a given technique ID."""
    # Direct mapping from technique ID to common names
    name_map: dict[str, list[str]] = {
        "T1566": ["phishing", "spear phishing", "phishing attack", "malicious attachment", "email phishing"],
        "T1566.001": [
            "spear phishing",
            "phishing",
            "malicious attachment",
            "email phishing",
            "spear phishing via attachment",
        ],
        "T1566.002": ["spear phishing link", "phishing via link", "malicious link"],
        "T1190": ["exploit public-facing application", "public-facing application", "web application exploitation"],
        "T1133": ["external remote services", "remote service access", "vpn access", "external service"],
        "T1078": ["valid accounts", "stolen credentials", "credential reuse", "default credentials"],
        "T1059": ["command and scripting interpreter", "command execution", "scripting", "command-line"],
        "T1059.001": ["powershell execution", "powershell command", "powershell script"],
        "T1059.003": ["windows command shell", "cmd execution", "command prompt"],
        "T1059.004": ["unix shell", "bash command", "shell execution"],
        "T1203": ["client exploitation", "exploitation for client execution", "browser exploit"],
        "T1053": ["scheduled task", "scheduled job", "task scheduling", "cron job"],
        "T1053.005": ["scheduled task persistence", "scheduled task", "autorun task"],
        "T1053.003": ["scheduled task execution", "at command", "scheduled job"],
        "T1053.007": ["scheduled task local", "systemd timer", "local scheduled task"],
        "T1547": ["boot or logon autostart", "autostart execution", "registry run key", "startup persistence"],
        "T1547.001": ["registry run key", "autostart registry", "startup registry key", "registry persistence"],
        "T1543": ["create or modify system process", "service creation", "system process persistence"],
        "T1136": ["create account", "account creation", "new user account"],
        "T1136.001": ["local account", "local user creation", "create local account"],
        "T1136.002": ["domain account", "create domain account", "ad account creation"],
        "T1548": ["abuse elevation control mechanism", "privilege escalation", "uac bypass", "elevation"],
        "T1548.003": ["bypass user account control", "uac bypass", "elevated execution"],
        "T1548.001": ["elevated execution with prompt", "uac prompt bypass"],
        "T1068": ["exploitation for privilege escalation", "exploit for escalation", "privilege escalation exploit"],
        "T1027": ["obfuscated files", "obfuscation", "obfuscated information", "code obfuscation"],
        "T1070": ["indicator removal", "clear logs", "delete logs", "artifacts removal", "log cleaning"],
        "T1036": ["masquerading", "file masquerading", "rename file", "double extension"],
        "T1140": ["deobfuscate decode data", "deobfuscation", "decode encoded data"],
        "T1211": ["signed binary proxy execution", "proxy execution", "signed binary"],
        "T1562": ["impair defenses", "disable security tools", "defense evasion", "modify security"],
        "T1562.001": ["disable or modify tools", "disable windows defender", "disable av", "disable security tool"],
        "T1564": ["hide artifact", "alternate data stream", "file hiding", "hide data"],
        "T1003": ["os credential dumping", "credential dump", "lsass dump", "memory credential"],
        "T1003.001": ["lsass memory dump", "lsass credential", "lsass memory", "credential dump lsass"],
        "T1003.002": ["sam credential dump", "sam registry", "security account manager"],
        "T1003.003": ["ntds credential dump", "ntds.dit", "domain controller credential"],
        "T1003.004": ["lsa secrets", "lsa cache", "lsa credential dump"],
        "T1003.006": ["dcsync", "dcsync credential dump", "replication credential"],
        "T1003.007": ["password store", "credential store", "password hash dump"],
        "T1110": ["brute force", "password brute force", "credential brute force", "password guessing"],
        "T1110.001": ["password guessing", "password brute", "dictionary attack"],
        "T1110.003": ["password spraying", "spray attack", "spray brute force"],
        "T1046": ["network service discovery", "port scanning", "service scanning", "network enumeration"],
        "T1087": ["account discovery", "find user", "enumerate account", "account enumeration"],
        "T1018": ["remote system discovery", "network scanning", "discover remote system"],
        "T1083": ["file and directory discovery", "file discovery", "directory enumeration", "find file"],
        "T1082": ["system information discovery", "system info", "os discovery", "system enumeration"],
        "T1482": ["domain trust discovery", "trust enumeration", "domain enumeration"],
        "T1021": ["remote services", "lateral movement", "remote service execution", "pass-through authentication"],
        "T1021.002": ["smb windows admin share", "smb lateral movement", "admin share", "smb exec"],
        "T1021.001": ["remote desktop protocol", "rdp lateral movement", "remote desktop"],
        "T1021.003": ["dcom lateral movement", "distributed component object model", "dcom exec"],
        "T1550": ["use alternate authentication material", "pass the hash", "pass the ticket", "token theft"],
        "T1550.002": ["pass the hash", "pass-the-hash", "ntlm hash", "pass hash"],
        "T1550.003": ["pass the ticket", "kerberos ticket", "ticket pass"],
        "T1550.001": ["application access token", "access token", "token impersonation"],
        "T1113": ["screen capture", "screenshot", "capture screen", "screen capture collection"],
        "T1005": ["data from local system", "local data collection", "local file collection"],
        "T1114": ["email collection", "gather victim email", "mailbox collection", "email harvesting"],
        "T1071": ["application layer protocol", "c2 communication", "protocol communication"],
        "T1071.004": ["dns protocol", "c2 via dns", "dns tunneling", "dns communication"],
        "T1573": ["encrypted channel", "encryption c2", "encrypted communication"],
        "T1573.001": ["symmetric cryptography c2", "symmetric encryption"],
        "T1573.002": ["asymmetric cryptography c2", "asymmetric encryption"],
        "T1102": ["web service c2", "web service", "web-based c2", "web panel"],
        "T1041": ["exfiltration over c2 channel", "c2 exfiltration", "exfiltration c2", "data exfiltration"],
        "T1567": ["exfiltration over web service", "web exfiltration", "cloud exfiltration", "web service exfil"],
        "T1486": ["data encrypted for impact", "ransomware", "data encryption", "encrypt data"],
        "T1489": ["service stop", "stop service", "service termination", "denial of service"],
        "T1490": ["inhibit system recovery", "prevent recovery", "disable restore", "delete backups"],
        "T1499": ["endpoint denial of service", "endpoint dos", "service disruption"],
        "T1195": ["supply chain compromise", "supply chain attack", "software supply chain"],
        "T1195.002": ["supply chain compromise software", "software supply chain attack", "compromised software"],
        "T1195.001": ["supply chain compromise hardware", "firmware compromise"],
    }

    return name_map.get(technique_id, [])


def _score_actor_match(response: str, expected_actor: str, sector: str) -> float:
    """Score how well a response matches an expected threat actor and sector."""
    if not response:
        return 0.0

    score = 0.0
    response_lower = response.lower()

    # Actor name match
    if expected_actor.lower() in response_lower:
        score += 0.5

    # Sector/industry match
    if sector.lower() in response_lower:
        score += 0.3

    # Context keywords
    context_keywords = ["apt", "threat actor", "campaign", "targeting", "attack"]
    if any(kw in response_lower for kw in context_keywords):
        score += 0.1

    return min(score, 1.0)


def _score_persona_realism(response: str, expected_traits: list[str]) -> float:
    """Score how realistic a persona response sounds."""
    if not response:
        return 0.0

    score = 0.0
    response_lower = response.lower()

    # Version numbers indicate specificity
    if re.search(r"\d+\.\d+(\.\d+)?", response):
        score += 0.3

    # Technical terms indicate realism
    tech_terms = ["port", "server", "configured", "running", "installed", "deployed"]
    matched_terms = sum(1 for t in tech_terms if t in response_lower)
    score += min(matched_terms * 0.1, 0.3)

    # Refusal patterns are realistic for social engineering defense
    refusal_patterns = ["not authorized", "submit a ticket", "help desk", "cannot share", "restricted"]
    if any(p in response_lower for p in refusal_patterns):
        score += 0.3

    # Length indicates detail level
    if len(response) > 50:
        score += 0.1

    return min(score, 1.0)


def _score_memory_recall(response: str, expected_concepts: list[str]) -> float:
    """Score how well a response recalls concepts from memory."""
    if not response:
        return 0.0

    response_lower = response.lower()

    # Check for "no information" / "don't recall" type responses
    no_recall_patterns = ["don't have", "do not have", "no information", "no record", "not found", "not recall"]
    if any(p in response_lower for p in no_recall_patterns):
        return 0.0

    # Count matching concepts
    matches = sum(1 for concept in expected_concepts if concept.lower() in response_lower)
    if not expected_concepts:
        return 0.0

    return min(matches / len(expected_concepts), 1.0)


# ── Benchmark Result & Report ─────────────────────────────────────────────────


@dataclass
class BenchmarkResult:
    name: str
    suite: str
    passed: bool
    score: float
    latency_ms: float
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class BenchmarkReport:
    run_id: str
    timestamp: str
    suite: str
    total_tests: int
    passed: int
    failed: int
    avg_score: float
    avg_latency_ms: float
    results: list[BenchmarkResult]
    summary: dict[str, Any]


def generate_report(results: list[BenchmarkResult], suite: str) -> BenchmarkReport:
    """Generate a summary report from a list of benchmark results."""
    total = len(results)
    if total == 0:
        return BenchmarkReport(
            run_id=str(uuid.uuid4()),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            suite=suite,
            total_tests=0,
            passed=0,
            failed=0,
            avg_score=0.0,
            avg_latency_ms=0.0,
            results=[],
            summary={"pass_rate": "0.0%"},
        )

    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    avg_score = sum(r.score for r in results) / total
    avg_latency = sum(r.latency_ms for r in results) / total
    pass_rate = f"{(passed / total * 100):.1f}%"

    summary: dict[str, Any] = {
        "pass_rate": pass_rate,
    }

    # Per-suite scores
    suites: dict[str, list[float]] = {}
    for r in results:
        suites.setdefault(r.suite, []).append(r.score)
    if len(suites) > 1:
        summary["suite_scores"] = {s: f"{sum(scores)/len(scores):.3f}" for s, scores in suites.items()}

    return BenchmarkReport(
        run_id=str(uuid.uuid4()),
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        suite=suite,
        total_tests=total,
        passed=passed,
        failed=failed,
        avg_score=round(avg_score, 3),
        avg_latency_ms=round(avg_latency, 1),
        results=results,
        summary=summary,
    )


def save_report(report: BenchmarkReport, path: str | Path) -> Path:
    """Save a benchmark report to a JSON file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    data: dict[str, Any] = {
        "run_id": report.run_id,
        "timestamp": report.timestamp,
        "suite": report.suite,
        "total_tests": report.total_tests,
        "passed": report.passed,
        "failed": report.failed,
        "avg_score": report.avg_score,
        "avg_latency_ms": report.avg_latency_ms,
        "summary": report.summary,
        "results": [
            {
                "name": r.name,
                "suite": r.suite,
                "passed": r.passed,
                "score": r.score,
                "latency_ms": r.latency_ms,
                "error": r.error,
                **({"details": r.details} if r.details else {}),
            }
            for r in report.results
        ],
    }

    p.write_text(json.dumps(data, indent=2))
    return p


# ── Async Benchmark Runners ──────────────────────────────────────────────────


async def run_cti_benchmarks(adapter: Any) -> list[BenchmarkResult]:
    """Run CTI accuracy benchmarks against a LLM adapter."""
    results: list[BenchmarkResult] = []

    for qa in CTI_TECHNIQUE_QUERIES:
        t0 = time.monotonic()
        try:
            resp = await adapter.query_data(qa["query"])
            text = resp.get("response", "") if isinstance(resp, dict) else str(resp)
            score = _score_technique_match(text, qa["expected_technique"])
            latency = (time.monotonic() - t0) * 1000
            results.append(
                BenchmarkResult(
                    name=f"cti_technique_{qa['expected_technique']}",
                    suite="cti",
                    passed=score >= 0.3,
                    score=score,
                    latency_ms=latency,
                    details={"query": qa["query"], "expected_technique": qa["expected_technique"]},
                )
            )
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            results.append(
                BenchmarkResult(
                    name=f"cti_technique_{qa['expected_technique']}",
                    suite="cti",
                    passed=False,
                    score=0.0,
                    latency_ms=latency,
                    error=str(exc),
                )
            )

    for qa in CTI_ACTOR_QUERIES:
        t0 = time.monotonic()
        try:
            resp = await adapter.query_data(qa["query"])
            text = resp.get("response", "") if isinstance(resp, dict) else str(resp)
            score = _score_actor_match(text, qa["expected_actor"], qa["sector"])
            latency = (time.monotonic() - t0) * 1000
            results.append(
                BenchmarkResult(
                    name=f"cti_actor_{qa['expected_actor'].replace(' ', '_')}",
                    suite="cti",
                    passed=score >= 0.3,
                    score=score,
                    latency_ms=latency,
                    details={"query": qa["query"], "expected_actor": qa["expected_actor"]},
                )
            )
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            results.append(
                BenchmarkResult(
                    name=f"cti_actor_{qa['expected_actor'].replace(' ', '_')}",
                    suite="cti",
                    passed=False,
                    score=0.0,
                    latency_ms=latency,
                    error=str(exc),
                )
            )

    return results


async def run_deception_benchmarks(hisoka: Any) -> list[BenchmarkResult]:
    """Run persona realism benchmarks against the Hisoka pipeline."""
    results: list[BenchmarkResult] = []

    for qa in PERSONA_REALISM_QUERIES:
        t0 = time.monotonic()
        try:
            resp = await hisoka.generate_response(qa["query"])
            text = resp.text if hasattr(resp, "text") else str(resp)
            score = _score_persona_realism(text, qa["expected_traits"])
            latency = (time.monotonic() - t0) * 1000
            results.append(
                BenchmarkResult(
                    name=f"persona_{qa['query'][:30].replace(' ', '_')}",
                    suite="deception",
                    passed=score >= 0.3,
                    score=score,
                    latency_ms=latency,
                    details={"query": qa["query"]},
                )
            )
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            results.append(
                BenchmarkResult(
                    name=f"persona_{qa['query'][:30].replace(' ', '_')}",
                    suite="deception",
                    passed=False,
                    score=0.0,
                    latency_ms=latency,
                    error=str(exc),
                )
            )

    return results


async def run_memory_benchmarks(memory: Any) -> list[BenchmarkResult]:
    """Run memory recall benchmarks against the HisokaMemory instance."""
    results: list[BenchmarkResult] = []

    test_concepts = [
        {
            "name": "ssh_config",
            "interaction": "Attacker used SSH with default configuration",
            "query": "Attacker used SSH to access the server and tried to escalate privileges",
            "concepts": ["ssh", "configuration", "privilege"],
        },
        {
            "name": "nmap_scan",
            "interaction": "Attacker ran nmap scan on the network",
            "query": "What network scanning was detected?",
            "concepts": ["nmap", "scan", "network"],
        },
        {
            "name": "cred_dump",
            "interaction": "Attacker performed credential dumping via lsass",
            "query": "What credential access techniques were used?",
            "concepts": ["credential", "dumping", "lsass"],
        },
        {
            "name": "persistence",
            "interaction": "Attacker created scheduled task for persistence",
            "query": "How did the attacker maintain persistence?",
            "concepts": ["scheduled", "task", "persistence"],
        },
        {
            "name": "lateral_movement",
            "interaction": "Attacker moved laterally via PsExec to file server",
            "query": "Describe the lateral movement observed",
            "concepts": ["lateral", "movement", "psexec"],
        },
    ]

    for test in test_concepts:
        t0 = time.monotonic()
        try:
            await memory.add_interaction(
                {
                    "content": test["interaction"],
                    "session_id": f"bench_{test['name']}",
                }
            )

            history = await memory.search_attacker_history(test["query"])
            text = ""
            if history and isinstance(history, list) and len(history) > 0:
                text = history[0].get("memory", "") if isinstance(history[0], dict) else str(history[0])

            score = _score_memory_recall(text, test["concepts"])
            latency = (time.monotonic() - t0) * 1000
            results.append(
                BenchmarkResult(
                    name=f"memory_{test['name']}",
                    suite="memory",
                    passed=score >= 0.3,
                    score=score,
                    latency_ms=latency,
                    details={"interaction": test["interaction"]},
                )
            )
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            results.append(
                BenchmarkResult(
                    name=f"memory_{test['name']}",
                    suite="memory",
                    passed=False,
                    score=0.0,
                    latency_ms=latency,
                    error=str(exc),
                )
            )

    return results
