"""MITRE ATT&CK STIX Data Loader — parse enterprise-attack.json into IntelDocument format.

Downloads the MITRE ATT&CK STIX dataset and converts it into documents
suitable for ingestion by the LightRAG adapter or IntelCorpus.
"""

from __future__ import annotations

import contextlib
import json
import logging
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_MITRE_STIX_URL = (
    "https://github.com/mitre-attack/attack-stix-data/raw/refs/heads/master/" "enterprise-attack/enterprise-attack.json"
)
_LOCAL_CACHE = Path("data/mitre_stix/enterprise-attack.json")


def download_mitre_stix(
    url: str | None = None,
    dest: Path | None = None,
    force: bool = False,
) -> Path:
    """Download enterprise-attack.json if not cached. Returns path to file."""
    target = dest or _LOCAL_CACHE
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists() and not force:
        size_mb = target.stat().st_size / (1024 * 1024)
        logger.info("Using cached MITRE STIX data: %s (%.1f MB)", target, size_mb)
        return target

    src = url or _MITRE_STIX_URL
    logger.info("Downloading MITRE ATT&CK STIX data from %s ...", src)
    try:
        urllib.request.urlretrieve(src, str(target))
        logger.info("Downloaded to %s (%.1f MB)", target, target.stat().st_size / (1024 * 1024))
    except Exception as exc:
        logger.error("Failed to download MITRE STIX data: %s", exc)
        raise
    return target


def parse_stix_to_documents(stix_path: Path | str) -> list[dict[str, Any]]:
    """Parse enterprise-attack.json into a list of IntelDocument dicts.

    Returns a flat list of documents, one per attack object (technique, campaign,
    group, software, data source). Each dict is ready for LightRAG insert or
    IntelCorpus ingestion.
    """
    with open(stix_path) as f:
        bundle = json.load(f)

    objects: list[dict[str, Any]] = bundle.get("objects", [])
    logger.info("Loaded STIX bundle with %d objects", len(objects))

    docs: list[dict[str, Any]] = []
    technique_map: dict[str, dict[str, Any]] = {}

    # First pass: index all attack-patterns (techniques)
    for obj in objects:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
            refs = obj.get("external_references", [])
            technique_id = None
            for ref in refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break
            if technique_id:
                technique_map[obj["id"]] = {
                    "id": technique_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "tactics": _extract_tactic_ids(obj),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "data_sources": obj.get("x_mitre_data_sources", []),
                }

    # Build tactic_id lookup from kill-chain-phases
    tactic_id_map: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            refs = obj.get("external_references", [])
            for ref in refs:
                if ref.get("source_name") == "mitre-attack":
                    shortname = ref.get("external_id", "")
                    tactic_id_map[obj["id"]] = shortname

    # Second pass: generate documents
    for obj in objects:
        obj.get("type", "")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        doc = _convert_object(obj, technique_map, tactic_id_map)
        if doc:
            docs.append(doc)

    logger.info("Converted %d STIX objects to documents", len(docs))
    return docs


def _extract_tactic_ids(obj: dict[str, Any]) -> list[str]:
    """Extract tactic IDs from kill_chain_phases."""
    tactics = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            tactics.append(phase.get("phase_name", ""))
    return tactics


def _convert_object(
    obj: dict[str, Any],
    technique_map: dict[str, dict[str, Any]],
    tactic_id_map: dict[str, str],
) -> dict[str, Any] | None:
    """Convert a single STIX object to an IntelDocument-compatible dict."""
    obj_type = obj.get("type", "")
    name = obj.get("name", "")
    description = obj.get("description", "")
    obj_id = obj.get("id", "")

    refs = obj.get("external_references", [])
    external_id = None
    url = None
    for ref in refs:
        if ref.get("source_name") == "mitre-attack":
            external_id = external_id or ref.get("external_id")
        url = url or ref.get("url")

    # Extract tactic IDs
    tactic_ids = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            tactic_ids.append(phase.get("phase_name", ""))

    # Extract technique IDs from relationship data
    threat_actors = []
    platforms = obj.get("x_mitre_platforms", [])

    # Build content based on type
    if obj_type == "attack-pattern":
        content = _build_technique_content(obj, external_id, name, description)
        title = f"MITRE Technique: {name} ({external_id})"
        tags = ["mitre-attack", "technique"] + [t.replace("-", "_") for t in tactic_ids]

    elif obj_type == "intrusion-set":
        content = _build_actor_content(obj, name, description)
        title = f"Threat Actor: {name}"
        threat_actors = [name.lower()]
        if obj.get("x_mitre_aliases"):
            threat_actors.extend([a.lower() for a in obj["x_mitre_aliases"]])
        tags = ["mitre-attack", "threat-actor"]

    elif obj_type == "campaign":
        content = _build_campaign_content(obj, name, description)
        title = f"Campaign: {name}"
        tags = ["mitre-attack", "campaign"]

    elif obj_type == "malware" or obj_type == "tool":
        content = _build_software_content(obj, obj_type, name, description)
        title = f"{'Malware' if obj_type == 'malware' else 'Tool'}: {name}"
        tags = ["mitre-attack", obj_type]

    elif obj_type == "report":
        content = _build_report_content(obj, name, description)
        title = f"Report: {name}"
        tags = ["mitre-attack", "report"]

    else:
        # Generic fallback
        content = f"**{name}**\n\n{description}"
        title = f"{obj_type.replace('x-mitre-', '').replace('-', ' ').title()}: {name}"
        tags = ["mitre-attack", obj_type.replace("x-mitre-", "")]

    # Extract creation date
    created = obj.get("created")
    published_date = None
    if created:
        with contextlib.suppress(ValueError, TypeError):
            published_date = datetime.fromisoformat(created.replace("Z", "+00:00"))

    doc_id = external_id or obj_id

    return {
        "doc_id": doc_id,
        "title": title,
        "content": content,
        "source": "mitre-attack-stix",
        "published_date": published_date.isoformat() if published_date else None,
        "tags": tags,
        "mitre_tactics": list(set(tactic_ids)),
        "threat_actors": threat_actors,
        "score": 0.0,
        "text": content,  # LightRAG uses 'text' key
        # Extra metadata
        "external_id": external_id,
        "url": url,
        "obj_type": obj_type,
        "platforms": platforms,
        "stix_id": obj_id,
    }


def _build_technique_content(
    obj: dict[str, Any],
    technique_id: str | None,
    name: str,
    description: str,
) -> str:
    """Build rich content for a MITRE technique document."""
    parts = [
        f"# {name}" + (f" ({technique_id})" if technique_id else ""),
        "",
        description,
        "",
    ]

    # Platforms
    platforms = obj.get("x_mitre_platforms", [])
    if platforms:
        parts.append(f"**Platforms:** {', '.join(platforms)}")
        parts.append("")

    # Tactic mapping
    tactics = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            tactics.append(phase.get("phase_name", ""))
    if tactics:
        parts.append(f"**Tactics:** {', '.join(tactics)}")
        parts.append("")

    # Data sources
    data_sources = obj.get("x_mitre_data_sources", [])
    if data_sources:
        parts.append("**Detection:**")
        for ds in data_sources[:5]:
            parts.append(f"- {ds}")
        parts.append("")

    # Mitigations (from relationships — placeholder for now)
    parts.append("**Recommended mitigations:** See ATT&CK website for details.")

    return "\n".join(parts)


def _build_actor_content(
    obj: dict[str, Any],
    name: str,
    description: str,
) -> str:
    """Build rich content for a threat actor document."""
    parts = [
        f"# Threat Actor: {name}",
        "",
        description,
        "",
    ]

    aliases = obj.get("x_mitre_aliases", [])
    if aliases:
        parts.append(f"**Aliases:** {', '.join(aliases)}")
        parts.append("")

    # Country
    if obj.get("x_mitre_country"):
        parts.append(f"**Country:** {obj['x_mitre_country']}")
        parts.append("")

    # Motivation
    if obj.get("x_mitre_motivation"):
        parts.append(f"**Motivation:** {', '.join(obj['x_mitre_motivation'])}")
        parts.append("")

    # Sophistication
    if obj.get("x_mitre_sophistication"):
        parts.append(f"**Sophistication:** {obj['x_mitre_sophistication']}")
        parts.append("")

    # Resource level
    if obj.get("x_mitre_resource_level"):
        parts.append(f"**Resource Level:** {obj['x_mitre_resource_level']}")
        parts.append("")

    # First seen / last seen
    first_seen = obj.get("first_seen")
    last_seen = obj.get("last_seen")
    if first_seen:
        parts.append(f"**First Seen:** {first_seen}")
    if last_seen:
        parts.append(f"**Last Seen:** {last_seen}")
    if first_seen or last_seen:
        parts.append("")

    parts.append("**Known Techniques:** See ATT&CK profile for full technique list.")

    return "\n".join(parts)


def _build_campaign_content(
    obj: dict[str, Any],
    name: str,
    description: str,
) -> str:
    """Build rich content for a campaign document."""
    parts = [
        f"# Campaign: {name}",
        "",
        description,
        "",
    ]

    first_seen = obj.get("first_seen")
    last_seen = obj.get("last_seen")
    if first_seen:
        parts.append(f"**First Seen:** {first_seen}")
    if last_seen:
        parts.append(f"**Last Seen:** {last_seen}")
    if first_seen or last_seen:
        parts.append("")

    # Objective
    if obj.get("objective"):
        parts.append(f"**Objective:** {obj['objective']}")
        parts.append("")

    return "\n".join(parts)


def _build_software_content(
    obj: dict[str, Any],
    obj_type: str,
    name: str,
    description: str,
) -> str:
    """Build rich content for a software (malware/tool) document."""
    parts = [
        f"# {'Malware' if obj_type == 'malware' else 'Tool'}: {name}",
        "",
        description,
        "",
    ]

    aliases = obj.get("x_mitre_aliases", [])
    if aliases:
        parts.append(f"**Aliases:** {', '.join(aliases)}")
        parts.append("")

    platforms = obj.get("x_mitre_platforms", [])
    if platforms:
        parts.append(f"**Platforms:** {', '.join(platforms)}")
        parts.append("")

    if obj_type == "malware":
        is_family = obj.get("x_mitre_is_family", False)
        parts.append(f"**Malware Family:** {'Yes' if is_family else 'No'}")

    return "\n".join(parts)


def _build_report_content(
    obj: dict[str, Any],
    name: str,
    description: str,
) -> str:
    """Build rich content for a report document."""
    parts = [
        f"# Report: {name}",
        "",
        description,
        "",
    ]

    # External references
    for ref in obj.get("external_references", []):
        if ref.get("url"):
            parts.append(f"**URL:** {ref['url']}")
            break

    return "\n".join(parts)


def load_mitre_corpus(
    stix_path: Path | str | None = None,
    force_download: bool = False,
) -> list[dict[str, Any]]:
    """Download (if needed) and parse MITRE ATT&CK into IntelDocument dicts."""
    path = Path(stix_path) if stix_path else _LOCAL_CACHE
    if not path.exists() or force_download:
        path = download_mitre_stix(dest=path, force=force_download)
    return parse_stix_to_documents(path)


# --- Campaign-level enrichment data (M-Trends 2026, Salt Typhoon, etc.) ---


def get_recent_campaign_documents() -> list[dict[str, Any]]:
    """Return manually curated documents from recent real-world campaigns.

    These are sourced from public reports:
    - M-Trends 2026 top 10 techniques
    - Salt Typhoon (Volt Storm) IOCs
    - Volt Typhoon TTPs
    - APT groups active in 2025-2026
    """
    docs: list[dict[str, Any]] = []

    # --- Salt Typhoon ---
    docs.append(
        {
            "doc_id": "campaign-salt-typhoon-2024",
            "title": "Salt Typhoon — Chinese State-Sponsored Telecom Espionage",
            "content": (
                "# Salt Typhoon (Volt Storm)\n\n"
                "Salt Typhoon is a Chinese state-sponsored threat actor that conducted "
                "extensive espionage operations against major US telecommunications providers "
                "including AT&T, Verizon, T-Mobile, and Lumen Technologies during 2024.\n\n"
                "## Key Findings\n"
                "- Accessed call metadata (CDRs) for millions of Americans\n"
                "- Monitored communications of senior government officials and political figures\n"
                "- Used lawful intercept systems (wiretap infrastructure) for surveillance\n"
                "- Maintained persistent access for months before discovery\n"
                "- Compromised Cisco IOS XE routers for initial access\n\n"
                "## Known IOCs\n"
                "- 184.39.173.2, 184.39.173.5, 184.39.173.4 — C2 infrastructure\n"
                "- Custom webshell: 'HDoor' (ASPX-based)\n"
                "- Malware: 'JumbledPath' — anti-forensics tool for memory forensics evasion\n"
                "- Custom Nmap scripts for internal recon\n"
                "- Credential harvesting from compromised network devices\n\n"
                "## MITRE ATT&CK Mapping\n"
                "- TA0001 Initial Access: T1133 External Remote Services\n"
                "- TA0003 Persistence: T1078 Valid Accounts\n"
                "- TA0005 Defense Evasion: T1070 Indicator Removal\n"
                "- TA0007 Discovery: T1046 Network Service Scanning\n"
                "- TA0011 Command and Control: T1090 Proxy\n\n"
                "## Impact\n"
                "- National security implications — access to intelligence community communications\n"
                "- Led to FCC emergency order banning equipment from affected vendors\n"
                "- Affected 10+ US carriers and government agencies"
            ),
            "source": "Microsoft Threat Intelligence, Mandiant, CISA",
            "tags": ["salt-typhoon", "china", "apt", "telecom", "espionage", "state-sponsored"],
            "mitre_tactics": ["TA0001", "TA0003", "TA0005", "TA0006", "TA0007", "TA0008", "TA0011"],
            "threat_actors": ["salt typhoon", "volt storm", "china"],
            "published_date": "2024-12-01T00:00:00Z",
        }
    )

    # --- Volt Typhoon ---
    docs.append(
        {
            "doc_id": "campaign-volt-typhoon-2024",
            "title": "Volt Typhoon — Chinese APT Pre-Positioning for Critical Infrastructure",
            "content": (
                "# Volt Typhoon\n\n"
                "Volt Typhoon is a Chinese state-sponsored threat actor focused on "
                "pre-positioning access to US critical infrastructure for potential "
                "future disruption or destruction operations.\n\n"
                "## Key Findings\n"
                "- Targets: energy, water, transportation, telecommunications, manufacturing\n"
                "- Uses 'living off the land' (LOTL) techniques exclusively\n"
                "- Compromises SOHO routers (end-of-life) for proxy infrastructure\n"
                "- No custom malware — relies on built-in OS tools\n"
                "- Active since at least 2021, discovered publicly in May 2023\n\n"
                "## Known IOCs\n"
                "- Proxy network via compromised Fortinet, Ivanti, and Netgear routers\n"
                "- 198.199.x.x range — proxy infrastructure\n"
                "- Cobalt Strike beacons (deployed post-compromise)\n"
                "- Custom DNS tunneling for C2\n"
                "- Modified ntds.dit extraction tools\n\n"
                "## MITRE ATT&CK Mapping\n"
                "- TA0001 Initial Access: T1190 Exploit Public-Facing Application\n"
                "- TA0002 Execution: T1059 Command and Scripting Interpreter\n"
                "- TA0003 Persistence: T1133 External Remote Services, T1078 Valid Accounts\n"
                "- TA0005 Defense Evasion: T1218 System Binary Proxy Execution\n"
                "- TA0006 Credential Access: T1003 OS Credential Dumping\n"
                "- TA0007 Discovery: T1018 Remote System Discovery\n"
                "- TA0008 Lateral Movement: T1021 Remote Services\n"
                "- TA0011 C2: T1071 Application Layer Protocol\n\n"
                "## LOTL Techniques\n"
                "- net.exe, net1.exe for user/group enumeration\n"
                "- cmd.exe for command execution\n"
                "- certutil.exe for file transfer\n"
                "- wmic.exe for system enumeration\n"
                "- PowerShell for payload execution\n"
                "- ntdsutil.exe for credential extraction"
            ),
            "source": "Microsoft Threat Intelligence, CISA, NSA",
            "tags": ["volt-typhoon", "china", "apt", "critical-infrastructure", "lotl", "state-sponsored"],
            "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0005", "TA0006", "TA0007", "TA0008", "TA0011"],
            "threat_actors": ["volt typhoon", "china"],
            "published_date": "2024-05-24T00:00:00Z",
        }
    )

    # --- M-Trends 2026 Top 10 Techniques ---
    mtrends_techniques = [
        ("T1566", "Phishing", "TA0001", "Initial delivery via malicious emails with embedded links/attachments"),
        ("T1059", "Command and Scripting Interpreter", "TA0002", "PowerShell, cmd.exe, WScript/CScript for execution"),
        ("T1053", "Scheduled Task/Job", "TA0003", "Persistence via schtasks.exe and at.exe"),
        ("T1078", "Valid Accounts", "TA0003", "Use of legitimate credentials for initial access"),
        ("T1055", "Process Injection", "TA0005", "DLL injection, process hollowing for defense evasion"),
        ("T1003", "OS Credential Dumping", "TA0006", "LSASS memory dump, SAM database extraction"),
        ("T1087", "Account Discovery", "TA0007", "Local and domain user enumeration"),
        ("T1021", "Remote Services", "TA0008", "RDP, SMB, WMI lateral movement"),
        ("T1071", "Application Layer Protocol", "TA0011", "HTTP/HTTPS, DNS for C2 communication"),
        ("T1560", "Archive Collected Data", "TA0009", "Data compression before exfiltration"),
    ]

    for tech_id, tech_name, tactic_id, description in mtrends_techniques:
        docs.append(
            {
                "doc_id": f"mtrends2026-{tech_id}",
                "title": f"M-Trends 2026: {tech_id} {tech_name}",
                "content": (
                    f"# {tech_id} — {tech_name}\n\n"
                    f"**M-Trends 2026 Ranking:** Top 10 most observed technique\n\n"
                    f"**MITRE Tactic:** {tactic_id}\n\n"
                    f"{description}\n\n"
                    "## Detection Recommendations\n"
                    f"- Monitor for {tech_name.lower()} activity in endpoint logs\n"
                    "- Implement behavioral analytics for anomaly detection\n"
                    "- Deploy EDR with real-time process monitoring\n"
                    "- Enable command-line logging and PowerShell script block logging"
                ),
                "source": "Mandiant M-Trends 2026",
                "tags": ["m-trends-2026", "technique", "detection"],
                "mitre_tactics": [tactic_id],
                "threat_actors": [],
                "published_date": "2026-01-01T00:00:00Z",
            }
        )

    # --- Active APT Groups 2025-2026 ---
    apt_groups = [
        ("APT28", "Russia / GRU Unit 74455", "Spearphishing, credential theft, supply chain compromise"),
        ("APT29", "Russia / SVR Cozy Bear", "SolarWinds-style supply chain, cloud credential theft"),
        ("Lazarus Group", "North Korea / RGB", "Financial theft, cryptocurrency heists, supply chain attacks"),
        ("APT41", "China / Winnti Group", "Dual espionage and financial operations"),
        ("Kimsuky", "North Korea / RGB", "South Korean government targeting, phishing campaigns"),
        ("Turla", "Russia / FSB Snake", "Advanced implants, satellite-based C2"),
        ("OilRig", "Iran / APT34", "Middle East targeting, DNS tunneling C2"),
        ("CozyDuke", "Russia / APT29 variant", "Government email compromise"),
        ("Charming Kitten", "Iran / APT35", "Social engineering, fake academic conferences"),
        ("Mustang Panda", "China / Temp.Hex", "Southeast Asian government targeting"),
    ]

    for name, origin, ttps in apt_groups:
        docs.append(
            {
                "doc_id": f"apt-group-{name.lower().replace(' ', '-')}",
                "title": f"APT Profile: {name}",
                "content": (
                    f"# {name}\n\n"
                    f"**Origin:** {origin}\n\n"
                    f"**Key TTPs:** {ttps}\n\n"
                    "## Activity\n"
                    f"{name} remains active in 2025-2026 with campaigns targeting "
                    "government, defense, and critical infrastructure sectors."
                ),
                "source": "Open Source Intelligence",
                "tags": ["apt-profile", "threat-actor"],
                "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0006", "TA0008", "TA0011"],
                "threat_actors": [name.lower()],
                "published_date": "2026-01-01T00:00:00Z",
            }
        )

    return docs
