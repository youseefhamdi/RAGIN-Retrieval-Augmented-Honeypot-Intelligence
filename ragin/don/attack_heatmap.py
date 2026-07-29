"""
ATT&CK Navigator Heatmap Generator for Don — produces JSON layers
compatible with the MITRE ATT&CK Navigator tool.

Generates heatmaps from extracted TTPs, with color-coding by confidence,
frequency, and detection status.  Can overlay multiple sessions or
compare attacker profiles.

Usage::

    from ragin.don.attack_heatmap import ATTCKHeatmapGenerator

    gen = ATTCKHeatmapGenerator()
    layer = gen.generate_layer(
        ttps=[("T1566", 0.9), ("T1059", 0.7)],
        title="Session ABC — Attacker Profile",
    )
    gen.save_layer(layer, "heatmap.json")

    # Navigator-compatible JSON is ready to load at:
    # https://mitre-attack.github.io/attack-navigator/
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── ATT&CK Matrix Structure (Enterprise v15) ──────────────────────────────────
# Tactic ID → (name, short_name, technique_ids)
# Techniques are generated compactly; full details come from the STIX/CTI data.

_TACTIC_DEFS: dict[str, tuple[str, str, list[str]]] = {
    "TA0043": (
        "Reconnaissance",
        "recon",
        [
            "T1595",
            "T1595.001",
            "T1595.002",
            "T1595.003",
            "T1592",
            "T1592.001",
            "T1592.002",
            "T1592.003",
            "T1592.004",
            "T1589",
            "T1589.001",
            "T1589.002",
            "T1589.003",
            "T1590",
            "T1590.001",
            "T1590.002",
            "T1590.003",
            "T1590.004",
            "T1590.005",
            "T1590.006",
            "T1591",
            "T1591.001",
            "T1591.002",
            "T1591.003",
            "T1591.004",
            "T1593",
            "T1593.001",
            "T1593.002",
            "T1593.003",
            "T1594",
            "T1596",
            "T1596.001",
            "T1596.002",
            "T1596.003",
            "T1596.004",
            "T1596.005",
            "T1597",
            "T1597.001",
            "T1597.002",
            "T1598",
            "T1598.001",
            "T1598.002",
            "T1598.003",
            "T1599",
            "T1599.001",
        ],
    ),
    "TA0042": (
        "Resource Development",
        "resource-dev",
        [
            "T1583",
            "T1583.001",
            "T1583.002",
            "T1583.003",
            "T1583.004",
            "T1583.005",
            "T1583.006",
            "T1584",
            "T1584.001",
            "T1584.002",
            "T1584.003",
            "T1584.004",
            "T1584.005",
            "T1584.006",
            "T1587",
            "T1587.001",
            "T1587.002",
            "T1587.003",
            "T1587.004",
            "T1588",
            "T1588.001",
            "T1588.002",
            "T1588.003",
            "T1588.004",
            "T1588.005",
            "T1588.006",
            "T1588.007",
            "T1608",
            "T1608.001",
            "T1608.002",
            "T1608.003",
            "T1608.004",
            "T1608.005",
        ],
    ),
    "TA0001": (
        "Initial Access",
        "initial-access",
        [
            "T1189",
            "T1190",
            "T1133",
            "T1200",
            "T1566",
            "T1566.001",
            "T1566.002",
            "T1566.003",
            "T1078",
            "T1078.001",
            "T1078.002",
            "T1078.003",
            "T1078.004",
            "T1195",
            "T1195.001",
            "T1195.002",
            "T1195.003",
            "T1199",
            "T1133.001",
            "T1133.002",
            "T1091",
            "T1091.001",
            "T1198",
            "T1534",
            "T1048",
            "T1048.001",
            "T1048.002",
            "T1048.003",
            "T1102",
            "T1102.001",
            "T1102.002",
            "T1102.003",
        ],
    ),
    "TA0002": (
        "Execution",
        "execution",
        [
            "T1059",
            "T1059.001",
            "T1059.002",
            "T1059.003",
            "T1059.004",
            "T1059.005",
            "T1059.006",
            "T1059.007",
            "T1059.008",
            "T1059.009",
            "T1203",
            "T1047",
            "T1053",
            "T1053.001",
            "T1053.002",
            "T1053.003",
            "T1053.004",
            "T1053.005",
            "T1053.006",
            "T1053.007",
            "T1072",
            "T1072.001",
            "T1072.002",
            "T1569",
            "T1569.001",
            "T1569.002",
            "T1106",
            "T1070.006",
            "T1129",
            "T1048.001",
            "T1048.002",
            "T1609",
            "T1609.001",
            "T1610",
            "T1648",
            "T1648.001",
            "T1204",
            "T1204.001",
            "T1204.002",
            "T1204.003",
            "T1620",
            "T1036.005",
            "T1127",
            "T1127.001",
            "T1059.010",
            "T1059.011",
            "T1059.012",
        ],
    ),
    "TA0003": (
        "Persistence",
        "persistence",
        [
            "T1098",
            "T1098.001",
            "T1098.002",
            "T1098.003",
            "T1098.004",
            "T1098.005",
            "T1098.006",
            "T1136",
            "T1136.001",
            "T1136.002",
            "T1136.003",
            "T1543",
            "T1543.001",
            "T1543.002",
            "T1543.003",
            "T1543.004",
            "T1547",
            "T1547.001",
            "T1547.002",
            "T1547.003",
            "T1547.004",
            "T1547.005",
            "T1547.006",
            "T1547.007",
            "T1547.008",
            "T1547.009",
            "T1547.010",
            "T1547.012",
            "T1547.013",
            "T1547.014",
            "T1547.015",
            "T1574",
            "T1574.001",
            "T1574.002",
            "T1574.004",
            "T1574.005",
            "T1574.006",
            "T1574.007",
            "T1574.008",
            "T1574.009",
            "T1574.010",
            "T1574.011",
            "T1574.012",
            "T1574.013",
            "T1574.014",
            "T1133",
            "T1133.001",
            "T1133.002",
            "T1546",
            "T1546.001",
            "T1546.002",
            "T1546.003",
            "T1546.004",
            "T1546.005",
            "T1546.006",
            "T1546.007",
            "T1546.008",
            "T1546.009",
            "T1546.010",
            "T1546.011",
            "T1546.012",
            "T1546.013",
            "T1546.014",
            "T1546.015",
            "T1546.016",
            "T1546.017",
            "T1546.018",
            "T1546.019",
            "T1543.003",
            "T1543.004",
            "T1197",
            "T1554",
            "T1137",
            "T1137.001",
            "T1137.002",
            "T1137.003",
            "T1137.004",
            "T1137.005",
            "T1137.006",
            "T1505",
            "T1505.001",
            "T1505.002",
            "T1505.003",
            "T1505.004",
            "T1505.005",
            "T1556",
            "T1556.001",
            "T1556.002",
            "T1556.003",
            "T1556.004",
            "T1556.005",
            "T1556.006",
            "T1556.007",
            "T1556.008",
            "T1554",
            "T1078.001",
            "T1078.002",
            "T1078.003",
            "T1078.004",
            "T1199",
            "T1098.001",
            "T1557",
            "T1557.001",
            "T1557.002",
            "T1557.003",
        ],
    ),
    "TA0004": (
        "Privilege Escalation",
        "priv-esc",
        [
            "T1548",
            "T1548.001",
            "T1548.002",
            "T1548.003",
            "T1548.004",
            "T1548.005",
            "T1548.006",
            "T1068",
            "T1611",
            "T1612",
            "T1574",
            "T1055",
            "T1055.001",
            "T1055.002",
            "T1055.003",
            "T1055.004",
            "T1055.005",
            "T1055.006",
            "T1055.007",
            "T1055.008",
            "T1055.009",
            "T1055.010",
            "T1055.011",
            "T1055.012",
            "T1055.013",
            "T1055.014",
            "T1055.015",
            "T1543",
            "T1543.001",
            "T1543.002",
            "T1543.003",
            "T1543.004",
            "T1547",
            "T1547.001",
            "T1547.002",
            "T1547.003",
            "T1547.004",
            "T1547.005",
            "T1547.006",
            "T1547.007",
            "T1547.008",
            "T1547.009",
            "T1547.010",
            "T1547.012",
            "T1547.013",
            "T1547.014",
            "T1547.015",
            "T1053",
            "T1053.001",
            "T1053.002",
            "T1053.003",
            "T1053.004",
            "T1053.005",
            "T1053.006",
            "T1053.007",
            "T1134",
            "T1134.001",
            "T1134.002",
            "T1134.003",
            "T1134.004",
            "T1134.005",
        ],
    ),
    "TA0005": (
        "Defense Evasion",
        "defense-evasion",
        [
            "T1027",
            "T1027.001",
            "T1027.002",
            "T1027.003",
            "T1027.004",
            "T1027.005",
            "T1027.006",
            "T1027.007",
            "T1027.008",
            "T1027.009",
            "T1027.010",
            "T1027.011",
            "T1027.012",
            "T1027.013",
            "T1027.014",
            "T1027.015",
            "T1036",
            "T1036.001",
            "T1036.002",
            "T1036.003",
            "T1036.004",
            "T1036.005",
            "T1036.006",
            "T1036.007",
            "T1036.008",
            "T1036.009",
            "T1036.010",
            "T1036.011",
            "T1036.012",
            "T1036.013",
            "T1070",
            "T1070.001",
            "T1070.002",
            "T1070.003",
            "T1070.004",
            "T1070.005",
            "T1070.006",
            "T1070.007",
            "T1070.008",
            "T1070.009",
            "T1070.010",
            "T1070.011",
            "T1070.012",
            "T1070.013",
            "T1070.014",
            "T1070.015",
            "T1070.016",
            "T1140",
            "T1112",
            "T1197",
            "T1140",
            "T1562",
            "T1562.001",
            "T1562.002",
            "T1562.003",
            "T1562.004",
            "T1562.005",
            "T1562.006",
            "T1562.007",
            "T1562.008",
            "T1562.009",
            "T1562.010",
            "T1562.011",
            "T1562.012",
            "T1574",
            "T1202",
            "T1218",
            "T1218.001",
            "T1218.002",
            "T1218.003",
            "T1218.004",
            "T1218.005",
            "T1218.006",
            "T1218.007",
            "T1218.008",
            "T1218.009",
            "T1218.010",
            "T1218.011",
            "T1218.012",
            "T1218.013",
            "T1218.014",
            "T1218.015",
            "T1221",
            "T1216",
            "T1216.001",
            "T1216.002",
            "T1535",
            "T1548",
            "T1550",
            "T1550.001",
            "T1550.002",
            "T1550.003",
            "T1550.004",
            "T1550.005",
            "T1550.006",
            "T1553",
            "T1553.001",
            "T1553.002",
            "T1553.003",
            "T1553.004",
            "T1553.005",
            "T1553.006",
            "T1574.001",
            "T1574.002",
            "T1574.003",
            "T1574.004",
            "T1574.005",
            "T1612",
            "T1620",
            "T1622",
            "T1480",
            "T1480.001",
        ],
    ),
    "TA0006": (
        "Credential Access",
        "cred-access",
        [
            "T1003",
            "T1003.001",
            "T1003.002",
            "T1003.003",
            "T1003.004",
            "T1003.005",
            "T1003.006",
            "T1003.007",
            "T1003.008",
            "T1110",
            "T1110.001",
            "T1110.002",
            "T1110.003",
            "T1110.004",
            "T1555",
            "T1555.001",
            "T1555.002",
            "T1555.003",
            "T1555.004",
            "T1555.005",
            "T1555.006",
            "T1212",
            "T1187",
            "T1557",
            "T1557.001",
            "T1557.002",
            "T1557.003",
            "T1558",
            "T1558.001",
            "T1558.002",
            "T1558.003",
            "T1558.004",
            "T1558.005",
            "T1558.006",
            "T1111",
            "T1056",
            "T1056.001",
            "T1056.002",
            "T1056.003",
            "T1056.004",
            "T1528",
            "T1539",
            "T1552",
            "T1552.001",
            "T1552.002",
            "T1552.003",
            "T1552.004",
            "T1552.005",
            "T1552.006",
            "T1552.007",
            "T1552.008",
            "T1528.001",
            "T1040",
            "T1558.001",
            "T1649",
            "T1621",
            "T1621.001",
        ],
    ),
    "TA0007": (
        "Discovery",
        "discovery",
        [
            "T1082",
            "T1083",
            "T1087",
            "T1087.001",
            "T1087.002",
            "T1087.003",
            "T1087.004",
            "T1046",
            "T1135",
            "T1040",
            "T1081",
            "T1081.001",
            "T1081.002",
            "T1081.003",
            "T1081.004",
            "T1069",
            "T1069.001",
            "T1069.002",
            "T1069.003",
            "T1057",
            "T1012",
            "T1018",
            "T1016",
            "T1016.001",
            "T1016.002",
            "T1033",
            "T1007",
            "T1049",
            "T1039",
            "T1058",
            "T1058.001",
            "T1058.002",
            "T1058.003",
            "T1058.004",
            "T1058.005",
            "T1482",
            "T1518",
            "T1518.001",
            "T1518.002",
            "T1614",
            "T1614.001",
            "T1049",
            "T1010",
            "T1518.001",
            "T1518.002",
            "T1622",
        ],
    ),
    "TA0008": (
        "Lateral Movement",
        "lateral-movement",
        [
            "T1210",
            "T1534",
            "T1570",
            "T1563",
            "T1563.001",
            "T1563.002",
            "T1021",
            "T1021.001",
            "T1021.002",
            "T1021.003",
            "T1021.004",
            "T1021.005",
            "T1021.006",
            "T1021.007",
            "T1570",
            "T1080",
            "T1550",
            "T1550.001",
            "T1550.002",
            "T1550.003",
            "T1550.004",
            "T1550.005",
            "T1550.006",
            "T1072",
            "T1072.001",
            "T1072.002",
            "T1091",
            "T1091.001",
            "T1021.001",
            "T1021.002",
            "T1021.003",
            "T1021.004",
            "T1021.005",
            "T1021.006",
            "T1021.007",
            "T1563.001",
            "T1563.002",
            "T1550.001",
            "T1550.002",
            "T1550.003",
            "T1550.004",
            "T1550.005",
            "T1550.006",
            "T1021.006",
        ],
    ),
    "TA0009": (
        "Collection",
        "collection",
        [
            "T1005",
            "T1039",
            "T1025",
            "T1074",
            "T1074.001",
            "T1074.002",
            "T1114",
            "T1114.001",
            "T1114.002",
            "T1114.003",
            "T1113",
            "T1125",
            "T1115",
            "T1530",
            "T1560",
            "T1560.001",
            "T1560.002",
            "T1560.003",
            "T1119",
            "T1056",
            "T1056.001",
            "T1056.002",
            "T1056.003",
            "T1056.004",
            "T1123",
            "T1185",
            "T1185.001",
            "T1056.001",
        ],
    ),
    "TA0011": (
        "Command and Control",
        "c2",
        [
            "T1071",
            "T1071.001",
            "T1071.002",
            "T1071.003",
            "T1071.004",
            "T1105",
            "T1104",
            "T1090",
            "T1090.001",
            "T1090.002",
            "T1090.003",
            "T1090.004",
            "T1102",
            "T1102.001",
            "T1102.002",
            "T1102.003",
            "T1573",
            "T1573.001",
            "T1573.002",
            "T1572",
            "T1008",
            "T1101",
            "T1101.001",
            "T1568",
            "T1568.001",
            "T1568.002",
            "T1568.003",
            "T1095",
            "T1095.001",
            "T1583.006",
            "T1584.006",
            "T1132",
            "T1132.001",
            "T1132.002",
            "T1001",
            "T1001.001",
            "T1001.002",
            "T1001.003",
            "T1567",
            "T1567.001",
            "T1567.002",
            "T1567.003",
            "T1567.004",
            "T1008",
            "T1095",
            "T1132.001",
            "T1132.002",
        ],
    ),
    "TA0010": (
        "Exfiltration",
        "exfiltration",
        [
            "T1020",
            "T1020.001",
            "T1020.002",
            "T1030",
            "T1030.001",
            "T1041",
            "T1048",
            "T1048.001",
            "T1048.002",
            "T1048.003",
            "T1048.004",
            "T1011",
            "T1011.001",
            "T1567",
            "T1567.001",
            "T1567.002",
            "T1567.003",
            "T1567.004",
            "T1029",
            "T1537",
            "T1052",
            "T1052.001",
            "T1074.001",
            "T1074.002",
        ],
    ),
    "TA0040": (
        "Impact",
        "impact",
        [
            "T1485",
            "T1486",
            "T1490",
            "T1491",
            "T1491.001",
            "T1491.002",
            "T1499",
            "T1499.001",
            "T1499.002",
            "T1499.003",
            "T1499.004",
            "T1496",
            "T1496.001",
            "T1496.002",
            "T1496.003",
            "T1498",
            "T1498.001",
            "T1498.002",
            "T1491.001",
            "T1491.002",
            "T1495",
            "T1491.001",
            "T1491.002",
            "T1565",
            "T1565.001",
            "T1565.002",
            "T1565.003",
            "T1531",
            "T1499.001",
            "T1499.002",
            "T1499.003",
            "T1499.004",
            "T1495",
            "T1561",
            "T1561.001",
            "T1561.002",
        ],
    ),
    "TA0041": (
        "Recovery",
        "recovery",
        [
            "T1490",
            "T1489",
        ],
    ),
}


# ── ATT&CK Navigator Layer Schema (v4.5) ───────────────────────────────────────


def _make_technique(tech_id: str, score: float = 0, color: str = "") -> dict[str, Any]:
    """Create a single ATT&CK Navigator technique entry."""
    entry: dict[str, Any] = {"techniqueID": tech_id, "tactic": "", "enabled": True}
    if score:
        entry["score"] = score
    if color:
        entry["color"] = color
    return entry


def _score_to_color(score: float) -> str:
    """Map a 0.0–1.0 score to a red-yellow-green color string."""
    if score >= 0.8:
        return "#d32f2f"  # red — high confidence
    if score >= 0.6:
        return "#f57c00"  # orange
    if score >= 0.4:
        return "#fbc02d"  # yellow
    if score > 0:
        return "#4caf50"  # green — low confidence
    return ""


@dataclass
class HeatmapLayer:
    """A single ATT&CK Navigator layer object."""

    name: str = "RAGIN Heatmap"
    description: str = ""
    version: int = 4
    domain: str = "enterprise-attack"
    techniques: list[dict[str, Any]] = field(default_factory=list)
    gradient: dict[str, Any] = field(
        default_factory=lambda: {
            "colors": ["#4caf50", "#fbc02d", "#f57c00", "#d32f2f"],
            "minValue": 0,
            "maxValue": 100,
        }
    )
    legendItems: list[dict[str, str]] = field(
        default_factory=lambda: [
            {"label": "Detected (high confidence)", "color": "#d32f2f"},
            {"label": "Detected (medium confidence)", "color": "#f57c00"},
            {"label": "Detected (low confidence)", "color": "#fbc02d"},
            {"label": "Not detected", "color": "#4caf50"},
        ]
    )
    metadata: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
            "domain": self.domain,
            "description": self.description,
            "gradient": self.gradient,
            "legendItems": self.legendItems,
            "techniques": self.techniques,
            "metadata": self.metadata,
        }


# ── Core Generator ─────────────────────────────────────────────────────────────


class ATTCKHeatmapGenerator:
    """Generates ATT&CK Navigator JSON layers from extracted TTPs."""

    def __init__(self, enterprise_version: str = "15") -> None:
        self.enterprise_version = enterprise_version
        self._all_technique_ids: set[str] = set()
        for _tid, (_name, _short, techs) in _TACTIC_DEFS.items():
            self._all_technique_ids.update(techs)

    # ── Public API ──────────────────────────────────────────────────────────

    def generate_layer(
        self,
        ttps: list[tuple[str, float]] | None = None,
        title: str = "RAGIN Attacker Heatmap",
        description: str = "",
        metadata: dict[str, str] | None = None,
    ) -> HeatmapLayer:
        """
        Create a Navigator layer from a list of (technique_id, confidence) tuples.

        Parameters
        ----------
        ttps : list of (technique_id, confidence)
            Confidence is 0.0–1.0.  Technique IDs should be like "T1566" or
            "T1566.001".  Sub-techniques are supported.
        title : str
            Layer name shown in Navigator.
        description : str
            Free-text description.
        metadata : dict
            Key-value pairs shown in Navigator's metadata panel.

        Returns
        -------
        HeatmapLayer
        """
        ttps = ttps or []
        ttp_map: dict[str, float] = {}
        for tid, conf in ttps:
            norm = tid.upper().strip()
            ttp_map[norm] = max(ttp_map.get(norm, 0.0), conf)

        techniques = self._build_technique_list(ttp_map)

        layer = HeatmapLayer(
            name=title,
            description=description or f"Generated by RAGIN at {datetime.now(timezone.utc).isoformat()}",
            techniques=techniques,
        )
        if metadata:
            layer.metadata = [{"key": k, "value": v} for k, v in metadata.items()]
        layer.metadata.append({"key": "generated_by", "value": "ragin/don/attack_heatmap"})
        layer.metadata.append({"key": "version", "value": self.enterprise_version})

        logger.info(
            "Generated layer '%s' with %d techniques (%d active)",
            title,
            len(techniques),
            sum(1 for t in techniques if t.get("score", 0) > 0),
        )
        return layer

    def generate_comparison_layer(
        self,
        profile_a: list[tuple[str, float]],
        profile_b: list[tuple[str, float]],
        title: str = "Profile Comparison",
    ) -> HeatmapLayer:
        """
        Overlay two attacker profiles.  Score = A score − B score.
        Positive = seen more in A, negative = seen more in B.
        """
        map_a = {tid.upper(): conf for tid, conf in profile_a}
        map_b = {tid.upper(): conf for tid, conf in profile_b}

        all_ids = set(map_a.keys()) | set(map_b.keys())
        techniques = []
        for tid in sorted(all_ids):
            diff = map_a.get(tid, 0) - map_b.get(tid, 0)
            techniques.append(
                {
                    "techniqueID": tid,
                    "score": round(diff * 100, 1),
                    "color": _score_to_color(abs(diff)),
                    "enabled": True,
                }
            )

        layer = HeatmapLayer(name=title, techniques=techniques)
        layer.gradient = {
            "colors": ["#424242", "#1976d2", "#d32f2f"],
            "minValue": -100,
            "maxValue": 100,
        }
        layer.metadata = [
            {"key": "profile_a_count", "value": str(len(map_a))},
            {"key": "profile_b_count", "value": str(len(map_b))},
        ]
        return layer

    def generate_tactic_summary(
        self,
        ttps: list[tuple[str, float]],
    ) -> dict[str, dict[str, Any]]:
        """
        Aggregate TTPs by tactic and compute coverage stats.

        Returns dict of tactic_id → {name, count, max_confidence, techniques}.
        """
        # Map each technique to its parent tactic
        tech_to_tactic: dict[str, str] = {}
        for tid, (_name, _short, techs) in _TACTIC_DEFS.items():
            for t in techs:
                tech_to_tactic[t] = tid

        tactic_stats: dict[str, dict[str, Any]] = {}
        for tid, conf in ttps:
            norm = tid.upper().strip()
            tactic_id = tech_to_tactic.get(norm, "")
            if not tactic_id:
                # Try parent technique (strip sub-technique suffix)
                parent = norm.split(".")[0]
                tactic_id = tech_to_tactic.get(parent, "")
            if not tactic_id:
                continue

            if tactic_id not in tactic_stats:
                tactic_stats[tactic_id] = {
                    "name": _TACTIC_DEFS[tactic_id][0],
                    "count": 0,
                    "max_confidence": 0.0,
                    "techniques": [],
                }
            stats = tactic_stats[tactic_id]
            stats["count"] += 1
            stats["max_confidence"] = max(stats["max_confidence"], conf)
            stats["techniques"].append(norm)

        return tactic_stats

    def save_layer(self, layer: HeatmapLayer, path: str | Path) -> Path:
        """Write a layer JSON file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(layer.to_dict(), indent=2), encoding="utf-8")
        logger.info("Saved layer to %s", p)
        return p

    def load_layer(self, path: str | Path) -> HeatmapLayer:
        """Load a layer JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        layer = HeatmapLayer(
            name=data.get("name", ""),
            description=data.get("description", ""),
            domain=data.get("domain", "enterprise-attack"),
            techniques=data.get("techniques", []),
            gradient=data.get("gradient", {}),
            legendItems=data.get("legendItems", []),
            metadata=data.get("metadata", []),
        )
        return layer

    # ── Private helpers ─────────────────────────────────────────────────────

    def _build_technique_list(
        self,
        ttp_map: dict[str, float],
    ) -> list[dict[str, Any]]:
        """Build Navigator technique list: highlight detected, grey-out rest."""
        techniques = []
        for _tid, (_name, _short, techs) in _TACTIC_DEFS.items():
            for tech_id in techs:
                score = ttp_map.get(tech_id, 0)
                color = _score_to_color(score)
                entry = _make_technique(tech_id, score=round(score * 100, 1), color=color)
                entry["tactic"] = _short
                techniques.append(entry)
        return techniques

    def ttps_to_navigator_export(
        self,
        ttps: list[tuple[str, float]],
        output_path: str | Path,
    ) -> Path:
        """Convenience: generate layer and save in one call."""
        layer = self.generate_layer(ttps=ttps)
        return self.save_layer(layer, output_path)


# ── CLI entrypoint ─────────────────────────────────────────────────────────────


def _cli() -> None:
    """Command-line helper for quick heatmap generation."""
    import argparse

    parser = argparse.ArgumentParser(description="Generate ATT&CK Navigator heatmap from RAGIN TTPs")
    parser.add_argument(
        "-t",
        "--ttps",
        nargs="*",
        default=[],
        help="TTP IDs (e.g., T1566 T1059.001)",
    )
    parser.add_argument(
        "-c",
        "--confidences",
        nargs="*",
        type=float,
        default=[],
        help="Confidence scores (0–1) parallel to --ttps",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="heatmap.json",
        help="Output JSON file",
    )
    parser.add_argument(
        "--title",
        default="RAGIN Heatmap",
        help="Layer title",
    )
    args = parser.parse_args()

    pairs = list(zip(args.ttps, args.confidences, strict=False)) if args.confidences else [(t, 1.0) for t in args.ttps]

    gen = ATTCKHeatmapGenerator()
    path = gen.ttps_to_navigator_export(pairs, args.output)
    print(f"✓ Saved to {path}  ({len(pairs)} TTPs)")


if __name__ == "__main__":
    _cli()
