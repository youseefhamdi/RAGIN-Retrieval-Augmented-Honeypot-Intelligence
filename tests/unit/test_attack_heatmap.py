"""Unit tests for ATT&CK Navigator heatmap generation."""

from __future__ import annotations

import json
from pathlib import Path

from ragin.don.attack_heatmap import (
    ATTCKHeatmapGenerator,
    HeatmapLayer,
    _make_technique,
    _score_to_color,
)


class TestScoreToColor:
    def test_high_confidence(self) -> None:
        assert _score_to_color(0.9) == "#d32f2f"  # red

    def test_medium_high(self) -> None:
        assert _score_to_color(0.7) == "#f57c00"  # orange

    def test_medium(self) -> None:
        assert _score_to_color(0.5) == "#fbc02d"  # yellow

    def test_low(self) -> None:
        assert _score_to_color(0.3) == "#4caf50"  # green

    def test_zero(self) -> None:
        assert _score_to_color(0.0) == ""


class TestMakeTechnique:
    def test_basic(self) -> None:
        tech = _make_technique("T1566", score=0.9, color="#d32f2f")
        assert tech["techniqueID"] == "T1566"
        assert tech["score"] == 0.9
        assert tech["color"] == "#d32f2f"
        assert tech["enabled"] is True

    def test_no_score(self) -> None:
        tech = _make_technique("T1566")
        assert "score" not in tech
        assert "color" not in tech


class TestHeatmapLayer:
    def test_to_dict(self) -> None:
        layer = HeatmapLayer(
            name="Test Layer",
            description="Test description",
            techniques=[{"techniqueID": "T1566", "score": 90}],
        )
        d = layer.to_dict()
        assert d["name"] == "Test Layer"
        assert d["description"] == "Test description"
        assert d["domain"] == "enterprise-attack"
        assert len(d["techniques"]) == 1
        assert "versions" in d
        assert d["versions"]["attack"] == "15"


def _tech_scores(layer: HeatmapLayer) -> dict[str, float]:
    """Helper: extract techniqueID → score for techniques that HAVE a score."""
    return {t["techniqueID"]: t["score"] for t in layer.techniques if "score" in t}


class TestATTCKHeatmapGenerator:
    def setup_method(self) -> None:
        self.gen = ATTCKHeatmapGenerator()

    def test_generate_layer_empty(self) -> None:
        layer = self.gen.generate_layer()
        assert isinstance(layer, HeatmapLayer)
        assert layer.name == "RAGIN Attacker Heatmap"
        # Layer contains ALL ATT&CK techniques (~600+)
        assert len(layer.techniques) > 500

    def test_generate_layer_with_ttps(self) -> None:
        ttps = [("T1566", 0.9), ("T1059.001", 0.7)]
        layer = self.gen.generate_layer(
            ttps=ttps,
            title="Session Test",
            description="Test session",
        )
        assert layer.name == "Session Test"
        assert layer.description == "Test session"

        # Only the provided TTPs should have scores
        scores = _tech_scores(layer)
        assert scores["T1566"] == 90.0
        assert scores["T1059.001"] == 70.0

        # Parent T1059 should NOT be scored (sub-technique only)
        assert "T1059" not in scores

    def test_generate_layer_duplicate_ttps(self) -> None:
        # Duplicate TTPs should keep max confidence (see line 417)
        ttps = [("T1566", 0.5), ("T1566", 0.9)]
        layer = self.gen.generate_layer(ttps=ttps)
        scores = _tech_scores(layer)
        assert scores["T1566"] == 90.0

    def test_generate_layer_metadata(self) -> None:
        metadata = {"session_id": "test-123", "source_ip": "192.168.1.1"}
        layer = self.gen.generate_layer(ttps=[], metadata=metadata)

        # Metadata is appended as key-value pairs
        meta_dict = {m["key"]: m["value"] for m in layer.metadata}
        assert meta_dict["session_id"] == "test-123"
        assert meta_dict["source_ip"] == "192.168.1.1"
        assert meta_dict["generated_by"] == "ragin/don/attack_heatmap"

    def test_generate_comparison_layer(self) -> None:
        profile_a = [("T1566", 0.9), ("T1059", 0.7)]
        profile_b = [("T1566", 0.3), ("T1059", 0.8)]

        layer = self.gen.generate_comparison_layer(
            profile_a=profile_a,
            profile_b=profile_b,
            title="Attacker Comparison",
        )

        assert layer.name == "Attacker Comparison"

        # Comparison layer only contains the union of profile A∪B
        scores = {t["techniqueID"]: t["score"] for t in layer.techniques}
        # T1566: (0.9 - 0.3) * 100 = 60
        assert scores["T1566"] == 60.0
        # T1059: (0.7 - 0.8) * 100 = -10
        assert scores["T1059"] == -10.0

    def test_generate_tactic_summary(self) -> None:
        ttps = [
            ("T1566", 0.9),  # Initial Access
            ("T1059", 0.7),  # Execution
            ("T1003", 0.8),  # Credential Access
        ]
        summary = self.gen.generate_tactic_summary(ttps)

        assert "TA0001" in summary  # Initial Access
        assert "TA0002" in summary  # Execution
        assert "TA0006" in summary  # Credential Access

        assert summary["TA0001"]["count"] == 1
        assert summary["TA0001"]["max_confidence"] == 0.9

    def test_save_and_load_layer(self, tmp_path: Path) -> None:
        ttps = [("T1566", 0.9), ("T1059", 0.7)]
        layer = self.gen.generate_layer(ttps=ttps, title="Save Test")

        save_path = tmp_path / "test_heatmap.json"
        result_path = self.gen.save_layer(layer, save_path)
        assert result_path.exists()

        loaded = self.gen.load_layer(save_path)
        assert loaded.name == "Save Test"
        assert len(loaded.techniques) == len(layer.techniques)

    def test_ttps_to_navigator_export(self, tmp_path: Path) -> None:
        ttps = [("T1566", 0.9), ("T1059", 0.7)]
        output_path = tmp_path / "navigator_export.json"

        result = self.gen.ttps_to_navigator_export(ttps, output_path)
        assert result.exists()

        data = json.loads(result.read_text())
        assert "techniques" in data
        assert "versions" in data
        assert data["versions"]["navigator"] == "4.9.1"

    def test_generate_layer_completeness(self) -> None:
        layer = self.gen.generate_layer()
        d = layer.to_dict()
        assert "gradient" in d
        assert "legendItems" in d
        assert len(d["legendItems"]) == 4
        # All 14 tactics represented
        tactic_shorts = {t["tactic"] for t in layer.techniques if t.get("tactic")}
        assert len(tactic_shorts) >= 14


class TestHeatmapIntegration:
    def test_end_to_end_workflow(self, tmp_path: Path) -> None:
        """Test complete workflow: generate → save → load → verify."""
        gen = ATTCKHeatmapGenerator()

        observed_ttps = [
            ("T1566.001", 0.95),  # Spearphishing Attachment
            ("T1059.001", 0.85),  # PowerShell
            ("T1003.001", 0.90),  # LSASS Memory
            ("T1021.001", 0.75),  # RDP
        ]

        layer = gen.generate_layer(
            ttps=observed_ttps,
            title="APT29 Attack Profile",
            description="Observed TTPs from simulated APT29 engagement",
            metadata={
                "session_id": "apt29-sim-001",
                "duration_hours": "48",
                "detection_rate": "0.85",
            },
        )

        output_file = tmp_path / "apt29_heatmap.json"
        gen.save_layer(layer, output_file)

        loaded = gen.load_layer(output_file)
        assert loaded.name == "APT29 Attack Profile"

        # Verify exactly 4 scored techniques
        scores = _tech_scores(loaded)
        assert len(scores) == 4
        assert "T1566.001" in scores
        assert "T1059.001" in scores
        assert "T1003.001" in scores
        assert "T1021.001" in scores

        # Verify Navigator compatibility
        nav_json = json.loads(output_file.read_text())
        assert nav_json["versions"]["attack"] == "15"
        assert nav_json["domain"] == "enterprise-attack"

    def test_tactic_summary_matches_layer(self) -> None:
        """Tactic summary count should match scored techniques in layer."""
        gen = ATTCKHeatmapGenerator()
        ttps = [
            ("T1566", 0.9),
            ("T1566.001", 0.85),
            ("T1059.001", 0.7),
            ("T1003", 0.8),
        ]
        layer = gen.generate_layer(ttps=ttps)
        summary = gen.generate_tactic_summary(ttps)

        # T1566 + T1566.001 both map to TA0001
        assert summary["TA0001"]["count"] == 2
        assert summary["TA0002"]["count"] == 1
        assert summary["TA0006"]["count"] == 1

        # Layer should have exactly 4 scored entries
        scores = _tech_scores(layer)
        assert len(scores) == 4
