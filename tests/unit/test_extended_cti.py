"""Unit tests for the extended CTI loader (CISA KEV + recent campaigns)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from ragin.don.extended_cti_loader import (
    RECENT_APT_CAMPAIGNS,
    ExtendedCTILoader,
    ExtendedCTIResult,
)


class TestRecentCampaignDocuments:
    def test_campaigns_not_empty(self) -> None:
        assert len(RECENT_APT_CAMPAIGNS) >= 10

    def test_all_campaigns_have_required_fields(self) -> None:
        required = {"id", "title", "content", "actors", "sectors", "year", "source"}
        for campaign in RECENT_APT_CAMPAIGNS:
            missing = required - set(campaign.keys())
            assert not missing, f"Campaign {campaign.get('id', '?')} missing: {missing}"

    def test_campaign_years_span(self) -> None:
        years = {c["year"] for c in RECENT_APT_CAMPAIGNS}
        assert 2024 in years
        assert 2025 in years
        assert 2026 in years

    def test_campaign_actors_covered(self) -> None:
        all_actors = set()
        for c in RECENT_APT_CAMPAIGNS:
            all_actors.update(a.lower() for a in c["actors"])
        assert "salt typhoon" in all_actors
        assert "volt typhoon" in all_actors
        assert "lazarus" in all_actors
        assert "apt28" in all_actors or "apt29" in all_actors

    def test_campaigns_contain_mitre_refs(self) -> None:
        for c in RECENT_APT_CAMPAIGNS:
            assert "MITRE ATT&CK" in c["content"], f"{c['id']} missing MITRE refs"

    def test_get_returns_copy(self) -> None:
        loader = ExtendedCTILoader()
        docs = loader.get_recent_campaign_documents()
        docs.clear()
        # Original should be unchanged
        assert len(loader.get_recent_campaign_documents()) > 0


class TestExtendedCTILoader:
    def test_init_creates_dir(self, tmp_path: Path) -> None:
        data_dir = tmp_path / "new_dir" / "sub"
        loader = ExtendedCTILoader(data_dir=data_dir)
        assert data_dir.exists()

    def test_load_all_returns_result(self, tmp_path: Path) -> None:
        loader = ExtendedCTILoader(data_dir=tmp_path / "cti")
        result = loader.load_all()
        assert isinstance(result, ExtendedCTIResult)
        assert result.campaigns_loaded > 0
        assert result.total_documents > 0

    def test_load_all_includes_campaigns(self, tmp_path: Path) -> None:
        loader = ExtendedCTILoader(data_dir=tmp_path / "cti")
        result = loader.load_all()
        assert result.campaigns_loaded == len(RECENT_APT_CAMPAIGNS)


class TestCISAKEV:
    def test_load_kev_from_cache(self, tmp_path: Path) -> None:
        """Test loading KEV from cache when network fails."""
        # Create a fake cache
        fake_kev = {
            "catalogVersion": "2024.01.01",
            "dateReleased": "2024-01-15",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "vendorProject": "TestVendor",
                    "product": "TestProduct",
                    "vulnerabilityName": "Test Vuln",
                    "shortDescription": "A test vulnerability",
                    "requiredAction": "Apply patch",
                    "dateAdded": "2024-01-10",
                    "knownRansomwareCampaignUse": "Known",
                },
            ],
        }
        cache_path = tmp_path / "cisa_kev.json"
        with open(cache_path, "w") as f:
            json.dump(fake_kev, f)

        loader = ExtendedCTILoader(data_dir=tmp_path)
        # Mock urllib to fail so it falls back to cache
        with patch("ragin.don.extended_cti_loader.urllib.request.urlopen", side_effect=Exception("network error")):
            result = loader.load_cisa_kev()

        assert result["catalog_version"] == "2024.01.01"
        assert result["count"] == 1
        assert result["vulns"][0]["cveID"] == "CVE-2024-0001"

    def test_get_kev_as_documents(self, tmp_path: Path) -> None:
        """Test converting KEV entries to RAG-compatible documents."""
        fake_kev = {
            "catalogVersion": "2024.01.01",
            "dateReleased": "2024-01-15",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "vendorProject": "Apache",
                    "product": "HTTP Server",
                    "vulnerabilityName": "HTTP Request Smuggling",
                    "shortDescription": "A smuggling vulnerability",
                    "requiredAction": "Update to latest version",
                    "dateAdded": "2024-01-10",
                    "knownRansomwareCampaignUse": "Unknown",
                },
            ],
        }
        cache_path = tmp_path / "cisa_kev.json"
        with open(cache_path, "w") as f:
            json.dump(fake_kev, f)

        loader = ExtendedCTILoader(data_dir=tmp_path)
        with patch("ragin.don.extended_cti_loader.urllib.request.urlopen", side_effect=Exception("fail")):
            docs = loader.get_kev_as_documents()

        assert len(docs) == 1
        assert docs[0]["id"] == "kev-CVE-2024-1234"
        assert "Apache" in docs[0]["title"]
        assert "Apache" in docs[0]["content"]
        assert docs[0]["category"] == "cisa-kev"

    def test_get_kev_max_entries(self, tmp_path: Path) -> None:
        """Test max_entries parameter limits output."""
        vulns = [
            {
                "cveID": f"CVE-2024-{i:04d}",
                "vendorProject": "V",
                "product": "P",
                "vulnerabilityName": "V",
                "shortDescription": "D",
                "requiredAction": "A",
                "dateAdded": "2024-01-01",
                "knownRansomwareCampaignUse": "Unknown",
            }
            for i in range(50)
        ]
        fake_kev = {
            "catalogVersion": "1",
            "dateReleased": "2024-01-15",
            "vulnerabilities": vulns,
        }
        cache_path = tmp_path / "cisa_kev.json"
        with open(cache_path, "w") as f:
            json.dump(fake_kev, f)

        loader = ExtendedCTILoader(data_dir=tmp_path)
        with patch("ragin.don.extended_cti_loader.urllib.request.urlopen", side_effect=Exception("fail")):
            docs = loader.get_kev_as_documents(max_entries=10)

        assert len(docs) == 10

    def test_load_all_includes_kev(self, tmp_path: Path) -> None:
        """Test load_all includes KEV documents in total."""
        fake_kev = {
            "catalogVersion": "1",
            "dateReleased": "2024-01-15",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-9999",
                    "vendorProject": "V",
                    "product": "P",
                    "vulnerabilityName": "V",
                    "shortDescription": "D",
                    "requiredAction": "A",
                    "dateAdded": "2024-01-01",
                    "knownRansomwareCampaignUse": "Unknown",
                },
            ],
        }
        cache_path = tmp_path / "cisa_kev.json"
        with open(cache_path, "w") as f:
            json.dump(fake_kev, f)

        loader = ExtendedCTILoader(data_dir=tmp_path)
        with patch("ragin.don.extended_cti_loader.urllib.request.urlopen", side_effect=Exception("fail")):
            result = loader.load_all()

        # Should have campaigns + at least 1 KEV doc
        assert result.total_documents > result.campaigns_loaded

    def test_load_all_handles_network_failure_gracefully(self, tmp_path: Path) -> None:
        """Test load_all doesn't crash when KEV fetch fails."""
        loader = ExtendedCTILoader(data_dir=tmp_path / "cti")
        with patch("ragin.don.extended_cti_loader.urllib.request.urlopen", side_effect=Exception("network error")):
            result = loader.load_all()

        # Should still load campaigns even if KEV fails
        assert result.campaigns_loaded > 0
        assert result.total_documents > 0
        assert any("CISA KEV" in e for e in result.errors)
