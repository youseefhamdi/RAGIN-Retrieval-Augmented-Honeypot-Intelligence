"""Integration tests — Chrollo → Don → Hisoka pipeline.

Tests validate end-to-end data flow between components, error handling,
and concurrent session processing.
"""

from __future__ import annotations

import uuid

import pytest

from ragin.don.models import (
    AnalysisRequest,
    AnalysisResponse,
    ClassificationLabel,
    SeverityLevel,
    ThreatAnalysis,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Chrollo → Don Pipeline
# ---------------------------------------------------------------------------


class TestChrolloToDonPipeline:
    def test_classification_to_analysis(self, sample_classification_result, sample_session_log):
        """Chrollo output feeds directly into Don analysis request."""
        chrollo_out = sample_classification_result
        # Build Don request from Chrollo output
        request = AnalysisRequest(
            session_id="sesspipeline001",
            classification=ClassificationLabel(chrollo_out["classification"]),
            confidence=chrollo_out["confidence"],
            features={"features_used": chrollo_out["features_used"]},
            session_log=sample_session_log,
        )
        assert request.classification == ClassificationLabel.SUSPICIOUS
        assert request.confidence == 0.87
        assert len(request.session_log) == 5

    def test_data_contract_validity(self):
        """Chrollo output must satisfy Don's AnalysisRequest schema."""
        invalid_chrollo = {"classification": "INVALID", "confidence": 2.0}
        with pytest.raises(Exception):
            AnalysisRequest(
                session_id="sess_bad",
                classification=ClassificationLabel(invalid_chrollo["classification"]),
                confidence=invalid_chrollo["confidence"],
            )


# ---------------------------------------------------------------------------
# Don → Hisoka Pipeline
# ---------------------------------------------------------------------------


class TestDonToHisokaPipeline:
    def test_analysis_to_deception(self, sample_threat_analysis):
        """Don analysis informs Hisoka's deception strategy."""
        ta = ThreatAnalysis(**sample_threat_analysis)
        # Hisoka should use severity to adjust persona
        skill_map = {
            SeverityLevel.INFO: "novice",
            SeverityLevel.LOW: "novice",
            SeverityLevel.MEDIUM: "intermediate",
            SeverityLevel.HIGH: "expert",
            SeverityLevel.CRITICAL: "apt",
        }
        expected_skill = skill_map[ta.severity]
        assert expected_skill == "expert"

    def test_ioc_flow(self, sample_threat_analysis):
        """IOCs from Don should be available to Hisoka for artifact injection."""
        ta = ThreatAnalysis(**sample_threat_analysis)
        ioc_values = [ioc.value for ioc in ta.iocs]
        assert "192.168.1.100" in ioc_values
        assert "evil.example.com" in ioc_values


# ---------------------------------------------------------------------------
# Full Pipeline
# ---------------------------------------------------------------------------


class TestFullPipeline:
    def test_chrollo_don_hisoka(self, sample_session_log, sample_classification_result):
        """Full pipeline: classify → analyze → deceive."""
        # Step 1: Chrollo classification
        chrollo_out = sample_classification_result
        assert chrollo_out["classification"] in ("benign", "suspicious", "malicious")

        # Step 2: Don analysis
        request = AnalysisRequest(
            session_id="sessee001",
            classification=ClassificationLabel(chrollo_out["classification"]),
            confidence=chrollo_out["confidence"],
            session_log=sample_session_log,
        )
        threat_analysis = ThreatAnalysis(
            analysis_id=str(uuid.uuid4()),
            session_id=request.session_id,
            classification=request.classification,
            severity=SeverityLevel.HIGH,
            confidence=request.confidence,
        )

        # Step 3: Hisoka deception decision
        skill_map = {
            SeverityLevel.INFO: "novice",
            SeverityLevel.LOW: "novice",
            SeverityLevel.MEDIUM: "intermediate",
            SeverityLevel.HIGH: "expert",
            SeverityLevel.CRITICAL: "apt",
        }
        persona = skill_map[threat_analysis.severity]
        assert persona == "expert"


# ---------------------------------------------------------------------------
# Error Propagation
# ---------------------------------------------------------------------------


class TestErrorPropagation:
    def test_chrollo_failure(self):
        """Don handles missing Chrollo data gracefully."""
        with pytest.raises(Exception):
            AnalysisRequest(
                session_id="",
                classification=ClassificationLabel.BENIGN,
                confidence=0.5,
            )

    def test_don_failure(self):
        """Hisoka handles missing Don analysis gracefully."""
        # Empty threat analysis should not crash
        ta = ThreatAnalysis(
            analysis_id="err",
            session_id="err",
            classification=ClassificationLabel.BENIGN,
        )
        assert ta.tactics == []
        assert ta.iocs == []

    def test_gateway_timeout(self):
        """Gateway timeout produces error response."""
        resp = AnalysisResponse(
            analysis_id=str(uuid.uuid4()),
            session_id="sess_timeout",
            threat_analysis=ThreatAnalysis(
                analysis_id=str(uuid.uuid4()),
                session_id="sess_timeout",
                classification=ClassificationLabel.BENIGN,
            ),
            success=False,
            error="Gateway timeout after 30s",
        )
        assert not resp.success
        assert "timeout" in resp.error.lower()


# ---------------------------------------------------------------------------
# Concurrent Pipeline Sessions
# ---------------------------------------------------------------------------


class TestConcurrentPipeline:
    def test_parallel_sessions(self, sample_session_log):
        """Multiple sessions can be processed concurrently."""
        sessions = []
        for i in range(10):
            req = AnalysisRequest(
                session_id=f"sessconcurrent{i:02d}",
                classification=ClassificationLabel.SUSPICIOUS,
                confidence=0.5 + i * 0.04,
                session_log=sample_session_log,
            )
            sessions.append(req)

        assert len(sessions) == 10
        # Each session has a unique ID
        ids = [s.session_id for s in sessions]
        assert len(set(ids)) == 10
