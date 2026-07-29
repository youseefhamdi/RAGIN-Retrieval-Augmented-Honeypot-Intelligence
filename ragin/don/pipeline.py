"""DonPipeline — orchestrates Don's full analysis flow and forwards to Hisoka."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx

from .models import (
    AnalysisRequest,
    AnalysisResponse,
    ThreatAnalysis,
)
from .rag_engine import ThreatRAGEngine

logger = logging.getLogger(__name__)

_DEFAULT_HISOKA_URL = os.environ.get("RAGIN_HISOKA_URL", "http://localhost:8082")
_DEFAULT_GATEWAY_URL = os.environ.get("RAGIN_GATEWAY_URL", "http://localhost:8080")


class DonPipeline:
    """Orchestrate Don analysis and forward to Hisoka."""

    def __init__(
        self,
        rag_engine: ThreatRAGEngine | None = None,
        gateway_url: str | None = None,
        hisoka_url: str | None = None,
        api_key: str | None = None,
        use_lightrag: bool = False,
        lightrag_workdir: str | None = None,
    ) -> None:
        self._gateway_url = gateway_url or _DEFAULT_GATEWAY_URL
        self._hisoka_url = (hisoka_url or _DEFAULT_HISOKA_URL).rstrip("/")
        self._api_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        self._use_lightrag = use_lightrag

        if use_lightrag and rag_engine is None:
            from .lightrag_adapter import LightRAGAdapter

            workdir = lightrag_workdir or os.path.join(os.environ.get("RAGIN_DATA_DIR", "data"), "lightrag")
            self._lightrag_adapter = LightRAGAdapter(working_dir=workdir)
            self._rag = ThreatRAGEngine(
                gateway_url=self._gateway_url,
                lightrag_adapter=self._lightrag_adapter,
            )
            logger.info("DonPipeline using LightRAG adapter (workdir=%s)", workdir)
        else:
            self._lightrag_adapter = None
            self._rag = rag_engine or ThreatRAGEngine(gateway_url=self._gateway_url)

        self._http = httpx.Client(timeout=60.0)
        logger.info(
            "DonPipeline initialised (gateway=%s, hisoka=%s, lightrag=%s)",
            self._gateway_url,
            self._hisoka_url,
            use_lightrag,
        )

    @property
    def lightrag_adapter(self):
        """Return the LightRAG adapter if configured, else None."""
        return self._lightrag_adapter

    def load_cti_corpus(
        self,
        mitre_stix_path: str | None = None,
        include_recent: bool = True,
        force_download: bool = False,
    ) -> dict[str, int]:
        """Load CTI data into the LightRAG adapter.

        Returns dict with 'mitre_attack_stix' and 'recent_campaigns' counts.
        Raises RuntimeError if no adapter is configured.
        """
        if self._lightrag_adapter is None:
            raise RuntimeError("load_cti_corpus requires use_lightrag=True in DonPipeline constructor")
        from .cti_corpus import load_full_cti_corpus

        return load_full_cti_corpus(
            self._lightrag_adapter,
            mitre_stix_path=mitre_stix_path,
            include_recent=include_recent,
            force_download=force_download,
        )

    def process_classification(
        self,
        classification_result: AnalysisRequest,
        session_log: list[dict[str, Any]],
    ) -> ThreatAnalysis:
        """Full processing: RAG analysis + report generation."""
        t0 = time.monotonic()
        logger.info(
            "Processing session %s (class=%s, conf=%.2f)",
            classification_result.session_id,
            classification_result.classification.value,
            classification_result.confidence,
        )

        analysis = self._rag.analyze(classification_result, session_log)

        # Generate narrative report
        analysis.narrative = self._rag.generate_report(analysis)

        elapsed = time.monotonic() - t0
        logger.info(
            "Analysis complete for %s: severity=%s, tactics=%d, actors=%d (%.2fs)",
            classification_result.session_id,
            analysis.severity.value,
            len(analysis.tactics),
            len(analysis.threat_actors),
            elapsed,
        )
        return analysis

    def process_and_forward(
        self,
        classification_result: AnalysisRequest,
        session_log: list[dict[str, Any]],
    ) -> AnalysisResponse:
        """Process classification and forward to Hisoka."""
        analysis = self.process_classification(classification_result, session_log)
        self.send_to_hisoka(analysis)
        return AnalysisResponse(
            analysis_id=analysis.analysis_id,
            session_id=analysis.session_id,
            threat_analysis=analysis,
            report=analysis.narrative,
        )

    def send_to_hisoka(self, analysis: ThreatAnalysis) -> bool:
        """Forward analysis to Hisoka for deception response generation."""
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        payload = {
            "analysis_id": analysis.analysis_id,
            "session_id": analysis.session_id,
            "classification": analysis.classification.value,
            "severity": analysis.severity.value,
            "confidence": analysis.confidence,
            "sophistication_score": analysis.sophistication_score,
            "tactics": [t.model_dump() for t in analysis.tactics],
            "threat_actors": [a.model_dump() for a in analysis.threat_actors],
            "iocs": [i.model_dump() for i in analysis.iocs],
            "narrative": analysis.narrative,
            "recommendations": analysis.recommendations,
        }

        try:
            resp = self._http.post(
                f"{self._hisoka_url}/api/v1/analysis",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            logger.info("Forwarded analysis %s to Hisoka", analysis.analysis_id)
            return True
        except httpx.HTTPError as exc:
            logger.error("Failed to forward to Hisoka: %s", exc)
            return False

    def health_check(self) -> dict[str, bool]:
        """Check connectivity to gateway and Hisoka."""
        result: dict[str, bool] = {}
        for name, url in [
            ("gateway", self._gateway_url),
            ("hisoka", self._hisoka_url),
        ]:
            try:
                resp = self._http.get(f"{url}/health", timeout=5.0)
                result[name] = resp.status_code == 200
            except Exception:
                result[name] = False
        return result
