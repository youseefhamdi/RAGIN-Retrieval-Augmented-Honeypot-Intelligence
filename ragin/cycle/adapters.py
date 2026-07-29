"""Adapters bridging native RAGIN components to harness protocol interfaces.

Each adapter wraps a monolithic component (Chrollo, Don, Hisoka) and exposes
the simplified (attacker_input, context) -> dict interface expected by the
Harness pipeline. This lets us hot-swap components without changing the harness.

Design: adapters are thin — they translate I/O shapes, not business logic.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class ChrolloAdapter:
    """Wraps ChrolloClassifier to conform to the Classifier protocol.

    Protocol: classify(attacker_input, session_context) -> dict
    Native:   classify(session_log: SessionLog) -> ClassificationResult
    """

    def __init__(self, classifier: Any = None) -> None:
        if classifier is None:
            from ragin.chrollo.classifier import ChrolloClassifier

            classifier = ChrolloClassifier()
        self._classifier = classifier

    def classify(self, attacker_input: str, session_context: dict[str, Any]) -> dict[str, Any]:
        from datetime import datetime, timezone

        from ragin.chrollo.models import CommandEntry, SessionLog

        session_id = session_context.get("session_id", "unknown")
        raw_commands = session_context.get("attacker_inputs", [])
        if not raw_commands and attacker_input:
            raw_commands = [attacker_input]

        # Convert string commands to CommandEntry objects
        now = datetime.now(timezone.utc)
        commands = []
        for cmd in raw_commands:
            if isinstance(cmd, dict):
                cmd = cmd.get("command", str(cmd))
            commands.append(CommandEntry(timestamp=now, command=str(cmd)))

        session_log = SessionLog(
            session_id=session_id,
            start_time=session_context.get("start_time", now),
            commands=commands,
            metadata=session_context.get("features", {}),
        )

        try:
            result = self._classifier.classify(session_log)
            return {
                "skill_level": result.skill_level.value,
                "confidence": result.confidence,
                "session_id": result.session_id,
                "features_used": result.features_used[:10],
                "feature_values": {k: round(v, 4) for k, v in list(result.feature_values.items())[:20]},
            }
        except Exception as e:
            logger.warning("Chrollo classify failed: %s", e)
            return {
                "skill_level": "novice",
                "confidence": 0.0,
                "error": str(e),
            }


class DonAdapter:
    """Wraps ThreatRAGEngine to conform to the CTIEngine protocol.

    Protocol: analyze(attacker_input, session_context) -> dict
    Native:   analyze(classification_result: AnalysisRequest, session_log: list) -> ThreatAnalysis
    """

    def __init__(self, engine: Any = None, gateway_url: str | None = None, api_key: str | None = None) -> None:
        if engine is None:
            from ragin.don.rag_engine import ThreatRAGEngine

            engine = ThreatRAGEngine(gateway_url=gateway_url, api_key=api_key)
        self._engine = engine

    def analyze(self, attacker_input: str, session_context: dict[str, Any]) -> dict[str, Any]:
        from ragin.don.models import AnalysisRequest, ClassificationLabel

        classification_str = session_context.get("classification", {}).get("skill_level", "unknown")
        classification_map = {
            "novice": ClassificationLabel.BENIGN,
            "intermediate": ClassificationLabel.SUSPICIOUS,
            "advanced": ClassificationLabel.MALICIOUS,
            "expert": ClassificationLabel.MALICIOUS,
        }
        classification_label = classification_map.get(classification_str, ClassificationLabel.SUSPICIOUS)
        confidence = session_context.get("classification", {}).get("confidence", 0.5)

        raw_session_id = session_context.get("session_id", "unknown")
        # AnalysisRequest.session_id must be alphanumeric (Pydantic validator)
        clean_session_id = "".join(c for c in raw_session_id if c.isalnum())[:128]

        features = dict(session_context.get("features", {}))
        if attacker_input:
            features.setdefault("attacker_input", attacker_input)

        req = AnalysisRequest(
            session_id=clean_session_id,
            classification=classification_label,
            confidence=confidence,
            features=features,
        )

        session_log = []
        for inp in session_context.get("attacker_inputs", []):
            session_log.append({"role": "attacker", "content": inp})
        for resp in session_context.get("system_responses", []):
            session_log.append({"role": "system", "content": resp})
        if attacker_input:
            session_log.append({"role": "attacker", "content": attacker_input})

        try:
            result = self._engine.analyze(req, session_log)
            return {
                "analysis_id": result.analysis_id,
                "severity": result.severity.value,
                "classification": result.classification.value,
                "confidence": result.confidence,
                "sophistication_score": result.sophistication_score,
                "threat_summary": result.summary if hasattr(result, "summary") else "",
                "recommendations": [
                    r if isinstance(r, str) else str(r) for r in getattr(result, "recommendations", [])
                ],
                "tactics": [
                    {"id": t.tactic_id, "name": t.tactic_name, "confidence": t.confidence} for t in result.tactics
                ],
                "threat_actors": [
                    {"name": a.name, "confidence": a.confidence, "known_ttps": a.known_ttps}
                    for a in result.threat_actors
                ],
                "iocs": [{"type": ioc.type.value, "value": ioc.value} for ioc in result.iocs[:20]],
                "ttps_seen": list(
                    {tid for a in result.threat_actors for tid in a.known_ttps}
                    | {tid for t in result.tactics for tid in t.techniques + t.sub_techniques}
                ),
                "extracted_techniques": list(
                    {tid for a in result.threat_actors for tid in a.known_ttps}
                    | {tid for t in result.tactics for tid in t.techniques + t.sub_techniques}
                ),
            }
        except Exception as e:
            logger.warning("Don analyze failed: %s", e)
            return {
                "threat_summary": "",
                "recommendations": [],
                "tactics": [],
                "threat_actors": [],
                "iocs": [],
                "ttps_seen": [],
                "extracted_techniques": [],
                "error": str(e),
            }


class HisokaAdapter:
    """Wraps AdaptiveDeceiver to conform to the Deceiver protocol.

    Protocol: generate_response(attacker_input, session_context) -> dict
    Native:   generate_response(attacker_input, session_context) -> DeceptionResponse

    The native API already takes (attacker_input, session_context) but returns
    a DeceptionResponse object. This adapter returns a plain dict.
    """

    def __init__(self, deceiver: Any = None, gateway_url: str | None = None, api_key: str | None = None) -> None:
        if deceiver is None:
            from ragin.hisoka.deceiver import AdaptiveDeceiver

            deceiver = AdaptiveDeceiver(gateway_url=gateway_url, api_key=api_key)
        self._deceiver = deceiver

    def generate_response(self, attacker_input: str, session_context: dict[str, Any]) -> dict[str, Any]:
        try:
            result = self._deceiver.generate_response(attacker_input, session_context)
            return {
                "session_id": result.session_id,
                "response_text": result.response_text,
                "persona_used": result.persona_used,
                "artifacts_injected": result.artifacts_injected,
                "engagement_score": result.engagement_score,
            }
        except Exception as e:
            logger.warning("Hisoka generate_response failed: %s", e)
            return {
                "response_text": "Error generating response.",
                "persona_used": "unknown",
                "artifacts_injected": False,
                "engagement_score": 0.0,
                "error": str(e),
            }
