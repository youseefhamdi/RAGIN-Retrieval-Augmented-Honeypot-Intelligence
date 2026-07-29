"""End-to-end Chrollo pipeline: parse → extract → classify → escalate."""

from __future__ import annotations

import logging
import os
import time

import httpx

from ragin.chrollo.classifier import ChrolloClassifier, ClassificationResult
from ragin.chrollo.models import (
    EscalationPayload,
    EscalationResponse,
    SessionLog,
)
from ragin.chrollo.session_parser import SessionLogParser

logger = logging.getLogger(__name__)

_DEFAULT_GATEWAY_URL = "http://localhost:8080"
_MAX_RETRIES = 3
_REQUEST_TIMEOUT = 30.0


class ChrolloPipeline:
    """Orchestrates classification and inter-component escalation.

    Flow:
        raw_log → parse → extract features → classify → escalate to Don / Hisoka
    """

    def __init__(
        self,
        classifier: ChrolloClassifier,
        gateway_url: str | None = None,
        *,
        api_key: str | None = None,
        rate_limit_rps: float = 10.0,
    ) -> None:
        self.classifier = classifier
        self.parser = SessionLogParser()
        self.gateway_url = (gateway_url or os.environ.get("RAGIN_GATEWAY_URL", _DEFAULT_GATEWAY_URL)).rstrip("/")

        # API key from param or env (never hardcoded)
        self.api_key = api_key or os.environ.get("RAGIN_GATEWAY_API_KEY", "")

        # Simple token-bucket rate limiter
        self._rate_limit_interval = 1.0 / max(rate_limit_rps, 0.1)
        self._last_request_ts = 0.0

    # ── Main entry point ─────────────────────────────────────────────────

    def process_session(self, session_log: SessionLog) -> ClassificationResult:
        """End-to-end: classify a parsed session and return the result."""
        return self.classifier.classify(session_log)

    def process_raw(self, raw_log: str) -> ClassificationResult:
        """Parse a raw log string, classify, and return the result."""
        session = self.parser.parse(raw_log)
        return self.classifier.classify(session)

    def process_json(self, json_log: str | dict) -> ClassificationResult:
        """Parse a JSON log, classify, and return the result."""
        session = self.parser.parse_json(json_log)
        return self.classifier.classify(session)

    # ── Escalation ───────────────────────────────────────────────────────

    def escalate_to_don(self, result: ClassificationResult, session_log: SessionLog) -> EscalationResponse:
        """Send classification to Don component for RAG threat intelligence analysis.

        Don enriches the classification with relevant CVEs, MITRE ATT&CK
        mappings, and threat intelligence context.
        """
        payload = EscalationPayload(
            session_id=result.session_id,
            skill_level=result.skill_level,
            confidence=result.confidence,
            features_used=result.features_used,
            session_log=session_log,
            request_id=f"chrollo-don-{int(time.time() * 1000)}",
        )
        return self._send_escalation(endpoint="/api/v1/don/analyze", payload=payload)

    def escalate_to_hisoka(self, result: ClassificationResult, session_log: SessionLog) -> EscalationResponse:
        """Send classification to Hisoka for adaptive deception response.

        Hisoka uses the skill level to select appropriate deception strategies:
        - Novice: basic tarpit responses
        - Intermediate: realistic but misleading responses
        - Expert: sophisticated counter-intelligence
        - APT: full adversarial engagement
        """
        payload = EscalationPayload(
            session_id=result.session_id,
            skill_level=result.skill_level,
            confidence=result.confidence,
            features_used=result.features_used,
            session_log=session_log,
            request_id=f"chrollo-hisoka-{int(time.time() * 1000)}",
        )
        return self._send_escalation(endpoint="/api/v1/hisoka/engage", payload=payload)

    # ── Async variants ───────────────────────────────────────────────────

    async def process_session_async(self, session_log: SessionLog) -> ClassificationResult:
        """Async variant of process_session."""
        return self.classifier.classify(session_log)

    async def escalate_to_don_async(self, result: ClassificationResult, session_log: SessionLog) -> EscalationResponse:
        """Async escalation to Don."""
        payload = EscalationPayload(
            session_id=result.session_id,
            skill_level=result.skill_level,
            confidence=result.confidence,
            features_used=result.features_used,
            session_log=session_log,
            request_id=f"chrollo-don-{int(time.time() * 1000)}",
        )
        return await self._send_escalation_async(endpoint="/api/v1/don/analyze", payload=payload)

    async def escalate_to_hisoka_async(
        self, result: ClassificationResult, session_log: SessionLog
    ) -> EscalationResponse:
        """Async escalation to Hisoka."""
        payload = EscalationPayload(
            session_id=result.session_id,
            skill_level=result.skill_level,
            confidence=result.confidence,
            features_used=result.features_used,
            session_log=session_log,
            request_id=f"chrollo-hisoka-{int(time.time() * 1000)}",
        )
        return await self._send_escalation_async(endpoint="/api/v1/hisoka/engage", payload=payload)

    # ── HTTP transport ───────────────────────────────────────────────────

    def _build_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _rate_limit_wait(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request_ts
        if elapsed < self._rate_limit_interval:
            time.sleep(self._rate_limit_interval - elapsed)
        self._last_request_ts = time.monotonic()

    def _send_escalation(self, endpoint: str, payload: EscalationPayload) -> EscalationResponse:
        """Synchronous HTTP POST to a downstream component."""
        self._rate_limit_wait()
        url = f"{self.gateway_url}{endpoint}"

        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            for attempt in range(_MAX_RETRIES):
                try:
                    resp = client.post(
                        url,
                        json=payload.model_dump(mode="json"),
                        headers=self._build_headers(),
                    )
                    resp.raise_for_status()
                    return EscalationResponse(**resp.json())
                except httpx.HTTPStatusError as e:
                    logger.warning(
                        "Escalation to %s failed (attempt %d): %s",
                        endpoint,
                        attempt + 1,
                        e,
                    )
                    if attempt == _MAX_RETRIES - 1:
                        return EscalationResponse(
                            request_id=payload.request_id,
                            status="error",
                            message=str(e),
                        )
                except httpx.RequestError as e:
                    logger.warning(
                        "Escalation network error to %s (attempt %d): %s",
                        endpoint,
                        attempt + 1,
                        e,
                    )
                    if attempt == _MAX_RETRIES - 1:
                        return EscalationResponse(
                            request_id=payload.request_id,
                            status="error",
                            message=f"Network error: {e}",
                        )

        # Unreachable but satisfies type checker
        return EscalationResponse(request_id=payload.request_id, status="error", message="Max retries exceeded")

    async def _send_escalation_async(self, endpoint: str, payload: EscalationPayload) -> EscalationResponse:
        """Async HTTP POST to a downstream component."""
        self._rate_limit_wait()
        url = f"{self.gateway_url}{endpoint}"

        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            for attempt in range(_MAX_RETRIES):
                try:
                    resp = await client.post(
                        url,
                        json=payload.model_dump(mode="json"),
                        headers=self._build_headers(),
                    )
                    resp.raise_for_status()
                    return EscalationResponse(**resp.json())
                except (httpx.HTTPStatusError, httpx.RequestError) as e:
                    logger.warning(
                        "Async escalation to %s failed (attempt %d): %s",
                        endpoint,
                        attempt + 1,
                        e,
                    )
                    if attempt == _MAX_RETRIES - 1:
                        return EscalationResponse(
                            request_id=payload.request_id,
                            status="error",
                            message=str(e),
                        )

        return EscalationResponse(request_id=payload.request_id, status="error", message="Max retries exceeded")
