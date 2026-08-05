"""Shared GatewayClient for LLM Gateway /v1/chat completions.

Consolidates HTTP transport, auth, and response parsing so callers
(Don's ThreatRAGEngine, Hisoka's ResponseGenerator) don't duplicate
the raw HTTP call.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)


class GatewayClient:
    """Thin HTTP client for LLM Gateway chat completions.

    Handles: request serialisation, auth headers, transport errors,
    response extraction.  Callers layer on budget checks, circuit
    breakers, PII redaction, cost tracking, fallback logic, etc.
    """

    _MAX_RETRIES = 1
    _BASE_BACKOFF = 1.0

    def __init__(
        self,
        gateway_url: str = "http://localhost:8080",
        api_key: str | None = None,
        timeout: float = 20.0,
        default_model: str = "openai/gpt-4o-mini",
    ) -> None:
        self._gateway_url = gateway_url.rstrip("/")
        self._api_key = api_key
        self._default_model = default_model
        self._timeout = timeout

    @property
    def gateway_url(self) -> str:
        return self._gateway_url

    @property
    def default_model(self) -> str:
        return self._default_model

    def generate(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> tuple[str, dict[str, int]]:
        """Send a chat-completion request and return (content, usage).

        Raises requests.RequestException on transport / server errors so callers
        can implement their own retry / fallback / circuit-breaker logic.
        """
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        payload: dict[str, Any] = {
            "model": model or self._default_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }

        url = f"{self._gateway_url}/v1/chat/completions"

        resp = self._post(url, payload, headers)
        data = resp.json()
        choices = data.get("choices", [])
        usage: dict[str, int] = data.get("usage", {})
        if choices:
            msg = choices[0].get("message", {}) or {}
            content: str | None = msg.get("content")
            if content is not None:
                return content, usage

            # content is None — reasoning model burned tokens on COT.
            # NEVER return reasoning_content (it leaks internal deliberation).
            reasoning = msg.get("reasoning_content") or msg.get("reasoning") or ""
            if reasoning:
                logger.info("Reasoning content (logged for analysis, not served): %s", reasoning[:500])

            # Retry once with higher max_tokens so model reaches a final answer
            try:
                retry = dict(payload)
                retry["max_tokens"] = max(256, max_tokens * 2)
                resp2 = self._post(url, retry, headers)
                data2 = resp2.json()
                choices2 = data2.get("choices", [])
                if choices2:
                    msg2 = choices2[0].get("message", {}) or {}
                    content2 = msg2.get("content")
                    if content2 is not None:
                        return content2, data2.get("usage", {})
            except Exception:
                logger.warning("Retry with higher max_tokens also failed")

            # Still null after retry — caller handles safe fallback
            return "", usage
        return "", usage

    def _post(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str],
    ) -> requests.Response:
        """POST with retries for transient failures (timeouts, 5xx)."""
        last_exc: Exception | None = None
        for attempt in range(self._MAX_RETRIES + 1):
            if attempt > 0:
                backoff = self._BASE_BACKOFF * (2 ** (attempt - 1))
                logger.warning(
                    "Gateway POST attempt %d/%d, sleeping %.0fs", attempt + 1, self._MAX_RETRIES + 1, backoff
                )
                time.sleep(backoff)
            try:
                resp = requests.post(url, json=payload, headers=headers, timeout=self._timeout)
                if resp.status_code in (408, 429, 502, 503, 504):
                    last_exc = requests.HTTPError(
                        f"{resp.status_code} {resp.reason}",
                        response=resp,
                    )
                    continue
                resp.raise_for_status()
                return resp
            except (requests.ConnectionError, requests.ReadTimeout) as exc:
                last_exc = exc
                continue
            except requests.HTTPError as exc:
                if resp is not None and resp.status_code in (408, 429, 502, 503, 504):
                    last_exc = exc
                    continue
                raise
        raise requests.ReadTimeout(
            f"Gateway POST failed after {self._MAX_RETRIES + 1} attempts: {last_exc}"
        ) from last_exc
