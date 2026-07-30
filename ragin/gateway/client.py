"""Shared GatewayClient for LLM Gateway /v1/chat/completions.

Consolidates HTTP transport, auth, and response parsing so callers
(Don's ThreatRAGEngine, Hisoka's ResponseGenerator) don't duplicate
the raw httpx call.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class GatewayClient:
    """Thin HTTP client for LLM Gateway chat completions.

    Handles: request serialisation, auth headers, transport errors,
    response extraction.  Callers layer on budget checks, circuit
    breakers, PII redaction, cost tracking, fallback logic, etc.
    """

    def __init__(
        self,
        gateway_url: str = "http://localhost:8080",
        api_key: str | None = None,
        timeout: float = 30.0,
        default_model: str = "moonshotai/kimi-k3-free",
    ) -> None:
        self._gateway_url = gateway_url.rstrip("/")
        self._api_key = api_key
        self._default_model = default_model
        self._http = httpx.Client(timeout=timeout)

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

        Raises httpx.HTTPError on transport / server errors so callers
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

        resp = self._http.post(
            f"{self._gateway_url}/v1/chat/completions",
            json=payload,
            headers=headers,
        )
        resp.raise_for_status()
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
                resp2 = self._http.post(
                    f"{self._gateway_url}/v1/chat/completions",
                    json=retry,
                    headers=headers,
                )
                resp2.raise_for_status()
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
