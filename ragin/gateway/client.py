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
        default_model: str = "inclusionai/ling-3.0-flash:free",
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
            if content is None:
                content = msg.get("reasoning") or ""
            return content, usage
        return "", usage
