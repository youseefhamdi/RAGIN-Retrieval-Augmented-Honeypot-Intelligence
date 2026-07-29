"""Shared production infrastructure for RAGIN Python components.

Circuit breaker, cost tracker, rate limiter, prompt token limiter, hashing.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from enum import Enum
from typing import Any

logger = logging.getLogger("ragin.utils")

# ---------------------------------------------------------------------------
# IP Hashing (SHA-256 at pipeline ingestion)
# ---------------------------------------------------------------------------

_IP_HASH_SALT = "ragin-ip-v1"  # rotate to invalidate old hashes


def hash_ip(source_ip: str) -> str:
    """SHA-256 hash an IP address for privacy-preserving pipeline ingestion.

    Returns the hex digest.  Non-IP values (e.g. "unknown") pass through
    unchanged so debugging / sentinel values survive.
    """
    if not source_ip or source_ip in ("unknown", "_", "0.0.0.0", "::"):
        return source_ip
    return hashlib.sha256(f"{source_ip}{_IP_HASH_SALT}".encode()).hexdigest()


# ---------------------------------------------------------------------------
# PII Redaction (re-export from monitoring.audit)
# ---------------------------------------------------------------------------

from ragin.monitoring.audit import _redact_dict, _redact_pii  # noqa: E402, F401

# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------


class _CBState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Simple circuit breaker — closed → open → half-open → closed.

    After ``threshold`` consecutive failures the circuit opens and blocks
    calls for ``timeout_s`` seconds.  A single success in half-open closes it.
    """

    def __init__(self, threshold: int = 5, timeout_s: float = 60.0) -> None:
        self._threshold = threshold
        self._timeout_s = timeout_s
        self._state = _CBState.CLOSED
        self._fail_count = 0
        self._last_failure: float = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            if self._state == _CBState.OPEN and time.monotonic() - self._last_failure >= self._timeout_s:
                self._state = _CBState.HALF_OPEN
            return self._state.value

    def allow(self) -> bool:
        """Return True if a call is allowed."""
        with self._lock:
            if self._state == _CBState.CLOSED:
                return True
            if self._state == _CBState.HALF_OPEN:
                return True
            if self._state == _CBState.OPEN:
                if time.monotonic() - self._last_failure >= self._timeout_s:
                    self._state = _CBState.HALF_OPEN
                    return True
                return False
        return False

    def record_success(self) -> None:
        with self._lock:
            self._fail_count = 0
            self._state = _CBState.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._fail_count += 1
            self._last_failure = time.monotonic()
            if self._fail_count >= self._threshold:
                self._state = _CBState.OPEN
                logger.warning("Circuit breaker OPEN after %d failures", self._fail_count)

    def reset(self) -> None:
        with self._lock:
            self._fail_count = 0
            self._state = _CBState.CLOSED


# ---------------------------------------------------------------------------
# Cost Tracker
# ---------------------------------------------------------------------------

# Approximate token cost per 1M tokens (input, output)
_PRICING: dict[str, tuple[float, float]] = {
    "inclusionai/ling-3.0-flash:free": (0.0, 0.0),
    "inclusionai/ling-3.0-flash:via-openrouter": (0.0, 0.0),
    "meta-llama/llama-3.1-8b-instruct": (0.10, 0.10),
    "meta-llama/llama-3.1-70b-instruct": (0.60, 0.80),
    "qwen/qwen-32b": (0.50, 1.00),
    "qwen/qwen-2.5-72b-instruct": (0.80, 1.60),
    "deepseek/deepseek-coder-v2": (0.30, 0.60),
    "google/gemma-2-9b-it": (0.10, 0.10),
    "anthropic/claude-3.5-haiku": (0.25, 1.25),
    "local/qwen2.5-32b": (0.0, 0.0),
}


class CostTracker:
    """Thread-safe cost tracker with budget enforcement.

    Reads usage from LLM gateway responses (``usage.prompt_tokens``,
    ``usage.completion_tokens``) and computes USD cost.
    """

    def __init__(
        self,
        daily_budget_usd: float = 100.0,
        monthly_budget_usd: float = 2000.0,
        per_request_budget_usd: float = 0.10,
    ) -> None:
        self._daily_budget = daily_budget_usd
        self._monthly_budget = monthly_budget_usd
        self._per_request_budget = per_request_budget_usd
        self._lock = threading.Lock()
        self._total_cost: float = 0.0
        self._daily_cost: float = 0.0
        self._daily_reset: float = self._next_day_boundary()
        self._costs: list[dict[str, Any]] = []

    def check_budget(self, component: str) -> bool:
        """Return True if budget allows the request."""
        self._maybe_reset_daily()
        with self._lock:
            if self._daily_cost >= self._daily_budget:
                logger.warning("Daily budget exhausted ($%.2f)", self._daily_cost)
                return False
            if self._total_cost >= self._monthly_budget:
                logger.warning("Monthly budget exhausted ($%.2f)", self._total_cost)
                return False
        return True

    def record(self, component: str, model: str, usage: dict[str, int]) -> float:
        """Compute cost from usage dict, record it, return USD."""
        input_tokens = usage.get("prompt_tokens", 0)
        output_tokens = usage.get("completion_tokens", 0)
        cost = self._compute_cost(model, input_tokens, output_tokens)
        self._maybe_reset_daily()
        with self._lock:
            self._total_cost += cost
            self._daily_cost += cost
            self._costs.append(
                {
                    "timestamp": time.time(),
                    "component": component,
                    "model": model,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "cost_usd": cost,
                }
            )
        if cost > 0:
            logger.debug("Cost recorded: $%.6f (%s/%s)", cost, component, model)
        return cost

    def get_usage(self) -> dict[str, Any]:
        with self._lock:
            return {
                "total_cost_usd": round(self._total_cost, 6),
                "daily_cost_usd": round(self._daily_cost, 6),
                "daily_budget_usd": self._daily_budget,
                "monthly_budget_usd": self._monthly_budget,
                "total_requests": len(self._costs),
            }

    def _compute_cost(self, model: str, input_tokens: int, output_tokens: int) -> tuple[float, float] | float:  # type: ignore[override]
        """Return USD cost for the given token counts."""
        pricing = _PRICING.get(model, (0.0, 0.0))
        input_rate, output_rate = pricing[0], pricing[1]
        cost = (input_tokens * input_rate + output_tokens * output_rate) / 1_000_000
        return cost  # type: ignore[return-value]

    def _next_day_boundary(self) -> float:
        import datetime

        now = datetime.datetime.now()
        tomorrow = now + datetime.timedelta(days=1)
        boundary = tomorrow.replace(hour=0, minute=0, second=0, microsecond=0)
        return boundary.timestamp()

    def _maybe_reset_daily(self) -> None:
        now = time.time()
        if now >= self._daily_reset:
            with self._lock:
                self._daily_cost = 0.0
                self._daily_reset = self._next_day_boundary()
                logger.info("Daily cost counter reset")


# ---------------------------------------------------------------------------
# Rate Limiter (Token Bucket)
# ---------------------------------------------------------------------------


class RateLimiter:
    """Per-key token bucket rate limiter.

    Each key (e.g. IP address or session ID) gets ``max_tokens`` tokens
    that refill at ``refill_per_s`` tokens per second.
    """

    def __init__(self, max_tokens: int = 60, refill_per_s: float = 1.0) -> None:
        self._max = max_tokens
        self._refill = refill_per_s
        self._buckets: dict[str, tuple[float, float]] = {}  # key → (tokens, last_refill)
        self._lock = threading.Lock()

    def allow(self, key: str = "_global", cost: int = 1) -> bool:
        """Consume *cost* tokens. Return True if allowed."""
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(self._max), now))
            elapsed = now - last
            tokens = min(self._max, tokens + elapsed * self._refill)
            if tokens >= cost:
                tokens -= cost
                self._buckets[key] = (tokens, now)
                return True
            self._buckets[key] = (tokens, now)
            return False

    def remaining(self, key: str = "_global") -> float:
        with self._lock:
            tokens, last = self._buckets.get(key, (float(self._max), time.monotonic()))
            elapsed = time.monotonic() - last
            return min(self._max, tokens + elapsed * self._refill)


# ---------------------------------------------------------------------------
# Prompt Token Limiter
# ---------------------------------------------------------------------------

# Rough estimate: ~4 chars per token (English text average)
_CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    """Rough token count from text length."""
    return max(1, len(text) // _CHARS_PER_TOKEN)


class PromptTokenLimiter:
    """Rejects prompts exceeding a token budget."""

    def __init__(self, max_prompt_tokens: int = 32_000) -> None:
        self._max = max_prompt_tokens

    def check(self, text: str) -> bool:
        """Return True if text is within budget."""
        return estimate_tokens(text) <= self._max

    def truncate(self, text: str) -> str:
        """Truncate text to fit within token budget (best-effort)."""
        max_chars = self._max * _CHARS_PER_TOKEN
        if len(text) <= max_chars:
            return text
        return text[:max_chars]
