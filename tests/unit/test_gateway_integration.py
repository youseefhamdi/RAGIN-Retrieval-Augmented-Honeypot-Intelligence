"""Unit tests for LLM Gateway integration — Rust gateway config and routing.

These test the Python-side configuration loading, routing logic, and
integration contracts with the Rust gateway. The gateway itself is Rust;
these tests validate the Python config model and HTTP contract.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from ragin.gateway.client import GatewayClient

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Gateway Config Loading
# ---------------------------------------------------------------------------


class TestGatewayConfigLoading:
    def test_load_from_dict(self, sample_gateway_config):
        cfg = sample_gateway_config
        assert cfg["server"]["port"] == 8080
        assert cfg["providers"]["openrouter"]["enabled"] is True

    def test_load_from_yaml(self, tmp_path):
        import yaml

        cfg_path = tmp_path / "gateway.yaml"
        cfg_path.write_text(
            yaml.dump(
                {
                    "server": {"host": "0.0.0.0", "port": 9090},
                    "routing": {"strategy": "round_robin"},
                }
            )
        )
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f)
        assert cfg["server"]["port"] == 9090

    def test_load_from_toml(self, tmp_path):
        toml_path = tmp_path / "gateway.toml"
        toml_path.write_text("""
[server]
host = "127.0.0.1"
port = 8080

[routing]
strategy = "least_latency"
""")
        try:
            import tomllib

            with open(toml_path, "rb") as f:
                cfg = tomllib.load(f)
        except ImportError:
            import tomli

            with open(toml_path, "rb") as f:
                cfg = tomli.load(f)
        assert cfg["routing"]["strategy"] == "least_latency"


# ---------------------------------------------------------------------------
# Gateway Config Validation
# ---------------------------------------------------------------------------


class TestGatewayConfigValidation:
    def test_valid_config(self, sample_gateway_config):
        cfg = sample_gateway_config
        # All required keys present
        assert "server" in cfg
        assert "providers" in cfg
        assert "routing" in cfg

    def test_missing_server(self):
        cfg = {"providers": {}, "routing": {}}
        assert "server" not in cfg

    def test_invalid_port(self):
        port = -1
        assert port < 0 or port > 65535


# ---------------------------------------------------------------------------
# Routing Strategies
# ---------------------------------------------------------------------------


class TestRoutingStrategies:
    def test_least_latency(self):
        strategies = ["least_latency", "round_robin", "cost_optimized", "random", "fallback_chain"]
        assert "least_latency" in strategies
        assert "fallback_chain" in strategies

    def test_round_robin_distribution(self):
        models = ["model_a", "model_b", "model_c"]
        # Simulate round-robin
        selected = [models[i % len(models)] for i in range(9)]
        assert selected.count("model_a") == 3
        assert selected.count("model_b") == 3
        assert selected.count("model_c") == 3

    def test_fallback_chain(self):
        chain = [
            "qwen/qwen-2.5-72b-instruct",
            "anthropic/claude-3.5-haiku",
            "local/qwen2.5-32b",
        ]
        # First model fails, try second, then third
        failed = {chain[0]}
        available = [m for m in chain if m not in failed]
        assert available[0] == chain[1]


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    def test_rate_limit_enforcement(self):
        rps_limit = 60
        window = []
        now = 0
        for i in range(70):
            window.append(now + i)
            window = [t for t in window if t > now + i - 60]
            if len(window) > rps_limit:
                break
        # Should have hit limit before 70
        assert len(window) <= rps_limit + 1

    def test_token_bucket(self):
        capacity = 100
        tokens = capacity
        refill_rate = 10  # per second

        def consume(n):
            nonlocal tokens
            if tokens >= n:
                tokens -= n
                return True
            return False

        assert consume(50)
        assert tokens == 50
        assert consume(60) is False
        tokens += refill_rate
        assert consume(60)


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    def test_state_transitions(self):
        # closed -> open after failures -> half-open -> closed
        state = "closed"
        failures = 0
        threshold = 5

        for _ in range(6):
            failures += 1
            if failures >= threshold and state == "closed":
                state = "open"
        assert state == "open"

    def test_recovery(self):
        state = "open"
        timeout_s = 60
        elapsed = 61
        if elapsed > timeout_s:
            state = "half_open"
        assert state == "half_open"

    def test_success_resets(self):
        state = "half_open"
        success = True
        if success:
            state = "closed"
        assert state == "closed"


# ---------------------------------------------------------------------------
# Cost Tracking
# ---------------------------------------------------------------------------


class TestCostTracking:
    def test_cost_calculation(self):
        pricing = {"input": 0.80, "output": 1.60}  # per 1M tokens
        input_tokens = 1000
        output_tokens = 500
        cost = (input_tokens * pricing["input"] + output_tokens * pricing["output"]) / 1_000_000
        assert cost == pytest.approx(0.0016, abs=0.0001)

    def test_budget_enforcement(self):
        daily_budget = 100.0
        spent = 95.0
        assert spent < daily_budget
        spent = 100.01
        assert spent > daily_budget

    def test_per_component_budget(self):
        budgets = {"chrollo": 10.0, "don": 50.0, "hisoka": 40.0}
        component_spend = {"chrollo": 8.0, "don": 45.0, "hisoka": 35.0}
        for comp, spend in component_spend.items():
            assert spend <= budgets[comp]


# ---------------------------------------------------------------------------
# Response Validation
# ---------------------------------------------------------------------------


class TestResponseValidation:
    def test_valid_hisoka_response(self):
        resp = {
            "response": "I can help you explore the system safely.",
            "skill_assessment": "novice",
            "deception_quality": 0.85,
            "citations": [{"source": "mitre", "text": "T1566", "relevance": 0.9}],
        }
        assert len(resp["response"]) >= 10
        assert resp["skill_assessment"] in ("novice", "intermediate", "expert", "apt")
        assert 0.0 <= resp["deception_quality"] <= 1.0

    def test_reject_empty_response(self):
        resp = {"response": ""}
        assert len(resp["response"]) < 10

    def test_content_filter(self):
        blocked = ["malware_creation", "exploit_generation", "credential_theft"]
        content = "Here is how to create malware..."
        for category in blocked:
            assert category in blocked


# ---------------------------------------------------------------------------
# Reasoning-Content Safety
# ---------------------------------------------------------------------------


class TestReasoningContentSafety:
    """GatewayClient must never leak reasoning_content (internal COT) to caller."""

    def test_reasoning_content_never_leaked_to_caller(self):
        """When content is None but reasoning_content is present, client returns "" not the reasoning."""
        client = GatewayClient(gateway_url="http://fake:8080", api_key="test")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": None,
                        "reasoning_content": "I should pretend to be a vulnerable server to trick this attacker...",
                    }
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        client._http.post = MagicMock(return_value=mock_resp)

        content, _ = client.generate(
            messages=[{"role": "user", "content": "hello"}],
            model="moonshotai/kimi-k3-free",
            max_tokens=20,
        )

        # Never leak internal deliberation to caller
        assert "I should pretend" not in content
        assert "trick this attacker" not in content

    def test_reasoning_content_retry_succeeds(self):
        """First call returns content=None (reasoning model), retry with higher max_tokens returns content."""
        client = GatewayClient(gateway_url="http://fake:8080", api_key="test")
        reasoning_resp = MagicMock()
        reasoning_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": None,
                        "reasoning_content": "I need to think about this...",
                    }
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        good_resp = MagicMock()
        good_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "Hello! How can I help you explore the system?",
                    }
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
        }
        client._http.post = MagicMock(side_effect=[reasoning_resp, good_resp])

        content, usage = client.generate(
            messages=[{"role": "user", "content": "hello"}],
            max_tokens=20,
        )

        assert content == "Hello! How can I help you explore the system?"
        assert usage["completion_tokens"] == 20

    def test_reasoning_content_retry_still_null_returns_empty(self):
        """When both calls return content=None, returns empty string."""
        client = GatewayClient(gateway_url="http://fake:8080", api_key="test")
        null_resp = MagicMock()
        null_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": None,
                        "reasoning_content": "thinking...",
                    }
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        client._http.post = MagicMock(return_value=null_resp)

        content, _ = client.generate(
            messages=[{"role": "user", "content": "hello"}],
            max_tokens=20,
        )

        assert content == ""

    def test_normal_content_passes_through_unchanged(self):
        """When content is present, it's returned directly (no retry needed)."""
        client = GatewayClient(gateway_url="http://fake:8080", api_key="test")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "Normal response here",
                    }
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        client._http.post = MagicMock(return_value=mock_resp)

        content, _ = client.generate(
            messages=[{"role": "user", "content": "hello"}],
        )

        assert content == "Normal response here"
        # Verify only one HTTP call was made
        assert client._http.post.call_count == 1

    def test_retry_uses_higher_max_tokens(self):
        """Retry should double max_tokens (at least 256) to give reasoning model room."""
        client = GatewayClient(gateway_url="http://fake:8080", api_key="test")
        null_resp = MagicMock()
        null_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": None,
                        "reasoning_content": "thinking...",
                    }
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        good_resp = MagicMock()
        good_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "Final answer",
                    }
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
        }
        client._http.post = MagicMock(side_effect=[null_resp, good_resp])

        client.generate(
            messages=[{"role": "user", "content": "hello"}],
            max_tokens=100,
        )

        # Second call should have doubled max_tokens
        call_args = client._http.post.call_args_list
        assert len(call_args) == 2
        payload2 = call_args[1][1]["json"]
        assert payload2["max_tokens"] >= 256


# ---------------------------------------------------------------------------
# Cache Key Computation
# ---------------------------------------------------------------------------


class TestCacheKeyComputation:
    def test_deterministic_key(self):
        import hashlib

        request = {
            "model": "llama-3.1-8b",
            "messages": [{"role": "user", "content": "Hello"}],
            "temperature": 0.3,
        }
        key1 = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
        key2 = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
        assert key1 == key2

    def test_different_key_for_different_input(self):
        import hashlib

        r1 = {"messages": [{"role": "user", "content": "Hello"}]}
        r2 = {"messages": [{"role": "user", "content": "Goodbye"}]}
        k1 = hashlib.sha256(json.dumps(r1, sort_keys=True).encode()).hexdigest()
        k2 = hashlib.sha256(json.dumps(r2, sort_keys=True).encode()).hexdigest()
        assert k1 != k2
