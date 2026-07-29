"""Health checking for RAGIN components."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx


class HealthState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    """Health status of a single component."""

    name: str
    state: HealthState
    latency_ms: float = 0.0
    message: str = ""
    version: str = ""
    uptime_s: float = 0.0
    dependencies: dict[str, str] = field(default_factory=dict)


@dataclass
class HealthReport:
    """Aggregated health report across all components."""

    state: HealthState = HealthState.HEALTHY
    components: dict[str, ComponentHealth] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    version: str = "1.0.0"


class HealthChecker:
    """Checks health of RAGIN system components."""

    def __init__(self) -> None:
        self._start_time = time.time()
        self._components: dict[str, dict[str, Any]] = {
            "gateway": {"url": "http://localhost:8080/health"},
            "redis": {"url": "http://localhost:6379"},
        }

    def register_component(self, name: str, url: str) -> None:
        self._components[name] = {"url": url}

    def check_all(self) -> HealthReport:
        """Check all registered components and return aggregated report."""
        report = HealthReport()
        report.components["monitoring"] = ComponentHealth(
            name="monitoring",
            state=HealthState.HEALTHY,
            uptime_s=time.time() - self._start_time,
            version="1.0.0",
        )

        for name, config in self._components.items():
            report.components[name] = self.check_component(name, config["url"])

        unhealthy = sum(1 for c in report.components.values() if c.state == HealthState.UNHEALTHY)
        degraded = sum(1 for c in report.components.values() if c.state == HealthState.DEGRADED)

        if unhealthy > 0:
            report.state = HealthState.UNHEALTHY
        elif degraded > 0:
            report.state = HealthState.DEGRADED

        return report

    def check_gateway(self) -> ComponentHealth:
        """Check LLM gateway health."""
        return self.check_component("gateway", "http://localhost:8080/health")

    def check_redis(self) -> ComponentHealth:
        """Check Redis health."""
        return self.check_component("redis", "http://localhost:6379")

    def check_component(self, name: str, url: str) -> ComponentHealth:
        """Check a named component's health by attempting a connection."""
        start = time.time()
        try:
            resp = httpx.get(url, timeout=5.0)
            latency = (time.time() - start) * 1000
            if resp.status_code == 200:
                return ComponentHealth(
                    name=name,
                    state=HealthState.HEALTHY,
                    latency_ms=latency,
                    message="OK",
                )
            return ComponentHealth(
                name=name,
                state=HealthState.DEGRADED,
                latency_ms=latency,
                message=f"HTTP {resp.status_code}",
            )
        except Exception as exc:
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name=name,
                state=HealthState.UNHEALTHY,
                latency_ms=latency,
                message=str(exc)[:200],
            )
