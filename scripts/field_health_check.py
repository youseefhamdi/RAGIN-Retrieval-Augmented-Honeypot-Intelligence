#!/usr/bin/env python3
"""RAGIN Field Health Check — continuous monitoring for deployed honeypot stack."""

import json
import logging
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "logs"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / "health_monitor.log"),
    ],
)
logger = logging.getLogger("ragin.health")

# ─── Service Definitions ─────────────────────────────────────────────────────

SERVICES = {
    "gateway": {"port": 8080, "path": "/health"},
    "chrollo": {"port": 8081, "path": "/health"},
    "don": {"port": 8082, "path": "/health"},
    "hisoka": {"port": 8083, "path": "/health"},
    "redis": {"port": 6379, "path": None},  # TCP check
    "prometheus": {"port": 9090, "path": "/-/healthy"},
    "grafana": {"port": 3000, "path": "/api/health"},
}

# ─── Health Check ────────────────────────────────────────────────────────────


class HealthChecker:
    """Checks all RAGIN services and reports status."""

    def __init__(self, log_dir: Path = LOG_DIR):
        self.log_dir = log_dir
        self.status_file = log_dir / "health_status.json"
        self.alert_log = log_dir / "health_alerts.jsonl"
        self.history: list[dict] = []
        self.consecutive_failures: dict[str, int] = {}

    def check_service(self, name: str, cfg: dict) -> dict:
        """Check a single service's health."""
        port = cfg["port"]
        path = cfg.get("path")
        result = {
            "service": name,
            "port": port,
            "healthy": False,
            "latency_ms": 0,
            "error": None,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

        start = time.monotonic()

        try:
            if path is None:
                # TCP check (Redis)
                import socket

                with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
                    result["healthy"] = True
            else:
                resp = httpx.get(
                    f"http://127.0.0.1:{port}{path}",
                    timeout=5.0,
                )
                result["healthy"] = resp.status_code == 200
                result["status_code"] = resp.status_code
        except httpx.TimeoutException:
            result["error"] = "timeout"
        except httpx.ConnectError:
            result["error"] = "connection_refused"
        except Exception as e:
            result["error"] = str(e)[:200]

        result["latency_ms"] = round((time.monotonic() - start) * 1000, 1)
        return result

    def check_docker(self) -> dict:
        """Check Docker container status."""
        import subprocess

        result = {"healthy": False, "containers": {}}

        try:
            proc = subprocess.run(
                ["docker", "compose", "ps", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=str(ROOT),
            )
            for line in proc.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    container = json.loads(line)
                    name = container.get("Name", "unknown")
                    state = container.get("State", "unknown")
                    result["containers"][name] = {
                        "state": state,
                        "health": container.get("Health", "N/A"),
                    }
                except json.JSONDecodeError:
                    pass

            result["healthy"] = all(c["state"] == "running" for c in result["containers"].values())
        except Exception as e:
            result["error"] = str(e)[:200]

        return result

    def check_disk(self) -> dict:
        """Check disk usage."""
        import shutil

        result = {"healthy": True}
        try:
            total, used, free = shutil.disk_usage("/")
            used_pct = (used / total) * 100
            result["total_gb"] = round(total / (1024**3), 1)
            result["used_gb"] = round(used / (1024**3), 1)
            result["free_gb"] = round(free / (1024**3), 1)
            result["used_pct"] = round(used_pct, 1)
            if used_pct > 90:
                result["healthy"] = False
                result["warning"] = f"Disk usage {used_pct:.1f}% — critical"
            elif used_pct > 80:
                result["warning"] = f"Disk usage {used_pct:.1f}% — warning"
        except Exception as e:
            result["error"] = str(e)[:200]

        return result

    def check_redis_memory(self) -> dict:
        """Check Redis memory usage."""
        result = {"healthy": True}
        try:
            import socket

            with socket.create_connection(("127.0.0.1", 6379), timeout=3) as s:
                s.sendall(b"INFO memory\r\n")
                data = s.recv(4096).decode()

            for line in data.split("\n"):
                if line.startswith("used_memory_human:"):
                    result["used_memory"] = line.split(":", 1)[1].strip()
                elif line.startswith("maxmemory_human:"):
                    result["maxmemory"] = line.split(":", 1)[1].strip()
        except Exception as e:
            result["error"] = str(e)[:200]

        return result

    def run_checks(self) -> dict:
        """Run all health checks and return aggregated result."""
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "services": {},
            "docker": {},
            "disk": {},
            "redis_memory": {},
            "overall_healthy": True,
        }

        # Service health checks
        for name, cfg in SERVICES.items():
            result = self.check_service(name, cfg)
            report["services"][name] = result
            if not result["healthy"]:
                report["overall_healthy"] = False
                self.consecutive_failures[name] = self.consecutive_failures.get(name, 0) + 1
            else:
                self.consecutive_failures[name] = 0

        # Docker status
        report["docker"] = self.check_docker()

        # Disk usage
        report["disk"] = self.check_disk()
        if not report["disk"].get("healthy", True):
            report["overall_healthy"] = False

        # Redis memory
        report["redis_memory"] = self.check_redis_memory()

        # Check for critical failures
        for name, count in self.consecutive_failures.items():
            if count >= 3:
                report["overall_healthy"] = False
                self._alert(name, count)

        # Save status
        self._save_status(report)
        self.history.append(report)

        # Keep only last 100 in memory
        if len(self.history) > 100:
            self.history = self.history[-100:]

        return report

    def _alert(self, service: str, failures: int):
        """Write alert to log file."""
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": service,
            "consecutive_failures": failures,
            "severity": "critical" if failures >= 5 else "warning",
        }
        with open(self.alert_log, "a") as f:
            f.write(json.dumps(alert) + "\n")
        logger.warning(
            "ALERT: %s has failed %d consecutive health checks",
            service,
            failures,
        )

    def _save_status(self, report: dict):
        """Save current status to JSON file."""
        with open(self.status_file, "w") as f:
            json.dump(report, f, indent=2)

    def print_report(self, report: dict):
        """Print a human-readable health report."""
        status = "✓ HEALTHY" if report["overall_healthy"] else "✗ DEGRADED"
        print(f"\n{'='*60}")
        print(f" RAGIN Health Report — {report['timestamp']}")
        print(f" Overall: {status}")
        print(f"{'='*60}\n")

        print("Services:")
        for name, result in report["services"].items():
            icon = "✓" if result["healthy"] else "✗"
            latency = f"{result['latency_ms']}ms" if result["latency_ms"] else "N/A"
            error = f" ({result['error']})" if result.get("error") else ""
            print(f"  {icon} {name:12s}  port={result['port']}  latency={latency}{error}")

        print("\nDocker:")
        for name, info in report.get("docker", {}).get("containers", {}).items():
            icon = "✓" if info["state"] == "running" else "✗"
            print(f"  {icon} {name:30s}  state={info['state']}  health={info.get('health', 'N/A')}")

        disk = report.get("disk", {})
        if disk:
            print(f"\nDisk: {disk.get('used_gb', '?')}/{disk.get('total_gb', '?')} GB ({disk.get('used_pct', '?')}%)")

        redis = report.get("redis_memory", {})
        if redis.get("used_memory"):
            print(f"Redis: {redis['used_memory']} / {redis.get('maxmemory', '?')}")

        print()


# ─── Continuous Monitor ──────────────────────────────────────────────────────


def continuous_monitor(interval: int = 60, log_dir: Path = LOG_DIR):
    """Run health checks continuously."""
    checker = HealthChecker(log_dir)
    running = True

    def handle_signal(sig, frame):
        nonlocal running
        logger.info("Received signal %s — shutting down", sig)
        running = False

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    logger.info("Starting continuous health monitor (interval=%ds)", interval)

    while running:
        try:
            report = checker.run_checks()
            checker.print_report(report)

            if not report["overall_healthy"]:
                logger.warning("System is DEGRADED — check alerts at %s", checker.alert_log)
        except Exception as e:
            logger.error("Health check failed: %s", e)

        # Sleep in small increments to allow signal handling
        for _ in range(interval):
            if not running:
                break
            time.sleep(1)

    logger.info("Health monitor stopped")


# ─── One-shot Check ──────────────────────────────────────────────────────────


def one_shot():
    """Run a single health check."""
    checker = HealthChecker()
    report = checker.run_checks()
    checker.print_report(report)
    return 0 if report["overall_healthy"] else 1


# ─── CLI ──────────────────────────────────────────────────────────────────────


def main():
    import argparse

    parser = argparse.ArgumentParser(description="RAGIN Field Health Check")
    parser.add_argument("--continuous", "-c", action="store_true", help="Run continuously (default: one-shot)")
    parser.add_argument("--interval", "-i", type=int, default=60, help="Check interval in seconds (continuous mode)")
    parser.add_argument("--log-dir", type=Path, default=LOG_DIR, help="Log directory")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of formatted report")
    args = parser.parse_args()

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    if args.continuous:
        continuous_monitor(args.interval, args.log_dir)
    else:
        checker = HealthChecker(args.log_dir)
        report = checker.run_checks()

        if args.json:
            print(json.dumps(report, indent=2))
        else:
            checker.print_report(report)

        sys.exit(0 if report["overall_healthy"] else 1)


if __name__ == "__main__":
    main()
