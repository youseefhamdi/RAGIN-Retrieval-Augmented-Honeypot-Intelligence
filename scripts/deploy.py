#!/usr/bin/env python3
"""RAGIN Local Deployment Script — launches all components as managed processes."""

import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "logs"
DATA_DIR = ROOT / "data"
PID_DIR = ROOT / "logs"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ragin.deploy")

# ─── Configuration ───────────────────────────────────────────────────────────

SERVICES = {
    "chrollo": {
        "port": 8081,
        "component": "chrollo",
        "env": {"COMPONENT": "chrollo", "CHROLLO_PORT": "8081"},
    },
    "don": {
        "port": 8082,
        "component": "don",
        "env": {"COMPONENT": "don", "DON_PORT": "8082"},
    },
    "hisoka": {
        "port": 8083,
        "component": "hisoka",
        "env": {"COMPONENT": "hisoka", "HISOKA_PORT": "8083"},
    },
}

HEALTH_TIMEOUT = 30  # seconds to wait for each service


# ─── Helpers ──────────────────────────────────────────────────────────────────


def load_env(path: Path = ROOT / ".env") -> dict[str, str]:
    """Load .env file into dict."""
    env = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def check_redis() -> bool:
    """Verify Redis is reachable."""
    try:
        import redis

        r = redis.Redis()
        r.ping()
        logger.info("Redis: OK (localhost:6379)")
        return True
    except Exception as e:
        logger.error("Redis: FAILED — %s", e)
        return False


def check_port(port: int) -> bool:
    """Check if a port is already in use."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def wait_for_health(port: int, timeout: float = HEALTH_TIMEOUT) -> bool:
    """Poll /health endpoint until ready."""
    url = f"http://127.0.0.1:{port}/health"
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            resp = httpx.get(url, timeout=2.0)
            if resp.status_code == 200:
                data = resp.json()
                logger.info("  ✓ %s healthy (component=%s)", port, data.get("component", "?"))
                return True
        except Exception:
            pass
        time.sleep(0.5)
    logger.warning("  ✗ %s not ready after %.0fs", port, timeout)
    return False


def kill_process_on_port(port: int) -> None:
    """Kill any existing process on the given port."""
    try:
        result = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if f":{port}" in line and "LISTEN" in line:
                # Extract PID from the process info
                parts = line.split()
                for part in parts:
                    if "pid=" in part:
                        pid = int(part.split("=")[1].split(",")[0])
                        logger.info("Killing existing process %d on port %d", pid, port)
                        os.kill(pid, signal.SIGTERM)
                        time.sleep(1)
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
    except Exception as e:
        logger.debug("Could not kill process on port %d: %s", port, e)


# ─── Service Management ──────────────────────────────────────────────────────


class ServiceManager:
    """Manages RAGIN component processes."""

    def __init__(self, base_env: dict[str, str]):
        self.base_env = {**os.environ, **base_env}
        self.processes: dict[str, subprocess.Popen] = {}
        self.log_files: dict[str, open] = {}

    def start(self, name: str) -> bool:
        """Start a single component."""
        cfg = SERVICES[name]
        port = cfg["port"]

        if check_port(port):
            logger.warning("Port %d already in use, killing existing process", port)
            kill_process_on_port(port)
            time.sleep(1)

        log_path = LOG_DIR / f"{name}.log"
        log_file = open(log_path, "w")
        self.log_files[name] = log_file

        env = {
            **self.base_env,
            **cfg["env"],
            "API_KEY": self.base_env.get("API_KEY", "ragin-test-key-2024"),
            "REDIS_URL": self.base_env.get("REDIS_URL", "redis://localhost:6379/0"),
            "RAGIN_LOG_LEVEL": "INFO",
            "OPENROUTER_API_KEY": self.base_env.get("OPENROUTER_API_KEY", ""),
        }

        cmd = [
            sys.executable,
            "-m",
            "ragin.server",
            "--component",
            cfg["component"],
            "--port",
            str(port),
        ]

        logger.info("Starting %s on port %d...", name, port)
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )
        self.processes[name] = proc
        logger.info("  PID: %d (log: %s)", proc.pid, log_path)
        return True

    def start_all(self) -> dict[str, bool]:
        """Start all components and return health status."""
        results = {}
        for name in SERVICES:
            self.start(name)
            time.sleep(2)  # Stagger startup

        logger.info("\nWaiting for health checks...")
        for name in SERVICES:
            port = SERVICES[name]["port"]
            results[name] = wait_for_health(port)

        return results

    def stop(self, name: str) -> None:
        """Stop a single component."""
        if name in self.processes:
            proc = self.processes[name]
            logger.info("Stopping %s (PID %d)...", name, proc.pid)
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            del self.processes[name]
        if name in self.log_files:
            self.log_files[name].close()
            del self.log_files[name]

    def stop_all(self) -> None:
        """Stop all components."""
        for name in list(self.processes.keys()):
            self.stop(name)
        logger.info("All services stopped")

    def status(self) -> dict[str, dict]:
        """Get status of all components."""
        status = {}
        for name, cfg in SERVICES.items():
            port = cfg["port"]
            alive = name in self.processes and self.processes[name].poll() is None
            healthy = False
            if alive:
                try:
                    resp = httpx.get(f"http://127.0.0.1:{port}/health", timeout=2.0)
                    healthy = resp.status_code == 200
                except Exception:
                    pass
            status[name] = {
                "port": port,
                "alive": alive,
                "healthy": healthy,
                "pid": self.processes.get(name, None) and self.processes[name].pid,
            }
        return status


# ─── CLI ──────────────────────────────────────────────────────────────────────


def main():
    import argparse

    parser = argparse.ArgumentParser(description="RAGIN Local Deployment")
    parser.add_argument("action", choices=["start", "stop", "status", "restart"])
    parser.add_argument("--service", "-s", help="Specific service (default: all)")
    parser.add_argument("--wait", "-w", type=int, default=30, help="Health check timeout")
    args = parser.parse_args()

    env = load_env()
    # Export env for subprocesses
    for k, v in env.items():
        os.environ[k] = v

    mgr = ServiceManager(env)

    if args.action == "start":
        logger.info("=" * 60)
        logger.info("RAGIN LOCAL DEPLOYMENT")
        logger.info("=" * 60)

        # Pre-flight checks
        logger.info("\n[1/3] Pre-flight checks...")
        redis_ok = check_redis()
        if not redis_ok:
            logger.error("Redis is not running. Start with: redis-server --daemonize yes")
            sys.exit(1)

        api_key = env.get("OPENROUTER_API_KEY", "")
        if api_key:
            logger.info("OpenRouter API Key: %s...%s", api_key[:10], api_key[-4:])
        else:
            logger.warning("No OpenRouter API Key — LLM calls will fail")

        # Start services
        logger.info("\n[2/3] Starting services...")
        if args.service:
            mgr.start(args.service)
            time.sleep(2)
            port = SERVICES[args.service]["port"]
            ok = wait_for_health(port, timeout=args.wait)
            sys.exit(0 if ok else 1)
        else:
            results = mgr.start_all()

        # Summary
        logger.info("\n[3/3] Deployment Summary")
        logger.info("-" * 40)
        all_ok = True
        for name, healthy in results.items():
            status = "✓ HEALTHY" if healthy else "✗ FAILED"
            logger.info("  %s : %s (port %d)", name.upper(), status, SERVICES[name]["port"])
            if not healthy:
                all_ok = False

        logger.info("-" * 40)
        if all_ok:
            logger.info("All services operational!")
            logger.info("\nEndpoints:")
            logger.info("  Chrollo: http://127.0.0.1:8081/health")
            logger.info("  Don:     http://127.0.0.1:8082/health")
            logger.info("  Hisoka:  http://127.0.0.1:8083/health")
            logger.info("\nLogs:")
            for name in SERVICES:
                logger.info("  %s: %s", name, LOG_DIR / f"{name}.log")
        else:
            logger.error("Some services failed to start. Check logs.")

    elif args.action == "stop":
        if args.service:
            mgr.stop(args.service)
        else:
            mgr.stop_all()

    elif args.action == "status":
        status = mgr.status()
        for name, info in status.items():
            s = "✓" if info["healthy"] else ("~" if info["alive"] else "✗")
            logger.info("  %s %s — port %d, pid=%s", s, name.upper(), info["port"], info.get("pid", "N/A"))

    elif args.action == "restart":
        mgr.stop_all()
        time.sleep(2)
        mgr.start_all()


if __name__ == "__main__":
    main()
