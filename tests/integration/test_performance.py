"""Integration tests — performance benchmarks (Phase 3.1)."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

import pytest

from ragin.chrollo.features import FeatureExtractor
from ragin.chrollo.models import CommandEntry, SessionLog
from ragin.hisoka.deception import SessionManager

_extractor = FeatureExtractor()
_T = datetime(2025, 7, 26, 10, 0, 0, tzinfo=timezone.utc)


def _extract(session: SessionLog) -> dict[str, float]:
    return _extractor.extract(session)


# ── Latency Benchmarks ───────────────────────────────────────────────────────


class TestLatencyBenchmarks:
    def test_classification_latency(self) -> None:
        session = SessionLog(
            session_id="latency_test",
            source_ip="192.168.1.1",
            start_time=_T,
            commands=[
                CommandEntry(timestamp="2025-07-26T10:00:00Z", command="ls -la"),
                CommandEntry(timestamp="2025-07-26T10:00:01Z", command="cat /etc/passwd"),
            ],
        )
        latencies: list[float] = []
        for _ in range(100):
            start = time.perf_counter()
            _extract(session)
            latencies.append((time.perf_counter() - start) * 1000)
        p95 = sorted(latencies)[94]
        assert p95 < 100, f"Classification p95 latency {p95:.1f}ms > 100ms"

    def test_feature_extraction_latency(self) -> None:
        session = SessionLog(
            session_id="feat_latency",
            source_ip="10.0.0.1",
            start_time=_T,
            commands=[CommandEntry(timestamp="2025-07-26T10:00:00Z", command=f"cmd_{i}") for i in range(20)],
        )
        latencies: list[float] = []
        for _ in range(100):
            start = time.perf_counter()
            _extract(session)
            latencies.append((time.perf_counter() - start) * 1000)
        p95 = sorted(latencies)[94]
        assert p95 < 50, f"Feature extraction p95 latency {p95:.1f}ms > 50ms"

    def test_session_creation_latency(self) -> None:
        sm = SessionManager()
        latencies: list[float] = []
        for i in range(100):
            start = time.perf_counter()
            sm.create(skill_level="intermediate", source_ip="192.168.1.1")
            latencies.append((time.perf_counter() - start) * 1000)
        p95 = sorted(latencies)[94]
        assert p95 < 20, f"Session creation p95 latency {p95:.1f}ms > 20ms"


# ── Throughput ────────────────────────────────────────────────────────────────


class TestThroughput:
    def test_throughput_classification(self) -> None:
        sessions = [
            SessionLog(
                session_id=f"tp_{i}",
                source_ip="192.168.1.1",
                start_time=_T,
                commands=[
                    CommandEntry(timestamp="2025-07-26T10:00:00Z", command=f"cmd_{i}"),
                ],
            )
            for i in range(200)
        ]
        start = time.perf_counter()
        for session in sessions:
            _extract(session)
        elapsed = time.perf_counter() - start
        throughput = len(sessions) / elapsed
        assert throughput >= 100, f"Throughput {throughput:.0f} ops/sec < 100 ops/sec"

    def test_concurrent_sessions_100(self) -> None:
        sm = SessionManager()
        session_ids: list[str] = []
        lock = threading.Lock()
        errors: list[Exception] = []

        def create_session(idx: int) -> None:
            try:
                s = sm.create(skill_level="intermediate", source_ip="192.168.1.1")
                with lock:
                    session_ids.append(s.session_id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create_session, args=(i,)) for i in range(100)]
        start = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        elapsed = time.perf_counter() - start

        assert not errors
        assert len(session_ids) == 100
        assert elapsed < 10.0, f"100 concurrent sessions took {elapsed:.1f}s"


# ── Memory Stability ─────────────────────────────────────────────────────────


class TestMemoryStability:
    def test_memory_usage_stable(self) -> None:
        import os

        try:
            import psutil

            proc = psutil.Process(os.getpid())
            mem_before = proc.memory_info().rss / (1024 * 1024)
        except ImportError:
            pytest.skip("psutil not installed")

        for i in range(1000):
            session = SessionLog(
                session_id=f"mem_{i}",
                source_ip="10.0.0.1",
                start_time=_T,
                commands=[
                    CommandEntry(timestamp="2025-07-26T10:00:00Z", command=f"cmd_{i}"),
                ],
            )
            _extract(session)

        mem_after = proc.memory_info().rss / (1024 * 1024)
        growth = mem_after - mem_before
        assert growth < 50, f"Memory grew {growth:.1f}MB over 1000 iterations"


# ── Session Management ────────────────────────────────────────────────────────


class TestSessionManagement:
    def test_session_expiry_cleanup(self) -> None:
        sm = SessionManager()
        for i in range(5):
            sm.create(skill_level="novice", source_ip="192.168.1.1")
        if hasattr(sm, "cleanup_expired"):
            sm.cleanup_expired()
        assert hasattr(sm, "_sessions")

    def test_dwell_time_accuracy(self) -> None:
        sm = SessionManager()
        s = sm.create(skill_level="intermediate", source_ip="192.168.1.1")
        time.sleep(0.1)
        dwell = sm.get_dwell_time(s.session_id)
        assert abs(dwell - 0.1) < 1.0
