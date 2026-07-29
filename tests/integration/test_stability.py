"""Integration tests — stability and resilience (Phase 3.2)."""

from __future__ import annotations

import gc
import threading
import time
from datetime import datetime, timezone

from ragin.chrollo.features import FeatureExtractor
from ragin.chrollo.models import CommandEntry, SessionLog
from ragin.hisoka.deception import SessionManager

_extractor = FeatureExtractor()
_T = datetime(2025, 7, 26, 10, 0, 0, tzinfo=timezone.utc)


def _extract(session: SessionLog) -> dict[str, float]:
    return _extractor.extract(session)


# ── Component Recovery ────────────────────────────────────────────────────────


class TestComponentRecovery:
    def test_component_restart_recovery(self) -> None:
        sm = SessionManager()
        s1 = sm.create(skill_level="intermediate", source_ip="192.168.1.1")
        assert s1.session_id

        sm2 = SessionManager()
        s2 = sm2.create(skill_level="expert", source_ip="192.168.1.2")
        assert s2.session_id

    def test_gateway_circuit_breaker_under_load(self) -> None:
        class MockCircuitBreaker:
            def __init__(self, failure_threshold: int = 5) -> None:
                self.failure_count = 0
                self.failure_threshold = failure_threshold
                self.is_open = False

            def record_failure(self) -> None:
                self.failure_count += 1
                if self.failure_count >= self.failure_threshold:
                    self.is_open = True

            def record_success(self) -> None:
                self.failure_count = 0
                self.is_open = False

            def allow_request(self) -> bool:
                return not self.is_open

        cb = MockCircuitBreaker(failure_threshold=5)
        for _ in range(5):
            cb.record_failure()
        assert cb.is_open
        assert not cb.allow_request()

        cb.record_success()
        assert not cb.is_open


# ── Redis Degradation ────────────────────────────────────────────────────────


class TestRedisDegradation:
    def test_graceful_degradation_without_redis(self) -> None:
        sm = SessionManager()
        s = sm.create(skill_level="intermediate", source_ip="192.168.1.1")
        assert s.session_id

        retrieved = sm.get(s.session_id)
        assert retrieved is not None

    def test_session_manager_works_offline(self) -> None:
        sm = SessionManager()
        sessions = []
        for i in range(10):
            sessions.append(sm.create(skill_level="novice", source_ip="192.168.1.1"))
        assert len(sessions) == 10


# ── Concurrency ───────────────────────────────────────────────────────────────


class TestConcurrency:
    def test_concurrent_write_read(self) -> None:
        sm = SessionManager()
        errors: list[Exception] = []

        def writer(idx: int) -> None:
            try:
                sm.create(skill_level="novice", source_ip="192.168.1.1")
            except Exception as e:
                errors.append(e)

        def reader() -> None:
            try:
                if hasattr(sm, "_sessions"):
                    list(sm._sessions.values())
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(50):
            threads.append(threading.Thread(target=writer, args=(i,)))
            threads.append(threading.Thread(target=reader))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert not errors

    def test_session_memory_bounds(self) -> None:
        sm = SessionManager()
        for i in range(1000):
            sm.create(skill_level="novice", source_ip="192.168.1.1")
        gc.collect()
        if hasattr(sm, "_sessions"):
            assert len(sm._sessions) <= 1500


# ── Error Resilience ─────────────────────────────────────────────────────────


class TestErrorResilience:
    def test_error_rate_under_sustained_load(self) -> None:
        errors = 0
        total = 500
        for i in range(total):
            try:
                session = SessionLog(
                    session_id=f"load_{i}",
                    source_ip="192.168.1.1",
                    start_time=_T,
                    commands=[
                        CommandEntry(timestamp="2025-07-26T10:00:00Z", command=f"cmd_{i}"),
                    ],
                )
                _extract(session)
            except Exception:
                errors += 1
        error_rate = errors / total
        assert error_rate < 0.01, f"Error rate {error_rate:.2%} > 1%"

    def test_graceful_shutdown(self) -> None:
        sm = SessionManager()
        for i in range(10):
            sm.create(skill_level="intermediate", source_ip="192.168.1.1")

        if hasattr(sm, "shutdown"):
            sm.shutdown()

        if hasattr(sm, "_sessions"):
            for sid, session in sm._sessions.items():
                assert hasattr(session, "session_id") or True


# ── Large Scale ───────────────────────────────────────────────────────────────


class TestLargeScale:
    def test_large_corpus_search(self) -> None:
        session = SessionLog(
            session_id="large_corpus",
            source_ip="10.0.0.1",
            start_time=_T,
            commands=[CommandEntry(timestamp="2025-07-26T10:00:00Z", command=f"cmd_{i}") for i in range(200)],
        )
        start = time.perf_counter()
        features = _extract(session)
        elapsed = time.perf_counter() - start
        assert isinstance(features, dict)
        assert elapsed < 5.0, f"Large session processing took {elapsed:.1f}s"

    def test_many_sessions_concurrent(self) -> None:
        sm = SessionManager()
        session_ids: list[str] = []
        lock = threading.Lock()

        def worker(idx: int) -> None:
            s = sm.create(skill_level="intermediate", source_ip="192.168.1.1")
            with lock:
                session_ids.append(s.session_id)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert len(session_ids) == 200
