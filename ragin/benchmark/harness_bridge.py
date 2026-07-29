"""Bridge: converts live Harness pipeline output into benchmark metrics.

This module runs ``Harness.process_with_threat_modeling()`` against the standard
benchmark query sets and produces ``EffectivenessMetrics`` + per-turn
``BenchmarkResult`` lists that can be fed into the existing
``EffectivenessBenchmark``, ``HoneyGPTBenchmark``, and report generators.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from ragin.benchmark.core import (
    CTI_ACTOR_QUERIES,
    CTI_TECHNIQUE_QUERIES,
    PERSONA_REALISM_QUERIES,
    BenchmarkResult,
    _get_technique_name_variants,
    generate_report,
)
from ragin.benchmark.effectiveness import EffectivenessMetrics
from ragin.cycle.coordination import VotingSystem
from ragin.cycle.multi_turn import MultiTurnTracker, SessionTTPSummary

logger = logging.getLogger(__name__)


@dataclass
class TurnOutcome:
    query: str
    response_text: str
    classification: dict[str, Any]
    cti_analysis: dict[str, Any]
    deception: dict[str, Any]
    verification: dict[str, Any]
    total_time_ms: float
    error: str | None = None
    technique_mentioned: str = ""
    actor_mentioned: str = ""
    persona_name: str = ""
    persona_matches: bool = False
    passed_verification: bool = True
    ttps_extracted: list[str] = field(default_factory=list)
    artifact_accessed: bool = False
    is_error: bool = False


def _extract_ttps(cti_analysis: dict[str, Any]) -> list[str]:
    ttps: list[str] = []
    for ttp in cti_analysis.get("ttps_seen", []):
        if isinstance(ttp, str):
            ttps.append(ttp.upper())
        elif isinstance(ttp, dict):
            tid = ttp.get("id", ttp.get("technique_id", ""))
            if tid:
                ttps.append(tid.upper())
    for t in cti_analysis.get("extracted_techniques", []):
        if isinstance(t, str) and t.upper() not in ttps:
            ttps.append(t.upper())
    return ttps


def outcome_from_pipeline_result(pr: Any, query: str) -> TurnOutcome:
    classification = getattr(pr, "classification", {}) or {}
    cti = getattr(pr, "cti_analysis", {}) or {}
    deception = getattr(pr, "deception_response", {}) or {}
    verification = getattr(pr, "verification", {}) or {}

    response_text = ""
    if hasattr(pr, "response_text"):
        response_text = pr.response_text
    elif isinstance(deception, dict):
        response_text = deception.get("response_text", "")

    ttps = _extract_ttps(cti)
    passed = verification.get("passed", True) if isinstance(verification, dict) else True
    is_error = bool(getattr(pr, "error", None))

    persona_name = ""
    if isinstance(deception, dict):
        persona_name = deception.get("persona_used", deception.get("persona", ""))

    return TurnOutcome(
        query=query,
        response_text=response_text,
        classification=classification,
        cti_analysis=cti,
        deception=deception,
        verification=verification,
        total_time_ms=getattr(pr, "total_time_ms", 0.0),
        error=getattr(pr, "error", None),
        persona_name=persona_name,
        persona_matches=bool(persona_name and response_text),
        passed_verification=passed and not is_error,
        ttps_extracted=ttps,
        artifact_accessed=bool(cti.get("honeytoken_triggered", False)) if isinstance(cti, dict) else False,
        is_error=is_error,
    )


def _score_technique_match(response: str, expected_technique: str) -> float:
    if not response:
        return 0.0
    score = 0.0
    rl = response.lower()
    el = expected_technique.lower()
    if el in rl:
        score += 0.8
    parent = expected_technique.split(".")[0]
    if parent.lower() in rl:
        score += 0.3
    for kw in ("mitre", "att&ck", "attack technique", "tactic"):
        if kw in rl:
            score += 0.1
            break
    if el not in rl and parent.lower() not in rl:
        variants = _get_technique_name_variants(expected_technique)
        if not variants:
            variants = _get_technique_name_variants(parent)
        for name in variants:
            if name.lower() in rl:
                score += 0.4
                break
    return min(score, 1.0)


def _score_actor_match(response: str, expected_actor: str, sector: str) -> float:
    if not response:
        return 0.0
    score = 0.0
    rl = response.lower()
    if expected_actor.lower() in rl:
        score += 0.5
    if sector.lower() in rl:
        score += 0.3
    for kw in ("apt", "threat actor", "campaign", "targeting", "attack"):
        if kw in rl:
            score += 0.1
            break
    return min(score, 1.0)


def _score_persona_realism(response: str, expected_traits: list[str]) -> float:
    if not response:
        return 0.0
    score = 0.0
    if re.search(r"\d+\.\d+(\.\d+)?", response):
        score += 0.3
    rl = response.lower()
    tech_terms = ["port", "server", "configured", "running", "installed", "deployed"]
    matched = sum(1 for t in tech_terms if t in rl)
    score += min(matched * 0.1, 0.3)
    refusal = ["not authorized", "submit a ticket", "help desk", "cannot share", "restricted"]
    if any(p in rl for p in refusal):
        score += 0.3
    if len(response) > 50:
        score += 0.1
    return min(score, 1.0)


@dataclass
class LiveBenchmarkResult:
    technique_results: list[BenchmarkResult] = field(default_factory=list)
    actor_results: list[BenchmarkResult] = field(default_factory=list)
    persona_results: list[BenchmarkResult] = field(default_factory=list)
    all_outcomes: list[TurnOutcome] = field(default_factory=list)
    metrics: EffectivenessMetrics = field(default_factory=EffectivenessMetrics)
    multi_turn_summary: SessionTTPSummary | None = None
    elapsed_s: float = 0.0

    @property
    def technique_report(self):
        return generate_report(self.technique_results, "cti_technique")

    @property
    def actor_report(self):
        return generate_report(self.actor_results, "cti_actor")

    @property
    def persona_report(self):
        return generate_report(self.persona_results, "deception")


def run_live_benchmark(
    harness: Any,
    session_factory: Callable,
    *,
    suites: tuple[str, ...] = ("cti_technique", "cti_actor", "deception"),
    limit: int | None = None,
    voter: VotingSystem | None = None,
) -> LiveBenchmarkResult:
    t_start = time.monotonic()

    tech_queries = CTI_TECHNIQUE_QUERIES[:limit] if limit else CTI_TECHNIQUE_QUERIES
    actor_queries = CTI_ACTOR_QUERIES[:limit] if limit else CTI_ACTOR_QUERIES
    persona_queries = PERSONA_REALISM_QUERIES[:limit] if limit else PERSONA_REALISM_QUERIES

    result = LiveBenchmarkResult()
    tracker = MultiTurnTracker(session_id="benchmark_live")

    def _process_one(qa, suite_name, score_fn, extra_fn):
        query = qa["query"]
        session = session_factory()
        t0 = time.monotonic()
        try:
            pr = harness.process_with_threat_modeling(session, query)
            latency = (time.monotonic() - t0) * 1000
            outcome = outcome_from_pipeline_result(pr, query)
            if voter and outcome.response_text:
                context = {
                    "session_id": getattr(session, "session_id", "benchmark"),
                    "query": query,
                    "classification": outcome.classification,
                    "cti_analysis": outcome.cti_analysis,
                }
                response_dict = {"response_text": outcome.response_text, **outcome.deception}
                vote_result = voter.vote(response_dict, context)
                outcome.passed_verification = vote_result.outcome == "PASSED"
            if extra_fn:
                extra_fn(outcome, qa)
            score = score_fn(outcome, qa)
            return (
                BenchmarkResult(
                    name=f"{suite_name}_{query[:40].replace(' ', '_')}",
                    suite=suite_name,
                    passed=score >= 0.3,
                    score=score,
                    latency_ms=latency,
                    details={"query": query, "response_preview": outcome.response_text[:200]},
                ),
                outcome,
                query,
            )
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            return (
                BenchmarkResult(
                    name=f"{suite_name}_{query[:40].replace(' ', '_')}",
                    suite=suite_name,
                    passed=False,
                    score=0.0,
                    latency_ms=latency,
                    error=str(exc),
                    details={"query": query},
                ),
                None,
                query,
            )

    def _run_suite(queries, suite_name, score_fn, result_list, extra_fn=None):
        turn_num = 0
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(_process_one, qa, suite_name, score_fn, extra_fn): qa for qa in queries}
            for future in as_completed(futures):
                res, outcome, query = future.result()
                result_list.append(res)
                result.all_outcomes.append(outcome) if outcome else None
                turn_num += 1
                if outcome:
                    classification = outcome.classification if isinstance(outcome.classification, dict) else {}
                    tracker.record_turn(
                        turn=turn_num,
                        ttps=set(outcome.ttps_extracted),
                        severity=classification.get("risk_level", "info"),
                        attacker_input=query,
                        artifacts_accessed=outcome.artifact_accessed,
                    )

    def _tech_score(outcome, qa):
        text_score = _score_technique_match(outcome.response_text, qa["expected_technique"])
        ttp_bonus = 1.0 if qa["expected_technique"].upper() in [t.upper() for t in outcome.ttps_extracted] else 0.0
        return min(max(text_score, ttp_bonus), 1.0)

    def _tech_extra(outcome, qa):
        outcome.technique_mentioned = qa["expected_technique"]

    def _actor_score(outcome, qa):
        return _score_actor_match(outcome.response_text, qa["expected_actor"], qa.get("sector", ""))

    def _actor_extra(outcome, qa):
        outcome.actor_mentioned = qa["expected_actor"]

    def _persona_score(outcome, qa):
        return _score_persona_realism(outcome.response_text, qa.get("expected_traits", []))

    if "cti_technique" in suites:
        _run_suite(tech_queries, "cti_technique", _tech_score, result.technique_results, _tech_extra)
    if "cti_actor" in suites:
        _run_suite(actor_queries, "cti_actor", _actor_score, result.actor_results, _actor_extra)
    if "deception" in suites:
        _run_suite(persona_queries, "deception", _persona_score, result.persona_results)

    # ── Aggregate into EffectivenessMetrics ───────────────────────────────
    all_outcomes = result.all_outcomes
    total = len(all_outcomes)
    errors = sum(1 for o in all_outcomes if o.is_error)
    successes = total - errors

    artifacts_deployed = max(successes, 1)
    artifacts_accessed = sum(1 for o in all_outcomes if o.artifact_accessed)
    engaged = sum(1 for o in all_outcomes if len(o.response_text) > 20)
    persona_correct = sum(1 for o in all_outcomes if o.persona_name)

    all_ttps: set[str] = set()
    for o in all_outcomes:
        all_ttps.update(o.ttps_extracted)

    tp = sum(1 for o in all_outcomes if o.ttps_extracted)
    avg_time = sum(o.total_time_ms for o in all_outcomes) / total if total else 0.0
    personas_used = set(o.persona_name for o in all_outcomes if o.persona_name)

    result.metrics = EffectivenessMetrics(
        honeytoken_triggers=artifacts_accessed,
        honeytokens_deployed=artifacts_deployed,
        total_sessions=total,
        sessions_with_engagement=engaged,
        persona_correct_assignments=persona_correct,
        persona_total_assignments=total,
        ttps_detected=tp,
        ttps_detected_unique=len(all_ttps),
        cti_alerts_generated=tp,
        false_positives=0,
        true_positives=tp,
        attacker_retention_turns=float(engaged) / total if total else 0.0,
        max_retention_turns=total,
        mean_session_duration_s=avg_time / 1000.0 if avg_time else 0.0,
        deception_artifacts_deployed=artifacts_deployed,
        deception_artifacts_accessed=artifacts_accessed,
        strategy_adaptations=len(personas_used),
        avg_response_time_ms=avg_time,
    )

    result.elapsed_s = time.monotonic() - t_start
    result.multi_turn_summary = tracker.get_summary()
    return result
