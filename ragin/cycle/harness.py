"""Harness — stateless orchestration loop for RAGIN.

Design principles from Anthropic Managed Agents + revfactory/harness:
- Harness = the loop (stateless, replaceable, crash-safe)
- All state lives in Session (append-only event log)
- Crashes don't lose data — wake(sessionId) resumes from log
- Pipeline pattern: Chrollo → Don → Hisoka (sequential dependent tasks)
- Producer-Reviewer: Hisoka generates → EvasionDetector verifies
- emitEvent() writes to session log for durable recording

The harness itself holds NO session state. It receives a Session object,
runs the pipeline, and emits events. If it crashes mid-pipeline, the next
harness instance picks up by replaying the session log.
"""

from __future__ import annotations

import contextlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from ragin.cycle.session import EventType, Session

logger = logging.getLogger(__name__)


try:
    from ragin.cycle.coordination import (
        DeceptionReviewer,
        EnhancedProducerReviewer,
        ExpertPool,
        QualityReviewer,
        SecurityReviewer,
        Supervisor,
        VotingSystem,
    )

    HAS_COORDINATION = True
except ImportError:
    HAS_COORDINATION = False


class Classifier(Protocol):
    """Interface for the Chrollo classifier."""

    def classify(self, attacker_input: str, session_context: dict[str, Any]) -> dict[str, Any]:
        """Classify attacker skill level. Returns dict with 'skill_level', 'confidence'."""
        ...


class CTIEngine(Protocol):
    """Interface for the Don CTI engine."""

    def analyze(
        self,
        attacker_input: str,
        session_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze threat intelligence. Returns dict with 'threat_summary', 'recommendations'."""
        ...


class Deceiver(Protocol):
    """Interface for the Hisoka deceiver."""

    def generate_response(
        self,
        attacker_input: str,
        session_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate deception response. Returns dict with 'response_text', 'persona_used', etc."""
        ...


class ResponseVerifier(Protocol):
    """Interface for response verification (Producer-Reviewer pattern)."""

    def verify(
        self,
        response: dict[str, Any],
        session_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Verify response quality. Returns dict with 'passed', 'issues', 'confidence'."""
        ...


@dataclass
class PipelineResult:
    """Result of a single harness pipeline execution."""

    session_id: str
    attacker_input: str
    classification: dict[str, Any] = field(default_factory=dict)
    cti_analysis: dict[str, Any] = field(default_factory=dict)
    deception_response: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)
    total_time_ms: float = 0.0
    events_emitted: int = 0
    error: str | None = None

    @property
    def response_text(self) -> str:
        return self.deception_response.get("response_text", "")

    @property
    def passed_verification(self) -> bool:
        return self.verification.get("passed", True)


@dataclass
class _ProcessContext:
    """Mutable state bundled through pipeline stages.

    Reduces parameter threading across stage methods and
    keeps events_emitted in one place.
    """

    result: PipelineResult
    session: Session
    events_emitted: int = 0
    context: dict[str, Any] = field(default_factory=dict)

    def emit(self, event_type: EventType, data: dict, source: str) -> None:
        self.session.emit(event_type, data, source=source)
        self.events_emitted += 1


class Harness:
    """Stateless orchestration loop for RAGIN.

    The harness holds NO session state. It receives a Session object,
    runs the pipeline, and emits events. If it crashes mid-pipeline,
    the next harness instance picks up by replaying the session log.

    Pipeline: Chrollo (classify) → Don (CTI) → Hisoka (deceive) → Verify

    Usage::

        harness = Harness(
            classifier=ChrolloClassifier(),
            cti_engine=ThreatRAGEngine(),
            deceiver=AdaptiveDeceiver(),
        )
        session = Session.create(source_ip="10.0.0.1")
        result = harness.process(session, "whoami")
        print(result.response_text)
    """

    def __init__(
        self,
        classifier: Classifier | None = None,
        cti_engine: CTIEngine | None = None,
        deceiver: Deceiver | None = None,
        verifier: ResponseVerifier | None = None,
        max_retries: int = 2,
    ) -> None:
        self._classifier = classifier
        self._cti_engine = cti_engine
        self._deceiver = deceiver
        self._verifier = verifier
        self._max_retries = max_retries

    # ------------------------------------------------------------------
    # Context helpers
    # ------------------------------------------------------------------

    def _enrich_context(self, ctx: _ProcessContext) -> dict[str, Any]:
        return {
            **ctx.context,
            "classification": ctx.result.classification,
            "cti_analysis": ctx.result.cti_analysis,
        }

    def _emit_attacker_input(self, ctx: _ProcessContext, attacker_input: str) -> None:
        ctx.emit(EventType.ATTACKER_INPUT, {"command": attacker_input}, source="harness")

    def _build_and_store_context(self, ctx: _ProcessContext) -> dict[str, Any]:
        ctx.context = ctx.session.build_context()
        return ctx.context

    def _record_pipeline_error(self, ctx: _ProcessContext, error: str) -> None:
        ctx.result.error = error
        ctx.emit(EventType.ERROR, {"stage": "pipeline", "error": error}, source="harness")

    def _finalize_result(self, ctx: _ProcessContext, start: float) -> PipelineResult:
        ctx.result.total_time_ms = (time.monotonic() - start) * 1000
        ctx.result.events_emitted = ctx.events_emitted
        return ctx.result

    # ------------------------------------------------------------------
    # Pipeline stage helpers  (used by all process_* variants)
    # ------------------------------------------------------------------

    def _run_classification(self, ctx: _ProcessContext, attacker_input: str, timer=None) -> None:
        if not self._classifier:
            return
        try:
            with timer.track("classification") if timer else contextlib.nullcontext():
                ctx.result.classification = self._classifier.classify(attacker_input, ctx.context)
            ctx.emit(EventType.CLASSIFICATION, ctx.result.classification, source="chrollo")
        except Exception as e:
            logger.warning("Classification failed: %s", e)
            ctx.result.classification = {
                "skill_level": "novice",
                "confidence": 0.0,
                "error": str(e),
            }
            ctx.emit(EventType.ERROR, {"stage": "classification", "error": str(e)}, source="chrollo")

    def _run_cti_lookup(self, ctx: _ProcessContext, attacker_input: str, timer=None) -> None:
        if not self._cti_engine:
            return
        try:
            with timer.track("cti_lookup") if timer else contextlib.nullcontext():
                ctx.result.cti_analysis = self._cti_engine.analyze(attacker_input, ctx.context)
            ctx.emit(EventType.CTI_LOOKUP, ctx.result.cti_analysis, source="don")
        except Exception as e:
            logger.warning("CTI lookup failed: %s", e)
            ctx.result.cti_analysis = {
                "threat_summary": "",
                "recommendations": [],
                "error": str(e),
            }
            ctx.emit(EventType.ERROR, {"stage": "cti_lookup", "error": str(e)}, source="don")

    def _run_response_generation(self, ctx: _ProcessContext, attacker_input: str, timer=None) -> None:
        if not self._deceiver:
            return
        try:
            enriched = self._enrich_context(ctx)
            with timer.track("response") if timer else contextlib.nullcontext():
                ctx.result.deception_response = self._deceiver.generate_response(attacker_input, enriched)
            ctx.emit(
                EventType.RESPONSE_GENERATE,
                {
                    "persona_used": ctx.result.deception_response.get("persona_used", ""),
                    "engagement_score": ctx.result.deception_response.get("engagement_score", 0.0),
                },
                source="hisoka",
            )
            if ctx.result.deception_response.get("honeytoken_triggered"):
                ctx.result.cti_analysis["honeytoken_triggered"] = True
        except Exception as e:
            logger.warning("Response generation failed: %s", e)
            ctx.result.deception_response = {
                "response_text": "Error generating response.",
                "error": str(e),
            }
            ctx.emit(EventType.ERROR, {"stage": "response_generate", "error": str(e)}, source="hisoka")

    def _run_verification(
        self,
        ctx: _ProcessContext,
        event_type: EventType = EventType.RESPONSE_VERIFY,
        event_source: str = "verifier",
        timer=None,
    ) -> None:
        if not self._verifier or not ctx.result.deception_response:
            return
        try:
            with timer.track("verify") if timer else contextlib.nullcontext():
                ctx.result.verification = self._verifier.verify(ctx.result.deception_response, ctx.context)
            ctx.emit(event_type, ctx.result.verification, source=event_source)
            if not ctx.result.passed_verification and self._max_retries > 0:
                retry_events = self._retry_with_feedback(ctx, ctx.result, ctx.context)
                ctx.events_emitted += retry_events
        except Exception as e:
            logger.warning("Verification failed: %s", e)
            ctx.result.verification = {"passed": True, "error": str(e)}

    def _emit_system_response(self, ctx: _ProcessContext, extra: dict | None = None) -> None:
        data: dict[str, Any] = {
            "text": ctx.result.response_text,
            "persona_used": ctx.result.deception_response.get("persona_used", ""),
        }
        if extra:
            data.update(extra)
        ctx.emit(EventType.SYSTEM_RESPONSE, data, source="harness")

    # ------------------------------------------------------------------
    # Extension stage helpers  (process_with_* variants only)
    # ------------------------------------------------------------------

    def _run_threat_modeling(
        self,
        ctx: _ProcessContext,
        attacker_input: str,
        threat_modeler: Any,
        timer=None,
    ):
        """Run STRIDE threat modeling. Returns the threat_model object or None."""
        try:
            if timer:
                with timer.track("threat_modeling"):
                    threat_model = threat_modeler.analyze(attacker_input, ctx.context)
            else:
                threat_model = threat_modeler.analyze(attacker_input, ctx.context)
            ctx.emit(EventType.THREAT_MODEL, threat_model.to_dict(), source="threat_modeler")
            ctx.context["threat_model"] = threat_model.to_dict()
            return threat_model
        except Exception as e:
            logger.warning("Threat modeling failed: %s", e)
            ctx.emit(EventType.ERROR, {"stage": "threat_modeling", "error": str(e)}, source="threat_modeler")
            return None

    def _run_supervisor_routing(self, ctx: _ProcessContext, supervisor: Any, attacker_input: str):
        """Run supervisor routing. Returns the routing_decision or None."""
        if not HAS_COORDINATION:
            return None
        try:
            decision = supervisor.route(
                session_context=ctx.context,
                classification=ctx.result.classification,
                session_id=ctx.session.session_id,
                current_persona=ctx.context.get("persona", ""),
            )
            ctx.emit(
                EventType.CLASSIFICATION,
                {"routing_decision": decision.to_dict(), "stage": "supervisor"},
                source="supervisor",
            )
            ctx.context["supervisor_routing"] = decision.to_dict()
            ctx.context["persona"] = decision.persona
            ctx.context["risk_level"] = decision.risk_level.value
            ctx.context["context_enrichments"] = decision.context_enrichments
            return decision
        except Exception as e:
            logger.warning("Supervisor routing failed: %s", e)
            ctx.emit(EventType.ERROR, {"stage": "supervisor_routing", "error": str(e)}, source="supervisor")
            return None

    def _run_expert_analysis(
        self,
        ctx: _ProcessContext,
        routing_decision: Any,
        expert_pool: Any,
        attacker_input: str,
    ) -> None:
        if not routing_decision.needs_expert:
            return
        try:
            expert_task = {
                "techniques": ctx.context.get("observed_ttps", []),
                "attacker_input": attacker_input,
                "domain": routing_decision.expert_domain,
            }
            expert_result = expert_pool.dispatch(routing_decision.expert_domain, expert_task, ctx.context)
            ctx.emit(
                EventType.CTI_LOOKUP,
                {
                    "expert_domain": routing_decision.expert_domain,
                    "expert_result": expert_result.to_dict(),
                    "stage": "expert_pool",
                },
                source="expert_pool",
            )
            ctx.context["expert_analysis"] = expert_result.to_dict()
        except Exception as e:
            logger.warning("Expert dispatch failed: %s", e)
            ctx.emit(EventType.ERROR, {"stage": "expert_dispatch", "error": str(e)}, source="expert_pool")

    def _run_voting(self, ctx: _ProcessContext, routing_decision: Any, voting_system: Any) -> None:
        if not routing_decision.needs_voting:
            return
        try:
            vote_result = voting_system.vote(ctx.result.deception_response, ctx.context)
            ctx.emit(
                EventType.RESPONSE_VERIFY,
                {
                    "vote_outcome": vote_result.outcome.value,
                    "confidence": vote_result.confidence,
                    "dissent_count": vote_result.dissent_count,
                    "stage": "voting_system",
                },
                source="voting_system",
            )
            if vote_result.final_response != ctx.result.deception_response:
                ctx.result.deception_response = vote_result.final_response
                ctx.result.verification["voting_applied"] = True
        except Exception as e:
            logger.warning("Voting failed: %s", e)
            ctx.emit(EventType.ERROR, {"stage": "voting", "error": str(e)}, source="voting_system")

    def _run_enhanced_review(self, ctx: _ProcessContext, enhanced_reviewer: Any) -> None:
        if not ctx.result.deception_response:
            return
        try:
            review_result = enhanced_reviewer.review(ctx.result.deception_response, ctx.context)
            ctx.emit(
                EventType.RESPONSE_VERIFY,
                {
                    "passed": review_result.get("passed", True),
                    "confidence": review_result.get("confidence", 0.0),
                    "stage": "enhanced_review",
                },
                source="enhanced_reviewer",
            )
            ctx.result.verification["enhanced_review"] = review_result
        except Exception as e:
            logger.warning("Enhanced review failed: %s", e)

    def _run_attack_chain(self, ctx: _ProcessContext, attack_chain_builder: Any) -> None:
        try:
            observed_ttps = ctx.context.get("observed_ttps", [])
            ttp_history = ctx.context.get("ttp_history", [])
            if not observed_ttps and not ttp_history:
                return
            chain = attack_chain_builder.build_from_session_context(ctx.session.session_id, ctx.context)
            if chain.step_count > 0:
                ctx.emit(EventType.ATTACK_CHAIN, chain.to_dict(), source="attack_chain_builder")
                ctx.result.verification["attack_chain"] = chain.to_dict()
        except Exception as e:
            logger.warning("Attack chain building failed: %s", e)

    def _run_finding(self, ctx: _ProcessContext, threat_model: Any) -> None:
        if not threat_model or threat_model.overall_risk not in ("high", "critical"):
            return
        ctx.emit(
            EventType.FINDING,
            {
                "session_id": ctx.session.session_id,
                "risk_level": threat_model.overall_risk,
                "threat_count": threat_model.threat_count,
                "high_risk_threats": [t.to_dict() for t in threat_model.high_risk_threats],
                "source_ip": ctx.context.get("source_ip", ""),
            },
            source="threat_modeler",
        )

    def _run_mtta(
        self,
        ctx: _ProcessContext,
        mtta_tracker: Any,
        timer,
        threat_model: Any,
        events_at_end: int,
    ) -> None:
        try:
            interaction_id = f"{ctx.session.session_id}-{events_at_end}"
            mtta_tracker.record_interaction(
                interaction_id=interaction_id,
                session_id=ctx.session.session_id,
                attacker_input=ctx.result.attacker_input,
                stages=timer.timings if timer else [],
                total_duration_ms=ctx.result.total_time_ms,
                metadata={
                    "threat_model_risk": threat_model.overall_risk if threat_model else "unknown",
                },
            )
        except Exception as e:
            logger.warning("MTTA recording failed: %s", e)

    def _init_timer(self, mtta_tracker=None):
        """Return a StageTimer if mtta_tracker is available, else None."""
        if mtta_tracker:
            try:
                from ragin.cycle.metrics import StageTimer

                return StageTimer()
            except ImportError:
                pass
        return None

    # ------------------------------------------------------------------
    # Public process methods
    # ------------------------------------------------------------------

    def process(
        self,
        session: Session,
        attacker_input: str,
    ) -> PipelineResult:
        start = time.monotonic()
        ctx = _ProcessContext(
            result=PipelineResult(session_id=session.session_id, attacker_input=attacker_input),
            session=session,
        )

        try:
            self._emit_attacker_input(ctx, attacker_input)
            self._build_and_store_context(ctx)
            self._run_classification(ctx, attacker_input)
            self._run_cti_lookup(ctx, attacker_input)
            self._run_response_generation(ctx, attacker_input)
            self._run_verification(ctx)
            self._emit_system_response(ctx)
        except Exception as e:
            logger.error("Pipeline error: %s", e, exc_info=True)
            self._record_pipeline_error(ctx, str(e))

        return self._finalize_result(ctx, start)

    def process_with_supervisor(
        self,
        session: Session,
        attacker_input: str,
        supervisor: Any = None,
        voting_system: Any = None,
        expert_pool: Any = None,
        enhanced_reviewer: Any = None,
    ) -> PipelineResult:
        start = time.monotonic()
        ctx = _ProcessContext(
            result=PipelineResult(session_id=session.session_id, attacker_input=attacker_input),
            session=session,
        )
        routing_decision = None

        try:
            self._emit_attacker_input(ctx, attacker_input)
            self._build_and_store_context(ctx)
            self._run_classification(ctx, attacker_input)
            routing_decision = self._run_supervisor_routing(ctx, supervisor, attacker_input)
            self._run_cti_lookup(ctx, attacker_input)
            self._run_expert_analysis(ctx, routing_decision, expert_pool, attacker_input)
            self._run_response_generation(ctx, attacker_input)
            self._run_voting(ctx, routing_decision, voting_system)
            if enhanced_reviewer:
                self._run_enhanced_review(ctx, enhanced_reviewer)
            self._run_verification(ctx)
            persona = routing_decision.persona if routing_decision else ""
            self._emit_system_response(ctx, {"persona": persona})
        except Exception as e:
            logger.error("Pipeline error: %s", e, exc_info=True)
            self._record_pipeline_error(ctx, str(e))

        return self._finalize_result(ctx, start)

    def process_with_threat_modeling(
        self,
        session: Session,
        attacker_input: str,
        threat_modeler: Any = None,
        response_verifier: Any = None,
        attack_chain_builder: Any = None,
        mtta_tracker: Any = None,
    ) -> PipelineResult:
        start = time.monotonic()
        timer = self._init_timer(mtta_tracker)
        ctx = _ProcessContext(
            result=PipelineResult(session_id=session.session_id, attacker_input=attacker_input),
            session=session,
        )
        threat_model = None

        try:
            self._emit_attacker_input(ctx, attacker_input)
            self._build_and_store_context(ctx)
            self._run_classification(ctx, attacker_input, timer)
            threat_model = self._run_threat_modeling(ctx, attacker_input, threat_modeler, timer)
            self._run_cti_lookup(ctx, attacker_input, timer)
            self._run_response_generation(ctx, attacker_input, timer)

            # Use threat-model-aware verifier if provided, else standard verifier
            verifier = response_verifier or self._verifier
            if verifier and ctx.result.deception_response:
                # Temporarily swap so _run_verification uses the right verifier
                original = self._verifier
                self._verifier = verifier
                self._run_verification(ctx, EventType.VERIFICATION, "threat_model_verifier", timer)
                self._verifier = original

            self._emit_system_response(ctx)
            self._run_attack_chain(ctx, attack_chain_builder)
            self._run_finding(ctx, threat_model)
        except Exception as e:
            logger.error("Pipeline error: %s", e, exc_info=True)
            self._record_pipeline_error(ctx, str(e))

        result = self._finalize_result(ctx, start)
        self._run_mtta(ctx, mtta_tracker, timer, threat_model, ctx.events_emitted)
        return result

    def _retry_with_feedback(
        self,
        ctx: _ProcessContext,
        failed_result: PipelineResult,
        context: dict[str, Any],
    ) -> int:
        """Retry response generation with verification feedback.

        Returns the number of events emitted during retries.
        """
        issues = failed_result.verification.get("issues", [])
        feedback = f"Previous response had issues: {'; '.join(issues)}. Improve."
        events = 0

        for attempt in range(self._max_retries):
            try:
                enriched_context = {
                    **context,
                    "classification": failed_result.classification,
                    "cti_analysis": failed_result.cti_analysis,
                    "feedback": feedback,
                    "retry_attempt": attempt + 1,
                }
                new_response = self._deceiver.generate_response(failed_result.attacker_input, enriched_context)

                # Verify again
                if self._verifier:
                    new_verification = self._verifier.verify(new_response, enriched_context)
                    if new_verification.get("passed", True):
                        ctx.session.emit(
                            EventType.RESPONSE_GENERATE,
                            {
                                "persona_used": new_response.get("persona_used", ""),
                                "retry_attempt": attempt + 1,
                            },
                            source="hisoka",
                        )
                        events += 1
                        failed_result.deception_response = new_response
                        return events

                # If verifier passed or no verifier, accept response
                if not self._verifier:
                    failed_result.deception_response = new_response
                    return events

            except Exception:
                continue

        return events
