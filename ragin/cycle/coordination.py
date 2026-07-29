"""Multi-Agent Coordination patterns for RAGIN harness.

Design principles from Anthropic Managed Agents + revfactory/harness + visa/vvaharness:

- Supervisor: dynamic persona routing based on session state + attacker behavior
- Voting: multi-agent consensus for high-stakes responses (evasion detection, artifact injection)
- Expert Pool: route complex CTI analysis to specialized experts
- Delegation Chain: hierarchical task decomposition for complex multi-step attacks
- Enhanced Producer-Reviewer: configurable review agents with structured feedback

All patterns emit SESSION events for durable audit trail. The Harness delegates
to these coordination primitives; the primitives never hold session state.

Usage::

    supervisor = Supervisor(persona_routing_fn=my_routing_fn)
    voter = VotingSystem(verifiers=[VerifierA(), VerifierB(), VerifierC()])
    experts = ExpertPool(agents={"cve": CVEExpert(), "apt": APTExpert()})
    delegator = DelegationChain(steps=[...])

    # In harness.process():
    strategy = supervisor.route(session, context, classification)
    if strategy.needs_voting:
        vote = voter.vote(response, context)
    if strategy.needs_expert:
        expert_result = experts.dispatch(strategy.expert_domain, task)
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

logger = logging.getLogger(__name__)


# ── Protocols ────────────────────────────────────────────────────────────────


class Reviewer(Protocol):
    """Protocol for a review agent that validates response quality."""

    def review(
        self,
        response: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Review a response. Returns dict with 'passed', 'confidence', 'issues', 'suggestion'."""
        ...


class ExpertAgent(Protocol):
    """Protocol for a specialized expert agent."""

    def analyze(
        self,
        task: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze a task. Returns domain-specific result dict."""
        ...


class DelegationStep(Protocol):
    """Protocol for a step in a delegation chain."""

    def execute(
        self,
        task: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute this step. Returns result dict."""
        ...


# ── Enums ────────────────────────────────────────────────────────────────────


class PersonaRoute(str, Enum):
    """How the supervisor routes persona selection."""

    AUTO = "auto"
    FIXED = "fixed"
    ESCALATE = "escalate"


class RiskLevel(str, Enum):
    """Risk classification levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VoteOutcome(str, Enum):
    """Result of a multi-agent vote."""

    UNANIMOUS = "unanimous"
    MAJORITY = "majority"
    SPLIT = "split"
    FAILED = "failed"


class DelegationStatus(str, Enum):
    """Status of a delegation chain step."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


# ── Data classes ─────────────────────────────────────────────────────────────


@dataclass
class RoutingDecision:
    """Supervisor routing decision for persona selection."""

    persona: str
    reason: str
    route: PersonaRoute
    risk_level: RiskLevel = RiskLevel.LOW
    needs_voting: bool = False
    needs_expert: bool = False
    expert_domain: str = ""
    context_enrichments: list[str] = field(default_factory=list)
    confidence: float = 1.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "persona": self.persona,
            "reason": self.reason,
            "route": self.route.value,
            "risk_level": self.risk_level.value,
            "needs_voting": self.needs_voting,
            "needs_expert": self.needs_expert,
            "expert_domain": self.expert_domain,
            "context_enrichments": self.context_enrichments,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


@dataclass
class VoteResult:
    """Result of a multi-agent voting round."""

    outcome: VoteOutcome
    votes: list[dict[str, Any]]
    final_response: dict[str, Any]
    confidence: float
    dissent_count: int = 0
    total_voters: int = 0
    reasoning: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "votes": self.votes,
            "final_response": self.final_response,
            "confidence": self.confidence,
            "dissent_count": self.dissent_count,
            "total_voters": self.total_voters,
            "reasoning": self.reasoning,
            "timestamp": self.timestamp,
        }


@dataclass
class ExpertResult:
    """Result from an expert agent dispatch."""

    domain: str
    result: dict[str, Any]
    confidence: float
    expert_id: str = ""
    fallback_used: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "result": self.result,
            "confidence": self.confidence,
            "expert_id": self.expert_id,
            "fallback_used": self.fallback_used,
            "timestamp": self.timestamp,
        }


@dataclass
class DelegationResult:
    """Result of a delegation chain execution."""

    steps: list[dict[str, Any]]
    final_result: dict[str, Any]
    total_steps: int = 0
    completed_steps: int = 0
    failed_steps: int = 0
    total_time_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": self.steps,
            "final_result": self.final_result,
            "total_steps": self.total_steps,
            "completed_steps": self.completed_steps,
            "failed_steps": self.failed_steps,
            "total_time_ms": self.total_time_ms,
            "timestamp": self.timestamp,
        }


# ── 3.2 Supervisor: Dynamic Persona Routing ─────────────────────────────────


class Supervisor:
    """Dynamic persona routing based on session state + attacker behavior.

    The Supervisor sits between Chrollo (classification) and Hisoka (deception)
    and decides WHICH persona to use, whether to escalate to voting or experts,
    and what context enrichments to inject.

    Decision factors:
    - Skill level from Chrollo classification
    - Accumulated TTPs from session history
    - Risk level escalation
    - Session depth (interaction count)
    - Evasion detection signals

    Usage::

        supervisor = Supervisor()
        decision = supervisor.route(
            session_context={...},
            classification={"skill_level": "advanced", "confidence": 0.9},
            session_id="ses-abc",
        )
        if decision.needs_voting:
            # Route through VotingSystem before sending response
        if decision.needs_expert:
            # Route to ExpertPool for domain analysis
    """

    # Escalation thresholds
    RISK_VOTE_THRESHOLD = RiskLevel.HIGH
    RISK_EXPERT_THRESHOLD = RiskLevel.MEDIUM
    DEPTH_VOTE_THRESHOLD = 15  # interactions before triggering voting
    ELEVATED_SKILL_LEVELS = {"advanced", "expert"}

    def __init__(
        self,
        persona_routing_fn: Callable[[str, dict[str, Any]], str] | None = None,
    ) -> None:
        self._persona_routing_fn = persona_routing_fn
        self._strategy_history: dict[str, list[RoutingDecision]] = {}

    def route(
        self,
        session_context: dict[str, Any],
        classification: dict[str, Any],
        session_id: str = "",
        current_persona: str = "",
    ) -> RoutingDecision:
        """Compute routing decision for the current interaction.

        Args:
            session_context: Reconstructed context from Session.build_context()
            classification: Output from Chrollo classifier
            session_id: Session identifier for history tracking
            current_persona: Currently active persona name

        Returns:
            RoutingDecision with persona, risk level, voting/expert flags
        """
        skill_level = classification.get("skill_level", "novice")
        confidence = classification.get("confidence", 0.0)
        interaction_count = session_context.get("interaction_count", 0)

        # Compute risk level
        risk_level = self._compute_risk(skill_level, confidence, interaction_count, session_context)

        # Determine if voting is needed
        needs_voting = self._needs_voting(risk_level, interaction_count, skill_level, session_context)

        # Determine if expert analysis is needed
        needs_expert, expert_domain = self._needs_expert(risk_level, skill_level, session_context)

        # Select persona
        persona, persona_reason = self._select_persona(skill_level, risk_level, current_persona, session_context)

        # Build context enrichments
        enrichments = self._build_enrichments(skill_level, risk_level, session_context)

        # Determine route type
        if needs_voting or needs_expert or current_persona and current_persona != persona:
            route = PersonaRoute.ESCALATE
        else:
            route = PersonaRoute.AUTO

        decision = RoutingDecision(
            persona=persona,
            reason=persona_reason,
            route=route,
            risk_level=risk_level,
            needs_voting=needs_voting,
            needs_expert=needs_expert,
            expert_domain=expert_domain,
            context_enrichments=enrichments,
            confidence=confidence,
        )

        if session_id:
            self._strategy_history.setdefault(session_id, []).append(decision)

        return decision

    def get_history(self, session_id: str) -> list[RoutingDecision]:
        """Get routing decision history for a session."""
        return self._strategy_history.get(session_id, [])

    def clear_session(self, session_id: str) -> None:
        """Clear history for a completed session."""
        self._strategy_history.pop(session_id, None)

    def _compute_risk(
        self,
        skill_level: str,
        confidence: float,
        interaction_count: int,
        context: dict[str, Any],
    ) -> RiskLevel:
        """Compute composite risk level from multiple signals."""
        score = 0

        # Skill level contribution
        skill_scores = {"novice": 0, "intermediate": 1, "advanced": 2, "expert": 3}
        score += skill_scores.get(skill_level, 0)

        # Confidence contribution
        if confidence > 0.8:
            score += 1

        # Interaction depth contribution
        if interaction_count >= 20:
            score += 2
        elif interaction_count >= 10:
            score += 1

        # Check for evasion indicators in context
        if context.get("evasion_detected", False):
            score += 2

        # Check TTPs in context
        ttps = context.get("observed_ttps", [])
        if len(ttps) >= 5:
            score += 1
        dangerous_ttps = {"T1486", "T1003", "T1055", "T1562"}
        if set(ttps) & dangerous_ttps:
            score += 2

        # Map score to risk level
        if score >= 6:
            return RiskLevel.CRITICAL
        if score >= 4:
            return RiskLevel.HIGH
        if score >= 2:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _needs_voting(
        self,
        risk_level: RiskLevel,
        interaction_count: int,
        skill_level: str,
        context: dict[str, Any],
    ) -> bool:
        """Determine if multi-agent voting should be triggered."""
        if risk_level == RiskLevel.CRITICAL:
            return True
        if risk_level == RiskLevel.HIGH and interaction_count >= self.DEPTH_VOTE_THRESHOLD:
            return True
        return bool(skill_level in self.ELEVATED_SKILL_LEVELS and context.get("evasion_detected", False))

    def _needs_expert(
        self,
        risk_level: RiskLevel,
        skill_level: str,
        context: dict[str, Any],
    ) -> tuple[bool, str]:
        """Determine if expert analysis is needed and which domain."""
        if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            ttps = set(context.get("observed_ttps", []))
            cve_ttps = {"T1190", "T1068", "T1133"}
            apt_ttps = {"T1562", "T1027", "T1070", "T1570"}
            cred_ttps = {"T1003", "T1110"}

            if ttps & cve_ttps:
                return True, "cve"
            if ttps & apt_ttps:
                return True, "apt"
            if ttps & cred_ttps:
                return True, "credential"

        if skill_level == "expert":
            return True, "advanced_tactics"

        return False, ""

    def _select_persona(
        self,
        skill_level: str,
        risk_level: RiskLevel,
        current_persona: str,
        context: dict[str, Any],
    ) -> tuple[str, str]:
        """Select appropriate persona based on signals."""
        # Use custom routing function if provided
        if self._persona_routing_fn:
            persona = self._persona_routing_fn(skill_level, context)
            return persona, f"Custom routing selected {persona}"

        # Persona escalation ladder based on attacker sophistication
        persona_map = {
            RiskLevel.LOW: ("sysadmin", "Baseline sysadmin persona for low-risk attacker"),
            RiskLevel.MEDIUM: (
                "security_analyst",
                "Escalated to security analyst — attacker showing intermediate skills",
            ),
            RiskLevel.HIGH: (
                "incident_responder",
                "Escalated to incident responder — high-risk attacker detected",
            ),
            RiskLevel.CRITICAL: (
                "soc_lead",
                "Escalated to SOC lead — critical risk, maximum engagement",
            ),
        }

        return persona_map.get(risk_level, ("sysadmin", "Default persona"))

    def _build_enrichments(
        self,
        skill_level: str,
        risk_level: RiskLevel,
        context: dict[str, Any],
    ) -> list[str]:
        """Build context enrichments for the deceiver."""
        enrichments = []

        if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            enrichments.append(f"Risk level {risk_level.value} — deploy maximum engagement")

        interaction_count = context.get("interaction_count", 0)
        if interaction_count >= 10:
            enrichments.append(f"Deep engagement ({interaction_count} turns) — attacker is committed")

        if context.get("evasion_detected", False):
            enrichments.append("Evasion behavior detected — attacker may be probing for honeypot markers")

        ttps = context.get("observed_ttps", [])
        if ttps:
            enrichments.append(f"Observed TTPs: {', '.join(ttps[:5])}")

        return enrichments


# ── 3.3 Multi-Agent Voting ───────────────────────────────────────────────────


class VotingSystem:
    """Multi-agent consensus for high-stakes response validation.

    Multiple reviewers independently evaluate a proposed response. The final
    outcome is determined by majority vote (or unanimity for critical actions).

    Triggers:
    - Risk level HIGH/CRITICAL
    - Evasion detected
    - Deep sessions (>15 interactions)
    - Artifact injection decisions

    Usage::

        voter = VotingSystem(
            verifiers=[security_verifier, quality_verifier, deception_verifier],
            threshold=0.6,  # 60% agreement needed
        )
        result = voter.vote(proposed_response, context)
        if result.outcome == VoteOutcome.FAILED:
            # Use fallback response
    """

    def __init__(
        self,
        verifiers: list[Reviewer] | None = None,
        threshold: float = 0.6,
        require_unanimity: bool = False,
    ) -> None:
        self._verifiers: list[Reviewer] = verifiers or []
        self._threshold = threshold
        self._require_unanimity = require_unanimity

    def add_verifier(self, verifier: Reviewer) -> None:
        """Add a verifier to the voting pool."""
        self._verifiers.append(verifier)

    def vote(
        self,
        proposed_response: dict[str, Any],
        context: dict[str, Any],
    ) -> VoteResult:
        """Run multi-agent vote on proposed response.

        Each verifier independently reviews the response. Votes are collected
        and the consensus is determined.

        Args:
            proposed_response: The response dict from Hisoka
            context: Session context including classification, CTI, etc.

        Returns:
            VoteResult with outcome, individual votes, and selected response
        """
        if not self._verifiers:
            return VoteResult(
                outcome=VoteOutcome.UNANIMOUS,
                votes=[],
                final_response=proposed_response,
                confidence=1.0,
                total_voters=0,
                reasoning="No verifiers configured — accepting response by default",
            )

        votes: list[dict[str, Any]] = []
        pass_count = 0

        for i, verifier in enumerate(self._verifiers):
            try:
                vote_result = verifier.review(proposed_response, context)
                vote_result["verifier_index"] = i
                vote_result["verifier_type"] = type(verifier).__name__
                votes.append(vote_result)

                if vote_result.get("passed", False):
                    pass_count += 1
            except Exception as e:
                logger.warning("Verifier %d failed: %s", i, e)
                votes.append(
                    {
                        "passed": False,
                        "confidence": 0.0,
                        "issues": [f"Verifier error: {e}"],
                        "verifier_index": i,
                        "verifier_type": type(verifier).__name__,
                        "error": str(e),
                    }
                )

        total = len(votes)
        if total == 0:
            return VoteResult(
                outcome=VoteOutcome.FAILED,
                votes=[],
                final_response=proposed_response,
                confidence=0.0,
                total_voters=0,
                reasoning="All verifiers failed",
            )

        pass_rate = pass_count / total
        dissent_count = total - pass_count

        # Determine outcome
        if self._require_unanimity:
            if pass_count == total:
                outcome = VoteOutcome.UNANIMOUS
            elif pass_count > 0:
                outcome = VoteOutcome.SPLIT
            else:
                outcome = VoteOutcome.FAILED
        else:
            if pass_count == total:
                outcome = VoteOutcome.UNANIMOUS
            elif pass_rate >= self._threshold:
                outcome = VoteOutcome.MAJORITY
            elif pass_rate > 0:
                outcome = VoteOutcome.SPLIT
            else:
                outcome = VoteOutcome.FAILED

        # Compute aggregate confidence
        confidences = [v.get("confidence", 0.0) for v in votes if "error" not in v]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        # If passed, use the best suggestion (highest confidence among passing votes)
        if outcome in (VoteOutcome.UNANIMOUS, VoteOutcome.MAJORITY):
            passing = [v for v in votes if v.get("passed", False)]
            best = max(passing, key=lambda v: v.get("confidence", 0)) if passing else {}
            suggestion = best.get("suggestion", "")
            final = {**proposed_response, "response_text": suggestion} if suggestion else proposed_response
        else:
            # On split/failed, use the proposed response but flag it
            final = {**proposed_response, "vetoed": True, "vote_outcome": outcome.value}

        reasoning_parts = []
        for v in votes:
            vtype = v.get("verifier_type", "unknown")
            passed = "PASS" if v.get("passed") else "FAIL"
            reasoning_parts.append(f"{vtype}: {passed}")

        return VoteResult(
            outcome=outcome,
            votes=votes,
            final_response=final,
            confidence=avg_confidence,
            dissent_count=dissent_count,
            total_voters=total,
            reasoning="; ".join(reasoning_parts),
        )


# ── 3.4 Expert Pool ──────────────────────────────────────────────────────────


class ExpertPool:
    """Routes complex CTI analysis to specialized expert agents.

    Each expert has a domain specialization. The pool dispatches tasks to
    the appropriate expert based on the Supervisor's routing decision.

    Built-in domains:
    - "cve": CVE/vulnerability analysis
    - "apt": Advanced persistent threat profiling
    - "credential": Credential attack analysis
    - "advanced_tactics": Multi-stage attack analysis

    Usage::

        pool = ExpertPool(agents={
            "cve": CVEExpert(),
            "apt": APTExpert(),
            "credential": CredentialExpert(),
        })
        result = pool.dispatch("cve", {"techniques": ["T1190"], ...}, context)
    """

    # Fallback results when no expert is available
    FALLBACK_RESULT: dict[str, Any] = {
        "analysis": "No specialized expert available for this domain",
        "confidence": 0.3,
        "recommendation": "Escalate to manual analyst review",
    }

    def __init__(
        self,
        agents: dict[str, ExpertAgent] | None = None,
    ) -> None:
        self._agents: dict[str, ExpertAgent] = agents or {}
        self._dispatch_history: list[ExpertResult] = []

    def register(self, domain: str, agent: ExpertAgent) -> None:
        """Register an expert agent for a domain."""
        self._agents[domain] = agent

    def dispatch(
        self,
        domain: str,
        task: dict[str, Any],
        context: dict[str, Any],
    ) -> ExpertResult:
        """Dispatch a task to the appropriate expert.

        Args:
            domain: Expert domain (e.g., "cve", "apt", "credential")
            task: Task description with relevant data
            context: Session context

        Returns:
            ExpertResult with domain analysis
        """
        agent = self._agents.get(domain)
        fallback_used = agent is None

        if agent is None:
            logger.info("No expert for domain '%s' — using fallback", domain)
            result = dict(self.FALLBACK_RESULT)
        else:
            try:
                result = agent.analyze(task, context)
            except Exception as e:
                logger.warning("Expert '%s' failed: %s", domain, e)
                result = {
                    "analysis": f"Expert analysis failed: {e}",
                    "confidence": 0.0,
                    "error": str(e),
                }
                fallback_used = True

        expert_result = ExpertResult(
            domain=domain,
            result=result,
            confidence=result.get("confidence", 0.0),
            expert_id=type(agent).__name__ if agent else "fallback",
            fallback_used=fallback_used,
        )
        self._dispatch_history.append(expert_result)
        return expert_result

    def get_domains(self) -> list[str]:
        """List registered expert domains."""
        return list(self._agents.keys())

    def get_history(self) -> list[ExpertResult]:
        """Get dispatch history."""
        return list(self._dispatch_history)

    def clear_history(self) -> None:
        """Clear dispatch history."""
        self._dispatch_history.clear()


# ── 3.5 Hierarchical Delegation Chain ───────────────────────────────────────


class DelegationChain:
    """Hierarchical task decomposition for complex multi-step attacks.

    For sophisticated attacks that require multiple analysis stages
    (e.g., initial recon → vulnerability identification → exploit planning →
    lateral movement analysis), the delegation chain breaks the work into
    ordered steps and runs them sequentially, with each step's output
    feeding into the next.

    Usage::

        chain = DelegationChain(steps=[
            recon_step,
            vuln_step,
            exploit_step,
            lateral_step,
        ])
        result = chain.execute(initial_task, context)
        if result.failed_steps > 0:
            # Handle partial failure
    """

    def __init__(
        self,
        steps: list[DelegationStep] | None = None,
        fail_fast: bool = True,
    ) -> None:
        self._steps: list[DelegationStep] = steps or []
        self._fail_fast = fail_fast

    def add_step(self, step: DelegationStep) -> None:
        """Add a step to the chain."""
        self._steps.append(step)

    def execute(
        self,
        initial_task: dict[str, Any],
        context: dict[str, Any],
    ) -> DelegationResult:
        """Execute the delegation chain.

        Each step receives the accumulated context from previous steps.
        If a step fails and fail_fast is True, the chain stops early.

        Args:
            initial_task: The initial task description
            context: Session context

        Returns:
            DelegationResult with step-by-step results
        """
        import time

        start = time.monotonic()
        step_results: list[dict[str, Any]] = []
        completed = 0
        failed = 0
        accumulated: dict[str, Any] = dict(initial_task)

        for i, step in enumerate(self._steps):
            step_record: dict[str, Any] = {
                "step_index": i,
                "step_type": type(step).__name__,
                "status": DelegationStatus.RUNNING.value,
            }

            try:
                result = step.execute(accumulated, context)
                step_record["status"] = DelegationStatus.COMPLETED.value
                step_record["result"] = result
                step_results.append(step_record)
                completed += 1

                # Feed output into next step's input
                accumulated = {**accumulated, **result, f"step_{i}_output": result}

            except Exception as e:
                logger.warning("Delegation step %d failed: %s", i, e)
                step_record["status"] = DelegationStatus.FAILED.value
                step_record["error"] = str(e)
                step_results.append(step_record)
                failed += 1

                if self._fail_fast:
                    # Mark remaining steps as skipped
                    for j in range(i + 1, len(self._steps)):
                        step_results.append(
                            {
                                "step_index": j,
                                "step_type": type(self._steps[j]).__name__,
                                "status": DelegationStatus.SKIPPED.value,
                            }
                        )
                    break

        elapsed_ms = (time.monotonic() - start) * 1000

        return DelegationResult(
            steps=step_results,
            final_result=accumulated,
            total_steps=len(self._steps),
            completed_steps=completed,
            failed_steps=failed,
            total_time_ms=elapsed_ms,
        )

    @property
    def step_count(self) -> int:
        """Number of steps in the chain."""
        return len(self._steps)


# ── 3.1 Enhanced Producer-Reviewer ───────────────────────────────────────────


class EnhancedProducerReviewer:
    """Extended Producer-Reviewer with configurable review agents.

    Builds on the basic Harness._retry_with_feedback() by adding:
    - Multiple reviewer types (security, quality, deception)
    - Structured feedback with severity levels
    - Configurable retry limits per reviewer type
    - Review audit trail

    Usage::

        reviewer = EnhancedProducerReviewer(
            reviewers=[SecurityReviewer(), QualityReviewer()],
            max_retries=3,
            escalation_threshold=0.3,
        )
        result = reviewer.review_and_retry(
            deceiver, proposed_response, context, session
        )
    """

    def __init__(
        self,
        reviewers: list[Reviewer] | None = None,
        max_retries: int = 2,
        escalation_threshold: float = 0.3,
    ) -> None:
        self._reviewers: list[Reviewer] = reviewers or []
        self._max_retries = max_retries
        self._escalation_threshold = escalation_threshold

    def review(
        self,
        response: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Run all reviewers and aggregate feedback.

        Returns dict with 'passed', 'issues', 'confidence', 'feedback'.
        Compatible with the ResponseVerifier protocol.
        """
        if not self._reviewers:
            return {"passed": True, "issues": [], "confidence": 1.0, "feedback": ""}

        all_issues: list[str] = []
        confidences: list[float] = []
        suggestions: list[str] = []
        passed_count = 0

        for reviewer in self._reviewers:
            try:
                result = reviewer.review(response, context)
                if result.get("passed", False):
                    passed_count += 1
                all_issues.extend(result.get("issues", []))
                confidences.append(result.get("confidence", 0.0))
                if result.get("suggestion"):
                    suggestions.append(result["suggestion"])
            except Exception as e:
                logger.warning("Reviewer %s failed: %s", type(reviewer).__name__, e)
                all_issues.append(f"Reviewer {type(reviewer).__name__} failed: {e}")

        total = len(self._reviewers)
        pass_rate = passed_count / total if total > 0 else 1.0
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        # Feedback text for retry
        feedback_parts = []
        if all_issues:
            feedback_parts.append(f"Issues: {'; '.join(all_issues[:5])}")
        if suggestions:
            feedback_parts.append(f"Suggestions: {'; '.join(suggestions[:3])}")

        return {
            "passed": pass_rate >= self._escalation_threshold,
            "issues": all_issues,
            "confidence": avg_confidence,
            "feedback": " ".join(feedback_parts),
            "pass_rate": pass_rate,
            "reviewer_count": total,
        }

    def review_and_retry(
        self,
        deceiver: Any,
        proposed_response: dict[str, Any],
        context: dict[str, Any],
        session: Any = None,
    ) -> dict[str, Any]:
        """Review and retry with feedback until passing or max retries.

        Args:
            deceiver: Deceiver instance with generate_response()
            proposed_response: Initial response from Hisoka
            context: Session context
            session: Optional Session for event emission

        Returns:
            Final response dict (either improved or original)
        """
        current_response = proposed_response
        current_context = dict(context)

        for attempt in range(self._max_retries + 1):
            review = self.review(current_response, current_context)

            if review["passed"]:
                if attempt > 0:
                    logger.info("Response passed review after %d retries", attempt)
                return {
                    **current_response,
                    "review_result": review,
                    "retry_count": attempt,
                }

            # Build feedback for retry
            feedback = review.get("feedback", "")
            current_context = {
                **current_context,
                "review_feedback": feedback,
                "retry_attempt": attempt + 1,
            }

            # Emit review event if session available
            if session is not None:
                try:
                    from ragin.cycle.session import EventType

                    session.emit(
                        EventType.RESPONSE_VERIFY,
                        {
                            "passed": False,
                            "attempt": attempt + 1,
                            "issues": review["issues"][:3],
                        },
                        source="enhanced_reviewer",
                    )
                except Exception:
                    pass  # Best-effort event emission

            if attempt < self._max_retries:
                try:
                    current_response = deceiver.generate_response(context.get("attacker_input", ""), current_context)
                except Exception as e:
                    logger.warning("Retry generation failed: %s", e)
                    break

        # Return last response even if not passing
        return {
            **current_response,
            "review_result": self.review(current_response, current_context),
            "retry_count": self._max_retries,
            "exhausted": True,
        }


# ── Built-in Reviewers ───────────────────────────────────────────────────────


class SecurityReviewer:
    """Reviews responses for security concerns — no credential leaks, no system info exposure."""

    LEAK_PATTERNS = [
        "internal ip",
        "192.168.",
        "10.0.",
        "172.16.",
        "password",
        "secret_key",
        "api_key",
        "private_key",
    ]

    def review(self, response: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        text = response.get("response_text", "").lower()
        issues: list[str] = []

        for pattern in self.LEAK_PATTERNS:
            if pattern in text:
                issues.append(f"Potential credential/IP leak: contains '{pattern}'")

        # Check for overly helpful responses
        helpful_phrases = [
            "here are the steps",
            "you can do this",
            "run this command",
            "try this",
        ]
        for phrase in helpful_phrases:
            if phrase in text:
                issues.append(f"Potentially too helpful: '{phrase}'")

        passed = len(issues) == 0
        return {
            "passed": passed,
            "issues": issues,
            "confidence": 1.0 if passed else 0.5,
            "suggestion": "" if passed else "Sanitize response to remove sensitive patterns",
        }


class QualityReviewer:
    """Reviews responses for quality — length, coherence, engagement."""

    MIN_RESPONSE_LENGTH = 10
    MAX_RESPONSE_LENGTH = 2000

    def review(self, response: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        text = response.get("response_text", "")
        issues: list[str] = []

        if len(text) < self.MIN_RESPONSE_LENGTH:
            issues.append(f"Response too short ({len(text)} chars, min {self.MIN_RESPONSE_LENGTH})")
        if len(text) > self.MAX_RESPONSE_LENGTH:
            issues.append(f"Response too long ({len(text)} chars, max {self.MAX_RESPONSE_LENGTH})")

        # Check for error strings
        if "error" in text.lower() and len(text) < 50:
            issues.append("Response appears to be an error message")

        passed = len(issues) == 0
        return {
            "passed": passed,
            "issues": issues,
            "confidence": 0.9 if passed else 0.4,
            "suggestion": "" if passed else "Adjust response length or remove error content",
        }


class DeceptionReviewer:
    """Reviews responses for deception quality — avoids honeypot giveaway patterns."""

    GIVEAWAY_PATTERNS = [
        "this is a honeypot",
        "this is a deception",
        "you are being monitored",
        "this is not a real",
        "fake",
        "canary",
    ]

    def review(self, response: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        text = response.get("response_text", "").lower()
        issues: list[str] = []

        for pattern in self.GIVEAWAY_PATTERNS:
            if pattern in text:
                issues.append(f"Deception giveaway: contains '{pattern}'")

        # Check persona consistency
        persona = response.get("persona_used", "")
        if not persona:
            issues.append("No persona specified in response")

        passed = len(issues) == 0
        return {
            "passed": passed,
            "issues": issues,
            "confidence": 1.0 if passed else 0.3,
            "suggestion": "" if passed else "Remove giveaway patterns and ensure persona consistency",
        }
