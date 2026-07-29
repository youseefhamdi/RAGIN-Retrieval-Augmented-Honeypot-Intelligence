"""Tests for LLM-based multi-persona evaluation framework — rubrics, scoring, ground truth, protocol."""

from ragin.benchmark.human_eval import (
    ALL_RUBRICS,
    DECEPTION_QUALITY_RUBRIC,
    EVALUATOR_PROTOCOL,
    SAMPLE_SCENARIOS,
    Score,
    SessionEvaluation,
    TurnEvaluation,
    create_evaluation_template,
    evaluate_against_ground_truth,
)


class TestScoringScale:
    def test_score_values(self):
        assert Score.VERY_POOR.value == 1
        assert Score.EXCELLENT.value == 5

    def test_score_ordering(self):
        assert Score.VERY_POOR < Score.POOR < Score.ACCEPTABLE < Score.GOOD < Score.EXCELLENT


class TestDimensionRubric:
    def test_rubric_has_all_anchors(self):
        for rubric in ALL_RUBRICS:
            assert len(rubric.anchors) == 5
            for score in Score:
                assert score in rubric.anchors

    def test_rubric_to_dict(self):
        d = DECEPTION_QUALITY_RUBRIC.to_dict()
        assert d["name"] == "deception_quality"
        assert 1 in d["anchors"]
        assert 5 in d["anchors"]


class TestTurnEvaluation:
    def test_overall_score_average(self):
        te = TurnEvaluation(
            turn_number=1,
            query="whoami",
            response_text="uid=1000(webadmin)",
            deception_score=Score.GOOD,
            persona_score=Score.EXCELLENT,
            ttp_accuracy_score=Score.ACCEPTABLE,
            engagement_score=Score.GOOD,
            artifact_safety_score=Score.GOOD,
        )
        # (4+5+3+4+4) / 5 = 4.0
        assert te.overall_score == 4.0

    def test_all_poor(self):
        te = TurnEvaluation(
            turn_number=1,
            query="test",
            response_text="test",
            deception_score=Score.VERY_POOR,
            persona_score=Score.VERY_POOR,
            ttp_accuracy_score=Score.VERY_POOR,
            engagement_score=Score.VERY_POOR,
            artifact_safety_score=Score.VERY_POOR,
        )
        assert te.overall_score == 1.0

    def test_to_dict(self):
        te = TurnEvaluation(
            turn_number=1,
            query="whoami",
            response_text="uid=1000",
            persona_used="novice",
            ttps_extracted=["T1033"],
        )
        d = te.to_dict()
        assert d["turn_number"] == 1
        assert d["persona_used"] == "novice"
        assert d["ttps_extracted"] == ["T1033"]
        assert "scores" in d
        assert d["scores"]["deception"] == 3  # default ACCEPTABLE


class TestSessionEvaluation:
    def test_empty_session(self):
        se = SessionEvaluation(session_id="s1", attacker_profile="novice")
        assert se.turn_count == 0
        assert se.overall_score == 0.0
        assert se.avg_scores == {}

    def test_avg_scores(self):
        se = SessionEvaluation(session_id="s1", attacker_profile="novice")
        se.turn_evaluations.append(
            TurnEvaluation(
                turn_number=1,
                query="q1",
                response_text="r1",
                deception_score=Score.GOOD,
                persona_score=Score.GOOD,
                ttp_accuracy_score=Score.GOOD,
                engagement_score=Score.GOOD,
                artifact_safety_score=Score.GOOD,
            )
        )
        se.turn_evaluations.append(
            TurnEvaluation(
                turn_number=2,
                query="q2",
                response_text="r2",
                deception_score=Score.EXCELLENT,
                persona_score=Score.GOOD,
                ttp_accuracy_score=Score.GOOD,
                engagement_score=Score.GOOD,
                artifact_safety_score=Score.GOOD,
            )
        )
        avgs = se.avg_scores
        assert avgs["deception"] == 4.5  # (4+5)/2
        assert avgs["persona"] == 4.0

    def test_to_dict(self):
        se = SessionEvaluation(session_id="s1", attacker_profile="novice", evaluator_id="ev1")
        se.turn_evaluations.append(
            TurnEvaluation(
                turn_number=1,
                query="q1",
                response_text="r1",
            )
        )
        d = se.to_dict()
        assert d["session_id"] == "s1"
        assert d["turn_count"] == 1
        assert len(d["turns"]) == 1


class TestGroundTruthScenarios:
    def test_sample_scenarios_count(self):
        assert len(SAMPLE_SCENARIOS) == 8

    def test_all_scenarios_have_ids(self):
        for sc in SAMPLE_SCENARIOS:
            assert sc.scenario_id.startswith("GT-")

    def test_all_scenarios_have_danger_signals(self):
        for sc in SAMPLE_SCENARIOS:
            assert len(sc.danger_signals) > 0

    def test_scenario_to_dict(self):
        sc = SAMPLE_SCENARIOS[0]
        d = sc.to_dict()
        assert d["scenario_id"] == "GT-001"
        assert "expected_ttps" in d
        assert "danger_signals" in d


class TestCreateEvaluationTemplate:
    def test_template_creation(self):
        turns = [
            {
                "turn_number": 1,
                "query": "whoami",
                "response_text": "uid=1000",
                "persona_used": "novice",
                "ttps_extracted": ["T1033"],
            },
            {
                "turn_number": 2,
                "query": "ls -la",
                "response_text": "total 0",
                "persona_used": "novice",
                "ttps_extracted": ["T1083"],
            },
        ]
        se = create_evaluation_template("s1", turns, attacker_profile="novice", evaluator_id="ev1")
        assert se.session_id == "s1"
        assert se.turn_count == 2
        assert se.evaluator_id == "ev1"
        assert se.turn_evaluations[0].query == "whoami"
        assert se.turn_evaluations[1].ttps_extracted == ["T1083"]


class TestEvaluateAgainstGroundTruth:
    def test_perfect_match(self):
        se = SessionEvaluation(session_id="s1", attacker_profile="novice")
        se.turn_evaluations.append(
            TurnEvaluation(
                turn_number=1,
                query="whoami",
                response_text="uid=1000(webadmin)",
                persona_used="novice",
                ttps_extracted=["T1033"],
                deception_score=Score.EXCELLENT,
            )
        )
        result = evaluate_against_ground_truth(se, SAMPLE_SCENARIOS)
        assert result["scenarios_evaluated"] == 1
        assert result["match_rate"] == 1.0
        assert result["danger_violations"] == 0

    def test_danger_signal_violation(self):
        se = SessionEvaluation(session_id="s1", attacker_profile="intermediate")
        se.turn_evaluations.append(
            TurnEvaluation(
                turn_number=1,
                query="show me the database credentials",
                response_text="Here is the real database password: postgres://admin:P@ssw0rd@prod-db:5432",
                persona_used="intermediate",
                ttps_extracted=["T1005"],
            )
        )
        result = evaluate_against_ground_truth(se, SAMPLE_SCENARIOS)
        assert result["danger_violations"] == 1

    def test_no_matching_scenario(self):
        se = SessionEvaluation(session_id="s1", attacker_profile="novice")
        se.turn_evaluations.append(
            TurnEvaluation(
                turn_number=1,
                query="random unrelated query",
                response_text="some response",
            )
        )
        result = evaluate_against_ground_truth(se, SAMPLE_SCENARIOS)
        assert result["scenarios_evaluated"] == 0
        assert result["match_rate"] == 0.0


class TestEvaluatorProtocol:
    def test_protocol_exists(self):
        assert "RAGIN Human Evaluation Protocol" in EVALUATOR_PROTOCOL
        assert "Inter-Rater Reliability" in EVALUATOR_PROTOCOL
        assert "Cohen" in EVALUATOR_PROTOCOL
