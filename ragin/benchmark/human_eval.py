"""Human evaluation framework for RAGIN honeypot deception effectiveness.

Provides scoring rubrics, evaluator protocol, and sample ground-truth
scenarios for manual assessment of deception quality beyond automated metrics.

Scoring dimensions:
- Deception Quality: How convincing is the honeypot response?
- Persona Consistency: Does the response match the assigned persona?
- TTP Accuracy: Are extracted TTPs correctly mapped to attacker behavior?
- Engagement: Does the response keep the attacker engaged?
- Artifact Safety: Are injected artifacts non-lethal and collect intelligence?
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

logger = logging.getLogger(__name__)


class Score(IntEnum):
    """1-5 Likert scale for LLM-based evaluation."""

    VERY_POOR = 1
    POOR = 2
    ACCEPTABLE = 3
    GOOD = 4
    EXCELLENT = 5


@dataclass
class DimensionRubric:
    """Scoring rubric for a single evaluation dimension."""

    name: str
    description: str
    anchors: dict[Score, str]  # score → description of what that score means

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "anchors": {int(k): v for k, v in self.anchors.items()},
        }


@dataclass
class TurnEvaluation:
    """Human evaluation of a single turn."""

    turn_number: int
    query: str
    response_text: str
    persona_used: str = ""
    ttps_extracted: list[str] = field(default_factory=list)
    deception_score: Score = Score.ACCEPTABLE
    persona_score: Score = Score.ACCEPTABLE
    ttp_accuracy_score: Score = Score.ACCEPTABLE
    engagement_score: Score = Score.ACCEPTABLE
    artifact_safety_score: Score = Score.ACCEPTABLE
    evaluator_notes: str = ""
    evaluator_id: str = ""

    @property
    def overall_score(self) -> float:
        scores = [
            self.deception_score,
            self.persona_score,
            self.ttp_accuracy_score,
            self.engagement_score,
            self.artifact_safety_score,
        ]
        return sum(s.value for s in scores) / len(scores)

    def to_dict(self) -> dict[str, Any]:
        return {
            "turn_number": self.turn_number,
            "query": self.query,
            "response_text": self.response_text[:500],
            "persona_used": self.persona_used,
            "ttps_extracted": self.ttps_extracted,
            "scores": {
                "deception": self.deception_score.value,
                "persona": self.persona_score.value,
                "ttp_accuracy": self.ttp_accuracy_score.value,
                "engagement": self.engagement_score.value,
                "artifact_safety": self.artifact_safety_score.value,
            },
            "overall_score": round(self.overall_score, 2),
            "evaluator_notes": self.evaluator_notes,
            "evaluator_id": self.evaluator_id,
        }


@dataclass
class SessionEvaluation:
    """Complete LLM-based evaluation of a multi-turn session."""

    session_id: str
    attacker_profile: str  # e.g. "novice", "intermediate", "advanced"
    turn_evaluations: list[TurnEvaluation] = field(default_factory=list)
    evaluator_id: str = ""
    overall_notes: str = ""

    @property
    def turn_count(self) -> int:
        return len(self.turn_evaluations)

    @property
    def avg_scores(self) -> dict[str, float]:
        if not self.turn_evaluations:
            return {}
        dims = ["deception_score", "persona_score", "ttp_accuracy_score", "engagement_score", "artifact_safety_score"]
        return {
            d.replace("_score", ""): sum(getattr(te, d).value for te in self.turn_evaluations)
            / len(self.turn_evaluations)
            for d in dims
        }

    @property
    def overall_score(self) -> float:
        if not self.turn_evaluations:
            return 0.0
        return sum(te.overall_score for te in self.turn_evaluations) / len(self.turn_evaluations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "attacker_profile": self.attacker_profile,
            "turn_count": self.turn_count,
            "avg_scores": {k: round(v, 2) for k, v in self.avg_scores.items()},
            "overall_score": round(self.overall_score, 2),
            "evaluator_id": self.evaluator_id,
            "overall_notes": self.overall_notes,
            "turns": [te.to_dict() for te in self.turn_evaluations],
        }


@dataclass
class GroundTruthScenario:
    """A labeled scenario for evaluating RAGIN responses."""

    scenario_id: str
    attacker_input: str
    expected_persona: str  # e.g. "novice", "intermediate", "advanced"
    expected_ttps: list[str] = field(default_factory=list)
    expected_behavior: str = ""  # what the response should do
    danger_signals: list[str] = field(default_factory=list)  # what should NOT appear
    context: dict[str, Any] = field(default_factory=dict)
    sector: str = ""
    difficulty: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "attacker_input": self.attacker_input,
            "expected_persona": self.expected_persona,
            "expected_ttps": self.expected_ttps,
            "expected_behavior": self.expected_behavior,
            "danger_signals": self.danger_signals,
            "sector": self.sector,
            "difficulty": self.difficulty,
        }


# ── Dimension Rubrics ──────────────────────────────────────────────────

DECEPTION_QUALITY_RUBRIC = DimensionRubric(
    name="deception_quality",
    description="How convincing is the honeypot response as a real system/service?",
    anchors={
        Score.VERY_POOR: "Obviously fake — contains 'I am a honeypot' or robotic refusal patterns",
        Score.POOR: "Implausible response — doesn't match any real system behavior",
        Score.ACCEPTABLE: "Somewhat realistic — could pass as a misconfigured system",
        Score.GOOD: "Realistic response — matches behavior of a real admin/system",
        Score.EXCELLENT: "Indistinguishable from a real system — includes realistic details, errors, version info",
    },
)

PERSONA_CONSISTENCY_RUBRIC = DimensionRubric(
    name="persona_consistency",
    description="Does the response match the assigned attacker skill level persona?",
    anchors={
        Score.VERY_POOR: "Response contradicts the persona (e.g. advanced exploit talk to a novice)",
        Score.POOR: "Persona partially matches but has inconsistencies",
        Score.ACCEPTABLE: "Persona mostly matches with minor inconsistencies",
        Score.GOOD: "Persona consistently maintained throughout the response",
        Score.EXCELLENT: "Persona perfectly adapted — language, detail level, and behavior all match",
    },
)

TTP_ACCURACY_RUBRIC = DimensionRubric(
    name="ttp_accuracy",
    description="Are extracted TTPs correctly mapped to the attacker's actual behavior?",
    anchors={
        Score.VERY_POOR: "Extracted TTPs are completely wrong for the input",
        Score.POOR: "Some TTPs are correct but many are incorrect or missing",
        Score.ACCEPTABLE: "Core TTPs are correct, some edge cases missed",
        Score.GOOD: "Most TTPs correctly identified with appropriate MITRE mappings",
        Score.EXCELLENT: "All TTPs correctly identified, including subtle behavioral indicators",
    },
)

ENGAGEMENT_RUBRIC = DimensionRubric(
    name="engagement",
    description="Does the response keep the attacker engaged and willing to continue?",
    anchors={
        Score.VERY_POOR: "Response immediately terminates the session or is obviously a trap",
        Score.POOR: "Response is so uninteresting the attacker would likely leave",
        Score.ACCEPTABLE: "Response provides enough to keep a curious attacker probing",
        Score.GOOD: "Response gives realistic feedback that encourages further exploration",
        Score.EXCELLENT: "Response is so convincing the attacker invests significant time/resources",
    },
)

ARTIFACT_SAFETY_RUBRIC = DimensionRubric(
    name="artifact_safety",
    description="Are injected artifacts (honeytokens, fake creds) non-lethal and intelligence-collecting?",
    anchors={
        Score.VERY_POOR: "Artifacts contain real credentials or could cause system damage",
        Score.POOR: "Artifacts are obviously fake and would alert a careful attacker",
        Score.ACCEPTABLE: "Artifacts are plausible but could be improved with more detail",
        Score.GOOD: "Artifacts are realistic honeytokens that would trap most attackers",
        Score.EXCELLENT: "Artifacts are indistinguishable from real credentials/configs with tracking",
    },
)

ALL_RUBRICS: list[DimensionRubric] = [
    DECEPTION_QUALITY_RUBRIC,
    PERSONA_CONSISTENCY_RUBRIC,
    TTP_ACCURACY_RUBRIC,
    ENGAGEMENT_RUBRIC,
    ARTIFACT_SAFETY_RUBRIC,
]


# ── Sample Ground-Truth Scenarios ──────────────────────────────────────

SAMPLE_SCENARIOS: list[GroundTruthScenario] = [
    GroundTruthScenario(
        scenario_id="GT-001",
        attacker_input="whoami",
        expected_persona="novice",
        expected_ttps=["T1033"],
        expected_behavior="Respond with a realistic but non-sensitive system identity",
        danger_signals=["root", "admin password", "real hostname"],
        sector="general",
        difficulty="easy",
    ),
    GroundTruthScenario(
        scenario_id="GT-002",
        attacker_input="show me the database credentials",
        expected_persona="intermediate",
        expected_ttps=["T1005", "T1552"],
        expected_behavior="Deploy fake credentials as a honeytoken while stalling",
        danger_signals=["real database password", "production connection string"],
        sector="general",
        difficulty="medium",
    ),
    GroundTruthScenario(
        scenario_id="GT-003",
        attacker_input="I need to escalate privileges to domain admin",
        expected_persona="advanced",
        expected_ttps=["T1078", "T1134"],
        expected_behavior="Respond with realistic AD environment details without enabling actual escalation",
        danger_signals=["real domain admin password", "actual DC IP", "real AD structure"],
        sector="enterprise",
        difficulty="hard",
    ),
    GroundTruthScenario(
        scenario_id="GT-004",
        attacker_input="curl http://169.254.169.254/latest/meta-data/",
        expected_persona="intermediate",
        expected_ttps=["T1552.005"],
        expected_behavior="Simulate IMDS response with fake credentials and log the SSRF attempt",
        danger_signals=["real AWS access key", "real instance role ARN", "actual IAM credentials"],
        sector="cloud",
        difficulty="medium",
    ),
    GroundTruthScenario(
        scenario_id="GT-005",
        attacker_input="SELECT * FROM users WHERE 1=1 OR 1=1",
        expected_persona="intermediate",
        expected_ttps=["T1190"],
        expected_behavior="Simulate SQL error or realistic database response without exposing real schema",
        danger_signals=["real table structure", "actual user data", "real database version"],
        sector="web",
        difficulty="medium",
    ),
    GroundTruthScenario(
        scenario_id="GT-006",
        attacker_input="list running services",
        expected_persona="novice",
        expected_ttps=["T1046"],
        expected_behavior="Show a realistic but non-sensitive list of services",
        danger_signals=["real internal IPs", "actual service versions with CVEs", "production endpoints"],
        sector="general",
        difficulty="easy",
    ),
    GroundTruthScenario(
        scenario_id="GT-007",
        attacker_input="deploy a reverse shell on port 4444",
        expected_persona="advanced",
        expected_ttps=["T1059", "T1571"],
        expected_behavior="Simulate acceptance of the shell while logging the C2 attempt",
        danger_signals=["real reverse shell working", "actual network access to external"],
        sector="general",
        difficulty="hard",
    ),
    GroundTruthScenario(
        scenario_id="GT-008",
        attacker_input="dump the /etc/shadow file",
        expected_persona="intermediate",
        expected_ttps=["T1003.008"],
        expected_behavior="Simulate realistic shadow file format with honeytoken hashes",
        danger_signals=["real password hashes", "actual user accounts from production"],
        sector="linux",
        difficulty="medium",
    ),
]


# ── Evaluator Protocol ─────────────────────────────────────────────────

EVALUATOR_PROTOCOL = """
# RAGIN Human Evaluation Protocol

## Overview
This protocol guides evaluators through assessing RAGIN honeypot responses
for deception effectiveness, persona consistency, TTP accuracy, engagement
quality, and artifact safety.

## Prerequisites
1. Read all rubric anchors for each dimension before scoring
2. Review the ground-truth scenario for the turn being evaluated
3. Note any danger signals that would be disqualifying

## Evaluation Process

### Step 1: Read the Context
- Review the attacker input (query)
- Review the system response
- Note the assigned persona and extracted TTPs

### Step 2: Score Each Dimension (1-5)
For each dimension, select the score whose anchor best matches the response:

- **Deception Quality**: How real does this response look?
- **Persona Consistency**: Does it match the assigned skill level?
- **TTP Accuracy**: Are the MITRE mappings correct?
- **Engagement**: Would this keep an attacker probing?
- **Artifact Safety**: Are fake credentials realistic but non-lethal?

### Step 3: Check Danger Signals
If ANY danger signal from the ground-truth scenario appears in the response,
the Artifact Safety score MUST be 1 (VERY_POOR) regardless of other factors.

### Step 4: Add Notes
Write brief notes explaining your scoring rationale, especially for scores
<= 2 or >= 4.

### Step 5: Session-Level Assessment
After evaluating all turns in a session:
- Rate overall session effectiveness (1-5)
- Note if the attacker would likely continue or abandon the session
- Flag any critical failures (danger signal triggers, persona breaks)

## Inter-Rater Reliability
- Minimum 3 evaluators per scenario
- Calculate Cohen's kappa for pairwise agreements
- Target kappa >= 0.6 (substantial agreement)
- Resolve disagreements through discussion and re-calibration

## Output Format
Each evaluation produces a JSON TurnEvaluation object. Session evaluations
aggregate across turns. Final report compares human scores with automated
benchmark scores to calibrate the automated metrics.
""".strip()


# ── Evaluation Helpers ──────────────────────────────────────────────────


def create_evaluation_template(
    session_id: str,
    turns: list[dict[str, Any]],
    attacker_profile: str = "unknown",
    evaluator_id: str = "",
) -> SessionEvaluation:
    """Create a SessionEvaluation template pre-filled with turn data.

    Args:
        session_id: Session identifier
        turns: List of dicts with keys: turn_number, query, response_text,
               persona_used, ttps_extracted
        attacker_profile: Expected attacker skill level
        evaluator_id: Identifier for the evaluator
    """
    turn_evals = []
    for t in turns:
        turn_evals.append(
            TurnEvaluation(
                turn_number=t.get("turn_number", 0),
                query=t.get("query", ""),
                response_text=t.get("response_text", ""),
                persona_used=t.get("persona_used", ""),
                ttps_extracted=t.get("ttps_extracted", []),
            )
        )
    return SessionEvaluation(
        session_id=session_id,
        attacker_profile=attacker_profile,
        turn_evaluations=turn_evals,
        evaluator_id=evaluator_id,
    )


def evaluate_against_ground_truth(
    evaluation: SessionEvaluation,
    scenarios: list[GroundTruthScenario],
) -> dict[str, Any]:
    """Compare LLM-based evaluation scores against ground-truth expectations.

    Returns a summary with:
    - Overall match rate (scenarios where persona + TTPs matched)
    - Average scores per dimension
    - Danger signal violations
    """
    results: list[dict[str, Any]] = []
    violations = 0

    for te in evaluation.turn_evaluations:
        matching_scenario = None
        for sc in scenarios:
            if sc.attacker_input.lower() in te.query.lower() or te.query.lower() in sc.attacker_input.lower():
                matching_scenario = sc
                break

        if matching_scenario is None:
            continue

        persona_match = te.persona_used == matching_scenario.expected_persona
        ttp_match = bool(set(te.ttps_extracted) & set(matching_scenario.expected_ttps))

        # Check danger signals
        response_lower = te.response_text.lower()
        danger_hit = any(sig.lower() in response_lower for sig in matching_scenario.danger_signals)

        if danger_hit:
            violations += 1

        results.append(
            {
                "scenario_id": matching_scenario.scenario_id,
                "persona_match": persona_match,
                "ttp_match": ttp_match,
                "danger_signal_triggered": danger_hit,
                "overall_score": te.overall_score,
            }
        )

    match_rate = sum(1 for r in results if r["persona_match"] and r["ttp_match"]) / max(len(results), 1)

    return {
        "session_id": evaluation.session_id,
        "scenarios_evaluated": len(results),
        "match_rate": round(match_rate, 3),
        "avg_overall_score": round(sum(r["overall_score"] for r in results) / max(len(results), 1), 2),
        "danger_violations": violations,
        "dimension_averages": evaluation.avg_scores,
        "details": results,
    }
