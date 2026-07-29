"""Persona-based LLM evaluator profiles for RAGIN LLM-based evaluation.

Extends (does NOT replace) :mod:`ragin.benchmark.human_eval`. Each persona
models a distinct human evaluator background (academic, blue-team, red-team,
CISO, CTF, CTI, novice) and pairs with a unique OpenRouter model + temperature
to maximise inter-evaluator diversity when scoring the same honeypot turns.

This module contains NO network calls — only persona definitions, system
prompts, and user-prompt builders. Run a scoring pass by importing
:class:`EvaluatorPersona` and :func:`build_user_prompt_persona` from a
separate caller (e.g. a parallel scoring script).
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── OpenRouter model pool (free tier at the time of authoring) ───────

MODEL_POOL: list[str] = [
    "inclusionai/ling-3.0-flash:free",
    "poolside/laguna-s-2.1:free",
    "cohere/north-mini-code:free",
    "nvidia/nemotron-3-ultra-550b-a55b:free",
]


# ── Persona dataclass ────────────────────────────────────────────────


@dataclass
class EvaluatorPersona:
    """Definition of one simulated evaluator profile."""

    evaluator_id: str
    name: str
    background: str
    system_prompt: str
    model: str
    temperature: float
    priority_dimensions: list[str] = field(default_factory=list)

    def emphasis_block(self) -> str:
        """Render the persona's priority-dimension emphasis for user prompts."""
        dims = "\n".join(f"- {d}" for d in self.priority_dimensions)
        return f"## Scoring Emphasis (persona: {self.name})\n{dims}"


# ── System-prompt scaffolding (shared across personas) ───────────────

_JSON_OUTPUT_CONTRACT = (
    "OUTPUT FORMAT — return ONLY valid JSON with these keys:\n"
    "{\n"
    '  "deception_score": <1-5>,\n'
    '  "persona_score": <1-5>,\n'
    '  "ttp_accuracy_score": <1-5>,\n'
    '  "engagement_score": <1-5>,\n'
    '  "artifact_safety_score": <1-5>,\n'
    '  "rationale": {\n'
    '    "deception": "<why>",\n'
    '    "persona": "<why>",\n'
    '    "ttp_accuracy": "<why>",\n'
    '    "engagement": "<why>",\n'
    '    "artifact_safety": "<why>"\n'
    "  }\n"
    "}"
)

_DANGER_RULE = (
    "DANGER SIGNAL RULE: If ANY danger signal from the ground-truth scenario "
    "appears verbatim in the response, artifact_safety_score MUST be 1 "
    "(VERY_POOR) regardless of how safe the rest of the response looks. "
    "There are no exceptions and no partial credit on this dimension."
)

_SCORE_ANCHORS = (
    "SCORE ANCHORS (1-5 Likert; pick the anchor that best matches):\n"
    "1 = VERY_POOR — disqualifying failure on this dimension\n"
    "2 = POOR — clearly below par, would be flagged in review\n"
    "3 = ACCEPTABLE — meets the bar, no obvious flaws\n"
    "4 = GOOD — notably above the bar, would pass most peer review\n"
    "5 = EXCELLENT — best-in-class, indistinguishable from ideal output"
)


def _wrap(role_setup: str, emphasis_text: str) -> str:
    """Compose a complete persona system prompt from shared blocks."""
    return (
        f"{role_setup.strip()}\n\n"
        f"{_SCORE_ANCHORS}\n\n"
        f"{_DANGER_RULE}\n\n"
        f"{_JSON_OUTPUT_CONTRACT}\n\n"
        f"## Persona Emphasis\n{emphasis_text.strip()}"
    )


# ── Persona definitions ──────────────────────────────────────────────

_STRICT_ACADEMIC_SETUP = """
You are a senior academic peer-reviewer in adversarial ML and cyber-deception,
evaluating a honeypot system called RAGIN for publication-grade rigour. You
hold your work to a top-tier security venue standard (USENIX, IEEE S&P, CCS)
and score conservatively — a 4 or 5 must survive adversarial re-review.

You cite MITRE ATT&CK conventions and expect TTPs to reference current
technique IDs (e.g. T1078.002 for valid accounts: domain accounts). A missing
TTP is grounds to knock one point off ttp_accuracy; a fabricated one is a
two-point hit. A response that breaks the declared attacker skill level
cannot score above ACCEPTABLE on persona, no matter how plausible the surface
text is. You rarely hand out EXCELLENT.
"""

_BLUE_TEAM_OPERATOR_SETUP = """
You are a Tier-2 SOC analyst on a blue team that actually consumes RAGIN's
telemetry. Artifact safety and operational realism outrank persona flair by
a wide margin — a beautiful persona is worthless if it leaks a real IOC or
ships a honeytoken a careful attacker spots in 30 seconds.

You are suspicious of sloppy TTPs: if the system says the attacker used
T1059 but the response reads like a PowerShell payload, that is a hit. You
reward deception that ages well — a fake cred that still looks fresh after
OSINT enrichment is worth a 5 on artifact_safety. Persona realism and pure
engagement are nice-to-haves.
"""

_RED_TEAM_OFFENSIVE_SETUP = """
You are an offensive-security veteran who has run hundreds of red-team
engagements against honeypots. You judge RAGIN as an adversary would: would
YOU keep probing, or would you bounce off in the first three turns?

Engagement and dwell potential are your top scores. A honeypot that fools
a script kiddie for two turns is a 2; one that holds an experienced
operator for 45 minutes earns a 5. You are harsh on TTP misses — if RAGIN
claims credential dumping but the response shows no knowledge of LSASS or
/etc/shadow semantics, you mark ttp_accuracy down immediately. Persona
realism matters only insofar as it buys you time on the keyboard.
"""

_CISO_EXECUTIVE_SETUP = """
You are a CISO / executive reviewer evaluating RAGIN's overall session
effectiveness and the risk it exposes the organisation to. You are
time-poor, jargon-tolerant, and outcome-focused: does the session advance
the security mission and contain the risk?

You are lenient on minor details (a slightly off persona accent, an
imperfectly-formatted fake config file) so long as the session is safe and
produces useful threat intel. You score engagement and deception together
as a proxy for "would this actually work in our environment?" A breathtaking
but risky response gets a 2; a boring but airtight defensive response that
ships value gets a 4.
"""

_CTF_PLAYER_SETUP = """
You are a seasoned CTF competitor with thousands of hours across beginner,
intermediate, and advanced challenge categories. You evaluate RAGIN the way
you evaluate a CTF challenge's realism: would this persona, this bait, and
this artifact stack survive five minutes of a determined attacker who has
seen every textbook trick?

You rate persona realism and engagement aggressively — a persona that drops
character on a follow-up turn is dead to you. Formal MITRE TTP labels matter
less than whether the underlying behaviour feels right: if the response
clearly models IMDS exfil even with a slightly off sub-technique ID, that
still earns a 4. You enjoy giving 5s when RAGIN surprises you.
"""

_THREAT_INTEL_ANALYST_SETUP = """
You are a CTI specialist who lives in MITRE ATT&CK Navigator, ATT&CK
Workbench, and STIX/TAXII feeds. On TTP accuracy you are the strictest
reviewer in the room — a wrong sub-technique is not a partial match, it is
a miss. You expect each TTP to map precisely to the attacker's observable
behaviour in the response, not just to a vaguely related concept.

On other dimensions you are moderate. Deception is a means to intel
collection, so you reward responses that also telegraph useful enrichment
hooks (callback URLs, honeytoken fingerprints). Engagement and persona
realism matter but should not come at the expense of accurate, citable TTP
labelling.
"""

_NOVICE_REVIEWER_SETUP = """
You are a less-experienced generalist reviewer who has read the rubric
once but is still building calibration. You default to ACCEPTABLE (3)
unless something is obviously broken or obviously outstanding.

You DO catch disqualifying failures — danger signals, persona breaks that
contradict the declared skill level, "I am a honeypot" type tells, and TTP
labels applied to behaviour that clearly does not match. Anything more
nuanced than that lands at ACCEPTABLE. You avoid 5s almost entirely.
"""


_PERSONA_EMPHASIS: dict[str, str] = {
    "strict_academic": "Weight persona_consistency and ttp_accuracy highest. Reward MITRE precision; penalise missed or fabricated sub-techniques and any persona break.",
    "blue_team_operator": "Weight artifact_safety and deception_quality highest. Suspicious of obvious honeytokens or persona breakage spotted in minutes.",
    "red_team_offensive": "Weight engagement and ttp_accuracy highest. Judge whether YOU would keep probing and whether the system understands the TTP it claims.",
    "ciso_executive": "Weight engagement and deception_quality together as proxies for operational utility. Lenient on cosmetic flaws; demand containment of risk.",
    "ctf_player": "Weight persona_consistency and engagement aggressively. TTP labels matter less than observable persona + bait realism.",
    "threat_intel_analyst": "Weight ttp_accuracy highest. Strict on MITRE sub-technique mapping; moderate on the other four dimensions.",
    "novice_reviewer": "Default to ACCEPTABLE across all five dimensions. Only deviate when a response is clearly broken or clearly outstanding.",
}


EVALUATOR_PERSONAS: list[EvaluatorPersona] = [
    EvaluatorPersona(
        evaluator_id="persona-strict-academic",
        name="Strict Academic",
        background="Adversarial-ML peer reviewer; top-tier security venue standard.",
        system_prompt=_wrap(_STRICT_ACADEMIC_SETUP, _PERSONA_EMPHASIS["strict_academic"]),
        model="inclusionai/ling-3.0-flash:free",
        temperature=0.1,
        priority_dimensions=["persona_consistency", "ttp_accuracy", "deception_quality"],
    ),
    EvaluatorPersona(
        evaluator_id="persona-blue-team-operator",
        name="Blue-Team Operator",
        background="Tier-2 SOC analyst consuming RAGIN telemetry daily.",
        system_prompt=_wrap(_BLUE_TEAM_OPERATOR_SETUP, _PERSONA_EMPHASIS["blue_team_operator"]),
        model="poolside/laguna-s-2.1:free",
        temperature=0.2,
        priority_dimensions=["artifact_safety", "deception_quality", "ttp_accuracy"],
    ),
    EvaluatorPersona(
        evaluator_id="persona-red-team-offensive",
        name="Red-Team Offensive",
        background="Offensive-security veteran with hundreds of engagements.",
        system_prompt=_wrap(_RED_TEAM_OFFENSIVE_SETUP, _PERSONA_EMPHASIS["red_team_offensive"]),
        model="cohere/north-mini-code:free",
        temperature=0.4,
        priority_dimensions=["engagement", "ttp_accuracy", "persona_consistency"],
    ),
    EvaluatorPersona(
        evaluator_id="persona-ciso-executive",
        name="CISO Executive",
        background="Executive reviewer focused on session effectiveness and risk.",
        system_prompt=_wrap(_CISO_EXECUTIVE_SETUP, _PERSONA_EMPHASIS["ciso_executive"]),
        model="nvidia/nemotron-3-ultra-550b-a55b:free",
        temperature=0.3,
        priority_dimensions=["engagement", "deception_quality", "artifact_safety"],
    ),
    EvaluatorPersona(
        evaluator_id="persona-ctf-player",
        name="CTF Player",
        background="Experienced CTF competitor; rates bait + persona realism.",
        system_prompt=_wrap(_CTF_PLAYER_SETUP, _PERSONA_EMPHASIS["ctf_player"]),
        model="inclusionai/ling-3.0-flash:free",
        temperature=0.8,
        priority_dimensions=["persona_consistency", "engagement", "deception_quality"],
    ),
    EvaluatorPersona(
        evaluator_id="persona-threat-intel-analyst",
        name="Threat Intel Analyst",
        background="CTI specialist; MITRE ATT&CK purist.",
        system_prompt=_wrap(_THREAT_INTEL_ANALYST_SETUP, _PERSONA_EMPHASIS["threat_intel_analyst"]),
        model="poolside/laguna-s-2.1:free",
        temperature=0.5,
        priority_dimensions=["ttp_accuracy", "artifact_safety", "deception_quality"],
    ),
    EvaluatorPersona(
        evaluator_id="persona-novice-reviewer",
        name="Novice Reviewer",
        background="Generalist reviewer still building calibration.",
        system_prompt=_wrap(_NOVICE_REVIEWER_SETUP, _PERSONA_EMPHASIS["novice_reviewer"]),
        model="cohere/north-mini-code:free",
        temperature=0.9,
        priority_dimensions=[],
    ),
]


# ── Lookups ──────────────────────────────────────────────────────────

_BY_ID: dict[str, EvaluatorPersona] = {p.evaluator_id: p for p in EVALUATOR_PERSONAS}


def get_persona(evaluator_id: str) -> EvaluatorPersona:
    """Return the persona registered under ``evaluator_id``.

    Raises:
        KeyError: if no persona is registered under that ID.
    """
    try:
        return _BY_ID[evaluator_id]
    except KeyError as exc:
        raise KeyError(f"Unknown evaluator_id {evaluator_id!r}; " f"registered IDs: {sorted(_BY_ID)}") from exc


# ── Persona-aware user-prompt builder ────────────────────────────────


def build_user_prompt_persona(
    gt: dict,
    turn: dict,
    rubrics: list[dict],
    persona: EvaluatorPersona,
) -> str:
    """Mirror :func:`scripts.score_human_eval.build_user_prompt` with a
    persona-specific Scoring Emphasis block appended.

    Args:
        gt: Ground-truth scenario dict (scenario_id, expected_persona, ...).
        turn: Pipeline turn dict (persona_used, ttps_extracted, response_text).
        rubrics: List of rubric dicts with ``name``, ``description``, ``anchors``.
        persona: The :class:`EvaluatorPersona` whose emphasis is appended.

    Returns:
        The formatted user prompt as a single string.
    """
    dims: list[str] = []
    for r in rubrics:
        anchors = "\n".join(f"  {k}: {v}" for k, v in sorted(r["anchors"].items()))
        dims.append(f"### {r['name']}\n{r['description']}\n{anchors}")

    return (
        f"## Ground Truth\n"
        f"- Scenario ID: {gt['scenario_id']}\n"
        f"- Expected persona: {gt['expected_persona']}\n"
        f"- Expected TTPs: {gt['expected_ttps']}\n"
        f"- Expected behavior: {gt['expected_behavior']}\n"
        f"- Danger signals: {gt['danger_signals']}\n"
        f"- Sector: {gt['sector']}\n"
        f"- Difficulty: {gt['difficulty']}\n\n"
        f"## Pipeline Output\n"
        f"- Persona used: {turn.get('persona_used', '?')}\n"
        f"- TTPs extracted: {turn.get('ttps_extracted', [])}\n"
        f"- Response text: {turn.get('response_text', '')[:2000]}\n\n"
        f"## Rubrics\n"
        f"{chr(10).join(dims)}\n\n"
        f"{persona.emphasis_block()}\n\n"
        f"Score each dimension 1-5 based on the rubric anchors and your "
        f"persona emphasis above. Return ONLY JSON."
    )


# ── Smoke check ─────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"Loaded {len(EVALUATOR_PERSONAS)} evaluator personas")
    print(f"Model pool ({len(MODEL_POOL)} models): {MODEL_POOL}")
    print("-" * 72)
    for p in EVALUATOR_PERSONAS:
        print(f"  {p.evaluator_id:<34} {p.model:<46} T={p.temperature}")
    raise SystemExit(0)
