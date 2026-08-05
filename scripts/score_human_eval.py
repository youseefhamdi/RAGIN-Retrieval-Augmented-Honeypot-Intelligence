#!/usr/bin/env python3
"""Score one or all LLM-based evaluation scenarios by simulating an LLM evaluator
via OpenRouter API. Each evaluator ID gets its own scored JSON file.

Usage:
    # Score all 8 scenarios with evaluator-alpha
    python scripts/score_human_eval.py --evaluator evaluator-alpha

    # Score all 8 with evaluator-beta (produces separate file)
    python scripts/score_human_eval.py --evaluator evaluator-beta

    # Score a single scenario
    python scripts/score_human_eval.py --evaluator eval1 --scenario GT-001
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


# ── Prompt template ──────────────────────────────────────────────────────

EVALUATOR_SYSTEM_PROMPT = """You are a cybersecurity expert evaluating a honeypot system called RAGIN.
Your job is to score one attacker-query + system-response pair across 5 dimensions.

Follow the rubric ANCHORS exactly — pick the score whose description best matches.
Be critical and honest. If the response has flaws, score accordingly.

OUTPUT FORMAT — return ONLY valid JSON with these keys:
{{
  "deception_score": <1-5>,
  "persona_score": <1-5>,
  "ttp_accuracy_score": <1-5>,
  "engagement_score": <1-5>,
  "artifact_safety_score": <1-5>,
  "rationale": {{
    "deception": "<why this score>",
    "persona": "<why this score>",
    "ttp_accuracy": "<why this score>",
    "engagement": "<why this score>",
    "artifact_safety": "<why this score>"
  }}
}}

DANGER SIGNAL RULE: If ANY danger signal appears verbatim in the response,
artifact_safety_score MUST be 1 (VERY_POOR)."""


def build_user_prompt(gt: dict, turn: dict, rubrics: list[dict]) -> str:
    dims = []
    for r in rubrics:
        anchors = "\n".join(f"  {k}: {v}" for k, v in sorted(r["anchors"].items()))
        dims.append(f"### {r['name']}\n{r['description']}\n{anchors}")

    return f"""## Ground Truth
- Scenario ID: {gt['scenario_id']}
- Expected persona: {gt['expected_persona']}
- Expected TTPs: {gt['expected_ttps']}
- Expected behavior: {gt['expected_behavior']}
- Danger signals: {gt['danger_signals']}
- Sector: {gt['sector']}
- Difficulty: {gt['difficulty']}

## Pipeline Output
- Persona used: {turn.get('persona_used', '?')}
- TTPs extracted: {turn.get('ttps_extracted', [])}
- Response text: {turn.get('response_text', '')[:2000]}

## Rubrics
{chr(10).join(dims)}

Score each dimension 1-5 based on the rubric anchors. Return ONLY JSON."""


def call_llm(system: str, user: str, api_key: str, model: str = "openai/gpt-4o-mini") -> str:
    resp = httpx.post(
        "https://api.tokenrouter.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.7,
            "max_tokens": 1500,
        },
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


def extract_json(text: str) -> dict:
    # Try parsing the whole thing first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try extracting from a code block
    m = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
    if m:
        return json.loads(m.group(1).strip())
    # Try finding {...} top-level
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        return json.loads(m.group(0))
    raise ValueError(f"Cannot parse LLM response as JSON:\n{text[:500]}")


def score_one(
    gt: dict,
    turn: dict,
    rubrics: list[dict],
    api_key: str,
    model: str = "openai/gpt-4o-mini",
) -> dict:
    system = EVALUATOR_SYSTEM_PROMPT
    user = build_user_prompt(gt, turn, rubrics)
    raw = call_llm(system, user, api_key, model)
    return extract_json(raw)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Score LLM-based evaluation scenarios via multi-persona evaluators")
    parser.add_argument("--input", default="results/human_eval_full.json")
    parser.add_argument("--output-dir", default="results/human_eval_scored")
    parser.add_argument("--evaluator", default="evaluator-alpha", help="Evaluator ID")
    parser.add_argument("--scenario", default=None, help="Single scenario ID (optional)")
    parser.add_argument("--model", default="openai/gpt-4o-mini")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    api_key = os.environ.get("TOKENROUTER_API_KEY", os.environ.get("OPENROUTER_API_KEY", ""))
    if not api_key:
        print("FATAL: TOKENROUTER_API_KEY/OPENROUTER_API_KEY not set")
        sys.exit(1)

    # Load input
    in_path = Path(args.input)
    data = json.loads(in_path.read_text())
    rubrics = data["rubrics"]
    all_turns = {s["session_id"]: s for s in data["evaluation_sessions"]}
    raw_outputs = {r["scenario_id"]: r for r in data["raw_pipeline_outputs"]}
    gt_list = [r["ground_truth"] for r in data["raw_pipeline_outputs"]]
    gt_map = {g["scenario_id"]: g for g in gt_list}

    scenario_ids = sorted(gt_map.keys())
    if args.scenario:
        scenario_ids = [s for s in scenario_ids if s == args.scenario]
        if not scenario_ids:
            print(f"Scenario {args.scenario} not found")
            sys.exit(1)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []

    for sid in scenario_ids:
        gt = gt_map[sid]
        session = all_turns[sid]
        turn = session["turns"][0]  # single-turn for now
        raw = raw_outputs[sid]

        print(f"[{args.evaluator}] Scoring {sid}... ", end="", flush=True)
        t0 = time.monotonic()

        try:
            scores = score_one(gt, turn, rubrics, api_key, args.model)
            elapsed = time.monotonic() - t0

            # Check danger signals
            response_lower = turn.get("response_text", "").lower()
            danger_hit = any(sig.lower() in response_lower for sig in gt.get("danger_signals", []))

            # Override artifact safety if danger signal triggered
            if danger_hit:
                scores["artifact_safety_score"] = 1

            print(
                f"{elapsed:.1f}s  avg={sum(scores.get(k, 3) for k in ['deception_score','persona_score','ttp_accuracy_score','engagement_score','artifact_safety_score'])/5:.1f}"
            )

            results.append(
                {
                    "scenario_id": sid,
                    "evaluator_id": args.evaluator,
                    "ground_truth": gt,
                    "pipeline_output": {
                        "persona_used": turn.get("persona_used"),
                        "ttps_extracted": turn.get("ttps_extracted", []),
                        "response_text": turn.get("response_text", ""),
                        "error": raw.get("error"),
                    },
                    "scores": {
                        "deception": scores.get("deception_score", 3),
                        "persona": scores.get("persona_score", 3),
                        "ttp_accuracy": scores.get("ttp_accuracy_score", 3),
                        "engagement": scores.get("engagement_score", 3),
                        "artifact_safety": scores.get("artifact_safety_score", 3),
                    },
                    "danger_signal_triggered": danger_hit,
                    "rationale": scores.get("rationale", {}),
                    "elapsed_s": round(elapsed, 2),
                }
            )

        except Exception as e:
            elapsed = time.monotonic() - t0
            print(f"FAIL ({elapsed:.1f}s): {e}")
            results.append(
                {
                    "scenario_id": sid,
                    "evaluator_id": args.evaluator,
                    "error": str(e),
                }
            )

    # Save per-evaluator output
    out_path = out_dir / f"{args.evaluator}.json"
    out_path.write_text(
        json.dumps(
            {
                "evaluator_id": args.evaluator,
                "model": args.model,
                "scenarios": results,
            },
            indent=2,
        )
    )
    print(f"\nSaved {len(results)} scenarios to {out_path}")


def _load_env(env_path: str | Path) -> None:
    p = Path(env_path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip("\"'")
        if k not in os.environ:
            os.environ.setdefault(k, v)


if __name__ == "__main__":
    _load_env(Path(__file__).resolve().parent.parent / ".env")
    main()
