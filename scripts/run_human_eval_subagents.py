#!/usr/bin/env python3
"""Multi-persona LLM evaluator driver for RAGIN LLM-based evaluation.

Fans 7 evaluator personas out across 8 ground-truth scenarios (56 LLM calls)
with bounded concurrency, retries, danger-signal override, and consensus metrics
(pairwise Cohen kappa + Krippendorff alpha).  Run ``--dry-run`` to verify wiring.

Usage:
    python scripts/run_human_eval_subagents.py --dry-run
    python scripts/run_human_eval_subagents.py --input results/human_eval_full.json
    python scripts/run_human_eval_subagents.py --evaluators persona-strict-academic,persona-novice-reviewer
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import re
import statistics
import sys
import time
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import numpy as np  # type: ignore

    _NUMPY_OK = True
except Exception:  # pragma: no cover
    np = None  # type: ignore
    _NUMPY_OK = False

import httpx

from ragin.benchmark.human_eval_personas import (
    EVALUATOR_PERSONAS,
    build_user_prompt_persona,
)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_PER_CALL_TIMEOUT = 30.0
SCORE_DIMS = ("deception", "persona", "ttp_accuracy", "engagement", "artifact_safety")
SCORE_KEYS = tuple(f"{d}_score" for d in SCORE_DIMS)
MAX_PERSONAS = 7


def _load_env(env_path: str | Path) -> None:
    p = Path(env_path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip("\"'"))


def extract_json(text: str) -> dict:
    """Tolerant JSON parser: raw -> code-fence -> top-level braces."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
    if m:
        return json.loads(m.group(1).strip())
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        return json.loads(m.group(0))
    raise ValueError(f"Cannot parse LLM response as JSON: {text[:500]}")


async def call_llm_async(client, api_key, persona, system, user, sem):
    """POST to OpenRouter with bounded concurrency + exponential backoff."""
    payload = {
        "model": persona.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": persona.temperature,
        "max_tokens": 1500,
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    backoffs = [0.0, 1.0, 2.0, 4.0]
    last_err: Exception | None = None
    async with sem:
        for sleep_s in backoffs:
            if sleep_s:
                await asyncio.sleep(sleep_s)
            try:
                resp = await client.post(
                    OPENROUTER_URL,
                    headers=headers,
                    json=payload,
                    timeout=DEFAULT_PER_CALL_TIMEOUT,
                )
                if resp.status_code in (429, 500, 502, 503, 504):
                    last_err = httpx.HTTPStatusError(f"{resp.status_code}", request=resp.request, response=resp)
                    continue
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"].strip()
            except (httpx.HTTPError, json.JSONDecodeError, KeyError) as e:
                last_err = e
                continue
    raise RuntimeError(f"LLM call failed after {len(backoffs)} attempts: {last_err}")


def _coerce_int(value, default=3):
    try:
        v = int(round(float(value)))
    except (TypeError, ValueError):
        return default
    return max(1, min(5, v))


def danger_signal_triggered(gt, response_text):
    rt = (response_text or "").lower()
    return any(str(s).lower() in rt for s in gt.get("danger_signals", []) or [])


async def score_pair(client, api_key, persona, gt, turn, rubrics, sem):
    """Score one (scenario, persona) pair with one JSON-retry fallback."""
    user = build_user_prompt_persona(gt, turn, rubrics, persona)
    t0 = time.monotonic()
    raw_text, scores, error = "", None, None
    for attempt_idx, sys_prompt in enumerate(
        (persona.system_prompt, persona.system_prompt + "\n\nRETURN ONLY JSON. NO PROSE. NO MARKDOWN."), 1
    ):
        try:
            raw_text = await call_llm_async(client, api_key, persona, sys_prompt, user, sem)
            scores = extract_json(raw_text)
            error = None
            break
        except Exception as e:
            error = f"attempt{attempt_idx}: {type(e).__name__}: {e}"
    elapsed = round(time.monotonic() - t0, 2)
    danger = danger_signal_triggered(gt, turn.get("response_text", ""))
    if scores is None:
        return {
            "scenario_id": gt["scenario_id"],
            "scores": {d: 3 for d in SCORE_DIMS},
            "rationale": {d: "" for d in SCORE_DIMS},
            "danger_signal_triggered": danger,
            "error": error or "unknown error",
            "raw_response_excerpt": "",
            "elapsed_s": elapsed,
        }
    coerced = {k: _coerce_int(scores.get(k, 3)) for k in SCORE_KEYS}
    if danger:
        coerced["artifact_safety_score"] = 1
    rationale = scores.get("rationale", {}) if isinstance(scores.get("rationale"), dict) else {}
    return {
        "scenario_id": gt["scenario_id"],
        "scores": {d: coerced[f"{d}_score"] for d in SCORE_DIMS},
        "rationale": {d: str(rationale.get(d, "")) for d in SCORE_DIMS},
        "danger_signal_triggered": danger,
        "error": None,
        "raw_response_excerpt": (raw_text or "")[:400],
        "elapsed_s": elapsed,
    }


def _mean(v):
    if not v:
        return 0.0
    return float(np.mean(v)) if _NUMPY_OK else statistics.fmean(v)


def _median(v):
    if not v:
        return 0.0
    return float(np.median(v)) if _NUMPY_OK else statistics.median(v)


def _std(v):
    if len(v) < 2:
        return 0.0
    return float(np.std(v, ddof=0)) if _NUMPY_OK else statistics.pstdev(v)


def cohens_kappa_ordinal(a, b):
    """Weighted (squared) Cohen's kappa on 5-class ordinal ratings."""
    if len(a) != len(b) or not a:
        return None
    n, cats = len(a), [1, 2, 3, 4, 5]

    def w(i, j):
        return 1.0 - ((i - j) ** 2) / 16.0

    po = sum(w(x, y) for x, y in zip(a, b, strict=False)) / n
    pe = sum(w(i, j) * (a.count(i) / n) * (b.count(j) / n) for i in cats for j in cats)
    if abs(1.0 - pe) < 1e-12:
        return None
    return (po - pe) / (1.0 - pe)


def krippendorff_alpha_ordinal(matrix):
    """Krippendorff alpha on 5-class ordinal. matrix[r][c]=rater/item rating; None=missing."""
    if not matrix or not matrix[0]:
        return None
    n_raters, n_items = len(matrix), len(matrix[0])
    values = [v for r in matrix for v in r if v is not None]
    if len(values) < 2:
        return None
    cats = sorted(set(values))
    cat_range = max(cats) - min(cats)

    def dist(i, j):
        return ((i - j) ** 2) / (cat_range**2) if cat_range else 0.0

    observed_num, denom = 0.0, 0
    for c in range(n_items):
        col = [matrix[r][c] for r in range(n_raters) if matrix[r][c] is not None]
        m = len(col)
        if m < 2:
            continue
        for i in range(m):
            for j in range(m):
                if i != j:
                    observed_num += dist(col[i], col[j])
        denom += m * (m - 1)
    if denom == 0:
        return None
    observed = observed_num / denom
    counts = {c: values.count(c) for c in cats}
    n_total = len(values)
    expected_num = 0.0
    for ci in cats:
        for cj in cats:
            if counts[ci] == 0 or counts[cj] == 0:
                continue
            pair = counts[ci] * (counts[cj] - 1) if ci == cj else counts[ci] * counts[cj]
            expected_num += dist(ci, cj) * pair
    expected = expected_num / (n_total * (n_total - 1)) if n_total > 1 else 1
    if abs(expected) < 1e-12:
        return None
    return 1.0 - (observed / expected)


def aggregate_consensus(per_persona):
    by_scenario: dict[str, dict[str, dict]] = {}
    for eid, payload in per_persona.items():
        for s in payload.get("scenarios", []):
            by_scenario.setdefault(s["scenario_id"], {})[eid] = s

    scenario_ids = sorted(by_scenario.keys())
    evaluator_ids = sorted(per_persona.keys())

    per_scenario_stats: dict[str, dict] = {}
    disagreements: list[str] = []
    all_by_dim: dict[str, list[float]] = {d: [] for d in SCORE_DIMS}
    all_overall: list[float] = []

    for sid in scenario_ids:
        emap = by_scenario[sid]
        per_dim: dict[str, dict] = {}
        for dim in SCORE_DIMS:
            vals = [emap[e]["scores"][dim] for e in evaluator_ids if e in emap]
            if not vals:
                continue
            per_dim[dim] = {
                "mean": round(_mean(vals), 3),
                "median": round(_median(vals), 3),
                "std_dev": round(_std(vals), 3),
                "min": int(min(vals)),
                "max": int(max(vals)),
            }
            all_by_dim[dim].extend(vals)

        overall_vals = [
            sum(emap[e]["scores"][d] for d in SCORE_DIMS) / len(SCORE_DIMS) for e in evaluator_ids if e in emap
        ]
        scenario_overall = _mean(overall_vals) if overall_vals else 0.0
        all_overall.extend(overall_vals)
        per_scenario_stats[sid] = {
            "per_dimension": per_dim,
            "overall_mean": round(scenario_overall, 3),
            "n_evaluators": len(overall_vals),
        }
        if any(per_dim.get(d, {}).get("std_dev", 0.0) > 1.0 for d in SCORE_DIMS):
            disagreements.append(sid)

    overall_dim_means = {d: round(_mean(v), 3) for d, v in all_by_dim.items() if v}

    pairwise_kappa: list[dict] = []
    kappa_values: list[float] = []
    for a, b in combinations(evaluator_ids, 2):
        ra, rb = [], []
        for sid in scenario_ids:
            if a in by_scenario[sid] and b in by_scenario[sid]:
                oa = sum(by_scenario[sid][a]["scores"][d] for d in SCORE_DIMS) / len(SCORE_DIMS)
                ob = sum(by_scenario[sid][b]["scores"][d] for d in SCORE_DIMS) / len(SCORE_DIMS)
                ra.append(int(round(oa)))
                rb.append(int(round(ob)))
        k = cohens_kappa_ordinal(ra, rb)
        if k is not None and not (isinstance(k, float) and math.isnan(k)):
            pairwise_kappa.append({"evaluator_a": a, "evaluator_b": b, "kappa": round(k, 4)})
            kappa_values.append(k)

    matrix: list[list[int | None]] = []
    for eid in evaluator_ids:
        row: list[int | None] = []
        for sid in scenario_ids:
            entry = by_scenario.get(sid, {}).get(eid)
            if entry is None:
                row.append(None)
                continue
            o = sum(entry["scores"][d] for d in SCORE_DIMS) / len(SCORE_DIMS)
            row.append(int(round(o)))
        matrix.append(row)

    kalpha = krippendorff_alpha_ordinal(matrix)
    note = None
    fallback = None
    if kalpha is None:
        note = (
            "Krippendorff alpha undefined (constant ratings or insufficient "
            "data); fallback = mean pairwise Cohen kappa."
        )
        fallback = _mean(kappa_values) if kappa_values else None

    return {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "n_scenarios": len(scenario_ids),
            "n_evaluators": len(evaluator_ids),
            "evaluator_ids": evaluator_ids,
        },
        "per_scenario": per_scenario_stats,
        "overall_dimension_means": overall_dim_means,
        "consensus_overall": round(_mean(all_overall), 3) if all_overall else 0.0,
        "agreement_metrics": {
            "cohens_kappa_pairwise": pairwise_kappa,
            "mean_pairwise_kappa": round(_mean(kappa_values), 4) if kappa_values else None,
            "krippendorff_alpha_ordinal": round(kalpha, 4) if kalpha is not None else None,
            "krippendorff_fallback_note": note,
            "krippendorff_fallback_value": round(fallback, 4) if fallback is not None else None,
        },
        "disagreements": disagreements,
    }


def write_dry_run_plan(out_dir, scenarios, personas):
    plan = {
        "meta": {
            "mode": "dry-run",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "n_scenarios": len(scenarios),
            "n_personas": len(personas),
            "total_calls": len(scenarios) * len(personas),
        },
        "scenarios": [s["scenario_id"] for s in scenarios],
        "personas": [
            {"evaluator_id": p.evaluator_id, "model": p.model, "temperature": p.temperature} for p in personas
        ],
        "calls": [
            {
                "scenario_id": s["scenario_id"],
                "evaluator_id": p.evaluator_id,
                "model": p.model,
                "temperature": p.temperature,
            }
            for s in scenarios
            for p in personas
        ],
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "dry_run_plan.json").write_text(json.dumps(plan, indent=2))
    return plan


async def run_pipeline(args):
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    per_persona_dir = out_dir / "per_persona"
    per_persona_dir.mkdir(parents=True, exist_ok=True)

    data = json.loads(Path(args.input).read_text())
    rubrics = data["rubrics"]
    all_turns = {s["session_id"]: s for s in data["evaluation_sessions"]}
    gt_map = {r["scenario_id"]: r["ground_truth"] for r in data["raw_pipeline_outputs"]}

    scenario_ids = sorted(gt_map.keys())
    if args.scenario:
        wanted = {s.strip() for s in args.scenario.split(",") if s.strip()}
        scenario_ids = [s for s in scenario_ids if s in wanted]
        if not scenario_ids:
            print("FATAL: --scenario filter matched no scenarios")
            sys.exit(1)
    scenarios = [gt_map[s] for s in scenario_ids]

    persona_by_id = {p.evaluator_id: p for p in EVALUATOR_PERSONAS}
    if args.evaluators:
        wanted_p = [p.strip() for p in args.evaluators.split(",") if p.strip()]
        missing = [p for p in wanted_p if p not in persona_by_id]
        if missing:
            print(f"FATAL: unknown persona IDs: {missing}")
            sys.exit(1)
        personas = [persona_by_id[p] for p in wanted_p]
    else:
        personas = list(EVALUATOR_PERSONAS)
    if len(personas) > MAX_PERSONAS:
        print(f"FATAL: --evaluators cap is {MAX_PERSONAS}; got {len(personas)}")
        sys.exit(1)

    print(f"[plan] scenarios={len(scenarios)} personas={len(personas)} total={len(scenarios)*len(personas)}")

    if args.dry_run:
        plan = write_dry_run_plan(out_dir, scenarios, personas)
        print(f"[dry-run] wrote {out_dir/'dry_run_plan.json'} ({plan['meta']['total_calls']} planned calls)")
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for p in personas:
            stub = {
                "evaluator_id": p.evaluator_id,
                "model": p.model,
                "temperature": p.temperature,
                "scored_at": ts,
                "scenarios": [
                    {
                        "scenario_id": s["scenario_id"],
                        "scores": {d: 3 for d in SCORE_DIMS},
                        "rationale": {d: "" for d in SCORE_DIMS},
                        "danger_signal_triggered": False,
                        "elapsed_s": 0.0,
                        "dry_run": True,
                    }
                    for s in scenarios
                ],
            }
            (per_persona_dir / f"{p.evaluator_id}.json").write_text(json.dumps(stub, indent=2))
        stub_consensus = {
            "meta": {
                "mode": "dry-run",
                "generated_at": ts,
                "n_scenarios": len(scenarios),
                "n_evaluators": len(personas),
                "evaluator_ids": [p.evaluator_id for p in personas],
            },
            "per_scenario": {},
            "overall_dimension_means": {d: 3.0 for d in SCORE_DIMS},
            "consensus_overall": 3.0,
            "agreement_metrics": {
                "cohens_kappa_pairwise": [],
                "mean_pairwise_kappa": None,
                "krippendorff_alpha_ordinal": None,
                "krippendorff_fallback_note": "dry-run: no real ratings",
                "krippendorff_fallback_value": None,
            },
            "disagreements": [],
        }
        (out_dir / "consensus.json").write_text(json.dumps(stub_consensus, indent=2))
        print(f"[dry-run] stubbed {len(personas)} per-persona files + consensus.json")
        return

    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        print("FATAL: OPENROUTER_API_KEY not set (use --dry-run to skip network)")
        sys.exit(1)

    sem = asyncio.Semaphore(args.max_concurrency)
    t0_all = time.monotonic()

    async with httpx.AsyncClient() as client:
        tasks = [
            (
                p.evaluator_id,
                sc,
                all_turns[sc["scenario_id"]]["turns"][0],
                score_pair(client, api_key, p, sc, all_turns[sc["scenario_id"]]["turns"][0], rubrics, sem),
            )
            for p in personas
            for sc in scenarios
        ]
        results = await asyncio.gather(*[t[3] for t in tasks])

    by_persona: dict[str, list[dict]] = {p.evaluator_id: [] for p in personas}
    for (pid, _sc, _turn, _), result in zip(tasks, results, strict=False):
        result["evaluator_id"] = pid
        by_persona[pid].append(result)

    for p in personas:
        payload = {
            "evaluator_id": p.evaluator_id,
            "model": p.model,
            "temperature": p.temperature,
            "scored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "scenarios": by_persona[p.evaluator_id],
        }
        (per_persona_dir / f"{p.evaluator_id}.json").write_text(json.dumps(payload, indent=2))

    consensus = aggregate_consensus({pid: {"scenarios": by_persona[pid]} for pid in by_persona})
    (out_dir / "consensus.json").write_text(json.dumps(consensus, indent=2))

    elapsed = time.monotonic() - t0_all
    am = consensus["agreement_metrics"]
    print(f"\n[done] {len(scenarios)} scenarios x {len(personas)} personas in {elapsed:.1f}s")
    print(f"[done] per_persona dir: {per_persona_dir}")
    print(f"[done] consensus: {out_dir/'consensus.json'}")
    print(
        f"[done] consensus_overall={consensus['consensus_overall']} "
        f"krippendorff_alpha={am['krippendorff_alpha_ordinal']} "
        f"mean_kappa={am['mean_pairwise_kappa']}"
    )
    print(f"[done] disagreements (std_dev>1.0): {consensus['disagreements']}")


def main():
    _load_env(Path(__file__).resolve().parent.parent / ".env")
    parser = argparse.ArgumentParser(description="Multi-persona LLM evaluator driver for RAGIN LLM-based evaluation")
    parser.add_argument("--input", default="results/human_eval_full.json")
    parser.add_argument("--output-dir", default="results/human_eval_subagents")
    parser.add_argument("--evaluators", default=None, help="Comma-separated persona IDs (default: all 7)")
    parser.add_argument("--scenario", default=None, help="Comma-separated scenario IDs to filter")
    parser.add_argument(
        "--max-concurrency", type=int, default=MAX_PERSONAS, help=f"Parallel HTTP fan-out cap (max {MAX_PERSONAS})"
    )
    parser.add_argument("--dry-run", action="store_true", help="Skip network; write fixture plan + stub outputs")
    args = parser.parse_args()

    if args.max_concurrency > MAX_PERSONAS:
        print(f"WARN: --max-concurrency={args.max_concurrency} > {MAX_PERSONAS}; clamping")
        args.max_concurrency = MAX_PERSONAS
    if args.max_concurrency < 1:
        args.max_concurrency = 1

    asyncio.run(run_pipeline(args))


if __name__ == "__main__":
    main()
