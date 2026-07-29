#!/usr/bin/env python3
"""Run the 8 ground-truth scenarios through the live RAGIN pipeline,
capture outputs, and produce pre-filled SessionEvaluation JSON for human scoring.

Usage:
    python scripts/run_human_eval.py
    python scripts/run_human_eval.py --output results/human_eval.json
    python scripts/run_human_eval.py --limit 3   # quick smoke test
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def load_env(env_path: str | Path) -> None:
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


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="RAGIN Human Evaluation Runner")
    parser.add_argument("--output", default="results/human_eval.json", help="Output JSON path")
    parser.add_argument("--limit", type=int, default=None, help="Limit scenarios (smoke test)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    load_env(Path(__file__).resolve().parent.parent / ".env")

    # --- Imports -----------------------------------------------------------
    from ragin.benchmark.harness_bridge import outcome_from_pipeline_result
    from ragin.benchmark.human_eval import (
        ALL_RUBRICS,
        EVALUATOR_PROTOCOL,
        SAMPLE_SCENARIOS,
        create_evaluation_template,
    )
    from ragin.cycle.adapters import ChrolloAdapter, DonAdapter, HisokaAdapter
    from ragin.cycle.harness import Harness
    from ragin.cycle.session import Session

    # --- Build real pipeline -----------------------------------------------
    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        print("WARNING: OPENROUTER_API_KEY not set; LLM stages will fail.")

    gateway = "https://openrouter.ai/api"

    print("[1/3] Initializing pipeline...")
    classifier = ChrolloAdapter()
    cti_engine = DonAdapter(gateway_url=gateway, api_key=api_key)
    deceiver = HisokaAdapter(gateway_url=gateway, api_key=api_key)

    harness = Harness(
        classifier=classifier,
        cti_engine=cti_engine,
        deceiver=deceiver,
    )
    print(f"  Harness ready ({len(SAMPLE_SCENARIOS)} scenarios loaded)")

    # --- Run scenarios -----------------------------------------------------
    scenarios = SAMPLE_SCENARIOS[: args.limit] if args.limit else SAMPLE_SCENARIOS

    print(f"\n[2/3] Running {len(scenarios)} scenarios through pipeline...")

    evaluation_sessions: list[dict] = []
    raw_results: list[dict] = []

    for idx, sc in enumerate(scenarios, 1):
        label = f"  [{idx}/{len(scenarios)}] {sc.scenario_id}: {sc.attacker_input[:50]}"
        print(f"{label:<65}", end="", flush=True)

        session = Session.create(source_ip=f"human-eval-{sc.scenario_id}")
        t0 = time.monotonic()

        try:
            pr = harness.process_with_threat_modeling(session, sc.attacker_input)
            elapsed = time.monotonic() - t0

            outcome = outcome_from_pipeline_result(pr, sc.attacker_input)

            # --- Pre-fill TurnEvaluation -----------------------------------
            turn_eval = {
                "turn_number": 1,
                "query": sc.attacker_input,
                "response_text": outcome.response_text,
                "persona_used": outcome.persona_name,
                "ttps_extracted": outcome.ttps_extracted,
            }

            session_eval = create_evaluation_template(
                session_id=sc.scenario_id,
                turns=[turn_eval],
                attacker_profile=sc.expected_persona,
            )

            evaluation_sessions.append(session_eval.to_dict())

            raw_results.append(
                {
                    "scenario_id": sc.scenario_id,
                    "ground_truth": sc.to_dict(),
                    "classification": outcome.classification,
                    "cti_analysis": outcome.cti_analysis,
                    "deception": outcome.deception,
                    "verification": outcome.verification,
                    "response_text": outcome.response_text,
                    "persona_name": outcome.persona_name,
                    "ttps_extracted": outcome.ttps_extracted,
                    "elapsed_s": round(elapsed, 2),
                    "error": outcome.error,
                }
            )

            print(f"  {elapsed:.1f}s  persona={outcome.persona_name or '?'}")

        except Exception as e:
            elapsed = time.monotonic() - t0
            print(f"  FAIL ({elapsed:.1f}s): {e}")
            raw_results.append(
                {
                    "scenario_id": sc.scenario_id,
                    "ground_truth": sc.to_dict(),
                    "error": str(e),
                }
            )

        finally:
            try:
                session.close("human_eval_complete")
            except Exception:
                pass

    # --- Build output ------------------------------------------------------
    print(f"\n[3/3] Writing results to {args.output} ...")

    output = {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_scenarios": len(scenarios),
            "description": "RAGIN Human Evaluation — pre-filled from live pipeline output. "
            "Scores default to ACCEPTABLE(3); evaluators must override.",
        },
        "evaluator_protocol": EVALUATOR_PROTOCOL,
        "rubrics": [r.to_dict() for r in ALL_RUBRICS],
        "evaluation_sessions": evaluation_sessions,
        "raw_pipeline_outputs": raw_results,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2, default=str))
    print(f"  Done — {len(scenarios)} scenarios, {out_path.stat().st_size / 1024:.0f} KB")


if __name__ == "__main__":
    main()
