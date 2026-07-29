#!/usr/bin/env python3
"""B4: No-RAG baseline comparison.

Compares RAGIN full pipeline (Chrollo→Don→Hisoka) vs baseline (Hisoka only, no Don CTI).
Demonstrates RAG augmentation value for the ESWA paper.

Usage:
    python scripts/run_baseline_comparison.py --limit 10
    python scripts/run_baseline_comparison.py --limit 10 --json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def create_harness(with_rag: bool = True):
    """Create a Harness with or without Don CTI engine."""
    from ragin.cycle.adapters import ChrolloAdapter, DonAdapter, HisokaAdapter
    from ragin.cycle.harness import Harness

    classifier = ChrolloAdapter()
    cti_engine = DonAdapter() if with_rag else None
    deceiver = HisokaAdapter(
        gateway_url="https://openrouter.ai/api",
        api_key=os.environ.get("OPENROUTER_API_KEY", ""),
    )

    harness = Harness(
        classifier=classifier,
        cti_engine=cti_engine,
        deceiver=deceiver,
    )
    return harness


def main() -> None:
    parser = argparse.ArgumentParser(description="RAGIN B4: No-RAG Baseline Comparison")
    parser.add_argument("--limit", type=int, default=10, help="Max queries per suite (default: 10)")
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout")
    parser.add_argument("--report", default="results/b4_baseline_comparison.json", help="Report output path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    from ragin.benchmark.harness_bridge import run_live_benchmark
    from ragin.cycle.session import Session

    session_counter = [0]

    def session_factory() -> Session:
        session_counter[0] += 1
        return Session.create(source_ip=f"b4-{session_counter[0]}")

    # ── Run with RAG (full pipeline) ─────────────────────────────────────
    print(f"[1/3] Running FULL pipeline (Don CTI enabled), limit={args.limit}...")
    harness_rag = create_harness(with_rag=True)
    result_rag = run_live_benchmark(
        harness=harness_rag,
        session_factory=session_factory,
        limit=args.limit,
    )
    print(f"  Done in {result_rag.elapsed_s:.1f}s")

    # ── Run without RAG (baseline) ───────────────────────────────────────
    print(f"\n[2/3] Running BASELINE (No Don CTI), limit={args.limit}...")
    harness_no_rag = create_harness(with_rag=False)
    result_no_rag = run_live_benchmark(
        harness=harness_no_rag,
        session_factory=session_factory,
        limit=args.limit,
    )
    print(f"  Done in {result_no_rag.elapsed_s:.1f}s")

    # ── Compare results ──────────────────────────────────────────────────
    print("\n[3/3] Comparison Results")
    print("=" * 70)

    rag_tech = result_rag.technique_report
    no_rag_tech = result_no_rag.technique_report
    rag_actor = result_rag.actor_report
    no_rag_actor = result_no_rag.actor_report
    rag_persona = result_rag.persona_report
    no_rag_persona = result_no_rag.persona_report

    print(f"\n{'Suite':<20} {'RAG':>10} {'No-RAG':>10} {'Delta':>10} {'RAG Win?':>10}")
    print("-" * 60)

    for name, r_rep, nr_rep in [
        ("CTI Technique", rag_tech, no_rag_tech),
        ("CTI Actor", rag_actor, no_rag_actor),
        ("Persona Realism", rag_persona, no_rag_persona),
    ]:
        r_score = r_rep.avg_score
        nr_score = nr_rep.avg_score
        delta = r_score - nr_score
        win = "✓" if delta > 0 else ("=" if delta == 0 else "✗")
        print(f"{name:<20} {r_score:>10.3f} {nr_score:>10.3f} {delta:>+10.3f} {win:>10}")

    # Overall
    r_overall = (rag_tech.avg_score + rag_actor.avg_score + rag_persona.avg_score) / 3
    nr_overall = (no_rag_tech.avg_score + no_rag_actor.avg_score + no_rag_persona.avg_score) / 3
    print("-" * 60)
    print(f"{'OVERALL':<20} {r_overall:>10.3f} {nr_overall:>10.3f} {r_overall - nr_overall:>+10.3f}")

    # EffectivenessMetrics comparison
    print("\n  Effectiveness Metrics:")
    print(f"  {'Metric':<35} {'RAG':>10} {'No-RAG':>10}")
    print(f"  {'-'*55}")
    for label, r_val, nr_val in [
        ("TTPs detected", result_rag.metrics.ttps_detected, result_no_rag.metrics.ttps_detected),
        ("Unique TTPs", result_rag.metrics.ttps_detected_unique, result_no_rag.metrics.ttps_detected_unique),
        (
            "Avg response time (ms)",
            f"{result_rag.metrics.avg_response_time_ms:.0f}",
            f"{result_no_rag.metrics.avg_response_time_ms:.0f}",
        ),
        (
            "Sessions with engagement",
            result_rag.metrics.sessions_with_engagement,
            result_no_rag.metrics.sessions_with_engagement,
        ),
    ]:
        print(f"  {label:<35} {r_val:>10} {nr_val:>10}")

    # Save report
    report_data = {
        "experiment": "B4_no_rag_baseline",
        "limit": args.limit,
        "rag": {
            "elapsed_s": result_rag.elapsed_s,
            "metrics": asdict(result_rag.metrics),
            "technique_avg": rag_tech.avg_score,
            "actor_avg": rag_actor.avg_score,
            "persona_avg": rag_persona.avg_score,
        },
        "no_rag": {
            "elapsed_s": result_no_rag.elapsed_s,
            "metrics": asdict(result_no_rag.metrics),
            "technique_avg": no_rag_tech.avg_score,
            "actor_avg": no_rag_actor.avg_score,
            "persona_avg": no_rag_persona.avg_score,
        },
    }

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report_data, indent=2, default=str))
    print(f"\n  Report saved to {report_path}")

    if args.json:
        print(json.dumps(report_data, indent=2, default=str))


if __name__ == "__main__":
    main()
