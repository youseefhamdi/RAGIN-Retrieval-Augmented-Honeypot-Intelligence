#!/usr/bin/env python3
"""Run live benchmark against the real RAGIN pipeline.

Creates Harness with real ChrolloAdapter/DonAdapter/HisokaAdapter,
runs all 65 benchmark queries through process_with_threat_modeling(),
and produces real measured results.

Usage:
    python scripts/run_live_benchmark.py
    python scripts/run_live_benchmark.py --limit 10   # quick smoke test
    python scripts/run_live_benchmark.py --json        # JSON output
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> None:
    parser = argparse.ArgumentParser(description="RAGIN Live Benchmark")
    parser.add_argument("--limit", type=int, default=None, help="Max queries per suite")
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout")
    parser.add_argument("--report", default="results/live_benchmark.json", help="Report output path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    # ── Build real components ────────────────────────────────────────────
    print("[1/4] Initializing real components...")

    from ragin.cycle.adapters import ChrolloAdapter, DonAdapter, HisokaAdapter
    from ragin.cycle.harness import Harness
    from ragin.cycle.session import Session

    classifier = ChrolloAdapter()
    cti_engine = DonAdapter()
    deceiver = HisokaAdapter(
        gateway_url="https://openrouter.ai/api",
        api_key=os.environ.get("OPENROUTER_API_KEY", ""),
    )

    harness = Harness(
        classifier=classifier,
        cti_engine=cti_engine,
        deceiver=deceiver,
    )
    print("  ✓ ChrolloAdapter (classifier)")
    print("  ✓ DonAdapter (cti_engine)")
    print("  ✓ HisokaAdapter (deceiver)")
    print("  ✓ Harness assembled")

    # ── Session factory ──────────────────────────────────────────────────
    session_counter = [0]

    def session_factory() -> Session:
        session_counter[0] += 1
        return Session.create(source_ip=f"benchmark-{session_counter[0]}")

    # ── Run benchmark ────────────────────────────────────────────────────
    print(f"\n[2/4] Running benchmark (limit={args.limit or 'all'})...")
    from ragin.benchmark.harness_bridge import run_live_benchmark

    result = run_live_benchmark(
        harness=harness,
        session_factory=session_factory,
        limit=args.limit,
    )

    # ── Print results ────────────────────────────────────────────────────
    print(f"\n[3/4] Results ({result.elapsed_s:.1f}s elapsed)")
    print("=" * 70)

    for suite_name, report in [
        ("CTI Technique", result.technique_report),
        ("CTI Actor", result.actor_report),
        ("Persona Realism", result.persona_report),
    ]:
        print(f"\n  {suite_name}:")
        print(f"    Total: {report.total_tests}  |  Passed: {report.passed}  |  Avg Score: {report.avg_score:.3f}")
        for r in report.results:
            icon = "✓" if r.passed else "✗"
            print(f"      {icon} {r.name[:55]:55s}  score={r.score:.3f}  latency={r.latency_ms:.0f}ms")
            if r.error:
                print(f"        error: {r.error[:80]}")

    m = result.metrics
    print("\n  EffectivenessMetrics:")
    print(f"    Total sessions:            {m.total_sessions}")
    print(f"    Sessions with engagement:  {m.sessions_with_engagement}")
    print(f"    Artifacts deployed:        {m.honeytokens_deployed}")
    print(f"    Artifacts accessed:        {m.honeytoken_triggers}")
    print(f"    TTPs detected:             {m.ttps_detected}")
    print(f"    Unique TTPs:               {m.ttps_detected_unique}")
    print(f"    Persona assignments:       {m.persona_total_assignments}")
    print(f"    Avg response time:         {m.avg_response_time_ms:.0f}ms")
    print(f"    Attacker retention:        {m.attacker_retention_turns:.2f}")
    print("=" * 70)

    # ── Save report ──────────────────────────────────────────────────────
    if args.json:
        from dataclasses import asdict

        print(json.dumps(asdict(result.metrics), indent=2, default=str))

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    from dataclasses import asdict

    report_data = {
        "elapsed_s": result.elapsed_s,
        "metrics": asdict(result.metrics),
        "technique_results": [asdict(r) for r in result.technique_results],
        "actor_results": [asdict(r) for r in result.actor_results],
        "persona_results": [asdict(r) for r in result.persona_results],
    }
    report_path.write_text(json.dumps(report_data, indent=2, default=str))
    print(f"\n[4/4] Report saved to {report_path}")


if __name__ == "__main__":
    main()
