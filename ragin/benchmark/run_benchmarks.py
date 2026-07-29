"""
Benchmark runner CLI — executes benchmark suites and produces reports.

Usage:
    python -m ragin.benchmark.run_benchmarks
    python -m ragin.benchmark.run_benchmarks --suite cti
    python -m ragin.benchmark.run_benchmarks --suite deception
    python -m ragin.benchmark.run_benchmarks --suite memory
    python -m ragin.benchmark.run_benchmarks --suite all --report results/benchmark_report.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging

from ragin.benchmark import (
    BenchmarkReport,
    BenchmarkResult,
    BenchmarkSuite,
    generate_report,
    run_cti_benchmarks,
    run_deception_benchmarks,
    run_memory_benchmarks,
    save_report,
)

logger = logging.getLogger(__name__)


def _print_results(report: BenchmarkReport) -> None:
    """Print benchmark results to console."""
    print("\n" + "=" * 70)
    print(f"  RAGIN Benchmark Report — {report.suite.upper()}")
    print(f"  Run ID: {report.run_id}")
    print(f"  Timestamp: {report.timestamp}")
    print("=" * 70)

    for r in report.results:
        status = "✓" if r.passed else "✗"
        print(f"\n  {status} {r.name}")
        print(f"    Score: {r.score:.3f}  |  Latency: {r.latency_ms:.1f}ms")
        if r.error:
            print(f"    Error: {r.error[:100]}")

    print("\n" + "-" * 70)
    print(f"  Total: {report.total_tests}  |  Passed: {report.passed}  |  Failed: {report.failed}")
    print(f"  Avg Score: {report.avg_score:.3f}  |  Avg Latency: {report.avg_latency_ms:.1f}ms")
    print(f"  Pass Rate: {report.summary.get('pass_rate', 'N/A')}")

    if report.summary.get("suite_scores"):
        print("\n  Suite Scores:")
        for suite, score in report.summary["suite_scores"].items():
            print(f"    {suite}: {score}")
    print("=" * 70 + "\n")


async def _run_suite(
    suite: str,
    adapter: object | None = None,
    hisoka: object | None = None,
    memory: object | None = None,
) -> BenchmarkReport:
    """Run a specific benchmark suite."""
    results: list[BenchmarkResult] = []

    if suite in (BenchmarkSuite.CTI, BenchmarkSuite.ALL):
        if adapter is None:
            print("[WARN] Skipping CTI benchmarks — no adapter provided")
        else:
            print("[INFO] Running CTI accuracy benchmarks...")
            cti_results = await run_cti_benchmarks(adapter)
            results.extend(cti_results)

    if suite in (BenchmarkSuite.DECEPTION, BenchmarkSuite.ALL):
        if hisoka is None:
            print("[WARN] Skipping deception benchmarks — no hisoka pipeline provided")
        else:
            print("[INFO] Running deception quality benchmarks...")
            deception_results = await run_deception_benchmarks(hisoka)
            results.extend(deception_results)

    if suite in (BenchmarkSuite.MEMORY, BenchmarkSuite.ALL):
        if memory is None:
            print("[WARN] Skipping memory benchmarks — no memory instance provided")
        else:
            print("[INFO] Running memory recall benchmarks...")
            memory_results = await run_memory_benchmarks(memory)
            results.extend(memory_results)

    return generate_report(results, suite)


async def main(
    adapter: object | None = None,
    hisoka: object | None = None,
    memory: object | None = None,
) -> None:
    """Main entry point for benchmark runner."""
    parser = argparse.ArgumentParser(description="RAGIN Benchmark Runner")
    parser.add_argument(
        "--suite",
        choices=[s.value for s in BenchmarkSuite],
        default="all",
        help="Benchmark suite to run",
    )
    parser.add_argument(
        "--report",
        default="results/benchmark_report.json",
        help="Output path for JSON report",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print results as JSON to stdout",
    )
    args = parser.parse_args()

    # ── Run benchmarks ────────────────────────────────────────────────────
    report = await _run_suite(
        args.suite,
        adapter=adapter,
        hisoka=hisoka,
        memory=memory,
    )

    # ── Output ────────────────────────────────────────────────────────────
    if args.json:
        from dataclasses import asdict

        print(json.dumps(asdict(report), indent=2, default=str))
    else:
        _print_results(report)

    # ── Save report ───────────────────────────────────────────────────────
    save_report(report, args.report)
    print(f"[INFO] Report saved to {args.report}")


def run() -> None:
    """Sync wrapper for CLI."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # ── Initialize components (sync, before event loop) ───────────────────
    adapter = None
    hisoka = None
    memory = None

    try:
        from ragin.don.cti_corpus import load_full_cti_corpus
        from ragin.don.lightrag_adapter import LightRAGAdapter

        adapter = LightRAGAdapter(
            working_dir="data/benchmark_lightrag",
            gateway_url="http://localhost:11434",
            model="gemma4local",
        )
        print("[INFO] LightRAG adapter initialized")

        print("[INFO] Loading CTI corpus into adapter (dense-only, no LightRAG graph)...")
        stats = load_full_cti_corpus(adapter, store_in_lightrag=False)
        print(f"[INFO] CTI corpus loaded: {sum(stats.values())} documents")
        print("[INFO] Pre-computing document embeddings for dense search...")
        adapter.precompute_embeddings()
        print("[INFO] Embeddings ready")
    except Exception as exc:
        print(f"[WARN] Could not init LightRAG adapter: {exc}")

    try:
        from ragin.hisoka.memory import HisokaMemory

        memory = HisokaMemory(
            llm_provider="litellm",
            llm_model="meta-llama/llama-3.1-8b-instruct",
            embedding_model="all-MiniLM-L6-v2",
            collection_name="benchmark_hisoka_memory",
        )
        print("[INFO] HisokaMemory initialized")
    except Exception as exc:
        print(f"[WARN] Could not init HisokaMemory: {exc}")

    try:
        from ragin.hisoka.pipeline import HisokaPipeline

        hisoka = HisokaPipeline(
            memory=memory,
        )
        print("[INFO] HisokaPipeline initialized")
    except Exception as exc:
        print(f"[WARN] Could not init HisokaPipeline: {exc}")

    asyncio.run(
        main(
            adapter=adapter,
            hisoka=hisoka,
            memory=memory,
        )
    )


if __name__ == "__main__":
    run()
