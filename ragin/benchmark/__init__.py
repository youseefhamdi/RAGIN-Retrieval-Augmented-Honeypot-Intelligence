"""Deception effectiveness metrics and benchmarking framework."""

from ragin.benchmark.core import (
    CTI_ACTOR_QUERIES,
    CTI_TECHNIQUE_QUERIES,
    PERSONA_REALISM_QUERIES,
    BenchmarkReport,
    BenchmarkResult,
    BenchmarkSuite,
    _score_actor_match,
    _score_memory_recall,
    _score_persona_realism,
    _score_technique_match,
    generate_report,
    run_cti_benchmarks,
    run_deception_benchmarks,
    run_memory_benchmarks,
    save_report,
)
from ragin.benchmark.effectiveness import (
    EffectivenessBenchmark,
    EffectivenessComparison,
    EffectivenessMetrics,
    EffectivenessReport,
)
from ragin.benchmark.honeygpt_benchmark import (
    HONEYGPT_BASELINE,
    CompetitiveDelta,
    HoneyGPTBenchmark,
    PersistentMemoryMetrics,
    PersonaSwitchingMetrics,
    RAGEnrichmentMetrics,
)

__all__ = [
    # Core benchmark harness
    "BenchmarkReport",
    "BenchmarkResult",
    "BenchmarkSuite",
    "CTI_ACTOR_QUERIES",
    "CTI_TECHNIQUE_QUERIES",
    "PERSONA_REALISM_QUERIES",
    "generate_report",
    "run_cti_benchmarks",
    "run_deception_benchmarks",
    "run_memory_benchmarks",
    "save_report",
    "_score_technique_match",
    "_score_actor_match",
    "_score_persona_realism",
    "_score_memory_recall",
    # Effectiveness metrics (new)
    "EffectivenessMetrics",
    "EffectivenessComparison",
    "EffectivenessBenchmark",
    "EffectivenessReport",
    # HoneyGPT competitive benchmark
    "HONEYGPT_BASELINE",
    "RAGEnrichmentMetrics",
    "PersonaSwitchingMetrics",
    "PersistentMemoryMetrics",
    "CompetitiveDelta",
    "HoneyGPTBenchmark",
]
