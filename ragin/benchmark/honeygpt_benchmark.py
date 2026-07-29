"""HoneyGPT competitive benchmark — head-to-head comparison.

HoneyGPT (arXiv 2406.01882, Computer Networks 2026) is the primary competitor.
Published baselines: 99%+ response rate, 3-month field deployment, SSH/Telnet only.

RAGIN's three differentiators that HoneyGPT lacks:
1. RAG-enhanced responses (CTI corpus: 780K+ docs, MITRE ATT&CK STIX)
2. Multi-persona deception (adaptive persona selection)
3. Persistent attacker memory (cross-session profiling via Mem0)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# HoneyGPT published baselines (from their paper)
# ---------------------------------------------------------------------------

HONEYGPT_BASELINE: dict[str, Any] = {
    "response_rate": 0.99,  # 99%+ across ATT&CK techniques
    "protocol_coverage": ["ssh", "telnet"],
    "persona_count": 1,  # single shell emulation
    "rag_enabled": False,
    "persistent_memory": False,
    "artifact_injection": False,
    "dwell_time_tracking": False,
    "multi_protocol": False,
    "attacker_profiling": False,
    "cost_aware_tokens": False,
    "mitre_stix_ingestion": False,
    "deployment_months": 3,
    "evaluation_sessions": 500,  # from their paper
}


# ---------------------------------------------------------------------------
# Metrics that directly measure RAGIN's 3 advantages
# ---------------------------------------------------------------------------


@dataclass
class RAGEnrichmentMetrics:
    """Advantage #1: RAG-enhanced responses (HoneyGPT has NONE).

    Measures how well RAGIN retrieves and integrates CTI context
    into deception responses vs. HoneyGPT's pure parametric generation.
    """

    # RAG retrieval quality
    queries_with_context: int = 0
    total_queries: int = 0
    context_relevance_scores: list[float] = field(default_factory=list)

    # CTI accuracy boost
    response_accuracy_with_rag: float = 0.0
    response_accuracy_without_rag: float = 0.0  # HoneyGPT equivalent

    # MITRE ATT&CK coverage
    techniques_covered: int = 0
    techniques_total: int = 2017  # Enterprise ATT&CK as of 2026

    # Corpus freshness
    documents_indexed: int = 0
    last_corpus_update: float = 0.0

    @property
    def rag_coverage_rate(self) -> float:
        if self.total_queries == 0:
            return 0.0
        return self.queries_with_context / self.total_queries

    @property
    def avg_context_relevance(self) -> float:
        if not self.context_relevance_scores:
            return 0.0
        return sum(self.context_relevance_scores) / len(self.context_relevance_scores)

    @property
    def accuracy_improvement(self) -> float:
        """How much RAG improves response accuracy vs HoneyGPT's parametric-only."""
        if self.response_accuracy_without_rag == 0:
            return 0.0
        delta = self.response_accuracy_with_rag - self.response_accuracy_without_rag
        return delta / self.response_accuracy_without_rag

    @property
    def mitre_coverage_rate(self) -> float:
        if self.techniques_total == 0:
            return 0.0
        return self.techniques_covered / self.techniques_total

    def to_dict(self) -> dict[str, Any]:
        return {
            "rag_coverage_rate": round(self.rag_coverage_rate, 4),
            "avg_context_relevance": round(self.avg_context_relevance, 4),
            "accuracy_improvement_pct": round(self.accuracy_improvement * 100, 2),
            "mitre_coverage_rate": round(self.mitre_coverage_rate, 4),
            "techniques_covered": self.techniques_covered,
            "documents_indexed": self.documents_indexed,
            "honeygpt_equivalent": 0.0,  # HoneyGPT has no RAG
        }


@dataclass
class PersonaSwitchingMetrics:
    """Advantage #2: Multi-persona deception (HoneyGPT has 1 persona).

    Measures RAGIN's ability to adapt persona based on attacker behavior,
    vs HoneyGPT's fixed single shell emulation.
    """

    # Persona deployment
    personas_available: int = 0
    persona_switches: int = 0
    total_sessions: int = 0

    # Persona correctness
    correct_persona_assignments: int = 0
    total_persona_assignments: int = 0

    # Attacker retention by persona
    retention_by_persona: dict[str, float] = field(default_factory=dict)

    # Behavioral adaptation
    adaptation_events: int = 0
    successful_adaptations: int = 0

    @property
    def persona_diversity(self) -> float:
        """How many different personas RAGIN uses vs HoneyGPT's 1."""
        if self.personas_available == 0:
            return 0.0
        return self.personas_available / 1.0  # vs HoneyGPT's 1 persona

    @property
    def switching_rate(self) -> float:
        if self.total_sessions == 0:
            return 0.0
        return self.persona_switches / self.total_sessions

    @property
    def assignment_accuracy(self) -> float:
        if self.total_persona_assignments == 0:
            return 0.0
        return self.correct_persona_assignments / self.total_persona_assignments

    @property
    def adaptation_success_rate(self) -> float:
        if self.adaptation_events == 0:
            return 0.0
        return self.successful_adaptations / self.adaptation_events

    @property
    def avg_retention_turns(self) -> float:
        if not self.retention_by_persona:
            return 0.0
        return sum(self.retention_by_persona.values()) / len(self.retention_by_persona)

    def to_dict(self) -> dict[str, Any]:
        return {
            "personas_available": self.personas_available,
            "honeygpt_personas": 1,
            "persona_diversity_ratio": round(self.persona_diversity, 2),
            "switching_rate": round(self.switching_rate, 4),
            "assignment_accuracy": round(self.assignment_accuracy, 4),
            "adaptation_success_rate": round(self.adaptation_success_rate, 4),
            "avg_retention_turns": round(self.avg_retention_turns, 2),
            "retention_by_persona": {k: round(v, 2) for k, v in self.retention_by_persona.items()},
        }


@dataclass
class PersistentMemoryMetrics:
    """Advantage #3: Persistent attacker memory (HoneyGPT has NONE).

    Measures cross-session attacker profiling via Mem0,
    vs HoneyGPT's session-scoped memory.
    """

    # Memory operations
    memories_stored: int = 0
    memories_retrieved: int = 0
    cross_session_retrievals: int = 0

    # Profiling quality
    profiles_generated: int = 0
    accurate_profiles: int = 0
    ttps_tracked_unique: int = 0

    # Recall accuracy
    perfect_recall_sessions: int = 0
    total_recall_sessions: int = 0

    # Dwell time
    avg_dwell_time_turns: float = 0.0
    max_dwell_time_turns: int = 0

    @property
    def memory_utilization(self) -> float:
        if self.memories_stored == 0:
            return 0.0
        return self.memories_retrieved / self.memories_stored

    @property
    def cross_session_rate(self) -> float:
        if self.memories_retrieved == 0:
            return 0.0
        return self.cross_session_retrievals / self.memories_retrieved

    @property
    def profile_accuracy(self) -> float:
        if self.profiles_generated == 0:
            return 0.0
        return self.accurate_profiles / self.profiles_generated

    @property
    def recall_accuracy(self) -> float:
        if self.total_recall_sessions == 0:
            return 0.0
        return self.perfect_recall_sessions / self.total_recall_sessions

    def to_dict(self) -> dict[str, Any]:
        return {
            "memories_stored": self.memories_stored,
            "memories_retrieved": self.memories_retrieved,
            "cross_session_retrievals": self.cross_session_retrievals,
            "memory_utilization": round(self.memory_utilization, 4),
            "cross_session_rate": round(self.cross_session_rate, 4),
            "profiles_generated": self.profiles_generated,
            "profile_accuracy": round(self.profile_accuracy, 4),
            "recall_accuracy": round(self.recall_accuracy, 4),
            "ttps_tracked_unique": self.ttps_tracked_unique,
            "avg_dwell_time_turns": round(self.avg_dwell_time_turns, 2),
            "honeygpt_equivalent": 0.0,
        }


# ---------------------------------------------------------------------------
# Competitive delta report
# ---------------------------------------------------------------------------


@dataclass
class CompetitiveDelta:
    """Head-to-head comparison: RAGIN vs HoneyGPT on each differentiator."""

    rag: RAGEnrichmentMetrics
    persona: PersonaSwitchingMetrics
    memory: PersistentMemoryMetrics
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rag_enrichment": self.rag.to_dict(),
            "persona_switching": self.persona.to_dict(),
            "persistent_memory": self.memory.to_dict(),
            "honeygpt_baseline": HONEYGPT_BASELINE,
            "timestamp": self.timestamp,
        }

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "RAGIN vs HoneyGPT — Competitive Delta Report",
            "=" * 60,
            "",
            "1. RAG-ENRICHED RESPONSES",
            "   HoneyGPT:  No RAG (parametric only)",
            f"   RAGIN:     {self.rag.rag_coverage_rate:.0%} context coverage, "
            f"{self.rag.avg_context_relevance:.2f} relevance",
            f"   Delta:     +{self.rag.accuracy_improvement * 100:.1f}% accuracy improvement",
            f"   MITRE:     {self.rag.techniques_covered}/{self.rag.techniques_total} techniques "
            f"({self.rag.mitre_coverage_rate:.1%})",
            "",
            "2. MULTI-PERSONA DECEPTION",
            "   HoneyGPT:  1 persona (fixed shell)",
            f"   RAGIN:     {self.persona.personas_available} personas, "
            f"{self.persona.assignment_accuracy:.0%} assignment accuracy",
            f"   Delta:     {self.persona.persona_diversity:.0f}x persona diversity, "
            f"+{self.persona.switching_rate:.0%} switching rate",
            "",
            "3. PERSISTENT ATTACKER MEMORY",
            "   HoneyGPT:  No cross-session memory",
            f"   RAGIN:     {self.memory.memories_stored} memories stored, "
            f"{self.memory.cross_session_rate:.0%} cross-session retrieval",
            f"   Delta:     {self.memory.profile_accuracy:.0%} profile accuracy, "
            f"{self.memory.recall_accuracy:.0%} recall accuracy",
            "",
            "=" * 60,
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------


class HoneyGPTBenchmark:
    """Run head-to-head benchmarks against HoneyGPT published baselines."""

    def __init__(self) -> None:
        self._results: list[CompetitiveDelta] = []

    def evaluate(
        self,
        rag: RAGEnrichmentMetrics,
        persona: PersonaSwitchingMetrics,
        memory: PersistentMemoryMetrics,
    ) -> CompetitiveDelta:
        delta = CompetitiveDelta(rag=rag, persona=persona, memory=memory)
        self._results.append(delta)
        return delta

    def get_latest(self) -> CompetitiveDelta | None:
        return self._results[-1] if self._results else None

    def get_all(self) -> list[CompetitiveDelta]:
        return list(self._results)

    def save_report(self, path: str) -> None:
        report = {
            "title": "RAGIN vs HoneyGPT Competitive Benchmark",
            "honeygpt_baseline": HONEYGPT_BASELINE,
            "results": [r.to_dict() for r in self._results],
        }
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
