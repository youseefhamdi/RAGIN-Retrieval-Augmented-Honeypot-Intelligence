"""ThreatRAGEngine — hybrid RAG engine combining vector similarity and BM25 keyword search."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from typing import TYPE_CHECKING, Any

import requests

from ragin.gateway.client import GatewayClient
from ragin.utils import CircuitBreaker, CostTracker, PromptTokenLimiter, _redact_pii

from .intel_corpus import IntelCorpus
from .models import (
    AnalysisRequest,
    GatewayMessage,
    GatewayRequest,
    SeverityLevel,
    ThreatAnalysis,
)
from .vector_store import VectorStore

if TYPE_CHECKING:
    from .lightrag_adapter import LightRAGAdapter

logger = logging.getLogger(__name__)

_DEFAULT_GATEWAY_URL = os.environ.get("RAGIN_GATEWAY_URL", "http://localhost:8080")
_DEFAULT_MODEL = os.environ.get("RAGIN_DON_MODEL", "moonshotai/kimi-k3-free")


class ThreatRAGEngine:
    """Hybrid RAG engine for threat intelligence analysis."""

    def __init__(
        self,
        vector_store_path: str | None = None,
        gateway_url: str | None = None,
        corpus_path: str | None = None,
        api_key: str | None = None,
        lightrag_adapter: LightRAGAdapter | None = None,
    ) -> None:
        self._gateway_url = (gateway_url or _DEFAULT_GATEWAY_URL).rstrip("/")
        self._api_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        self._model = _DEFAULT_MODEL

        # Production infrastructure
        self._circuit_breaker = CircuitBreaker(threshold=5, timeout_s=60.0)
        self._cost_tracker = CostTracker(daily_budget_usd=100.0, monthly_budget_usd=2000.0, per_request_budget_usd=0.10)
        self._prompt_limiter = PromptTokenLimiter(max_prompt_tokens=32_000)

        self._lightrag_adapter = lightrag_adapter
        if lightrag_adapter is not None:
            logger.info("ThreatRAGEngine using LightRAG adapter")
            self._vector_store = None
            self._corpus = None
        else:
            self._vector_store = VectorStore(store_path=vector_store_path)
            self._corpus = IntelCorpus(corpus_path=corpus_path)

        self._bm25_index: dict[str, list[str]] = {}  # term → [doc_ids]
        self._doc_store: dict[str, dict[str, Any]] = {}
        self._gateway = GatewayClient(
            gateway_url=self._gateway_url,
            api_key=self._api_key,
            timeout=200.0,
            default_model=self._model,
        )

        logger.info("ThreatRAGEngine initialised (gateway=%s)", self._gateway_url)

    # ------------------------------------------------------------------
    # Main analysis entry point
    # ------------------------------------------------------------------

    def analyze(
        self,
        classification_result: AnalysisRequest,
        session_log: list[dict[str, Any]],
    ) -> ThreatAnalysis:
        """Full threat analysis pipeline."""
        analysis_id = _make_id(classification_result.session_id)

        # 1. Build query from classification
        query = self._build_query(classification_result)

        # 2. Hybrid search
        intel_hits = self.hybrid_search(query, alpha=0.7)

        # 3. Build LLM context from hits
        self._build_context(intel_hits)

        # 4. Map tactics and identify actors
        from .threat_mapper import ThreatMapper

        mapper = ThreatMapper()
        tactics = mapper.map_to_mitre(classification_result.features)
        iocs = mapper.generate_ioc_list(session_log)
        actors = mapper.identify_actor(tactics, iocs)
        soph = mapper.calculate_sophistication_score(classification_result.features)

        # 5. Determine severity
        severity = self._derive_severity(
            classification_result.classification.value,
            classification_result.confidence,
            soph,
        )

        return ThreatAnalysis(
            analysis_id=analysis_id,
            session_id=classification_result.session_id,
            classification=classification_result.classification,
            severity=severity,
            confidence=classification_result.confidence,
            tactics=tactics,
            threat_actors=actors,
            iocs=iocs,
            sophistication_score=soph,
            intel_documents=[self._hit_to_intel_doc(h) for h in intel_hits[:10]],
            raw_features=classification_result.features,
        )

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search_threat_intel(self, query: str, top_k: int = 10) -> list[dict[str, Any]]:
        """Vector similarity search — routes to LightRAG adapter or VectorStore."""
        if self._lightrag_adapter is not None:
            return self._lightrag_adapter.search(query, top_k=top_k)
        return self._vector_store.search(query, top_k=top_k)

    def keyword_search(self, query: str) -> list[dict[str, Any]]:
        """BM25-style keyword search using term frequency."""
        terms = set(re.findall(r"\w+", query.lower()))
        if not terms:
            return []

        scores: dict[str, float] = {}
        for term in terms:
            doc_ids = self._bm25_index.get(term, [])
            for doc_id in doc_ids:
                scores[doc_id] = scores.get(doc_id, 0.0) + 1.0

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        results: list[dict[str, Any]] = []
        for doc_id, score in ranked:
            if doc_id in self._doc_store:
                entry = {**self._doc_store[doc_id], "score": score}
                results.append(entry)
        return results

    def hybrid_search(self, query: str, alpha: float = 0.7) -> list[dict[str, Any]]:
        """Combine vector and keyword results with weighted score fusion.

        When a LightRAG adapter is configured, delegates entirely to it
        (adapter handles its own hybrid scoring).
        """
        if self._lightrag_adapter is not None:
            return self._lightrag_adapter.hybrid_search(query, alpha=alpha)

        vec_results = self.search_threat_intel(query, top_k=20)
        kw_results = self.keyword_search(query)

        # Normalise scores and merge
        merged: dict[str, dict[str, Any]] = {}
        max_vec = max((r.get("score", 0) for r in vec_results), default=1.0) or 1.0
        max_kw = max((r.get("score", 0) for r in kw_results), default=1.0) or 1.0

        for r in vec_results:
            doc_id = r.get("doc_id", r.get("id", ""))
            norm_score = r.get("score", 0) / max_vec
            merged[doc_id] = {**r, "hybrid_score": alpha * norm_score}

        for r in kw_results:
            doc_id = r.get("doc_id", r.get("id", ""))
            norm_score = r.get("score", 0) / max_kw
            if doc_id in merged:
                merged[doc_id]["hybrid_score"] += (1 - alpha) * norm_score
            else:
                merged[doc_id] = {**r, "hybrid_score": (1 - alpha) * norm_score}

        ranked = sorted(merged.values(), key=lambda x: x.get("hybrid_score", 0), reverse=True)
        return ranked

    def _build_index(self, docs: list[dict[str, Any]]) -> None:
        """Build BM25 inverted index from docs."""
        for doc in docs:
            doc_id = doc.get("doc_id", doc.get("id", ""))
            if not doc_id:
                continue
            self._doc_store[doc_id] = doc
            text = doc.get("text", doc.get("content", doc.get("title", "")))
            terms = set(re.findall(r"\w+", text.lower()))
            for term in terms:
                self._bm25_index.setdefault(term, []).append(doc_id)

    # ------------------------------------------------------------------
    # LLM report generation
    # ------------------------------------------------------------------

    def generate_report(self, analysis: ThreatAnalysis) -> str:
        """Generate a human-readable threat report via the LLM Gateway."""
        system_prompt = (
            "You are a cybersecurity threat intelligence analyst. "
            "Write a concise threat analysis report based on the provided data. "
            "Include: threat summary, MITRE ATT&CK mapping, threat actor attribution, "
            "IOCs, and recommended countermeasures. Be factual — cite document sources."
        )

        context_parts = [
            f"Classification: {analysis.classification.value}",
            f"Severity: {analysis.severity.value}",
            f"Confidence: {analysis.confidence:.0%}",
            f"Sophistication: {analysis.sophistication_score:.0%}",
            "",
            "MITRE Tactics:",
        ]
        for t in analysis.tactics:
            context_parts.append(f"  - {t.tactic_id} ({t.tactic_name}) conf={t.confidence:.0%}")

        if analysis.threat_actors:
            context_parts.append("")
            context_parts.append("Suspected Threat Actors:")
            for a in analysis.threat_actors:
                context_parts.append(f"  - {a.name} (conf={a.confidence:.0%})")

        if analysis.iocs:
            context_parts.append("")
            context_parts.append("IOCs:")
            for ioc in analysis.iocs[:20]:
                context_parts.append(f"  - [{ioc.type.value}] {ioc.value}")

        request = GatewayRequest(
            model=self._model,
            messages=[
                GatewayMessage(role="system", content=system_prompt),
                GatewayMessage(role="user", content="\n".join(context_parts)),
            ],
        )

        return self._call_gateway(request)

    def _call_gateway(self, request: GatewayRequest) -> str:
        """Call the LLM Gateway via shared GatewayClient.

        Applies: PII redaction, circuit breaker, budget enforcement,
        prompt token limiting, cost tracking on response.
        """
        if not self._cost_tracker.check_budget("don"):
            logger.warning("Don budget exhausted — refusing LLM call")
            return "[Budget exhausted — report generation skipped]"

        if not self._circuit_breaker.allow():
            logger.warning("Don circuit breaker open — skipping LLM call")
            return "[Gateway circuit breaker open — report generation deferred]"

        messages = [{"role": m.role, "content": _redact_pii(m.content)} for m in request.messages]

        full_prompt = "\n".join(m["content"] for m in messages)
        if not self._prompt_limiter.check(full_prompt):
            messages[-1]["content"] = self._prompt_limiter.truncate(full_prompt)
            logger.warning("Don prompt truncated to fit token budget")

        try:
            content, usage = self._gateway.generate(
                messages=messages,
                model=request.model,
                temperature=request.temperature,
                max_tokens=request.max_tokens,
            )
            self._circuit_breaker.record_success()

            if usage:
                cost = self._cost_tracker.record("don", self._model, usage)
                if cost > 0:
                    logger.info("Don LLM cost: $%.6f", cost)

            return content
        except requests.RequestException as exc:
            self._circuit_breaker.record_failure()
            logger.error("Gateway call failed: %s", exc)
            return f"[Report generation failed: {exc}]"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_query(self, req: AnalysisRequest) -> str:
        parts = [
            req.classification.value,
            " ".join(req.features.get("observed_techniques", [])),
            " ".join(str(c) for c in req.features.get("commands", [])[:5]),
        ]
        return " ".join(parts).strip()

    def _build_context(self, hits: list[dict[str, Any]]) -> str:
        parts: list[str] = []
        for h in hits[:10]:
            title = h.get("title", h.get("doc_id", ""))
            content = h.get("content", h.get("text", ""))
            parts.append(f"[{title}] {content[:500]}")
        return "\n---\n".join(parts)

    def _hit_to_intel_doc(self, hit: dict[str, Any]) -> Any:
        from .models import IntelDocument

        return IntelDocument(
            doc_id=hit.get("doc_id", hit.get("id", "")),
            title=hit.get("title", "Unknown"),
            content=hit.get("content", hit.get("text", ""))[:2000],
            source=hit.get("source", ""),
            score=hit.get("hybrid_score", hit.get("score", 0.0)),
        )

    def _derive_severity(self, classification: str, confidence: float, sophistication: float) -> SeverityLevel:
        if classification == "malicious":
            if confidence > 0.8 and sophistication > 0.6:
                return SeverityLevel.CRITICAL
            if confidence > 0.6:
                return SeverityLevel.HIGH
            return SeverityLevel.MEDIUM
        if classification == "suspicious":
            if confidence > 0.7 and sophistication > 0.5:
                return SeverityLevel.HIGH
            return SeverityLevel.MEDIUM
        return SeverityLevel.INFO


def _make_id(session_id: str) -> str:
    ts = str(time.time_ns())
    raw = f"{session_id}:{ts}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
