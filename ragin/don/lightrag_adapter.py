"""LightRAG Adapter — drop-in replacement for VectorStore + IntelCorpus using LightRAG as backing RAG engine.

This module provides LightRAGAdapter, which exposes the same public interface
as VectorStore (add_documents, search, save, load) and IntelCorpus
(load_corpus, search_by_tactic, search_by_actor, get_context_window, document_count)
but delegates to LightRAG for graph-enhanced retrieval.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

_DEFAULT_WORKING_DIR = os.environ.get("RAGIN_LIGHTRAG_WORKING_DIR", "data/lightrag_storage")
_DEFAULT_GATEWAY_URL = os.environ.get("RAGIN_GATEWAY_URL", "http://localhost:8080")
_DEFAULT_MODEL = os.environ.get("RAGIN_DON_MODEL", "moonshotai/kimi-k3-free")


class LightRAGAdapter:
    """Drop-in replacement for VectorStore + IntelCorpus backed by LightRAG.

    Public interface matches VectorStore and IntelCorpus combined:
      - add_documents(docs, metadata=None) -> int
      - search(query, top_k=10) -> list[dict]
      - save(path=None) / load(path=None)
      - load_corpus(path=None) -> int
      - search_by_tactic(tactic) -> list[dict]
      - search_by_actor(actor_name) -> list[dict]
      - get_context_window(query, max_tokens=4000) -> str
      - document_count -> int
      - hybrid_search(query, alpha=0.7) -> list[dict]  (LightRAG native hybrid mode)
    """

    def __init__(
        self,
        working_dir: str | None = None,
        gateway_url: str | None = None,
        model: str | None = None,
    ) -> None:
        self._working_dir = Path(working_dir or _DEFAULT_WORKING_DIR)
        self._working_dir.mkdir(parents=True, exist_ok=True)
        self._gateway_url = (gateway_url or _DEFAULT_GATEWAY_URL).rstrip("/")
        self._model = model or _DEFAULT_MODEL

        # Cached SentenceTransformer (loaded lazily, reused across queries)
        self._embedder = None

        # Internal state for fallback index (tactic/actor search)
        self._documents: list[dict[str, Any]] = []
        self._tactic_index: dict[str, list[int]] = {}
        self._actor_index: dict[str, list[int]] = {}
        self._initialized = False
        self._storages_initialized = False
        self._rag = None  # LightRAG instance, lazy init

    # --- Lazy LightRAG initialization ---

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        try:
            from lightrag import LightRAG
            from lightrag.utils import EmbeddingFunc

            self._rag = LightRAG(
                working_dir=str(self._working_dir),
                llm_model_func=self._build_llm_func(),
                embedding_func=EmbeddingFunc(
                    embedding_dim=384,
                    max_token_size=512,
                    func=self._embedding_func,
                ),
                chunk_token_size=1200,
                chunk_overlap_token_size=100,
            )
            self._initialized = True
            self._storages_initialized = False
            logger.info(
                "LightRAGAdapter initialised (dir=%s, model=%s)",
                self._working_dir,
                self._model,
            )
        except ImportError as exc:
            logger.warning(
                "lightrag-hku not installed — falling back to numpy brute-force. "
                "Install: pip install lightrag-hku (%s)",
                exc,
            )
            self._initialized = True

    async def _ensure_all_initialized_async(self) -> None:
        """Ensure LightRAG is created AND storages initialized (async callers)."""
        self._ensure_initialized()
        if self._rag is not None and not self._storages_initialized:
            await self._rag.initialize_storages()
            self._storages_initialized = True

    def _ensure_all_initialized_sync(self) -> None:
        """Ensure LightRAG is created AND storages initialized (sync callers)."""
        self._ensure_initialized()
        if self._rag is not None and not self._storages_initialized:
            asyncio.run(self._rag.initialize_storages())
            self._storages_initialized = True

    def _build_llm_func(self) -> Any:
        """Build an LLM function that calls our LLM Gateway via OpenAI-compatible API."""
        import httpx

        gateway_url = self._gateway_url
        model = self._model
        api_key = os.environ.get("OPENROUTER_API_KEY", "")

        async def llm_func(prompt: str, **kwargs: Any) -> str:
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": kwargs.get("max_tokens", 2048),
            }
            try:
                async with httpx.AsyncClient(timeout=180.0) as client:
                    resp = await client.post(
                        f"{gateway_url}/v1/chat/completions",
                        json=payload,
                        headers=headers,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices:
                        msg = choices[0].get("message", {}) or {}
                        content = msg.get("content")
                        if content is None:
                            content = msg.get("reasoning") or ""
                        return content or ""
                    return ""
            except Exception as exc:
                logger.error("LightRAG LLM call failed: %s", exc)
                return ""

        return llm_func

    async def _embedding_func(self, texts: list[str]) -> np.ndarray:
        """Embed texts using sentence-transformers (same model as original VectorStore)."""
        try:
            from sentence_transformers import SentenceTransformer

            model_name = os.environ.get("RAGIN_EMBED_MODEL", "all-MiniLM-L6-v2")
            embedder = SentenceTransformer(model_name)
            vecs = embedder.encode(texts, show_progress_bar=False, normalize_embeddings=True)
            return np.asarray(vecs, dtype=np.float32)
        except ImportError:
            # Fallback: hash-based pseudo-embeddings for tests
            dimension = 384
            rng = np.random.RandomState(42)
            vecs = np.zeros((len(texts), dimension), dtype=np.float32)
            for i, t in enumerate(texts):
                seed = sum(ord(c) for c in t) % (2**31)
                rng.seed(seed)
                vecs[i] = rng.randn(dimension).astype(np.float32)
                norm = np.linalg.norm(vecs[i])
                if norm > 0:
                    vecs[i] /= norm
            return vecs

    # --- VectorStore interface ---

    def add_documents(
        self,
        docs: list[dict[str, Any]],
        metadata: list[dict[str, Any]] | None = None,
        store_in_lightrag: bool = True,
    ) -> int:
        """Index documents. Each doc must have 'text' key. Returns count added.

        Args:
            docs: List of document dicts.
            metadata: Optional per-doc metadata.
            store_in_lightrag: If True (default), also insert into LightRAG.
                Set False for dense-only benchmark to avoid entity-extraction overhead.
        """
        if not docs:
            return 0

        if store_in_lightrag:
            self._ensure_all_initialized_sync()

        texts = []
        for i, doc in enumerate(docs):
            text = doc.get("text", doc.get("content", ""))
            if metadata and i < len(metadata):
                meta = metadata[i]
                if meta.get("mitre_tactics"):
                    text += f"\nMITRE Tactics: {', '.join(meta['mitre_tactics'])}"
                if meta.get("threat_actors"):
                    text += f"\nThreat Actors: {', '.join(meta['threat_actors'])}"
            texts.append(text)

        # Store in internal index for tactic/actor search
        for i, doc in enumerate(docs):
            entry = {**doc}
            if metadata and i < len(metadata):
                entry["metadata"] = metadata[i]
            self._documents.append(entry)
        self._rebuild_indices()

        # Insert into LightRAG (skipped for dense-only benchmark)
        if store_in_lightrag and self._rag is not None:
            try:
                self._rag.insert(texts)
                logger.info("Inserted %d documents into LightRAG", len(texts))
            except Exception as exc:
                logger.error("LightRAG insert failed: %s", exc)

        return len(docs)

    def search(
        self,
        query_vector: list[float] | str | np.ndarray,
        top_k: int = 10,
    ) -> list[dict[str, Any]]:
        """Similarity search. Accepts raw text or pre-computed vector."""
        self._ensure_all_initialized_sync()

        if isinstance(query_vector, str):
            # Use LightRAG query_data for structured retrieval
            if self._rag is not None:
                try:
                    from lightrag import QueryParam

                    param = QueryParam(
                        mode="hybrid",
                        top_k=top_k,
                        chunk_top_k=top_k,
                    )
                    result = self._rag.query_data(query_vector, param=param)
                    # Convert LightRAG result to our format
                    return self._format_lightrag_results(result, top_k)
                except Exception as exc:
                    logger.error("LightRAG query failed, falling back: %s", exc)

            # Fallback: keyword search
            return self._fallback_search(query_vector, top_k)

        # Pre-computed vector: fallback brute-force
        return self._fallback_search_vector(query_vector, top_k)

    def hybrid_search(self, query: str, alpha: float = 0.7) -> list[dict[str, Any]]:
        """Hybrid search using LightRAG's native hybrid mode."""
        self._ensure_all_initialized_sync()

        if self._rag is not None:
            try:
                from lightrag import QueryParam

                param = QueryParam(
                    mode="hybrid",
                    top_k=20,
                    chunk_top_k=20,
                )
                result = self._rag.query_data(query, param=param)
                return self._format_lightrag_results(result, top_k=20)
            except Exception as exc:
                logger.error("LightRAG hybrid query failed: %s", exc)

        return self._fallback_search(query, 20)

    # --- Benchmark query interface ---

    async def query_data(self, query: str, mode: str = "dense", **kwargs: Any) -> dict[str, Any]:
        """CTI query-response for benchmarks. Returns {'response': answer}.

        Args:
            query: User query string.
            mode: ``"dense"`` (default) — vector/keyword retrieval, no LightRAG graph.
                  ``"graph"`` — LightRAG graph-enhanced retrieval (requires entity extraction).
        """
        context = ""

        if mode == "graph":
            await self._ensure_all_initialized_async()
            if self._rag is not None:
                try:
                    from lightrag import QueryParam

                    param = QueryParam(
                        mode="mix",
                        top_k=10,
                        only_need_context=True,
                        max_total_tokens=4000,
                    )
                    result = await self._rag.aquery(query, param=param)
                    if isinstance(result, str) and result:
                        context = result
                except Exception as exc:
                    logger.debug("LightRAG context query failed: %s", exc)

        if not context:
            results = self._dense_search(query, 10)
            if results:
                context = "\n---\n".join([r.get("content", r.get("text", "")) for r in results])

        if not context:
            return {"response": "No relevant threat intelligence found for this query."}

        system_prompt = (
            "You are a cyber threat intelligence analyst. Answer the query based "
            "on the provided context. Include relevant MITRE ATT&CK IDs "
            "(e.g., T1566.001, T1133) when applicable."
        )
        prompt = f"{system_prompt}\n\nRelevant threat intelligence context:\n" f"{context}\n\nQuery: {query}\n\nAnswer:"

        llm_func = self._build_llm_func()
        response = await llm_func(prompt)

        return {"response": response}

    # --- IntelCorpus interface ---

    def load_corpus(self, path: str | None = None) -> int:
        """Load documents from JSON/JSONL. Returns count loaded."""
        load_path = Path(path or self._working_dir / "corpus")
        if load_path.is_dir():
            return self._load_directory(load_path)
        if load_path.is_file():
            return self._load_file(load_path)
        logger.info("No corpus path at %s — starting fresh", load_path)
        return 0

    def search_by_tactic(self, tactic: str) -> list[dict[str, Any]]:
        """Return documents matching a MITRE tactic (case-insensitive)."""
        self._ensure_loaded()
        indices = self._tactic_index.get(tactic.lower(), [])
        return [self._documents[i] for i in indices]

    def search_by_actor(self, actor_name: str) -> list[dict[str, Any]]:
        """Return documents matching a threat actor (case-insensitive fuzzy)."""
        self._ensure_loaded()
        key = actor_name.lower()
        if key in self._actor_index:
            return [self._documents[i] for i in self._actor_index[key]]
        # Fuzzy partial match
        matches: list[int] = []
        for actor_key, idxs in self._actor_index.items():
            if key in actor_key or actor_key in key:
                matches.extend(idxs)
        return [self._documents[i] for i in sorted(set(matches))]

    def get_context_window(self, query: str, max_tokens: int = 4000) -> str:
        """Build a context string for LLM from relevant docs, respecting token budget."""
        self._ensure_all_initialized_sync()

        if self._rag is not None:
            try:
                from lightrag import QueryParam

                param = QueryParam(
                    mode="mix",
                    top_k=10,
                    only_need_context=True,
                    max_total_tokens=max_tokens,
                )
                result = self._rag.query(query, param=param)
                if isinstance(result, str) and result:
                    return result
            except Exception as exc:
                logger.error("LightRAG context query failed: %s", exc)

        # Fallback: keyword-based context building
        return self._fallback_context_window(query, max_tokens)

    # --- Persistence ---

    def save(self, path: str | None = None) -> None:
        """Persist store to disk."""
        save_path = Path(path or self._working_dir)
        save_path.mkdir(parents=True, exist_ok=True)

        # Save internal index
        docs_file = save_path / "documents.json"
        with open(docs_file, "w") as f:
            json.dump(self._documents, f, default=str)
        meta_file = save_path / "meta.json"
        with open(meta_file, "w") as f:
            json.dump(
                {"count": len(self._documents), "type": "lightrag_adapter"},
                f,
            )
        # LightRAG auto-persists to working_dir; also copy if different
        logger.info("LightRAGAdapter saved to %s (%d docs)", save_path, len(self._documents))

    def load(self, path: str | None = None) -> None:
        """Load persisted store from disk."""
        load_path = Path(path or self._working_dir)
        docs_file = load_path / "documents.json"
        if not docs_file.exists():
            logger.info("No existing store at %s, starting fresh", load_path)
            return
        with open(docs_file) as f:
            self._documents = json.load(f)
        self._rebuild_indices()
        logger.info("LightRAGAdapter loaded from %s (%d docs)", load_path, len(self._documents))

    @property
    def document_count(self) -> int:
        return len(self._documents)

    # --- Internal helpers ---

    def _rebuild_indices(self) -> None:
        self._tactic_index.clear()
        self._actor_index.clear()
        for i, doc in enumerate(self._documents):
            for t in doc.get("mitre_tactics", doc.get("metadata", {}).get("mitre_tactics", [])):
                self._tactic_index.setdefault(t.lower(), []).append(i)
            for a in doc.get("threat_actors", doc.get("metadata", {}).get("threat_actors", [])):
                self._actor_index.setdefault(a.lower(), []).append(i)

    def _ensure_loaded(self) -> None:
        if not self._documents:
            self.load_corpus()

    def _load_directory(self, dir_path: Path) -> int:
        total = 0
        for ext in ("*.json", "*.jsonl"):
            for fp in sorted(dir_path.glob(ext)):
                total += self._load_file(fp)
        self._rebuild_indices()
        return total

    def _load_file(self, fp: Path) -> int:
        count = 0
        try:
            if fp.suffix == ".jsonl":
                with open(fp) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            doc = json.loads(line)
                            self._documents.append(doc)
                            count += 1
                        except json.JSONDecodeError:
                            continue
            else:
                with open(fp) as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for doc in data:
                        self._documents.append(doc)
                        count += 1
                elif isinstance(data, dict):
                    self._documents.append(data)
                    count = 1
        except Exception as exc:
            logger.error("Failed to load %s: %s", fp, exc)
        if count:
            self._rebuild_indices()
        return count

    def _format_lightrag_results(self, result: dict[str, Any], top_k: int) -> list[dict[str, Any]]:
        """Convert LightRAG query_data result to our standard format."""
        results: list[dict[str, Any]] = []

        # Extract chunks from the result
        chunks = result.get("chunks", result.get("text", ""))
        if isinstance(chunks, str) and chunks:
            # Split by common delimiters
            parts = [c.strip() for c in chunks.split("\n---\n") if c.strip()]
            for i, part in enumerate(parts[:top_k]):
                results.append(
                    {
                        "doc_id": f"lightrag_chunk_{i}",
                        "title": f"LightRAG Result {i + 1}",
                        "content": part,
                        "text": part,
                        "score": 1.0 - (i * 0.05),  # Decreasing score
                        "source": "lightrag",
                    }
                )
        elif isinstance(chunks, list):
            for i, chunk in enumerate(chunks[:top_k]):
                if isinstance(chunk, dict):
                    results.append(
                        {
                            "doc_id": chunk.get("id", f"lightrag_chunk_{i}"),
                            "title": chunk.get("title", f"LightRAG Result {i + 1}"),
                            "content": chunk.get("content", chunk.get("text", "")),
                            "text": chunk.get("text", chunk.get("content", "")),
                            "score": chunk.get("score", 1.0 - (i * 0.05)),
                            "source": "lightrag",
                        }
                    )
                else:
                    results.append(
                        {
                            "doc_id": f"lightrag_chunk_{i}",
                            "title": f"LightRAG Result {i + 1}",
                            "content": str(chunk),
                            "text": str(chunk),
                            "score": 1.0 - (i * 0.05),
                            "source": "lightrag",
                        }
                    )

        # Also extract entities and relationships if present
        entities = result.get("entities", [])
        relationships = result.get("relationships", [])
        if entities or relationships:
            meta_entry = {
                "doc_id": "lightrag_metadata",
                "title": "Graph Metadata",
                "content": f"Entities: {len(entities)}, Relationships: {len(relationships)}",
                "text": f"Entities: {json.dumps(entities[:10])}\nRelationships: {json.dumps(relationships[:10])}",
                "score": 0.5,
                "source": "lightrag_graph",
                "entities": entities,
                "relationships": relationships,
            }
            results.append(meta_entry)

        return results

    def precompute_embeddings(self) -> None:
        """Pre-compute document embeddings for dense search.

        Call after loading documents, before benchmark runs. Separates
        the one-time encoding cost from the timed benchmark.
        """
        if not self._documents:
            logger.warning("No documents to embed")
            return
        try:
            from sentence_transformers import SentenceTransformer

            model_name = os.environ.get("RAGIN_EMBED_MODEL", "all-MiniLM-L6-v2")
            embedder = SentenceTransformer(model_name)
            doc_texts = [f"{d.get('title', '')} {d.get('content', d.get('text', ''))}" for d in self._documents]
            logger.info(
                "Pre-computing embeddings for %d docs using %s…",
                len(doc_texts),
                model_name,
            )
            self._doc_embeddings = embedder.encode(doc_texts, show_progress_bar=True, normalize_embeddings=True).astype(
                np.float32
            )
            logger.info("Embedding done, shape=%s", self._doc_embeddings.shape)
        except Exception as exc:
            logger.warning("Pre-compute embeddings failed: %s", exc)
            self._doc_embeddings = None

    def _dense_search(self, query: str, top_k: int) -> list[dict[str, Any]]:
        """Dense vector retrieval using sentence-transformers if available.

        Falls back to keyword search (same as _fallback_search) when
        sentence-transformers is not installed or embedding fails.
        """
        if not self._documents:
            return []

        try:
            from sentence_transformers import SentenceTransformer

            model_name = os.environ.get("RAGIN_EMBED_MODEL", "all-MiniLM-L6-v2")
            if self._embedder is None:
                self._embedder = SentenceTransformer(model_name)
            embedder = self._embedder

            doc_texts = [f"{d.get('title', '')} {d.get('content', d.get('text', ''))}" for d in self._documents]

            if not hasattr(self, "_doc_embeddings") or self._doc_embeddings is None:
                logger.info(
                    "Encoding %d documents with %s…",
                    len(doc_texts),
                    model_name,
                )
                self._doc_embeddings = embedder.encode(
                    doc_texts, show_progress_bar=False, normalize_embeddings=True
                ).astype(np.float32)

            query_vec = embedder.encode([query], normalize_embeddings=True).astype(np.float32)

            scores = self._doc_embeddings @ query_vec.T
            top_idx = np.argsort(-scores.ravel())[:top_k]

            logger.info(
                "Dense search [embedding] query=%.60s top_score=%.4f",
                query,
                float(scores.ravel()[top_idx[0]]),
            )

            return [{**self._documents[i], "score": float(scores.ravel()[i])} for i in top_idx]
        except Exception as exc:
            logger.warning(
                "Dense search [KEYWORD fallback] query=%.60s reason=%s",
                query,
                exc,
            )
            return self._keyword_search(query, top_k)

    def _keyword_search(self, query: str, top_k: int) -> list[dict[str, Any]]:
        """Keyword-based search — no model dependencies."""
        query_lower = query.lower()
        query_terms = set(query_lower.split())
        scored: list[tuple[int, float]] = []

        for i, doc in enumerate(self._documents):
            title = doc.get("title", "").lower()
            content = doc.get("content", doc.get("text", "")).lower()
            all_text = f"{title} {content}"
            score = sum(1.0 for term in query_terms if term in all_text)
            if score > 0:
                scored.append((i, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [{**self._documents[i], "score": s} for i, s in scored[:top_k]]

    def _fallback_search(self, query: str, top_k: int) -> list[dict[str, Any]]:
        """Keyword fallback search — delegates to _keyword_search."""
        return self._keyword_search(query, top_k)

    def _fallback_search_vector(self, query_vector: np.ndarray, top_k: int) -> list[dict[str, Any]]:
        """Brute-force vector search fallback."""
        if not self._documents:
            return []
        texts = [d.get("text", d.get("content", "")) for d in self._documents]
        doc_vecs = self._embedding_func_sync(texts)
        qvec = np.asarray(query_vector, dtype=np.float32).reshape(1, -1)
        scores = doc_vecs @ qvec.T
        top_idx = np.argsort(-scores.ravel())[:top_k]
        return [{**self._documents[i], "score": float(scores.ravel()[i])} for i in top_idx]

    def _embedding_func_sync(self, texts: list[str]) -> np.ndarray:
        """Synchronous embedding fallback for tests."""
        dimension = 384
        rng = np.random.RandomState(42)
        vecs = np.zeros((len(texts), dimension), dtype=np.float32)
        for i, t in enumerate(texts):
            seed = sum(ord(c) for c in t) % (2**31)
            rng.seed(seed)
            vecs[i] = rng.randn(dimension).astype(np.float32)
            norm = np.linalg.norm(vecs[i])
            if norm > 0:
                vecs[i] /= norm
        return vecs

    def _fallback_context_window(self, query: str, max_tokens: int) -> str:
        """Keyword-based context building fallback."""
        max_chars = max_tokens * 4
        query_terms = set(query.lower().split())

        relevant: list[dict[str, Any]] = []
        for doc in self._documents:
            title = doc.get("title", "").lower()
            content = doc.get("content", doc.get("text", "")).lower()
            all_text = f"{title} {content}"
            score = sum(1.0 for term in query_terms if term in all_text)
            if score > 0:
                relevant.append({**doc, "_relevance": score})

        relevant.sort(key=lambda d: d.get("_relevance", 0), reverse=True)

        parts: list[str] = []
        used_chars = 0
        for doc in relevant:
            title = doc.get("title", "Untitled")
            content = doc.get("content", doc.get("text", ""))
            entry = f"[{title}]\n{content}\n"
            if used_chars + len(entry) > max_chars:
                remaining = max_chars - used_chars
                if remaining > 100:
                    entry = entry[:remaining] + "..."
                    parts.append(entry)
                break
            parts.append(entry)
            used_chars += len(entry)

        if not parts:
            return "No relevant threat intelligence documents found for this query."

        return "\n---\n".join(parts)
