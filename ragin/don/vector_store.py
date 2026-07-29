"""VectorStore — FAISS-based vector store with sentence-transformer embeddings."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

_DEFAULT_STORE_PATH = os.environ.get("RAGIN_VECTOR_STORE_PATH", "data/vector_store")
_DEFAULT_EMBED_MODEL = os.environ.get("RAGIN_EMBED_MODEL", "all-MiniLM-L6-v2")


class VectorStore:
    """FAISS-backed vector store with optional sentence-transformer embeddings."""

    def __init__(self, store_path: str | None = None) -> None:
        self._store_path = Path(store_path or _DEFAULT_STORE_PATH)
        self._index: Any = None  # faiss.Index
        self._embedder: Any = None  # SentenceTransformer
        self._documents: list[dict[str, Any]] = []
        self._dimension: int = 384  # MiniLM default
        self._initialized = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        try:
            import faiss
            from sentence_transformers import SentenceTransformer

            self._embedder = SentenceTransformer(_DEFAULT_EMBED_MODEL)
            self._dimension = self._embedder.get_sentence_embedding_dimension()
            self._index = faiss.IndexFlatIP(self._dimension)
            self._initialized = True
            logger.info(
                "VectorStore initialised (dim=%d, model=%s)",
                self._dimension,
                _DEFAULT_EMBED_MODEL,
            )
        except ImportError as exc:
            logger.warning(
                "faiss/sentence-transformers not installed — falling back to "
                "numpy brute-force. Install: pip install faiss-cpu sentence-transformers (%s)",
                exc,
            )
            self._index = None
            self._embedder = None
            self._initialized = True

    # ------------------------------------------------------------------
    # Embedding
    # ------------------------------------------------------------------

    def _embed(self, texts: list[str]) -> np.ndarray:
        """Encode texts into L2-normalised embeddings."""
        self._ensure_initialized()
        if self._embedder is not None:
            vecs = self._embedder.encode(texts, show_progress_bar=False, normalize_embeddings=True)
            return np.asarray(vecs, dtype=np.float32)
        # Fallback: simple hash-based pseudo-embeddings (for tests / no GPU)
        rng = np.random.RandomState(42)
        vecs = np.zeros((len(texts), self._dimension), dtype=np.float32)
        for i, t in enumerate(texts):
            seed = sum(ord(c) for c in t) % (2**31)
            rng.seed(seed)
            vecs[i] = rng.randn(self._dimension).astype(np.float32)
            norm = np.linalg.norm(vecs[i])
            if norm > 0:
                vecs[i] /= norm
        return vecs

    # ------------------------------------------------------------------
    # Index
    # ------------------------------------------------------------------

    def add_documents(self, docs: list[dict[str, Any]], metadata: list[dict[str, Any]] | None = None) -> int:
        """Index documents. Each doc must have 'text' key. Returns count added."""
        self._ensure_initialized()
        if not docs:
            return 0
        texts = [d.get("text", d.get("content", "")) for d in docs]
        vecs = self._embed(texts)
        if self._index is not None:
            self._index.add(vecs)
        for i, doc in enumerate(docs):
            entry = {**doc}
            if metadata and i < len(metadata):
                entry["metadata"] = metadata[i]
            self._documents.append(entry)
        logger.info("Added %d documents to VectorStore", len(docs))
        return len(docs)

    def search(self, query_vector: list[float] | str | np.ndarray, top_k: int = 10) -> list[dict[str, Any]]:
        """Similarity search. Accepts raw text or pre-computed vector."""
        self._ensure_initialized()
        if isinstance(query_vector, str):
            qvec = self._embed([query_vector])[0:1]
        else:
            qvec = np.asarray([query_vector], dtype=np.float32)

        if not self._documents:
            return []

        if self._index is not None and self._index.ntotal > 0:
            k = min(top_k, self._index.ntotal)
            scores, indices = self._index.search(qvec, k)
            results = []
            for score, idx in zip(scores[0], indices[0], strict=False):
                if idx < 0 or idx >= len(self._documents):
                    continue
                entry = {**self._documents[idx], "score": float(score)}
                results.append(entry)
            return results

        # Fallback brute-force
        doc_vecs = self._embed([d.get("text", d.get("content", "")) for d in self._documents])
        scores = doc_vecs @ qvec.T
        top_idx = np.argsort(-scores.ravel())[:top_k]
        return [{**self._documents[i], "score": float(scores.ravel()[i])} for i in top_idx]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | None = None) -> None:
        """Persist store to disk."""
        save_path = Path(path or self._store_path)
        save_path.mkdir(parents=True, exist_ok=True)
        with open(save_path / "documents.json", "w") as f:
            json.dump(self._documents, f, default=str)
        with open(save_path / "meta.json", "w") as f:
            json.dump({"dimension": self._dimension, "count": len(self._documents)}, f)
        if self._index is not None:
            import faiss

            faiss.write_index(self._index, str(save_path / "index.faiss"))
        logger.info("VectorStore saved to %s (%d docs)", save_path, len(self._documents))

    def load(self, path: str | None = None) -> None:
        """Load persisted store from disk."""
        load_path = Path(path or self._store_path)
        docs_file = load_path / "documents.json"
        if not docs_file.exists():
            logger.info("No existing store at %s, starting fresh", load_path)
            return
        with open(docs_file) as f:
            self._documents = json.load(f)
        meta_file = load_path / "meta.json"
        if meta_file.exists():
            with open(meta_file) as f:
                meta = json.load(f)
                self._dimension = meta.get("dimension", 384)
        self._ensure_initialized()
        index_file = load_path / "index.faiss"
        if index_file.exists():
            import faiss

            self._index = faiss.read_index(str(index_file))
        logger.info("VectorStore loaded from %s (%d docs)", load_path, len(self._documents))

    @property
    def document_count(self) -> int:
        return len(self._documents)
