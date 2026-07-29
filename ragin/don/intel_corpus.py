"""IntelCorpus — load, index, and query the 780K+ threat intelligence document corpus."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_CORPUS_PATH = os.environ.get("RAGIN_CORPUS_PATH", "data/corpus")


class IntelCorpus:
    """Threat intelligence corpus with tactic/actor indexing and LLM context window builder."""

    def __init__(self, corpus_path: str | None = None) -> None:
        self._corpus_path = Path(corpus_path or _DEFAULT_CORPUS_PATH)
        self._documents: list[dict[str, Any]] = []
        self._tactic_index: dict[str, list[int]] = {}
        self._actor_index: dict[str, list[int]] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_corpus(self, path: str | None = None) -> int:
        """Load documents from JSON/JSONL. Returns count loaded."""
        load_path = Path(path or self._corpus_path)
        if load_path.is_dir():
            return self._load_directory(load_path)
        if load_path.is_file():
            return self._load_file(load_path)
        logger.warning("Corpus path not found: %s", load_path)
        return 0

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

    def _rebuild_indices(self) -> None:
        self._tactic_index.clear()
        self._actor_index.clear()
        for i, doc in enumerate(self._documents):
            for t in doc.get("mitre_tactics", []):
                self._tactic_index.setdefault(t.lower(), []).append(i)
            for a in doc.get("threat_actors", []):
                self._actor_index.setdefault(a.lower(), []).append(i)
        self._loaded = True
        logger.info(
            "Corpus indexed: %d docs, %d tactics, %d actors",
            len(self._documents),
            len(self._tactic_index),
            len(self._actor_index),
        )

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

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

    def search_by_keyword(self, keyword: str) -> list[dict[str, Any]]:
        """Simple keyword search across titles and content."""
        self._ensure_loaded()
        kw = keyword.lower()
        results: list[dict[str, Any]] = []
        for doc in self._documents:
            title = doc.get("title", "").lower()
            content = doc.get("content", "").lower()
            if kw in title or kw in content:
                results.append(doc)
        return results

    # ------------------------------------------------------------------
    # Context window builder
    # ------------------------------------------------------------------

    def get_context_window(self, query: str, max_tokens: int = 4000) -> str:
        """Build a context string for LLM from relevant docs, respecting token budget."""
        self._ensure_loaded()
        # Rough heuristic: 1 token ~ 4 chars
        max_chars = max_tokens * 4

        # Find relevant docs via keyword matching
        relevant: list[dict[str, Any]] = []
        query_lower = query.lower()
        query_terms = set(re.findall(r"\w+", query_lower))

        for doc in self._documents:
            score = 0
            title = doc.get("title", "").lower()
            content = doc.get("content", "").lower()
            tags = [t.lower() for t in doc.get("tags", [])]
            tactics = [t.lower() for t in doc.get("mitre_tactics", [])]
            actors = [a.lower() for a in doc.get("threat_actors", [])]

            all_text = f"{title} {content} {' '.join(tags)} {' '.join(tactics)} {' '.join(actors)}"
            for term in query_terms:
                if term in all_text:
                    score += 1
            if score > 0:
                relevant.append({**doc, "_relevance": score})

        relevant.sort(key=lambda d: d.get("_relevance", 0), reverse=True)

        # Build context respecting token budget
        parts: list[str] = []
        used_chars = 0
        for doc in relevant:
            title = doc.get("title", "Untitled")
            content = doc.get("content", "")
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

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load_corpus()

    @property
    def document_count(self) -> int:
        return len(self._documents)
