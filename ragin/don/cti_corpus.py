"""CTI Corpus Orchestrator — loads real-world threat intelligence into LightRAG.

Combines MITRE ATT&CK STIX data, M-Trends 2026 techniques, Salt Typhoon IOCs,
and active APT group profiles into the LightRAG adapter for unified querying.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ragin.don.lightrag_adapter import LightRAGAdapter
from ragin.don.mitre_cti_loader import (
    get_recent_campaign_documents,
    load_mitre_corpus,
)

logger = logging.getLogger(__name__)


def load_full_cti_corpus(
    adapter: LightRAGAdapter,
    mitre_stix_path: str | Path | None = None,
    include_recent: bool = True,
    force_download: bool = False,
    **kwargs,
) -> dict[str, int]:
    """Load the complete CTI corpus into the LightRAG adapter.

    Args:
        adapter: LightRAGAdapter instance.
        mitre_stix_path: Optional path to MITRE STIX JSON.
        include_recent: Whether to include recent campaign data.
        force_download: Force re-download of MITRE data.
        **kwargs: Passed through to adapter.add_documents().
            Use ``store_in_lightrag=False`` for dense-only benchmarks.

    Returns a breakdown of documents loaded by source.
    """
    stats: dict[str, int] = {}

    # 1. MITRE ATT&CK STIX dataset
    logger.info("Loading MITRE ATT&CK STIX data...")
    mitre_docs = load_mitre_corpus(stix_path=mitre_stix_path, force_download=force_download)
    if mitre_docs:
        count = adapter.add_documents(mitre_docs, **kwargs)
        stats["mitre_attack_stix"] = count
        logger.info("Loaded %d MITRE ATT&CK documents", count)
    else:
        stats["mitre_attack_stix"] = 0
        logger.warning("No MITRE ATT&CK documents loaded")

    # 2. Recent campaign data (M-Trends, Salt Typhoon, Volt Typhoon, APT profiles)
    if include_recent:
        logger.info("Loading recent campaign data...")
        campaign_docs = get_recent_campaign_documents()
        if campaign_docs:
            count = adapter.add_documents(campaign_docs, **kwargs)
            stats["recent_campaigns"] = count
            logger.info("Loaded %d recent campaign documents", count)
        else:
            stats["recent_campaigns"] = 0

    total = sum(stats.values())
    logger.info("CTI corpus loaded: %d total documents across %d sources", total, len(stats))

    return stats


def create_cti_adapter(
    working_dir: str | None = None,
    gateway_url: str | None = None,
    model: str | None = None,
    mitre_stix_path: str | Path | None = None,
    include_recent: bool = True,
    force_download: bool = False,
) -> LightRAGAdapter:
    """Create a fully-loaded LightRAG adapter with real CTI data.

    This is the main entry point for getting a working CTI-backed RAG system.
    """
    adapter = LightRAGAdapter(
        working_dir=working_dir,
        gateway_url=gateway_url,
        model=model,
    )

    load_full_cti_corpus(
        adapter=adapter,
        mitre_stix_path=mitre_stix_path,
        include_recent=include_recent,
        force_download=force_download,
    )

    return adapter
