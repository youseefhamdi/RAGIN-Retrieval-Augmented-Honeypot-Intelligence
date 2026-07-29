"""
Don — Hybrid RAG Threat Intelligence Engine (Phase 2.2)

Components:
    ThreatRAGEngine  — hybrid vector + keyword search with LLM report generation
    VectorStore      — FAISS-backed vector store with sentence-transformer embeddings
    LightRAGAdapter  — drop-in replacement for VectorStore + IntelCorpus using LightRAG
    ThreatMapper     — MITRE ATT&CK mapping and threat actor identification
    IntelCorpus      — 780K+ document corpus with tactic/actor indexing
    DonPipeline      — orchestration: classification → analysis → Hisoka
    CTIFeedManager   — live CTI feed connectors (MISP, OTX, RSS, CISA KEV)
    ATTCKHeatmapGenerator — ATT&CK Navigator JSON heatmap generation
"""

from .attack_heatmap import ATTCKHeatmapGenerator, HeatmapLayer
from .cti_corpus import create_cti_adapter, load_full_cti_corpus
from .cti_feeds import (
    CISAKEVConnector,
    CTIFeedItem,
    CTIFeedManager,
    MISPConnector,
    OTXConnector,
    RSSConnector,
)
from .intel_corpus import IntelCorpus
from .lightrag_adapter import LightRAGAdapter
from .mitre_cti_loader import (
    get_recent_campaign_documents,
    load_mitre_corpus,
    parse_stix_to_documents,
)
from .models import (
    IOC,
    AnalysisRequest,
    AnalysisResponse,
    ClassificationLabel,
    GatewayMessage,
    GatewayRequest,
    GatewayResponse,
    IntelDocument,
    IOCType,
    MITRETactic,
    MITRETacticID,
    SeverityLevel,
    ThreatActor,
    ThreatAnalysis,
)
from .pipeline import DonPipeline
from .rag_engine import ThreatRAGEngine
from .threat_mapper import ThreatMapper
from .vector_store import VectorStore

__all__ = [
    # Existing
    "ThreatRAGEngine",
    "VectorStore",
    "LightRAGAdapter",
    "ThreatMapper",
    "IntelCorpus",
    "DonPipeline",
    "create_cti_adapter",
    "load_full_cti_corpus",
    "load_mitre_corpus",
    "parse_stix_to_documents",
    "get_recent_campaign_documents",
    "AnalysisRequest",
    "AnalysisResponse",
    "ThreatAnalysis",
    "MITRETactic",
    "MITRETacticID",
    "ThreatActor",
    "IOC",
    "IOCType",
    "IntelDocument",
    "SeverityLevel",
    "ClassificationLabel",
    "GatewayMessage",
    "GatewayRequest",
    "GatewayResponse",
    # New: CTI Feeds
    "CTIFeedManager",
    "CTIFeedItem",
    "MISPConnector",
    "OTXConnector",
    "RSSConnector",
    "CISAKEVConnector",
    # New: ATT&CK Heatmap
    "ATTCKHeatmapGenerator",
    "HeatmapLayer",
]
