"""Unit tests for LightRAGAdapter — drop-in replacement for VectorStore + IntelCorpus.

Mirrors TestVectorStore and TestIntelCorpus patterns from test_don.py
to verify adapter compatibility.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from ragin.don.lightrag_adapter import LightRAGAdapter

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sample_docs() -> list[dict]:
    return [
        {
            "doc_id": "d1",
            "title": "APT28 Phishing Campaign",
            "content": "APT28 distributed malware via spearphishing emails targeting government agencies",
            "text": "APT28 distributed malware via spearphishing emails targeting government agencies",
            "mitre_tactics": ["TA0001", "TA0002"],
            "threat_actors": ["apt28"],
            "tags": ["phishing", "russia"],
        },
        {
            "doc_id": "d2",
            "title": "Lazarus Group Ransomware",
            "content": "Lazarus deployed ransomware targeting financial sector with encrypted channels",
            "text": "Lazarus deployed ransomware targeting financial sector with encrypted channels",
            "mitre_tactics": ["TA0040"],
            "threat_actors": ["lazarus group"],
            "tags": ["ransomware", "north korea"],
        },
        {
            "doc_id": "d3",
            "title": "Generic C2 Infrastructure",
            "content": "Command and control server used encrypted channels for communication",
            "text": "Command and control server used encrypted channels for communication",
            "mitre_tactics": ["TA0011"],
            "threat_actors": [],
            "tags": ["c2"],
        },
    ]


# ---------------------------------------------------------------------------
# VectorStore-compatible interface tests
# ---------------------------------------------------------------------------


class TestAddDocuments:
    def test_add_and_count(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        docs = _sample_docs()
        count = adapter.add_documents(docs)
        assert count == 3
        assert adapter.document_count == 3

    def test_add_empty(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        count = adapter.add_documents([])
        assert count == 0

    def test_add_with_metadata(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        docs = [{"text": "doc one", "doc_id": "d1"}]
        meta = [{"source": "test", "mitre_tactics": ["TA0001"]}]
        count = adapter.add_documents(docs, metadata=meta)
        assert count == 1

    def test_add_content_fallback(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        docs = [{"content": "uses content key not text", "doc_id": "d1"}]
        count = adapter.add_documents(docs)
        assert count == 1
        assert adapter.document_count == 1


class TestSearch:
    def test_text_query_returns_results(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter.add_documents(_sample_docs())
        results = adapter.search("APT28 phishing")
        assert isinstance(results, list)

    def test_search_empty_store(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        results = adapter.search("anything")
        assert results == []

    def test_search_with_vector(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter.add_documents(_sample_docs())
        qvec = np.zeros(384, dtype=np.float32)
        results = adapter.search(qvec, top_k=1)
        assert isinstance(results, list)


class TestHybridSearch:
    def test_hybrid_returns_list(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter.add_documents(_sample_docs())
        results = adapter.hybrid_search("APT28 ransomware")
        assert isinstance(results, list)

    def test_hybrid_empty_store(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        results = adapter.hybrid_search("anything")
        assert results == []


class TestPersistence:
    def test_save_and_load(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter.add_documents(_sample_docs())
        adapter.save()
        assert (tmp_path / "rag" / "documents.json").exists()
        assert (tmp_path / "rag" / "meta.json").exists()

        adapter2 = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter2.load()
        assert adapter2.document_count == 3

    def test_load_no_existing(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "empty"))
        adapter.load()  # should not raise
        assert adapter.document_count == 0


# ---------------------------------------------------------------------------
# IntelCorpus-compatible interface tests
# ---------------------------------------------------------------------------


class TestLoadCorpus:
    def test_load_json(self, tmp_path):
        docs = _sample_docs()
        corpus_path = tmp_path / "corpus.json"
        corpus_path.write_text(json.dumps(docs))
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        count = adapter.load_corpus(str(corpus_path))
        assert count == 3

    def test_load_jsonl(self, tmp_path):
        path = tmp_path / "test.jsonl"
        path.write_text(
            '{"title": "Doc1", "content": "content1", "text": "content1"}\n'
            '{"title": "Doc2", "content": "content2", "text": "content2"}\n'
        )
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        count = adapter.load_corpus(str(path))
        assert count == 2

    def test_load_single_dict(self, tmp_path):
        path = tmp_path / "single.json"
        path.write_text('{"title": "Only", "content": "one doc", "text": "one doc"}')
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        count = adapter.load_corpus(str(path))
        assert count == 1

    def test_load_nonexistent(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        count = adapter.load_corpus("/nonexistent/path")
        assert count == 0

    def test_load_malformed_jsonl(self, tmp_path):
        path = tmp_path / "bad.jsonl"
        path.write_text('{"ok": 1}\nnot json\n{"ok": 2}\n')
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        count = adapter.load_corpus(str(path))
        assert count == 2  # skips malformed


class TestTacticSearch:
    def test_search_by_tactic(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter.add_documents(_sample_docs())
        results = adapter.search_by_tactic("TA0001")
        assert len(results) == 1
        assert "APT28" in results[0]["title"]

    def test_search_by_tactic_case_insensitive(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter.add_documents(_sample_docs())
        results = adapter.search_by_tactic("ta0001")
        assert len(results) == 1

    def test_search_by_tactic_no_match(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter.add_documents(_sample_docs())
        results = adapter.search_by_tactic("TA9999")
        assert len(results) == 0


class TestActorSearch:
    def test_search_by_actor(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter.add_documents(_sample_docs())
        results = adapter.search_by_actor("apt28")
        assert len(results) == 1

    def test_search_by_actor_fuzzy(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter.add_documents(_sample_docs())
        results = adapter.search_by_actor("apt")
        assert len(results) >= 1

    def test_search_by_actor_no_match(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter.add_documents(_sample_docs())
        results = adapter.search_by_actor("nonexistent_actor")
        assert len(results) == 0


class TestContextWindow:
    def test_context_window_returns_string(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter.add_documents(_sample_docs())
        ctx = adapter.get_context_window("APT28 phishing", max_tokens=4000)
        assert isinstance(ctx, str)

    def test_context_window_has_content(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter.add_documents(_sample_docs())
        ctx = adapter.get_context_window("APT28 phishing", max_tokens=4000)
        assert "No relevant" in ctx or len(ctx) > 0

    def test_context_window_empty_store(self, tmp_path):
        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        ctx = adapter.get_context_window("anything")
        # LightRAG returns a no-context message when the store is empty
        assert "No relevant" in ctx or "no-context" in ctx or "not able to provide" in ctx


# ---------------------------------------------------------------------------
# MITRE STIX loader tests
# ---------------------------------------------------------------------------


class TestMitreLoader:
    def test_parse_stix_documents(self, tmp_path):
        """Test parsing a minimal STIX bundle."""
        bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--1",
                    "name": "Spearphishing",
                    "description": "Adversary sent spearphishing emails",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1566",
                            "url": "https://attack.mitre.org/techniques/T1566",
                        }
                    ],
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
                    "x_mitre_platforms": ["Windows", "Linux"],
                    "x_mitre_data_sources": ["Email gateway logs"],
                    "created": "2021-05-01T00:00:00Z",
                },
                {
                    "type": "intrusion-set",
                    "id": "intrusion-set--1",
                    "name": "APT28",
                    "description": "Russian state-sponsored threat actor",
                    "x_mitre_aliases": ["Fancy Bear", "Sofacy"],
                    "x_mitre_country": "Russia",
                    "created": "2020-01-01T00:00:00Z",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "G0007"}],
                },
                {
                    "type": "x-mitre-tactic",
                    "id": "x-mitre-tactic--1",
                    "name": "Initial Access",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "TA0001"}],
                },
            ],
        }
        stix_file = tmp_path / "test.json"
        stix_file.write_text(json.dumps(bundle))

        from ragin.don.mitre_cti_loader import parse_stix_to_documents

        docs = parse_stix_to_documents(stix_file)

        assert len(docs) >= 2  # attack-pattern + intrusion-set
        technique_docs = [d for d in docs if d["obj_type"] == "attack-pattern"]
        actor_docs = [d for d in docs if d["obj_type"] == "intrusion-set"]
        assert len(technique_docs) == 1
        assert len(actor_docs) == 1

        # Verify technique
        t = technique_docs[0]
        assert t["external_id"] == "T1566"
        assert "spearphishing" in t["title"].lower()
        assert t["mitre_tactics"] == ["initial-access"]

        # Verify actor
        a = actor_docs[0]
        assert a["external_id"] == "G0007"
        assert "apt28" in a["threat_actors"]

    def test_skips_revoked_objects(self, tmp_path):
        bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "ap--1",
                    "name": "Active",
                    "description": "Active technique",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1001"}],
                    "created": "2021-01-01T00:00:00Z",
                },
                {
                    "type": "attack-pattern",
                    "id": "ap--2",
                    "name": "Revoked",
                    "description": "Revoked technique",
                    "revoked": True,
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1002"}],
                    "created": "2021-01-01T00:00:00Z",
                },
            ],
        }
        stix_file = tmp_path / "test.json"
        stix_file.write_text(json.dumps(bundle))
        from ragin.don.mitre_cti_loader import parse_stix_to_documents

        docs = parse_stix_to_documents(stix_file)
        assert len(docs) == 1
        assert docs[0]["external_id"] == "T1001"


class TestRecentCampaigns:
    def test_returns_documents(self):
        from ragin.don.mitre_cti_loader import get_recent_campaign_documents

        docs = get_recent_campaign_documents()
        assert len(docs) > 0
        ids = [d["doc_id"] for d in docs]
        assert "campaign-salt-typhoon-2024" in ids
        assert "campaign-volt-typhoon-2024" in ids

    def test_has_mitre_tactics(self):
        from ragin.don.mitre_cti_loader import get_recent_campaign_documents

        docs = get_recent_campaign_documents()
        for doc in docs:
            assert "mitre_tactics" in doc
            assert isinstance(doc["mitre_tactics"], list)


# ---------------------------------------------------------------------------
# CTI Corpus orchestrator tests
# ---------------------------------------------------------------------------


@pytest.mark.integration()
@pytest.mark.slow()
class TestCTICorpus:
    def test_create_adapter_with_cti(self, tmp_path):
        """Integration test: create adapter and load real MITRE + campaign data."""
        from ragin.don.cti_corpus import create_cti_adapter

        adapter = create_cti_adapter(
            working_dir=str(tmp_path / "rag"),
            include_recent=True,
            force_download=False,
        )
        assert adapter.document_count > 0
        # Should have MITRE techniques + campaigns
        assert adapter.document_count > 50

    def test_load_full_corpus_stats(self, tmp_path):
        from ragin.don.cti_corpus import load_full_cti_corpus

        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        stats = load_full_cti_corpus(adapter, include_recent=True)
        assert "mitre_attack_stix" in stats
        assert stats["mitre_attack_stix"] > 0
        assert "recent_campaigns" in stats
        assert stats["recent_campaigns"] > 0


# ---------------------------------------------------------------------------
# ThreatRAGEngine with LightRAG adapter integration
# ---------------------------------------------------------------------------


class TestThreatRAGEngineWithAdapter:
    @pytest.mark.integration()
    @pytest.mark.slow()
    def test_engine_delegates_to_adapter(self, tmp_path):
        """Engine search_threat_intel routes through LightRAG adapter."""
        from ragin.don.rag_engine import ThreatRAGEngine

        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter.add_documents(_sample_docs())
        engine = ThreatRAGEngine(
            gateway_url="http://localhost:8080",
            lightrag_adapter=adapter,
        )

        results = engine.search_threat_intel("APT28 phishing")
        assert isinstance(results, list)
        # Adapter has docs, so results should come from adapter
        assert engine._lightrag_adapter is adapter
        assert engine._vector_store is None

    @pytest.mark.integration()
    @pytest.mark.slow()
    def test_engine_hybrid_search_delegates(self, tmp_path):
        from ragin.don.rag_engine import ThreatRAGEngine

        adapter = LightRAGAdapter(working_dir=str(tmp_path / "rag"))
        adapter.add_documents(_sample_docs())
        engine = ThreatRAGEngine(
            gateway_url="http://localhost:8080",
            lightrag_adapter=adapter,
        )

        results = engine.hybrid_search("APT28 ransomware")
        assert isinstance(results, list)

    def test_engine_without_adapter_uses_vectorstore(self, tmp_path):
        """Default path: no adapter → VectorStore is created."""
        from ragin.don.rag_engine import ThreatRAGEngine

        engine = ThreatRAGEngine(
            vector_store_path=str(tmp_path / "faiss"),
            gateway_url="http://localhost:8080",
        )
        assert engine._lightrag_adapter is None
        assert engine._vector_store is not None


# ---------------------------------------------------------------------------
# DonPipeline with use_lightrag flag
# ---------------------------------------------------------------------------


class TestDonPipelineWithLightRAG:
    def test_pipeline_creates_adapter(self, tmp_path):
        """Pipeline with use_lightrag=True creates a LightRAG adapter."""
        from ragin.don.pipeline import DonPipeline

        pipeline = DonPipeline(
            gateway_url="http://localhost:8080",
            hisoka_url="http://localhost:8082",
            use_lightrag=True,
            lightrag_workdir=str(tmp_path / "rag"),
        )
        assert pipeline.lightrag_adapter is not None
        assert isinstance(pipeline.lightrag_adapter, LightRAGAdapter)

    def test_pipeline_without_lightrag(self):
        """Default pipeline without use_lightrag has no adapter."""
        from ragin.don.pipeline import DonPipeline

        pipeline = DonPipeline(
            gateway_url="http://localhost:8080",
            hisoka_url="http://localhost:8082",
            use_lightrag=False,
        )
        assert pipeline.lightrag_adapter is None

    def test_pipeline_load_corpus_raises_without_adapter(self):
        """load_cti_corpus raises RuntimeError when adapter not configured."""
        from ragin.don.pipeline import DonPipeline

        pipeline = DonPipeline(
            gateway_url="http://localhost:8080",
            hisoka_url="http://localhost:8082",
            use_lightrag=False,
        )
        with pytest.raises(RuntimeError, match="use_lightrag=True"):
            pipeline.load_cti_corpus()

    @pytest.mark.integration()
    @pytest.mark.slow()
    def test_pipeline_load_corpus_works_with_adapter(self, tmp_path):
        """load_cti_corpus loads data into adapter."""
        from ragin.don.pipeline import DonPipeline

        pipeline = DonPipeline(
            gateway_url="http://localhost:8080",
            hisoka_url="http://localhost:8082",
            use_lightrag=True,
            lightrag_workdir=str(tmp_path / "rag"),
        )
        stats = pipeline.load_cti_corpus()
        assert stats["mitre_attack_stix"] > 0
        assert stats["recent_campaigns"] > 0
        assert pipeline.lightrag_adapter.document_count > 50
