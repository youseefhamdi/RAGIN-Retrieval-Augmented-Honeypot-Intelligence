# RAGIN — Competitive Landscape Analysis

**Date:** 2026-07-27  
**Author:** RAGIN Research  
**Classification:** Internal — Not for Distribution

---

## Executive Summary

RAGIN (Retrieval-Augmented Generative INtelligence) occupies a **unique intersection** of three capability domains that no existing open-source or commercial tool combines:

1. **RAG-enhanced threat intelligence ingestion** — MITRE ATT&CK STIX, APT campaign reports, 780K+ CTI documents
2. **Adaptive LLM-powered deception** — multi-persona, context-aware attacker engagement
3. **Persistent attacker profiling** — Mem0-backed memory, dwell-time analytics, engagement scoring

This document maps the competitive landscape across three verticals and positions RAGIN's differentiation.

---

## 1. LLM-Powered Honeypots & Deception Tools

### 1.1 HoneyGPT (2024–2026)
- **Source:** [arXiv 2406.01882](https://arxiv.org/html/2406.01882v1), Computer Networks (2026)
- **Architecture:** Cowrie extension + LLM (GPT-3.5/4) for SSH/Telnet terminal emulation
- **Key innovation:** Structured prompt engineering with Chain-of-Thought for long-term memory
- **Evaluation:** 3-month field deployment; 99%+ response rate across ATT&CK techniques
- **Limitations:**
  - **No RAG** — responses generated from LLM parametric knowledge only, no CTI corpus
  - **No multi-persona** — single shell emulation
  - **No persistent attacker memory** across sessions
  - **No artifact injection** — pure response generation
  - **Limited to SSH/Telnet** — single protocol

### 1.2 DecoyPot (2025)
- **Source:** ScienceDirect (S0167404825001476)
- **Architecture:** RAG-powered web API honeypot with command extractor
- **Key innovation:** Generates legitimate API responses using RAG; similarity score 0.978
- **Evaluation:** Tested across IoT, finance, healthcare, e-commerce API domains
- **Limitations:**
  - **API response mimicry only** — no interactive deception dialogue
  - **No MITRE ATT&CK integration** — no TTP mapping
  - **No attacker profiling** — no cross-session memory
  - **No artifact injection** — no honeytoken placement
  - **Single domain focus** — web API responses

### 1.3 Labyrinth (2025)
- **Source:** arXiv 2506.12989
- **Architecture:** Multi-layered defensive system against autonomous offensive AI
- **Key innovation:** 5-layer defense, deception detection, self-evolving
- **Limitations:**
  - **Defensive tool** — not attacker-facing
  - **No honeypot/deception engagement** — detects deception, doesn't perform it
  - **No CTI integration**

### 1.4 CogSec Agent (2025)
- **Source:** arXiv 2510.20444
- **Architecture:** Self-evolving cognitive security agent (3 agents + 4 modules)
- **Key innovation:** Red team agents probe for vulnerabilities; self-evolving defense
- **Limitations:**
  - **Defense-focused** — scans code, doesn't deceive attackers
  - **No CTI corpus integration**
  - **No attacker memory/profiling**

### 1.5 RAGIN vs. LLM Honeypot Category

| Capability | HoneyGPT | DecoyPot | Labyrinth | CogSec | **RAGIN** |
|---|---|---|---|---|---|
| LLM-powered responses | ✅ | ✅ | ✅ | ✅ | **✅** |
| RAG-enhanced (external corpus) | ❌ | ✅ | ❌ | ❌ | **✅** |
| MITRE ATT&CK STIX ingestion | ❌ | ❌ | ❌ | ❌ | **✅** |
| Multi-persona deception | ❌ | ❌ | ❌ | ❌ | **✅** |
| Persistent attacker memory | ❌ | ❌ | ❌ | ❌ | **✅** |
| Artifact injection (honeytokens) | ❌ | ❌ | ❌ | ❌ | **✅** |
| Multi-protocol support | SSH/Telnet | HTTP API | N/A | N/A | **SSH/HTTP/DB/FTP** |
| Dwell-time analytics | ❌ | ❌ | ❌ | ❌ | **✅** |
| Engagement scoring | ❌ | ❌ | ❌ | ❌ | **✅** |
| CTI-driven context enrichment | ❌ | Partial | ❌ | ❌ | **✅** |
| Cost-aware token management | ❌ | ❌ | ❌ | ❌ | **✅** |

---

## 2. CTI Intelligence Platforms

### 2.1 CTI-Thinker (2026)
- **Source:** arXiv 2603.06748
- **Architecture:** LLM + external knowledge graphs + self-correction loops
- **Focus:** Cyber threat intelligence knowledge graph construction
- **Limitation:** Analysis tool — no deception/engagement capability

### 2.2 CTI-Insight (2026)
- **Source:** arXiv 2601.13158
- **Architecture:** Multi-agent system — CogAgent (RAG), CogReasoner (GraphRAG), CogReporter
- **Focus:** Threat intelligence analysis with MITRE ATT&CK mapping
- **Limitation:** No deception/engagement — pure intelligence tool

### 2.3 CTI-LLM (2026)
- **Source:** arXiv 2603.01568
- **Architecture:** 4-stage pipeline — entity extraction, embedding, similarity, LLM verification
- **Focus:** Automated TTP extraction from reports
- **Limitation:** No deception/engagement

### 2.4 LLM-RAG (2026)
- **Source:** arXiv 2604.16227
- **Architecture:** RAG + SPG (Semantic Property Graph)
- **Focus:** Automated TTP extraction, adversary profiling
- **Limitation:** No deception/engagement

### 2.5 CIPHER (2025)
- **Source:** arXiv 2511.05535
- **Architecture:** RAG + multi-level context processing + structured knowledge base
- **Focus:** Open-source automated TTP extraction
- **Limitation:** No deception/engagement

### 2.6 CTI-SPG (2025)
- **Source:** arXiv 2507.04044
- **Architecture:** Structured Property Graph + entity/relation extraction
- **Focus:** Knowledge graph construction for CTI
- **Limitation:** No deception/engagement

### 2.7 ThreatLens (2026)
- **Source:** arXiv 2603.00795
- **Architecture:** Multi-agent — Triage → Evidence → Reason → Report
- **Focus:** Automated evidence-based threat reporting
- **Limitation:** No deception/engagement

### 2.8 RAGIN vs. CTI Platform Category

| Capability | CTI-Thinker | CTI-Insight | CIPHER | CTI-LLM | ThreatLens | **RAGIN** |
|---|---|---|---|---|---|---|
| TTP extraction from reports | ✅ | ✅ | ✅ | ✅ | ✅ | **✅** |
| Knowledge graph / property graph | ✅ | ✅ | ✅ | Partial | ❌ | **✅** (via LightRAG) |
| MITRE ATT&CK mapping | ❌ | ✅ | ✅ | ✅ | ✅ | **✅** |
| Multi-agent architecture | ❌ | ✅ | ❌ | ❌ | ✅ | **✅** (Don + Hisoka) |
| Active attacker engagement | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| Deception / honeypot | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| Persistent attacker memory | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| Artifact injection | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| Real-time engagement analytics | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |

---

## 3. Cognitive Security & Autonomous Defense

### 3.1 NidhogOS (2025)
- **Source:** arXiv 2510.07040
- **Architecture:** Autonomous cognitive security system, 22 real tools
- **Focus:** Security assessment, attack planning, autonomous defense
- **Limitation:** Defensive tool — no deception/engagement

### 3.2 CyberNorns (2025)
- **Source:** arXiv 2511.14965
- **Architecture:** Self-evolving cyber defense agents with LLM backbone
- **Focus:** Defense strategy generation, adaptive threat response
- **Limitation:** Defense-focused — no attacker engagement

### 3.3 RAGIN vs. Cognitive Security Category

| Capability | NidhogOS | CyberNorns | **RAGIN** |
|---|---|---|---|
| Autonomous operation | ✅ | ✅ | **✅** |
| LLM-powered decision making | ✅ | ✅ | **✅** |
| Self-evolving / adaptive | ✅ | ✅ | **✅** |
| CTI corpus integration | ❌ | ❌ | **✅** |
| Active attacker engagement | ❌ | ❌ | **✅** |
| Deception / honeypot | ❌ | ❌ | **✅** |
| Persistent memory | ❌ | Partial | **✅** (Mem0) |
| Multi-protocol support | ✅ (22 tools) | ❌ | **✅** (SSH/HTTP/DB/FTP) |

---

## 4. RAGIN's Unique Value Proposition

### 4.1 The Integration Gap

No existing tool bridges the gap between **CTI intelligence** and **active deception**:

- CTI platforms **analyze** threat intelligence but don't **engage** attackers
- Honeypots **engage** attackers but don't **leverage** CTI knowledge
- Cognitive agents **defend** but don't **deceive**

RAGIN is the first system to:
1. **Ingest** 780K+ CTI documents (MITRE ATT&CK STIX, APT campaigns, recent reports)
2. **Index** them via hybrid RAG (dense + sparse) for contextual retrieval
3. **Deceive** attackers using CTI-enriched, persona-driven responses
4. **Profile** attackers via persistent memory (Mem0) and engagement analytics
5. **Inject** realistic artifacts (honeytokens) during engagement
6. **Analyze** attacker TTPs in real-time and map to MITRE ATT&CK

### 4.2 Technical Differentiators

| Differentiator | Description |
|---|---|
| **LightRAG backbone** | Hybrid dense/sparse RAG with entity-relationship extraction; no other honeypot uses this |
| **Mem0 persistent memory** | Cross-session attacker profiling; no honeypot has this |
| **Multi-persona deception** | Adaptive persona selection based on attacker behavior; unique to RAGIN |
| **Artifact injection** | Realistic honeytokens planted during engagement; unique to RAGIN |
| **Cost-aware token management** | PromptTokenLimiter prevents token budget overrun; unique to RAGIN |
| **PII redaction** | Automatic redaction in attacker-facing responses; unique to RAGIN |
| **Circuit breaker** | Graceful degradation on LLM failures; unique to RAGIN |
| **Dwell-time analytics** | Tracks engagement duration and quality; unique to RAGIN |
| **Multi-protocol** | SSH, HTTP, DB, FTP deception in one system; unique to RAGIN |

### 4.3 Attack Vector Coverage

RAGIN's CTI corpus enables engagement across all 14 MITRE ATT&CK Enterprise tactics:

| Tactic | CTI Coverage | Deception Capability |
|---|---|---|
| Reconnaissance | ✅ (100+ techniques) | ✅ (fake metadata, misleading responses) |
| Resource Development | ✅ (50+ techniques) | ✅ (fake infrastructure hints) |
| Initial Access | ✅ (50+ techniques) | ✅ (fake credentials, misleading paths) |
| Execution | ✅ (200+ techniques) | ✅ (fake command outputs) |
| Persistence | ✅ (200+ techniques) | ✅ (fake scheduled tasks, services) |
| Privilege Escalation | ✅ (130+ techniques) | ✅ (fake admin accounts) |
| Defense Evasion | ✅ (300+ techniques) | ✅ (misleading forensic data) |
| Credential Access | ✅ (170+ techniques) | ✅ (honeytokens, fake credentials) |
| Discovery | ✅ (300+ techniques) | ✅ (fake network topology) |
| Lateral Movement | ✅ (100+ techniques) | ✅ (fake shares, misleading paths) |
| Collection | ✅ (100+ techniques) | ✅ (fake data repositories) |
| Command and Control | ✅ (200+ techniques) | ✅ (fake C2 endpoints) |
| Exfiltration | ✅ (50+ techniques) | ✅ (fake data stores) |
| Impact | ✅ (80+ techniques) | ✅ (fake critical systems) |

---

## 5. Limitations & Risks

### 5.1 Current Limitations
- **LLM hallucination risk** — CTI-enriched responses may contain inaccuracies
- **Dependency on LLM availability** — gateway downtime degrades deception quality
- **Limited APT campaign data** — currently hand-curated; needs automated ingestion
- **No real-time CTI feed integration** — static corpus, not live threat feeds
- **Evaluation gap** — no published benchmarks comparing deception effectiveness

### 5.2 Competitive Risks
- **HoneyGPT** could add RAG + MITRE integration
- **CTI-Insight** could add deception capability
- **Commercial vendors** (Recorded Future, Mandiant) could build integrated solutions
- **Open-source alternatives** may emerge as LLM honeypot research accelerates

---

## 6. Strategic Positioning

### 6.1 Target Users
- **Red teams** — deception-as-a-service for engagements
- **SOC teams** — honeypot deployment for attacker detection
- **Threat intelligence teams** — CTI enrichment for deception
- **Security researchers** — honeypot effectiveness studies
- **Critical infrastructure** — proactive attacker engagement

### 6.2 Go-to-Market
- **Open source** — MIT license, community-driven
- **Academic publication** — ESWA paper provides credibility
- **Integration ecosystem** — Don pipeline + Hisoka agents
- **CTI corpus as differentiator** — 780K+ documents, MITRE ATT&CK STIX

### 6.3 Next Steps
1. **Automated CTI ingestion** — live feeds, RSS, API integration
2. **Evaluation framework** — deception effectiveness benchmarks
3. **Persona library** — pre-built personas for common attack scenarios
4. **Artifact catalog** — honeytoken templates for different environments
5. **Integration APIs** — SIEM/SOAR connectors for automated response

---

## Appendix A: Competitive Sources

| Tool | Year | Source | Type |
|---|---|---|---|
| HoneyGPT | 2024–2026 | arXiv, Computer Networks | LLM honeypot |
| DecoyPot | 2025 | ScienceDirect | RAG honeypot |
| Labyrinth | 2025 | arXiv | Defensive system |
| CogSec Agent | 2025 | arXiv | Cognitive security |
| NidhogOS | 2025 | arXiv | Autonomous defense |
| CyberNorns | 2025 | arXiv | Self-evolving agents |
| CTI-Thinker | 2026 | arXiv | CTI analysis |
| CTI-Insight | 2026 | arXiv | CTI multi-agent |
| CTI-LLM | 2026 | arXiv | TTP extraction |
| LLM-RAG | 2026 | arXiv | RAG+SPG for CTI |
| CIPHER | 2025 | arXiv | RAG for TTP |
| CTI-SPG | 2025 | arXiv | Knowledge graphs |
| ThreatLens | 2026 | arXiv | Multi-agent reporting |

---

*Document generated by RAGIN competitive analysis pipeline.*
