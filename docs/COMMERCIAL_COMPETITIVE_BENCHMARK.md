# RAGIN — Commercial & Open-Source Competitive Benchmark

**Date:** 2026-07-27  
**Classification:** Internal — Not for Distribution  
**Supplements:** `docs/COMPETITIVE_ANALYSIS.md` (academic/research landscape)

---

## 1. Competitor Map

RAGIN competes across three verticals. This benchmark covers commercial deception platforms, open-source CTI platforms, and hybrid TIP/analytics vendors.

### 1.1 Deception Platforms (Commercial)

| Vendor | Product | Key Capability | Deployment | Pricing Model |
|--------|---------|----------------|------------|---------------|
| **Attivo (SentinelOne)** | Attivo Sentry deception platform | DeceptionAcross — endpoints, network, AD, cloud; integrated into Singularity XDR stack | Cloud/on-prem/hybrid | Enterprise license (bundled with SentinelOne) |
| **Illusive Networks** | Illusive ATT&CK Essentials / Protect | Deceptions Everywhere — no agents, AI-driven deception generation, covers physical/virtual/cloud/AD | Cloud SaaS + on-prem | ~$60/user/year (ATT&CK Essentials); higher tiers for Protect |
| **TrapX** | DeceptionGrid 6.0 | Deception-in-Depth — full OS replication, virtual environments, attack visualization, automated forensics | On-prem/hybrid | Enterprise license |

### 1.2 Open-Source CTI Platforms

| Tool | Focus | Key Capability | Maturity |
|------|-------|----------------|----------|
| **OpenCTI** (Filigran) | Threat intelligence platform | STIX2 native, 2200+ orgs; Community Edition (on-prem) + Enterprise (SaaS with AI, playbooks, PIRs, FINTEL, NLP search) | Production; active development |
| **MISP** | Threat sharing & correlation | Flexible data model, correlation engine, sharing groups, 120+ feeds, event distributions; deployable on-prem/cloud/SaaS | Production; long-established |

### 1.3 TIP + Analytics (Commercial)

| Vendor | Product | Key Capability | Pricing |
|--------|---------|----------------|---------|
| **ThreatConnect** | ThreatConnect Platform | TIP + built-in analytics (Risk Calculations, Attacker Graph, Intelligence Amplification), 160+ integrations, orchestration | Enterprise license |
| **Recorded Future** | Intelligence Cloud | AI-powered; Financial Intelligence, Brand Intelligence, Third-Party Intelligence, GenAI security | Enterprise license (premium) |
| **Anomali** | Anomali Intelligence Cloud | Cloud-native TIP; supports STIX/TAXII, STAXX/TAXIITAXII, 3rd-party tool integration, flexible storage | Enterprise license |

---

## 2. Feature Comparison Matrix

### 2.1 Deception Capabilities

| Capability | Attivo/SentinelOne | Illusive | TrapX | Trapster | **RAGIN** |
|------------|-------------------|----------|-------|----------|-----------|
| **Deception generation method** | Pre-built + configurable | AI-driven auto-generation | Template-based + full OS replication | LLM + YAML config (Trapster AI) | **LLM-generated, CTI-enriched, context-adaptive** |
| **Persona adaptation** | ❌ Static rules | ❌ Static profiles | ❌ Static templates | Partial (LLM prompt-driven) | **✅ 4-tier persona (novice→APT), dynamic selection** |
| **Deceptive response quality** | Low (static banners) | Medium (crafted lures) | Medium (OS emulation) | Medium (LLM + config) | **High (RAG-retrieved CTI + LLM generation)** |
| **Multi-protocol** | ✅ Endpoints, network, AD, cloud | ✅ Endpoints, servers, network | ✅ Full OS, network, cloud | SSH/HTTP (Community) | **✅ SSH/HTTP/DB/FTP** |
| **Active attacker engagement** | ⚠️ Alert-triggered, passive | ⚠️ Lure-based, semi-passive | ⚠️ Deception grid, semi-passive | ⚠️ Honeypot interaction | **✅ Real-time interactive dialogue** |
| **Honeytoken injection** | ✅ Canary credentials | ✅ Decoy files/accounts | ✅ Decoy data | ❌ | **✅ 6 types: credential, URL, API key, file path, DB record, SSH key** |
| **Honeytoken trigger tracking** | ✅ (enterprise) | ✅ (enterprise) | ✅ (enterprise) | ❌ | **✅ Alert tracking with alert_id, timestamp, source** |
| **Artifact realism** | Medium (pre-built templates) | High (AI-generated) | High (full OS replication) | Low-Medium (config files) | **High (LLM + CTI context: realistic creds, configs, data)** |

### 2.2 CTI & Intelligence Capabilities

| Capability | OpenCTI | MISP | ThreatConnect | Recorded Future | Anomali | **RAGIN** |
|------------|---------|------|---------------|-----------------|---------|-----------|
| **Live CTI feeds** | ✅ 100+ connectors (STIX/TAXII, MISP, CSV, API) | ✅ 120+ feeds | ✅ 160+ integrations | ✅ Proprietary collection | ✅ STIX/TAXII, 3rd-party | **✅ MISP, AlienVault OTX, RSS/Atom, CISA KEV (async)** |
| **RAG-based retrieval** | ❌ (keyword + filters) | ❌ (correlation engine) | ❌ (analytics engine) | ❌ (AI search) | ❌ (search + analytics) | **✅ LightRAG hybrid dense/sparse + Qdrant vector store** |
| **MITRE ATT&CK STIX ingestion** | ✅ (via connectors) | ✅ (via MISP events) | ✅ (mapped) | ✅ (mapped) | ✅ (mapped) | **✅ Native STIX parser + 719 techniques indexed** |
| **Automated TTP extraction** | ❌ (manual analyst) | ❌ (manual/correlation) | Partial (Risk Calc) | ✅ (NLP + ML) | Partial (search) | **✅ Keyword-to-ATT&CK + RAG context enrichment** |
| **Knowledge graph** | ✅ (via STIX relations) | ✅ (correlation) | ✅ (Attacker Graph) | ✅ (entity graph) | Partial | **✅ LightRAG entity-relationship extraction** |
| **Threat actor profiles** | ✅ (via reports) | ✅ (via events) | ✅ (via analytics) | ✅ (comprehensive) | ✅ (via feeds) | **✅ Memory-backed attacker profiling** |
| **ATT&CK Navigator heatmap** | ❌ | ❌ | ❌ | ❌ | ❌ | **✅ Programmatic generation, 719 techniques, comparison layers** |
| **Cost/token management** | N/A | N/A | N/A | N/A | N/A | **✅ PromptTokenLimiter, cost-aware routing** |

### 2.3 Attacker Engagement & Analytics

| Capability | Attivo | Illusive | TrapX | HoneyGPT | **RAGIN** |
|------------|--------|----------|-------|----------|-----------|
| **Persistent attacker memory** | ❌ | ❌ | ❌ | ❌ | **✅ Mem0-backed cross-session memory** |
| **Attacker profiling** | ❌ (alert-based) | ❌ (lure-based) | ❌ (forensics-based) | ❌ | **✅ Behavioral profiling, skill-level detection** |
| **Dwell-time tracking** | ⚠️ (passive monitoring) | ❌ | ⚠️ (attack visualization) | ❌ | **✅ Active dwell-time analytics** |
| **Engagement scoring** | ❌ | ❌ | ❌ | ❌ | **✅ Novel metric: deception quality scoring** |
| **Evasion detection** | ❌ | ❌ | ❌ | ❌ | **✅ Behavioral evasion pattern detection** |
| **Adaptive skill strategy** | ❌ | ❌ | ❌ | ❌ | **✅ Difficulty/technique adjustment per attacker** |
| **Real-time TTP mapping** | ❌ (post-incident) | ❌ (post-incident) | ❌ (post-incident) | ❌ | **✅ Live session → MITRE ATT&CK mapping** |
| **Intelligence cycle feedback** | ❌ | ❌ | ❌ | ❌ | **✅ Don ↔ Hisoka closed-loop learning** |

### 2.4 Deployment & Operations

| Aspect | Commercial (Attivo/Illusive/TrapX) | Open-Source (OpenCTI/MISP) | **RAGIN** |
|--------|-------------------------------------|---------------------------|-----------|
| **Deployment model** | Cloud SaaS / on-prem / hybrid | Self-hosted (on-prem/cloud) | **Self-hosted, Docker Compose, cloud-ready** |
| **LLM dependency** | ❌ None | ❌ None | ✅ Requires LLM gateway (OpenRouter/local) |
| **Infrastructure cost** | $$$ (enterprise license) | $ (server + storage) | **$ (server + LLM API costs)** |
| **Setup complexity** | High (enterprise install) | Medium (server + config) | **Medium (Docker Compose, env config)** |
| **Open source** | ❌ Proprietary | ✅ AGPL / BSD | **✅ MIT license** |
| **Academic backing** | ❌ | Partial | **✅ ESWA paper published** |
| **SIEM/SOAR integration** | ✅ Native | ✅ Via connectors | **❌ Not yet (planned)** |
| **Multi-tenant** | ✅ (enterprise) | ✅ (OpenCTI) | ❌ Single-tenant |

---

## 3. RAGIN's Unique Position

### 3.1 The Integration Gap (No Commercial Equivalent)

```
┌─────────────────────────────────────────────────────────────┐
│                    CAPABILITY MATRIX                         │
│                                                              │
│  CTI Analysis ────────────── Deception Generation            │
│  ┌──────────┐                ┌──────────────┐               │
│  │ OpenCTI  │                │ Attivo       │               │
│  │ MISP     │                │ Illusive     │               │
│  │ ThreatC. │                │ TrapX        │               │
│  │ Rec.Future│               │ HoneyGPT     │               │
│  └──────────┘                └──────────────┘               │
│        │                           │                          │
│        │    ╔═══════════════╗      │                          │
│        └───>║    RAGIN      ║<─────┘                          │
│             ║ (CTI + Decep) ║                                 │
│             ╚═══════════════╝                                 │
│                                                              │
│  No existing product bridges BOTH domains.                   │
└─────────────────────────────────────────────────────────────┘
```

**No commercial or open-source product combines:**
1. RAG-based CTI retrieval → fed into real-time deception generation
2. Multi-persona attacker adaptation with persistent memory
3. Honeytoken injection with trigger tracking
4. ATT&CK Navigator heatmap generation from live sessions
5. Closed-loop intelligence cycle (Don ↔ Hisoka feedback)

### 3.2 RAGIN vs. Each Competitor (Head-to-Head)

#### vs. Attivo/SentinelOne
- **Attivo advantage:** Enterprise-grade, SIEM/SOAR integration, thousands of deception templates, established customer base
- **RAGIN advantage:** LLM-generated dynamic deception (not template-based), CTI-enriched responses, RAG retrieval, MIT-licensed, academic validation
- **RAGIN gap:** No enterprise integration, no multi-tenant, LLM dependency

#### vs. Illusive Networks
- **Illusive advantage:** No agents required, AI-driven auto-generation, Cisco partnership, ~$60/user/year affordable pricing
- **RAGIN advantage:** Interactive attacker engagement (not just lures), persistent attacker memory, CTI corpus enrichment, honeynet-style deception
- **RAGIN gap:** No agentless deployment, no enterprise partnerships

#### vs. TrapX
- **TrapX advantage:** Full OS replication, Deception-in-Depth architecture, automated forensics, established platform
- **RAGIN advantage:** LLM-powered dynamic responses, CTI-driven context, persona adaptation, open-source
- **RAGIN gap:** No full OS replication, no automated forensics

#### vs. OpenCTI
- **OpenCTI advantage:** Mature TIP, 2200+ organizations, 100+ connectors, enterprise features (playbooks, PIRs, FINTEL)
- **RAGIN advantage:** Active deception (not just analysis), attacker engagement, honeytokens, memory-backed profiling
- **RAGIN gap:** Not a TIP — doesn't replace OpenCTI, complements it

#### vs. MISP
- **MISP advantage:** Battle-tested sharing platform, 120+ feeds, correlation engine, massive community
- **RAGIN advantage:** Active deception layer, LLM generation, attacker engagement, RAG retrieval
- **RAGIN gap:** Not a sharing platform — MISP could feed RAGIN's CTI pipeline

#### vs. HoneyGPT
- **HoneyGPT advantage:** Published research, field-tested (3 months), 99%+ response rate
- **RAGIN advantage:** RAG-enhanced (HoneyGPT uses parametric knowledge only), multi-persona, persistent memory, artifact injection, multi-protocol, ATT&CK mapping
- **RAGIN gap:** HoneyGPT has published evaluation data; RAGIN needs deception effectiveness benchmarks

---

## 4. Pricing & Deployment Comparison

| Product | Model | Approximate Cost | Deployment |
|---------|-------|-----------------|------------|
| Attivo (SentinelOne) | Enterprise license | $$$$ (bundled with SentinelOne) | Cloud/on-prem |
| Illusive | Per-user SaaS | ~$60/user/year (Essentials) | Cloud/on-prem |
| TrapX | Enterprise license | $$$ | On-prem/hybrid |
| OpenCTI Enterprise | SaaS subscription | $$/month (tiered) | Cloud SaaS |
| OpenCTI Community | Self-hosted | Free (+ infra) | On-prem |
| MISP | Self-hosted | Free (+ infra) | On-prem |
| ThreatConnect | Enterprise license | $$$ | Cloud/on-prem |
| Recorded Future | Enterprise license | $$$$ (premium) | Cloud SaaS |
| Anomali | Enterprise license | $$$ | Cloud/on-prem |
| **RAGIN** | **Open source** | **Free (+ LLM API costs)** | **Self-hosted** |

---

## 5. Strategic Recommendations

### 5.1 RAGIN Strengths to Emphasize
1. **Only RAG-enhanced honeypot** — CTI corpus feeds deception responses
2. **Only cross-domain bridge** — CTI analysis ↔ active deception
3. **Only persistent attacker memory** — Mem0-backed profiling
4. **Only intelligence cycle feedback** — closed-loop Don ↔ Hisoka learning
5. **Academic validation** — ESWA paper provides credibility

### 5.2 Gaps to Address (Post-Benchmark)
1. **SIEM/SOAR integration** — Splunk, Elastic, Sentinel connectors
2. **Deception effectiveness metrics** — published benchmarks vs. traditional honeypots
3. **Enterprise features** — multi-tenant, RBAC, audit logging
4. **Full OS replication** — TrapX-style deep deception (stretch goal)
5. **Cloud-native deployment** — Kubernetes, serverless options

### 5.3 Potential Integrations (Not Competition)
- **OpenCTI → RAGIN:** Feed CTI into RAG corpus
- **MISP → RAGIN:** Event data enrichment
- **RAGIN → Splunk/Elastic:** Alert forwarding
- **RAGIN → ATT&CK Navigator:** Heatmap visualization

---

## Appendix: Source References

| Competitor | Research Source | Date |
|------------|----------------|------|
| Attivo / SentinelOne | Attivo Networks (SentinelOne acquisition) | 2022+ |
| Illusive Networks | illusive.com, Cisco partnership docs | 2024–2026 |
| TrapX | DeceptionGrid 6.0 release, TrapX product docs | 2024–2026 |
| Trapster Community | GitHub: Trapster-AI/Trapster (asyncio honeypot) | 2026 |
| Trapster AI | trapster.ai (deception-as-a-service) | 2026 |
| OpenCTI | opencti.io, Filigran enterprise docs | 2024–2026 |
| MISP | misp-project.org, MISP Galaxy | 2024–2026 |
| ThreatConnect | threatconnect.com, threatconnect.ai | 2024–2026 |
| Recorded Future | recordedfuture.com, Intelligence Cloud docs | 2024–2026 |
| Anomali | anomalist.com, Anomali Intelligence Cloud docs | 2024–2026 |

---

*Document generated from RAGIN competitive benchmark research.*
