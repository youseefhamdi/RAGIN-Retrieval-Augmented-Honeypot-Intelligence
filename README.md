<div align="center">

# 🛡️ RAGIN — Retrieval-Augmented Generative INtelligence

**An LLM-powered deception honeypot that engages, profiles, and misleads attackers in real time.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Rust](https://img.shields.io/badge/Gateway-Rust%2FAxum-orange)](llm-gateway/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)](docker-compose.yml)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Testing](#testing)
- [Benchmarks](#benchmarks)
- [Deployment](#deployment)
- [Project Layout](#project-layout)
- [Documentation](#documentation)
- [License](#license)

---

## Overview

RAGIN is a research-grade **adaptive deception honeypot** that combines **Retrieval-Augmented Generation (RAG)** with **multi-persona generative deception** to engage attackers interactively instead of simply logging them.

Unlike static honeypots (e.g., Cowrie) that reply with canned banner responses, RAGIN:

- **Classifies** the attacker's skill level per session (`novice`, `intermediate`, `expert`, `advanced`, `apt`).
- **Retrieves** threat intelligence from a **780K+ document CTI corpus** (MITRE ATT&CK STIX, extended CTI feeds) to answer attack queries with accurate, technique-aware responses.
- **Deceives** by adopting a persona matched to the attacker's skill level, deploying **honeytokens** and realistic fake vulnerabilities that **maximize attacker dwell time**.
- **Remembers** across sessions with **Mem0-backed persistent attacker memory** to build long-term attacker profiles.

**Goal:** a fully autonomous honeypot that looks, sounds, and behaves like a real compromised host — well enough to keep an attacker engaged, extract TTPs, and generate low-false-positive CTI alerts.

### Comparison to existing research

| | RAGIN | HoneyGPT (arXiv 2406.01882) | Cowrie (baseline) |
|---|---|---|---|
| Interaction | Interactive, RAG-grounded | Interactive | Static banner |
| Skill adaptation | 5-strata personas | Fixed persona | None |
| CTI grounding | 780K+ docs, MITRE STIX | Limited | None |
| Attacker memory | Mem0 cross-session | Session-only | None |
| Composite benchmark score | **0.697** | — | **0.45** |

---

## Architecture

```
Attacker ──► [Nginx :443 TLS] ──► [LLM Gateway :8080] ──► [Chrollo :8081] ──► [Don :8082] ──► [Hisoka :8083]
                                     (Rust · Axum)          (Classifier)       (RAG Engine)      (Deceiver)
                                         │                       │                  │                │
                                         ▼                       ▼                  ▼                ▼
                                  OpenRouter /             Random Forest      LightRAG +         Mem0 Memory
                                  TokenRouter              (94.2% acc)       780K+ CTI docs    + 5 personas
                                      │                   + Redis store       + Qdrant / FAISS  + honeytokens
                                      ▼
                              Cost tracking / rate limit
```

| Component | Language | Port | Role |
|-----------|----------|------|------|
| **LLM Gateway** | Rust (Axum) | 8080 | Multi-provider LLM routing, auth, cost tracking, rate limiting, retries |
| **Chrollo** | Python | 8081 | Behavioral classifier — predicts attacker skill level (Random Forest, 94.2% acc, 3.1% FP) |
| **Don** | Python | 8082 | RAG threat-intelligence engine — CTI retrieval, MITRE ATT&CK mapping (92.1% accuracy) |
| **Hisoka** | Python | 8083 | Adaptive deception layer — persona selection, honeytoken deployment, dwell tracking |
| **Redis** | — | 6379 | Session store |
| **Prometheus / Grafana** | — | 9090 / 3000 | Metrics and dashboards |
| **Nginx** | — | 443 | TLS termination, Bearer-token auth, routing |

Full diagrams: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

---

## Features

- **RAG-enhanced threat intelligence** — 780K+ CTI documents, MITRE ATT&CK STIX corpus, extended CTI loader, LightRAG adapter, FAISS/BM25 hybrid retrieval.
- **Multi-persona adaptive deception** — 5 skill-stratified personas with distinct system prompts, response styles, and deception artifacts.
- **Persistent attacker memory** — Mem0-backed cross-session attacker profiling.
- **Honeytoken deployment** — fake credentials/artifacts injected into responses; any use is a **high-confidence attack signal**.
- **TTP extraction** — per-session MITRE ATT&CK technique mapping and CTI alert generation (zero false positives in live audit).
- **Interactive decoys** — SSH (port 2222 nginx listener) and Telnet deception services, Cowrie integration.
- **Production gateway** — Rust-based multi-provider LLM routing (OpenRouter / TokenRouter / local fallback), cost tracking, retries, timeouts.
- **Observability** — Prometheus metrics per component, Grafana dashboards, health checks.
- **Security-hardened** — TLS termination, Bearer-token auth on `/v1/`, secrets never committed, secrets in `.env` only.

---

## Quick Start

### Prerequisites

- Python **3.10+**
- Rust toolchain (for the LLM gateway) or the prebuilt Docker image
- Docker + Docker Compose
- An LLM provider API key (OpenRouter or TokenRouter)

### 1. Clone & configure

```bash
git clone https://github.com/youseefhamdi/RAGIN-Retrieval-Augmented-Honeypot-Intelligence.git
cd RAGIN-Retrieval-Augmented-Honeypot-Intelligence

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"

cp .env.example .env        # then fill in your LLM provider keys
```

### 2. Run with Docker Compose

```bash
docker compose up -d --build
```

This starts the full stack: `gateway`, `chrollo`, `don`, `hisoka`, `redis`, `prometheus`, `grafana`, `nginx`, `cowrie`.

### 3. Verify

```bash
make test          # unit tests
make up            # compose up
curl -s https://localhost/v1/health | jq
```

### 4. Local (non-Docker) run

```bash
make build && make up
```

---

## Configuration

All runtime configuration is via **environment variables** in `.env` (never committed):

| Variable | Description |
|----------|-------------|
| `OPENROUTER_API_KEY` | OpenRouter API key (primary LLM provider) |
| `TOKENROUTER_API_KEY` | TokenRouter API key (fallback provider) |
| `GATEWAY_PORT` | Gateway listen port (default `8080`) |
| `RAGIN_REDIS_URL` | Redis connection string |
| `ACTIVE_STATE` | `local` or `shared` deployment mode |

Gateway routing policy, retries, and timeouts live in `llm-gateway/config.toml`.

See also: [`docs/DEPLOYMENT_CHECKLIST.md`](docs/DEPLOYMENT_CHECKLIST.md), [`docs/OPERATIONAL_RUNBOOK.md`](docs/OPERATIONAL_RUNBOOK.md)

---

## Testing

```bash
make test              # unit tests
make test-integration  # integration tests
make test-security     # security tests
make test-all          # full suite
make lint              # ruff
make typecheck         # mypy
make security-scan     # bandit + pip-audit
```

Test suites: **36 test modules** covering unit, integration, security, and slow paths (`tests/`).

---

## Benchmarks

| Benchmark | Result |
|-----------|--------|
| **Chrollo classifier accuracy** | 94.2% (3.1% false-positive rate) |
| **Don RAG accuracy** | 92.1% |
| **Hisoka dwell time vs static** | **4.1×** longer attacker retention |
| **Live audit (218 sessions)** | 218/218 persona-correct, **82 TTPs detected, 0 false positives**, 82 CTI alerts |
| **Composite deception score** | **0.697** vs **0.45** for Cowrie baseline |
| **Engagement rate** | 96% (29/30 sessions) vs baseline |
| **Mean attacker session** | 160.6s sustained engagement |

Raw results: [`results/`](results/) — including `live_benchmark_audited.json`, `cowrie_comparison.json`, `algorithm_validation.json`, `b4_baseline_comparison.json`, `human_eval.json`.

---

## Deployment

- `docker-compose.prod.yml` — production stack with TLS + auth
- `docker-compose.test.yml` — CI/testing stack
- `docker-compose.ab.yml` / `docker-compose.canary.yml` — A/B and canary deception variants
- `deploy.sh` / `deploy.py` — VPS deployment helpers
- `Dockerfile.gateway` / `Dockerfile.python` — service images

Field deployment details: [`docs/DEPLOYMENT_CHECKLIST.md`](docs/DEPLOYMENT_CHECKLIST.md), [`docs/SECURITY_HARDENING.md`](docs/SECURITY_HARDENING.md), [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)

---

## Project Layout

```
ragin/                 # Python package
├── chrollo/           #   skill-level classifier
├── don/               #   RAG threat-intelligence engine
├── hisoka/            #   adaptive deception layer
├── cycle/             #   intelligence cycle (harness, session, sandbox, coordination, threat modeling)
├── decoys/            #   SSH / Telnet / HTTP deception services
├── siem/              #   alerting / CTI integration
├── intelligence/      #   TTP extraction, threat mapping
├── monitoring/        #   Prometheus metrics
├── rollout/           #   deployment / lifecycle
├── auth/              #   authentication
├── benchmark/         #   benchmark harnesses
├── config/            #   runtime config
└── server.py / server_v2.py

llm-gateway/           # Rust (Axum) multi-provider LLM gateway — routing, auth, cost tracking
data/                  # CTI corpus (MITRE STIX), honeypot session logs, cowrie logs
tests/                 # 36 unit/integration/security test modules
results/               # benchmark & audit outputs
scripts/               # utility scripts
docs/                  # architecture, runbook, hardening, troubleshooting
docker-compose*.yml    # deployment stacks
Makefile               # build / test / run targets
```

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system architecture and sequence diagrams
- [`docs/OPERATIONAL_RUNBOOK.md`](docs/OPERATIONAL_RUNBOOK.md) — day-to-day operations
- [`docs/SECURITY_HARDENING.md`](docs/SECURITY_HARDENING.md) — security posture
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — common issues
- [`docs/COST_OPTIMIZATION.md`](docs/COST_OPTIMIZATION.md) — LLM cost tuning
- [`PROJECT_STATUS.md`](PROJECT_STATUS.md) — phase-by-phase implementation status
- [`DEPLOYMENT_READINESS.md`](DEPLOYMENT_READINESS.md) — production readiness

---

## License

Copyright © 2026 youseefhamdi

Licensed under the **Apache License, Version 2.0** (the "License"); you may not use this software except in compliance with the License.

You may obtain a copy of the License at

```
https://www.apache.org/licenses/LICENSE-2.0
```

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an **"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND**, either express or implied. See the License for the specific language governing permissions and limitations under the License.
