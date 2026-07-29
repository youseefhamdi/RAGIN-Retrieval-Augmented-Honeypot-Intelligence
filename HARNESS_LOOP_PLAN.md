# RAGIN v2 — Harness & Loop Engineering Integration Plan

**Date:** 2026-07-29
**Status:** Active — Phase 3 ✅, Phase 4 ✅
**References:** Anthropic Managed Agents, revfactory/harness, HKUDS/OpenHarness, visa/vvaharness, cobusgreyling/loop-engineering

---

## Executive Summary

Six references that reshape how RAGIN should be built. The current implementation is a **linear pipeline** (Chrollo → Don → Hisoka). The references reveal it should be a **loop-driven, multi-agent harness** with:

- Decoupled brain/hands architecture (Anthropic)
- Production-grade agent loop with 43+ tools (OpenHarness)
- 6 team-architecture patterns for agent coordination (revfactory/harness)
- 11-stage vulnerability research pipeline with deterministic voting (VVAH)
- 7 production loop patterns with readiness scoring (loop-engineering)
- Structured pre-configuration yielding +60% quality improvement (revfactory A/B)

**Impact:** This changes RAGIN from "LLM honeypot" to "autonomous deception operating system."

---

## 1. What Each Reference Teaches RAGIN

### 1.1 Anthropic Managed Agents — Decouple Brain from Hands

**Core insight:** Harnesses encode assumptions that go stale as models improve. Design stable interfaces.

| Concept | Anthropic's Lesson | RAGIN Application |
|---------|-------------------|-------------------|
| **Session = append-only log** | Context lives outside the context window; durable, interrogatable | Attacker interaction log = session. Don't lose context on model changes. |
| **Harness = the loop** | Stateless, replaceable. Crashes don't lose data. | RAGIN's orchestrator should be a thin loop, not coupled to any model. |
| **Sandbox = execution env** | Credentials never reach the sandbox. | Attacker commands execute in isolated sandbox; CTI corpus is the "hands." |
| **Pets → Cattle** | Don't nurse containers back to health; provision new ones. | Honeypot instances are cattle. Attacker session survives instance death. |
| **Many brains, many hands** | Multiple LLMs can share sandbox; no coupling. | Chrollo, Don, Hisoka = different "brains" sharing one attacker session. |
| **TTFT optimization** | Decoupling dropped p50 TTFT 60%, p95 90%. | RAGIN response latency improves when harness isn't booting containers. |

**Action items:**
- [ ] Separate `Session` (durable event log) from `Harness` (orchestration loop) from `Sandbox` (attacker interaction)
- [ ] Make harness stateless — crash recovery via `wake(sessionId)` + `getSession(id)`
- [ ] Credentials in vault, never in sandbox

### 1.2 revfactory/harness — Team-Architecture Factory

**Core insight:** 6 pre-defined patterns for agent coordination. +60% quality with structured pre-configuration (A/B tested, n=15).

| Pattern | Description | RAGIN Fit |
|---------|-------------|-----------|
| **Pipeline** | Sequential dependent tasks | Chrollo → Don → Hisoka (current flow) |
| **Fan-out/Fan-in** | Parallel independent tasks | Multiple CTI feed ingestion in parallel |
| **Expert Pool** | Context-dependent selective invocation | Persona selection: route attacker to right "expert" |
| **Producer-Reviewer** | Generation + quality review | Hisoka generates response → EvasionDetector reviews |
| **Supervisor** | Central agent + dynamic task distribution | Orchestrator routes between personas/strategies |
| **Hierarchical Delegation** | Top-down recursive delegation | Complex multi-step attack → sub-task decomposition |

**Action items:**
- [ ] Map RAGIN components to the 6 patterns
- [ ] Implement Producer-Reviewer for deception response quality
- [ ] Implement Supervisor pattern for dynamic persona routing
- [ ] Use Expert Pool for CTI skill selection

### 1.3 HKUDS/OpenHarness — Production Agent Infrastructure

**Core insight:** Harness = Tools + Knowledge + Observation + Action + Permissions. 43+ tools, skills, memory, multi-agent coordination.

| Subsystem | OpenHarness | RAGIN Current | Gap |
|-----------|------------|---------------|-----|
| **Agent Loop** | Streaming tool-call cycle, retry, parallel exec | Linear request/response | No streaming, no retry, no parallel |
| **Tools** | 43 tools (file, shell, search, web, MCP) | 3 HTTP endpoints | No tool ecosystem |
| **Skills** | On-demand .md knowledge loading | Static prompts | No dynamic skill loading |
| **Memory** | MEMORY.md persistent, cross-session | Mem0 basic | No structured memory tiers |
| **Governance** | Multi-level permissions, path rules, hooks | Basic API key auth | No fine-grained permissions |
| **Swarm** | Subagent spawning, team coordination | Single-agent | No multi-agent coordination |
| **Context** | Auto-compact, session resume | No context management | Context loss on long sessions |

**Action items:**
- [ ] Implement streaming agent loop for Hisoka (real-time attacker interaction)
- [ ] Add skill system: CTI skills loaded on-demand per attack pattern
- [ ] Implement context compression for long attacker sessions
- [ ] Add permission layers: attacker can't escape sandbox, analyst can't modify honeypot
- [ ] Add PreToolUse/PostToolUse hooks for audit logging

### 1.4 visa/vvaharness — Vulnerability Research Pipeline

**Core insight:** 4-phase, 11-stage pipeline with multi-agent deterministic voting. Threat modeling BEFORE analysis. MTTA (Mean Time to Adapt) as primary metric.

| VVAH Stage | RAGIN Equivalent | What to Adopt |
|------------|-----------------|---------------|
| **S1 — Attack surface mapping** | Chrollo command classification | Add structured attack surface model |
| **S2 — Threat modeling** | Don CTI lookup | Add STRIDE/threat model before response |
| **S3 — Hunting plan** | Hisoka persona selection | Strategy planning before engagement |
| **S4 — Multi-lens research** | Don RAG query | Multiple CTI lenses, not just keyword |
| **S5 — Pre-filter** | Chrollo confidence filter | Deterministic gates before LLM |
| **S6 — Adversarial verification** | EvasionDetector | Verify response quality adversarially |
| **S7 — Deduplication** | — | Deduplicate attacker techniques across sessions |
| **S8 — Chain construction** | — | Build attack chains from observed TTPs |
| **S9 — SARIF emission** | — | Structured output (SARIF for findings) |
| **S10 — Remediation** | — | Auto-generate defensive recommendations |
| **S11 — Validation panel** | — | Multi-agent panel validates responses |

**Key VVAH patterns to adopt:**
- **Multi-agent deterministic voting** — multiple LLMs vote on response quality, reducing false positives
- **Threat modeling before analysis** — don't just respond, model the threat first
- **Structured triage artifacts** — every finding has CWE, severity, confidence, chain
- **MTTA as primary metric** — time from detection to validated response

**Action items:**
- [ ] Add threat modeling stage (S2) before Hisoka response generation
- [ ] Implement multi-agent voting for high-stakes responses
- [ ] Add structured finding output (MITRE ATT&CK mapping + confidence + chain)
- [ ] Track MTTA: time from attacker command to validated deception response

### 1.5 cobusgreyling/loop-engineering — Agent Loop Patterns

**Core insight:** 5 building blocks + Memory. 7 production patterns. Loop Readiness Score 0-100.

| Primitive | Loop-Engineering | RAGIN Application |
|-----------|------------------|-------------------|
| **Scheduling** | Cron, automations | Continuous CTI ingestion, honeypot health checks |
| **Worktrees** | Parallel without collisions | Multiple attacker sessions in isolation |
| **Skills** | Intent written once | CTI knowledge loaded per attack type |
| **Connectors** | MCP → real tools | SIEM integration, MISP feeds, OSINT tools |
| **Sub-agents** | Maker/checker split | Hisoka generates, EvasionDetector verifies |
| **State** | Memory outside the model | Attacker profiles, session history, TTP tracking |

**Most relevant patterns:**

| Pattern | Cadence | RAGIN Fit |
|---------|---------|-----------|
| **Daily Triage** | 1d-2h | Morning scan of overnight attacker activity |
| **CI Sweeper** | 5-15m | Continuous honeypot health + CTI freshness |
| **Dependency Sweeper** | 6h-1d | CTI feed updates, model version checks |
| **Issue Triage** | 2h-1d | Attacker session triage, priority scoring |

**Loop Readiness Score for RAGIN:**
- State file: Attacker profile DB ✓
- Triage skill: Chrollo classifier ✓
- Verifier: EvasionDetector (partial)
- Safety docs: Sandbox isolation (partial)
- Cost observability: PromptTokenLimiter ✓
- Run logs: Session history ✓
- Budget: $500/month cap ✓

**Action items:**
- [ ] Implement scheduled CTI ingestion loop (6h cadence)
- [ ] Add Loop Readiness Score for honeypot deployment
- [ ] Implement worktree-style session isolation
- [ ] Add run logs with structured JSON per engagement

---

## 2. RAGIN v2 Architecture

```
                    ┌─────────────────────────────────────┐
                    │         ORCHESTRATOR (Loop)          │
                    │  Schedule → Triage → Engage → Verify │
                    │         ← STATE / Memory →           │
                    └──────────┬──────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
     ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
     │   CHROLLO    │  │     DON     │  │   HISOKA    │
     │  (Brain 1)   │  │  (Brain 2)  │  │  (Brain 3)  │
     │ Classifier   │  │ RAG Engine  │  │  Deceiver    │
     │ + Threat     │  │ + CTI       │  │ + Personas   │
     │   Model      │  │   Lookup    │  │ + Memory     │
     └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
            │                │                │
            └────────────────┼────────────────┘
                             ▼
                    ┌─────────────────┐
                    │   SANDBOX       │
                    │  (Hands)        │
                    │  Attacker I/O   │
                    │  CTI Corpus     │
                    │  Honeytokens    │
                    └─────────────────┘
                             │
                    ┌─────────────────┐
                    │   SESSION LOG   │
                    │  (Append-only)  │
                    │  Durable state  │
                    │  Crash-safe     │
                    └─────────────────┘
```

### New Components

| Component | Role | Pattern |
|-----------|------|---------|
| **Orchestrator** | Stateless loop: schedule → triage → engage → verify | loop-engineering |
| **Session Log** | Append-only event store, survives crashes | Anthropic Managed Agents |
| **Threat Modeler** | STRIDE analysis before response generation | VVAH S2 |
| **Response Verifier** | Multi-agent voting on response quality | VVAH S6/S11 |
| **CTI Scheduler** | Continuous feed ingestion loop | loop-engineering CI Sweeper |
| **Skill Loader** | On-demand CTI knowledge per attack type | OpenHarness |
| **Finding Emitter** | Structured MITRE ATT&CK output | VVAH S9 |

---

## 3. Implementation Phases

### Phase 1: Session & Harness Decoupling (Week 1-2) ✅ DONE

| # | Task | Priority | Effort | Status |
|---|------|----------|--------|--------|
| 1.1 | Create `Session` class (append-only event log) | HIGH | 2d | ✅ `cycle/session.py` — event_log, build_context, emit |
| 1.2 | Create `Harness` class (stateless orchestration loop) | HIGH | 2d | ✅ `cycle/harness.py` — process_with_threat_modeling |
| 1.3 | Create `Sandbox` class (attacker interaction isolation) | HIGH | 1d | ✅ `cycle/sandbox.py` |
| 1.4 | Implement `wake(sessionId)` crash recovery | HIGH | 1d | ✅ Session.load / Session.create |
| 1.5 | Decouple Chrollo/Don/Hisoka from monolithic server | HIGH | 2d | ✅ `cycle/adapters.py` |
| 1.6 | Add `emitEvent()` to harness for durable recording | MED | 1d | ✅ Session.emit + event_log |

### Phase 2: Agent Loop & Streaming (Week 2-3)

| # | Task | Priority | Effort | Status |
|---|------|----------|--------|--------|
| 2.1 | Implement streaming agent loop (OpenHarness pattern) | HIGH | 3d | |
| 2.2 | Add parallel tool execution for CTI queries | MED | 2d | |
| 2.3 | Add API retry with exponential backoff | MED | 1d | |
| 2.4 | Add context compression for long sessions | HIGH | 2d | |
| 2.5 | Implement session resume from durable log | HIGH | 1d | |

### Phase 3: Multi-Agent Coordination (Week 3-4) ✅ DONE

| # | Task | Priority | Effort | Status |
|---|------|----------|--------|--------|
| 3.1 | Implement Producer-Reviewer pattern (Hisoka → Verifier) | HIGH | 2d | ✅ `cycle/coordination.py` — EnhancedProducerReviewer |
| 3.2 | Implement Supervisor pattern (dynamic persona routing) | HIGH | 2d | ✅ `cycle/coordination.py` — Supervisor with PersonaRoute |
| 3.3 | Add multi-agent voting for high-stakes responses | MED | 2d | ✅ `cycle/coordination.py` — VotingSystem, VoteResult |
| 3.4 | Implement Expert Pool for CTI skill selection | MED | 1d | ✅ `cycle/coordination.py` — ExpertPool, ExpertAgent |
| 3.5 | Add hierarchical delegation for complex attacks | LOW | 2d | ✅ `cycle/coordination.py` — DelegationChain |

### Phase 4: Threat Modeling & Verification (Week 4-5) ✅ DONE

| # | Task | Priority | Effort | Status |
|---|------|----------|--------|--------|
| 4.1 | Add STRIDE threat modeling stage before response | HIGH | 2d | ✅ `cycle/threat_modeling.py` — ThreatModeler, STRIDE patterns |
| 4.2 | Implement adversarial response verification | HIGH | 2d | ✅ `cycle/harness.py` — verification step + retry |
| 4.3 | Add structured finding output (MITRE + confidence) | MED | 1d | ✅ Finding events emitted for critical/high risk |
| 4.4 | Track MTTA metric across all engagements | MED | 1d | ✅ `cycle/metrics.py` — MTTATracker |
| 4.5 | Implement attack chain construction from TTPs | LOW | 2d | ✅ `cycle/threat_modeling.py` — AttackChainBuilder |

### Phase 5: Skills & Memory Tiers (Week 5-6)

| # | Task | Priority | Effort |
|---|------|----------|--------|
| 5.1 | Implement skill system (on-demand CTI knowledge) | HIGH | 2d |
| 5.2 | Add memory tiers (working → episodic → semantic) | HIGH | 2d |
| 5.3 | Implement PreToolUse/PostToolUse hooks | MED | 1d |
| 5.4 | Add permission layers (attacker sandbox, analyst access) | MED | 1d |
| 5.5 | Implement structured memory retrieval per attack type | MED | 2d |

### Phase 6: Scheduling & Loops (Week 6-7)

| # | Task | Priority | Effort |
|---|------|----------|--------|
| 6.1 | Implement scheduled CTI ingestion (6h cadence) | HIGH | 2d |
| 6.2 | Add honeypot health check loop (5m cadence) | MED | 1d |
| 6.3 | Implement attacker session triage loop | MED | 1d |
| 6.4 | Add Loop Readiness Score for deployment | LOW | 1d |
| 6.5 | Implement run logs with structured JSON | MED | 1d |

---

## 4. Updated Benchmark Expectations

### Current (v1)

| Metric | Value |
|--------|-------|
| Response rate | 99%+ |
| RAG accuracy improvement | +32.4% |
| Persona diversity | 7x |
| Persistent memory | New capability |
| Dwell time | 4.1x |

### Projected (v2 with Harness + Loop)

| Metric | v1 | v2 Projected | Improvement |
|--------|-----|-------------|-------------|
| Response quality (adversarial verified) | 94% | 97%+ | +3% via voting |
| False positive rate (threat classification) | 3.1% | <1% | +67% via multi-lens |
| MTTA (detection → validated response) | N/A | <2s | New metric |
| Session recovery (crash → resume) | 0% | 100% | New capability |
| Context retention (100+ turn sessions) | Degrades | Stable | Via compression |
| CTI freshness (feed → honeypot) | Hours | Minutes | Via scheduling |
| Attacker engagement depth | Surface | Multi-step chains | Via chain construction |
| Autonomous operation time | Hours | Days+ | Via loops + scheduling |

### HoneyGPT Gap Widens

| Capability | HoneyGPT | RAGIN v1 | RAGIN v2 |
|------------|----------|----------|----------|
| Response quality | 99% rate | 99% rate + RAG | 97%+ verified + RAG + voting |
| Session resilience | None | None | Crash-safe, auto-recovery |
| Threat modeling | None | None | STRIDE before response |
| Multi-agent verification | None | None | Producer-Reviewer + voting |
| Autonomous operation | 3 months | Manual | Continuous loops |
| Attack chain analysis | None | None | TTP chain construction |
| Context engineering | None | None | Compression + resume |

---

## 5. Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Complexity increase | HIGH | Phased rollout, each phase independently valuable |
| Token cost increase | MED | Budget caps already in place, add per-loop budgets |
| Model dependency | LOW | Anthropic's lesson: interfaces outlast implementations |
| Performance regression | MED | Benchmark at each phase, rollback capability |
| Over-engineering | MED | Start with v1 patterns that work, add only what's needed |

---

## 6. Success Criteria

| Criterion | Target | Measurement |
|-----------|--------|-------------|
| Crash recovery | 100% session survival | Kill harness mid-session, verify resume |
| Response quality | 97%+ adversarial verified | Multi-agent voting panel |
| MTTA | <2s detection → response | Timestamp tracking |
| Context retention | 100+ turns without degradation | Accuracy at turn 100 vs turn 1 |
| Autonomous operation | 24h+ without intervention | Loop scheduling + health checks |
| Loop readiness | Score 80+ | loop-audit equivalent |
| HoneyGPT delta | 5x+ advantage across all metrics | Comparative benchmark |

---

## 7. References

1. **Anthropic Managed Agents** — "Scaling Managed Agents: Decoupling the brain from the hands" (Apr 2026)
2. **revfactory/harness** — Team-Architecture Factory for Claude Code (8.5k stars)
3. **HKUDS/OpenHarness** — Open Agent Harness with 43+ tools (15.1k stars)
4. **visa/vvaharness** — 11-stage SAST pipeline with multi-agent voting (1.7k stars)
5. **cobusgreyling/loop-engineering** — 7 production loop patterns (9.5k stars)
6. **revfactory/claude-code-harness** — A/B test: +60% quality with structured pre-configuration (n=15)
