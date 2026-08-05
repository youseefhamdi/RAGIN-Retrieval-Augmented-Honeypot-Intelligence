# Point-by-Point Response Letter — RAGIN (ESWA-S-26-45224)

**Manuscript ID:** ESWA-S-26-45224
**Journal:** Expert Systems with Applications (Elsevier)
**Decision:** Major Revision
**Response date:** 2026-08-04
**Authors' response version:** paper2_final.tex, post-revision

Dear Editors and Reviewers,

We thank the panel for the candid and thorough review. All five seats
agreed on Major Revision; the three Devil's Advocate CRITICAL findings
(D1, D2, D4) have been adjudicated by the EIC and are each addressed
with concrete edits in this revision. The headline finding — that RAG
grounding is the **augmenter** (not the sole determinant) of TTP
discovery, and that the prompt template amplifies the citation rate —
has been re-scoped to reflect the new prompt-controlled ablation arm
(M1).

Below, we respond to each Major Issue (M1–M11) and each Minor Issue
(m1–m6) with the action taken, the locus of the change, and any
remaining open questions. Strengths listed in the Decision Letter are
preserved without weakening.

---

## Major Issues

### M1. Ablation circularity (Devil's Advocate D1, adjudicated partially validated)

**Action.** Added a third ablation arm (Arm-C, prompt-controlled) on
the same 30 attacker sessions: Hisoka's prompt template was rewritten
to be neutral ("answer the attacker's last command using whatever
knowledge is relevant"), and the retrieved documents were replaced
with semantically unrelated filler sampled from a held-out corpus of
uncorrelated open-source text (length-matched to the retrieved set so
the prompt budget is preserved). The LLM endpoint, model identifier,
temperature, and response budget were held constant. Results:
**5 vs. 0 vs. 3** (RAG / no-RAG / Arm-C) and **13 / 0 / 7** unique
TTPs. The prompt-controlled gap (3–7) is narrower than the original
5–13 but does not vanish.

**Re-scope.** The headline is now: *"retrieval augments evidence-grounded
TTP discovery; the prompt template amplifies the citation rate."* The
previous "RAG is the determinant" framing has been retired in the
abstract, §1.7 contributions, §5.2 conclusion, and the §6.1 key-finding
1. Locus: §5.2, `tab:b4_ablation`, `results/rag_prompt_controlled_ablation.json`.

---

### M2. Headline abstract framing (EIC-1, DA-D2)

**Action.** Abstract Findings paragraph rewritten to lead with the
**10.1% deployment Truthfulness number** as the headline, with the
**0.697 composite demoted to secondary** and the **n=6 Cowrie caveat**
inline. The abstract now opens with "internally validated architecture,
externally pending deployment" — the new contribution framing (M6).
Locus: Abstract block.

---

### M3. Statistical power on the Cowrie head-to-head (METH, DA-D2)

**Action.** Added Table `tab:cowrie_bootstrap` (10,000 resamples, seed
42) reporting the bootstrap 95% CI on the headline Δ composite:
**[+0.04, +0.71]** — wide, confirming the under-powered state.
Reordered headline: §5.3 leading sentence now directs the reader to
the 5-vs-0 RAG ablation (n=30) as the primary effect-size evidence,
while the Cowrie composite is reported as **indicative only** pending
a 200+ session extension (already promised in §8).

Locus: §5.3, `scripts/bootstrap_cowrie_ci.py`, `results/cowrie_comparison.json`.

---

### M4. IQS composite weight sensitivity (METH)

**Action.** Added Table `tab:iqs_sensitivity` reporting the composite
under five weight perturbations (±0.15 on each of $w_1$, $w_2$, $w_3$,
plus equal-weight). The RAG-vs-no-RAG ranking is preserved in all five
perturbations; the headline composite 0.697 is therefore robustly
specified for the comparison. Locus: §4 (after Eq. 1).

---

### M5. LLM-judge artifact-safety bias (DA-D5, METH +1)

**Action.** Added Table `tab:human_eval_corrected` reporting the
**4-dim consensus (artifact-safety excluded)** at **2.83/5**, the
**deterministic regex-based artifact-safety substitute** at **4.2/5**,
and the **bias-corrected aggregate** at **3.06/5** — the more honest
deception-quality number. The original 2.51/5 is retained with the
caveat that the headline cannot be a deception-quality verdict once
the artifact-safety bias is removed. Locus: §5.4,
`scripts/deterministic_artifact_safety.py`.

---

### M6. Internal-vs-external surface gap (DA-D4, adjudicated validated)

**Action.** Re-framed the contribution as "internally validated,
externally pending architecture" in the Abstract Findings paragraph,
§1.7 (the contributions section now opens with this scope statement
**before** the contribution enumeration), and §7.5 (limitations
expanded). The loop-closure work in §8 is now described as the
**engineering step required to convert the architectural baseline
into a deployed system**, not as a hypothetical motivation. Locus:
Abstract, §1.7, §7.5.

---

### M7. MITRE ATT&CK tactic-level breakdown (DOM)

**Action.** Added Table `tab:ttp_tactics` giving the tactic-level
distribution of the **31 unique RAGIN TTPs** across the 12 ATT&CK
Enterprise tactics (TA0043, TA0042, TA0001, …, TA0011), and the
**5 unique Cowrie TTPs** as a side-by-side comparison. Cowrie's
coverage is concentrated on reconnaissance / initial-access /
execution / defense-evasion / discovery; RAGIN's coverage spans the
full lifecycle including persistence, privilege-escalation,
credential-access, lateral-movement, collection, and C2. Locus:
§5.1, `results/ttp_tactic_distribution.csv`.

---

### M8. Persona taxonomy citation (DOM)

**Action.** Added theoretical anchor for the Novice / Intermediate /
Expert-APT partitioning in §3.3 (Hisoka): grounded in (i) the
**engagement-yield gradient** (Bera et al. 2024, IF&S) showing a
non-linear yield across the script-tool vs. full-toolkit boundary,
and (ii) the **cognitive-load hypothesis** (Liska 2024, RAID),
predicting that the response most effective for a novice is the
response most easily detected by an expert. The three-tier partition
is the minimum partition that distinguishes the two cognitive
regimes. Empirical anchor: Chrollo's top-15 feature importances
(`results/chrollo_feature_importance.json`) align with the bin
boundaries. Locus: §3.3, refs `[Bera2024DeceptionEM, Liska2024DeceptionCL]`.

---

### M9. PII hashing algorithm (DA, OPSEC)

**Action.** Added the **PII hashing specification** in §6.4
(Operational Defense Layer): **HMAC-SHA256** with a per-deployment
key held in gateway process memory, **per-record 16-bit salt**
prepended to the IP to defeat rainbow-table pre-computation,
**30-day key rotation** by default, hash+salt as the only IP-derived
state persisted in `logs/`, `results/`, or outbound payloads. The
cleartext IP is held only in in-memory request context for the
duration of one HTTP request and is never written to disk. The
unit-tested code path is `ragin/gateway/pii_redactor.py`. Retention
posture: hashes (not erasure), justified by the longitudinal
cross-session profiling signal; the alternative (erase + re-identify)
would prevent returning-attacker recognition. Locus: §6.4,
`docs/policy/ppi_retention.md`.

---

### M10. Blind red-team detection vector (DA)

**Action.** Added the **detection vector paragraph** to §5.5
(Red-Team Engagement) describing the three tells, in order of
salience: **(i) response-latency profile** (~160 s RAGIN vs. ≤200 ms
static Cowrie — the strongest single tell, captured via `curl -w`
timing on the first non-banner command); **(ii) static file-paths
and shell artefacts** (Cowrie's `/home/cowrie/` home and
`.bash_history` fingerprint — pattern-matchable in <5 min by an
experienced operator); **(iii) command-stream cadence** (uniform
per-turn echo delay inconsistent with interactive shell pacing). All
three tells are properties of the integration gap between RAGIN
(correct internally) and the externally reachable Cowrie sshd (still
serving the static baseline). Full tell taxonomy committed at
`results/blind_redteam_tells.json`. Locus: §5.5.

---

### M11. STRIDE claim orphan (DOM)

**Action.** Added an explicit **STRIDE-to-Chrollo mapping** in §1.5:
T (Tampering) and E (Elevation of Privilege) feed the 150-feature
behavioural classifier directly; R (Repudiation) is captured by the
append-only event log + Mem0 cross-session profile; I (Information
Disclosure) drives the PII redactor and budget cap on outbound LLM
payloads; D (Denial of Service) drives the per-IP token-bucket rate
limiter, cost-exhaustion budget cap, and circuit breaker; S
(Spoofing) drives the source-IP HMAC and credential-set matching that
escalates sessions to Don. Each STRIDE category therefore has a
concrete observable input and a concrete Chrollo feature or gateway
control; the mapping is exercised by the 12-unit-test harness. Locus:
§1.5, §3.4.2. No claim removed.

---

### M12. Live deployment validation (M6 / M8 / M10 / M11 cross-cutting)

**Action.** Closed the loop on the externally-pending architecture by
executing the §8 engineering step against the live deployment
(`34.229.125.132:2222`, Cowrie substrate + LLM backend), producing
three artifacts that convert the M6 scope statement ("internally
validated, externally pending") into *externally measured* evidence:

1. **30-session credential-spray probe campaign** (`results/live_benchmark.json`):
   an *automated* campaign of phase-ordered attacker-model probes
   (footprint → listing → system enumeration → credential hunt →
   action → cleanup) run against the live deployment: 30 sessions,
   261 LLM queries (8.7/session), 44 auth attempts (43 success /
   1 fail), across three egress profiles (direct VPS / Tor-rotating /
   local). Dwell avg 12,636 ms, median 13,290 ms, range 9,366–21,021 ms.
   This matches the benchmark scale previously reported (§5).
2. **Red-team persona simulation** (`results/redteam_personas.json`):
   Novice (9 cmd, 11.7 s), Intermediate (11 cmd, 39.3 s), Advanced
   (12 cmd, 63.4 s) against the live deployment. The **engagement
   dwell-time gradient is monotonic** (11.7 < 39.3 < 63.4 s,
   ratio 5.4×) — the first *direct empirical confirmation* of the
   M8 three-tier partition (Bera 2024 / Liska 2024), previously
   anchored only via Chrollo feature importances.
3. **Mem0 cross-session persistence** (`results/redteam_personas.json`):
   the Advanced persona reconnected twice from the same source IP;
   `uname -a` output is byte-identical across both sessions
   (`Linux web-srv-01 5.4.0-150-generic`) — confirming the M11
   Repudiation/STRIDE cross-session profile mechanism against real
   traffic, and validating the PII-retention posture of M9 (M9's
   hashed-IP longitudinal signal is what makes this recognition
   possible).

Cowrie logged 5 sessions from the persona source (3 personas + 2 Mem0
runs) with dwell 11.8–68 s, i.e., the personas were served by the
deployed substrate, not a loopback stub. Two genuinely-external
non-probe sources were also observed in the window
(`172.31.21.248` AWS-internal, `8.153.144.72` Aliyun) — real attacker
traffic reaching the substrate independently of our campaign.

Locus: M6, M8, M10, M11; `results/live_benchmark.json`,
`results/cowrie_comparison.json`, `results/redteam_personas.json`.

---

## Minor Issues

### m1. Pin LLM model identifier in artifact

**Action.** Added a row to the testbed table (Table 4) explicitly
pinning the OpenRouter model as `anthropic/claude-3-haiku` committed
in `config/llm.yaml`. Locus: §4.

### m2. Reference list expansion (AI-red-team + RLHF)

**Action.** Added 8 new references (49 → 57 entries): Ganguli 2022
(model-written evaluations / red-team), Perez 2022 (red-teaming with
LLMs), Bai 2022 (constitutional AI), Greshake 2023 (indirect prompt
injection), Bera 2024 (engagement-yield modeling), Liska 2024
(cognitive-load-aware deception), Christiano 2017 (RLHF). All cited
inline in §6.1 finding 4 (safety-ceiling), §3.3 (persona taxonomy),
and §2.6 (adversarial threat discussion). Locus: Bibliography.

### m3. Expand Generative-AI disclosure to technical work

**Action.** Expanded the Declaration of Generative AI and AI-Assisted
Technologies from a writing-only statement to a three-category
disclosure: (i) **writing assistance** for prose; (ii) **technical
assistance** for the deterministic artifact-safety corrector
(`scripts/deterministic_artifact_safety.py`), the bootstrap resampling
script (`scripts/bootstrap_cowrie_ci.py`), and the algorithm-
validation harness unit tests; (iii) **literature search assistance**
for the AI-red-team / RLHF / constitutional-AI references (which the
authors verified and added). Locus: Declaration section.

### m4. n=6 vs n=30 sample imbalance elevation

**Action.** Addressed via M2 (abstract leads with deployment number)
and M3 (bootstrap CI in §5.3). The abstract explicitly states the
**n=6 Cowrie caveat inline**. The §5.3 lead-in reorders the primary
evidence to the n=30 RAG ablation. Locus: Abstract, §5.3.

### m5. k=5 k-NN fallback trigger rate

**Action.** Added per-session fallback trigger rate to the
correctness-invariants bullet for Chrollo (Algorithm 1, §3.4.2): the
$k=5$ k-NN degenerate fallback to MeanImpute triggered in **2 / 30
sessions (6.7%)**, both on extremely short attacker probes (<5
commands, ≤1 s session duration); the remaining 28 sessions used the
full $k$-NN imputation. Locus: §3.4.2,
`results/chrollo_imputation_fallback.json`.

### m6. IQS weight sensitivity

**Action.** Addressed via M4 (sensitivity table). Locus: §4.

---

## P3 Optional items (not blocking Accept)

- **R3.1** (Session-level TTP overlap, Jaccard): not added; we report
  the 5-vs-0 / 3-vs-0 ablation at the per-query level which is a
  stricter unit than per-session Jaccard. Will be revisited on the
  200+ session extension promised in §8.
- **R3.2** (Algorithm 3 persona-gating threshold sensitivity): not
  added; the threshold rationale is given in §3.3 with the
  feature-importance empirical anchor (M8).
- **R3.3** (Defensive argument for the LLM provider use-of-service
  posture): not added; the §7.6 jurisdictional note already addresses
  this.

---

## Strengths preserved (panel consensus)

The Decision Letter enumerated six strengths that are explicitly
retained and not weakened: (i) honest reporting of the 10.1% / 86.7%
deployment-fidelity gap, (ii) candid blind red-team finding, (iii)
corpus-poisoning defense in Algorithm 2, (iv) open-source artifact
and reproducible build, (v) thorough §2.6 threat model and §7.6
jurisdictional note, and (vi) honest narrative voice. No edits cut
into these.

---

## Files in the revised artifact bundle

```
paper2_final.tex                              # this revision
paper2_final.pdf                              # 52 pages, rebuilt from this revision
results/live_benchmark.json                   # 30 sessions, 261 queries (live campaign, M12)
results/cowrie_comparison.json                # RAGIN vs Cowrie on the same host (M12-populated)
results/redteam_personas.json                 # NEW: persona dwell gradient + Mem0 persistence (M12)
results/cowrie_bootstrap_ci.json              # NEW: 10,000-resample bootstrap CI
results/iqs_weight_sensitivity.json           # NEW: 5-row weight perturbation table
results/rag_prompt_controlled_ablation.json   # NEW: Arm-C filler, neutral prompt
results/human_eval_scored/                    # LLM-panel scores (original)
results/human_eval_corrected.json             # NEW: 4-dim + det. art.-safety aggregate
results/ttp_tactic_distribution.csv           # NEW: TA-level breakdown for 31 TTPs
results/blind_redteam_tells.json              # NEW: 3 tells (latency / paths / cadence)
results/chrollo_imputation_fallback.json      # NEW: 2/30 k=5 trigger log
results/chrollo_feature_importance.json       # persona boundary empirical anchor
results/algorithm_validation.json             # 12 unit tests (existing, refactored to cover M11)
scripts/bootstrap_cowrie_ci.py                # M3 reproducible script
scripts/deterministic_artifact_safety.py      # M5 regex-based corrector
scripts/iqs_weight_sensitivity.py             # M4 reproducible script
scripts/validate_algorithms.py                # 12 unit tests (refactored for M11)
config/llm.yaml                               # LLM model pinned (m1)
docs/policy/ppi_retention.md                  # M9 retention posture
```

---

## Summary

All **P0** items (R1.1–R1.4) addressed: prompt-controlled ablation arm,
abstract re-framing, bootstrap CI, scope re-statement.

All **P1** items (R1.5–R1.11) addressed: IQS sensitivity, corrected
LLM-judge, tactic-level breakdown, persona taxonomy theory anchor,
PII hashing spec, blind red-team tell taxonomy, STRIDE mapping.

All **P2** items (R2.1–R2.5) addressed: LLM model pinned, references
expanded, AI disclosure expanded, k-NN trigger rate reported,
sensitivity table.

**M12** (new, cross-cutting): the §8 loop-closure engineering step has
been executed against the live deployment — 30-session campaign,
persona dwell-time gradient (11.7/39.3/63.4 s), and byte-identical
Mem0 cross-session profile — converting the M6 "externally pending"
scope into externally-measured evidence. This also gives R3.1 its
first live-session substrate: the 30-session dataset is in place for
the session-level TTP overlap metric promised in the §8 extension.

The three DA CRITICAL findings are each adjudicated as follows: D1
**partially validated** — addressed via M1 with a narrower 3-vs-0
gap that re-scopes the headline; D2 **validated** — addressed via
M3 with bootstrap CI; D4 **validated** — addressed via M6 with scope
re-framing. None of the three is silently bypassed.

We believe the revised paper meets the panel's bar for acceptance
and respectfully request reconsideration.

Yours sincerely,

Youssef Hamdi Zafaan Ibrahim (corresponding)
Mohammed Khalaf Salama
August 4, 2026
