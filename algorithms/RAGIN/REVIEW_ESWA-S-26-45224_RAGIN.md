# Editorial Review — RAGIN (ESWA-S-26-45224)

**Manuscript:** RAGIN: Retrieval-Augmented Honeypot Intelligence: Measuring Adaptive Deception Against Real and Simulated Adversaries
**Authors:** Youssef Hamdi Zafaan Ibrahim, Mohammed Khalaf Salama
**Journal:** Expert Systems with Applications (Elsevier)
**Manuscript ID:** ESWA-S-26-45224
**Decision:** **Major Revision**
**Decision Date:** 2026-08-04
**Review Mode:** full (5-seat panel + Devil's Advocate + editorial synthesis)

---

## Phase 0 — Field Analysis & Reviewer Configuration

**Field identification:**

| Dimension | Value |
|---|---|
| Primary discipline | Applied cybersecurity / cyber-deception |
| Secondary disciplines | Information retrieval (RAG), LLM safety, AI for cybersecurity |
| Research paradigm | Design-science / engineering systems research |
| Methodology type | Mixed (live deployment + ablation + LLM-as-judge + head-to-head + red-team) |
| Target journal tier | Q1 systems/AI application (ESWA) |
| Paper maturity | Near-submission; robust artifact, candid about limits |

**Reviewer Configuration Card (5 seats):**

| # | Role | Identity | Specific focus |
|---|---|---|---|
| 1 | EIC | ESWA Editor-in-Chief, cybersecurity track | Journal fit, originality vs. prior deception surveys, headline claims discipline |
| 2 | Methodology | Senior ML/security systems researcher (CMU SEI / SRI lineage) | Experimental design, statistical power, LLM-as-judge validity, ablation rigor |
| 3 | Domain | Cyber-deception researcher (MITRE Engage active) | Deception literature positioning, ATT&CK mapping, threat-model completeness |
| 4 | Perspective | Cross-disciplinary AI safety / RAG-security researcher | RAG-poisoning, LLM safety-alignment ceiling, dual-use implications |
| 5 | Devil's Advocate | Adversarial reviewer (former red-team operator) | Strongest counter-arguments, cherry-picking, headline 0.697 critique |

---

## Reviewer 1 — EIC Report (Journal Fit / Editorial Lens)

**Recommendation range:** Major Revision (lean toward Accept with revisions)

### Summary

The paper reports RAGIN, a three-component (Chrollo/Don/Hisoka) adaptive cyber-deception framework that wraps a Cowrie SSH honeypot in a 150-feature Random Forest classifier, a 780,600-document hybrid dense/sparse RAG engine, and a skill-stratified adaptive deception layer, all behind a safety-bounded LLM gateway. The empirical work is unusually honest: the authors publish both a 91.9% content-pass rate and a 10.1% quality-pass rate after a post-hoc quality audit, and surface a blind red-team finding that the deception did not yet hold attackers because the output was not connected to the attack surface.

### Originality / Significance

- **Comparable in scope to Mirage (Ref [14]) but extends the evidence-grounding axis.** Mirage demonstrated skill-adaptive deception in emulation; RAGIN's contribution is RAG-grounded, evidence-cited, MITRE-mapped deception on live session data.
- The **content-fidelity vs. deployment-fidelity gap** (architectural capability vs. live delivery) is a methodological contribution the field has been missing.
- The paper is positioned as a **reliability/measurement contribution**, not a leap-forward claim — correct posture for ESWA.

### Concerns

1. **Headline figure ambiguity (CRITICAL for editorial).** The 0.697 composite is the strongest repeated number but it is the *architectural* metric; the *deployment* metric is 10.1%. A skimmer could confuse the two. The paper attempts to disambiguate (Fig 2 left/right) but the abstract leans on 0.697. **Tighten the abstract's first numerical claim.**
2. **Scope of the "RAG determines TTP discovery" finding.** Use a per-session density with a confidence bound, not raw counts.
3. **n=6 Cowrie comparison.** Headline +0.380 gap is based on this underpowered comparison. Correctly flagged but should be elevated in the abstract.
4. **AI-disclosure compliance.** Generative-AI declaration covers writing only. ESWA requires disclosure of AI assistance in *technical* work too.

### Recommendation

**Major Revision.** Strong artifact, candid data, open-source. Path to accept: (a) abstract disambiguation, (b) per-session CIs for the ablation. Then this is a strong accept.

**Score:** Originality 7/10 • Rigor 7/10 • Significance 7/10 • Clarity 8/10 • Reproducibility 9/10

---

## Reviewer 2 — Methodology Reviewer Report

### Research Design

- **Mixed-methods design combining live deployment + matched ablation + head-to-head + red-team + LLM-as-judge.** Rare in ESWA submissions and a strength, but each component carries methodological tax.
- **Threat to internal validity from confounded factors.** The no-RAG ablation uses the "identical pipeline" but the upstream Chrollo and downstream Hisoka prompt are *unchanged* — RAG is the only manipulated variable. Good for the headline ablation but does not isolate the **interaction** between RAG and persona selection; the persona/memory subsystem is not ablated at all.

### Sampling & Statistical Power

- **n=30 attacker sessions** adequate for descriptive deployment reporting but inadequate for the +0.380 Cowrie gap. The 6 Cowrie sessions are an *order of magnitude* smaller — gap is suggestive, not definitive.
- **Action:** add bootstrap CIs on the headline composite and a power-analysis justification for the 200+ Cowrie extension Section 8 promises.
- **The "5 unique TTPs" finding** should report inter-session TTP overlap (Jaccard or similar).

### Constructs & Measurement

- **Threat to construct validity in the composite metric (IQS, Eq. 1).** Weights (w1=0.4, w2=0.35, w3=0.25) asserted without justification. **Action:** weight-sensitivity table, or report all three component scores prominently.
- **LLM-as-judge validity.** Single-model-judge (despite the "7 evaluation role descriptions"). Inter-judge agreement varies wildly. The paper reports κ=0.425 (moderate) for the consensus run and κ≈0.725 for the pilot. Sub-literature-norm. **Action:** item-level agreement, not just a single κ.
- **"Grounded" definition is post-hoc.** Audit is post-response, with the 90s latency budget. For 86.7% of queries the response was not delivered. Correctly disclosed. **Action:** also report the audit's *false-negative* rate.

### Reproducibility

- **Strong.** Open-source, JSON artifacts, version pins (scikit-learn, FAISS, BM25), concrete thresholds (τ=0.85, σ_min=0.20, α=0.7, β=0.3). Reproducible seed 42. 12 unit tests. Uncommon and welcome.
- **Gap:** LLM endpoints behind OpenRouter are not pinned. **Action:** pin model identifier and version in the artifact.

### Algorithm Correctness

- Algorithms 1–3 clear, I/O contracts explicit. Reject-band logic (τ−δ, τ) = (0.75, 0.85) well-justified.
- **Concern:** `k=5` k-NN degenerate case (n<5) falls back to mean-impute. Sound choice but **Action:** report trigger rate in the live 30 sessions.

### Recommendation

**Major Revision.** Methodology is above ESWA's median. Two material asks: (i) weight-sensitivity analysis for the IQS composite, (ii) per-session CIs on the head-to-head comparison.

**Score:** Design 7/10 • Statistical rigor 5/10 • Measurement 7/10 • Reproducibility 9/10 • Algorithm clarity 9/10

---

## Reviewer 3 — Domain Reviewer Report (Cyber Deception)

### Literature positioning

- **Positioning against Mirage (Ref [14])** correct and well-stated.
- **Positioning against LLM Agent Honeypot (Ref [25])** correct. The skill-stratification gap is real.
- **Missing reference: ThreatDefender, Calm-Hive, recent MITRE Engage TTP-to-Deception mapping.** Does not engage with post-2024 deception fidelity scoring (Bera et al. 2024) or engagement metrics (d-well / TTP-density).
- **Missing reference: AI-supported honeypot field studies at scale** (Genade et al. 2024, T-Pot / Modern Honey Network).

### Theoretical framing

- **Skill-stratification framework (Novice / Intermediate / Expert-APT, Table 5)** intuitive but not theoretically grounded. 150-feature Random Forest well-motivated but persona taxonomy lacks citation.
- **STRIDE-pattern threat modelling invoked but not used.** §1.5 says STRIDE runs in the loop; §3.5 does not describe how STRIDE informs Chrollo's escalation.

### MITRE ATT&CK coverage

- **31 unique ATT&CK techniques** is the right unit, but paper does not report *which tactics* are covered. Without a tactic-level breakdown (TA0001, TA0007, TA0011), the 31-technique count is uninformative.
- **Cowrie 3.0.x has no honeytoken engine** — correctly identified but the +30 honeytoken deployment claim is one-directional (RAGIN plants, Cowrie can't). Zero triggers — correctly disclosed in abstract but reads as a strength in the headline table.

### Threat model completeness

- **Strong (§2.6).** Trust boundaries, out-of-scope threats, LLM-specific abuse vectors addressed.
- **Missing: insider threat.** A defender who deploys RAGIN is trusting Chrollo's classifier. Training-data poisoning is a known ML supply-chain risk and is not covered.
- **Missing: prompt-injection empirical evaluation.** Threat model names it as in-scope but 86.7% timeout rate means the empirical run doesn't actually test injection throughput.

### Ethical framing

- **Appropriate.** PII hashing, no human subjects, jurisdictional note present.

### Recommendation

**Major Revision.** Domain positioning is good. Two material asks: (i) tactic-level distribution of the 31 surfaced TTPs, (ii) defensible citation for the persona framework.

**Score:** Literature coverage 6/10 • Theoretical grounding 5/10 • Domain novelty 7/10 • MITRE mapping 6/10 • Threat model 7/10

---

## Reviewer 4 — Perspective Reviewer Report (Cross-Disciplinary)

### Cross-disciplinary connections

- **Genuine contribution to the AI-safety literature on RAG poisoning.** The credibility gate (Algorithm 2, step 6) directly engages with the RAG-poisoning surveys (Refs [7], [13], [26]).
- **The "safety-aligned LLM ceiling" observation is a textbook dual-use insight.** The 86.7% timeout rate is mostly upstream safety alignment, not RAG itself. Paper-worthy finding for the AI-safety community; the paper names it but understates its implications.

### Practical and policy implications

- **For SOC practitioners:** deployment realistic (2 vCPU, 4 GB, $500/month). Cost-bounded LLM gateway operationally sound. PII hashing at ingestion a clean answer to GDPR/CCPA concerns that aren't even raised.
- **For policy makers:** §7.6 ethical statement appropriate but legal implications too thin. Honeypot legality varies by jurisdiction; generating attack-style output via a live LLM provider may constitute entrapment or unauthorized generation of exploit content.
- **For the AI-safety community:** artifact-safety scoring noise (Section 6.4) is a *methodological* finding relevant beyond this paper — LLM judges penalize plausible fabricated credentials because they mistake them for real leaks. A *bias* in the LLM judge, not a property of the deception.

### Broader implications

- **Strongest cross-disciplinary contribution is the architectural decoupling claim.** RAGIN separates generation (LLM-bound), evidence-grounding (RAG, version-pinned), and classifier (Random Forest, deterministic). The right substrate for *governed* generative AI in safety-critical contexts. Paper does not name this as a contribution; a future revision should.
- **Honest field-deployment data is rare.** 10.1% / 86.7% / 0.9% / 2.3% is a model for honest reporting.

### Cross-disciplinary opportunities the paper misses

- Does not cite the *AI red-teaming* literature (Ganguli et al. 2022; Perez et al. 2022).
- Does not engage with the *constitutional AI* / *RLHF* literature on safety-alignment conflict. Cite at least one.
- Does not cite the *agentic LLM* literature on tool-use and prompt injection (Greshake et al. 2023).

### Recommendation

**Major Revision.** Cross-disciplinary angle genuinely additive. Material asks: (i) cite AI-red-team and prompt-injection literatures, (ii) explicitly frame the safety-alignment ceiling as an AI-safety contribution.

**Score:** Cross-disciplinary connection 7/10 • Practical impact 8/10 • Broader implications 7/10 • Policy/ethics 6/10

---

## Reviewer 5 — Devil's Advocate Report

### Strongest Counter-Argument (≈270 words)

The headline claim "RAG grounding is the determinant of TTP discovery" is the entire empirical backbone of the paper, and it is **architecturally circular**. The ablation compares "RAGIN with Don" vs "RAGIN without Don" — but the LLM (Hisoka) is held constant, and Hisoka's prompt template **explicitly tells the model to use the retrieved documents as context**. When Don is removed, Hisoka is asked to generate deception responses with no retrieved context. The author-pipeline then evaluates *which MITRE ATT&CK techniques surfaced* by string-matching the LLM's output against the ATT&CK lexicon. Without retrieved grounding, the LLM never names an ATT&CK technique. With retrieved grounding, the LLM cites the technique it was shown. The 5-vs-0 result is therefore a measurement of how often an LLM cites documents it was given, not a measurement of how well RAG discovers TTPs the attacker actually used.

An independent verification would re-run the ablation with a *neutral* prompt that does not instruct the LLM to cite retrieved documents, and compare the *intrinsic* TTP-inference capability of the LLM against the retrieval-augmented version. The paper does not perform this control. The paper's most-cited finding is therefore an over-strong claim about a *prompt-mediated* effect, not a *retrieval-mediated* effect.

A second observable concern: the 0.697 vs. 0.317 composite is derived from a Cowrie sample of n=6 sessions. The paper admits this is "indicative pending a larger run," but the headline delta is presented as a result, not a hint. ESWA reviewers generally require 30+ samples for a paper's headline empirical claim — the paper does not meet this bar.

### Issue List

#### CRITICAL

- **D1 — Circular ablation logic.** The 5-vs-0 ablation measures the prompt-mediated citation rate, not retrieval-mediated TTP discovery. **Fix:** run an ablation where the prompt template is held constant and only the *retrieval* is changed; or a third arm where retrieved documents are *replaced with semantically unrelated documents*.
- **D2 — Headline composite based on n=6 Cowrie sessions.** The +0.380 delta is presented as a finding, not a hypothesis. **Fix:** report the 95% CI on the delta and rank-order the headline, or move the Cowrie comparison to supplementary material.

#### MAJOR

- **D3 — The "10.1% grounded" framing understates the failure.** 86.7% of queries timed out. A honeypot that can't respond to ~87% of attacker turns is not a deployment; it is a research artifact. **Fix:** reframe the deployment-fidelity number as "availability" or "session-completion rate," not "grounded share."
- **D4 — Internal-vs-external surface gap, but only flagged in Discussion.** The blind red-team found the external surface didn't engage attackers. **Fix:** the paper should not be accepted as a deployment result while the externally-reachable surface is unwired. Reframe as "an internally validated, externally pending" architecture.
- **D5 — LLM-judge artifact-safety bias.** Identified a scoring-rubric artifact but did not correct for it. **Fix:** report the deception-quality score with and without the artifact-safety dimension, or apply a deterministic rubric.

#### MINOR

- **D6 — Reference list is thin (40 entries).** For a paper that crosses cyber-deception, RAG, ML-IDS, and AI-safety, 40 references is light.
- **D7 — "Novelty" claim is partly a timeliness claim.** RAG-for-security is moving fast; the grounding-on-live-data claim may be obsolete within 12 months.
- **D8 — Algorithm 3's skill-gating thresholds (precision ≥ 0.5, speed ≥ 1.0 cmd/s) are asserted without sensitivity analysis.**

### Ignored Alternative Explanations

1. **The +0.380 composite compares a 3-component system to a 0-component system.** The Cowrie baseline is intentionally minimal. The comparison measures "do all three components help?" not "does RAG help?" The simpler one-knob-at-a-time ablations are missing.
2. **The 31 ATT&CK technique count may be library-quality confounded.** Don indexes MITRE ATT&CK directly, so Chrollo→Don→Hisoka can never *invent* a technique — only surface an indexed one. The 5-TTP finding may be a property of the index, not of the retrieval.
3. **The 4-byte PII hashing claim is undocumented.** No hash algorithm, no salt regime, no key-management description.

### Missing Stakeholder Perspectives

- **Red-teamers who detected the honeypot.** What did they detect? LLM-style response patterns, timing, static file paths? The detection vector is the most actionable finding for defenders and is missing.
- **The blue-team SOC operator.** The composite-IQS weights come from prior literature but the deployment target is a SOC. The weights should be either operator-calibrated or explicitly defended as a literature prior.
- **The LLM provider's perspective.** A system that generates attacker-persona output via OpenRouter is *use-of-service* the provider may not have anticipated.

### Observations (Non-Defects)

- The paper's willingness to publish the 10.1% / 86.7% numbers is *unusually honest* for the field.
- The code release is a real contribution.
- The honesty about the LLM-judge scoring artifact is a model for future papers.

### Recommendation

**Major Revision.** Contributions are real but the strongest empirical claim is on shakier ground than the paper presents. Two material replies required: (i) prompt-controlled ablation (D1), (ii) re-framing of headline numbers without leaning on the n=6 Cowrie comparison.

**Score:** Soundness of core argument 5/10 • Counter-argument survival 4/10 • Cherry-picking risk 5/10 • Stakeholder coverage 5/10

---

## Phase 2 — Editorial Synthesis

### Consensus Across the Panel

| Issue | EIC | METH | DOM | PERS | DA | Consensus |
|---|---|---|---|---|---|---|
| Headline-figure ambiguity (0.697 vs 10.1%) | ✓ | — | — | — | ✓ | 2-of-5, flagged |
| Statistical power on Cowrie n=6 | ✓ | ✓ | — | — | ✓ | 3-of-5 (CRITICAL-elevated) |
| Internal-vs-external surface gap | — | — | — | — | ✓ | 1-of-5 (DA CRITICAL, adjudicated) |
| LLM-judge artifact-safety bias | — | ✓ | — | — | ✓ | 2-of-5 (MAJOR) |
| IQS weight sensitivity | — | ✓ | — | — | ✓ | 2-of-5 (MAJOR) |
| MITRE tactic-level breakdown | — | — | ✓ | — | — | 1-of-5 (MAJOR) |
| Persona taxonomy citation | — | — | ✓ | — | — | 1-of-5 (MAJOR) |
| RAG-ablation circularity (D1) | — | — | — | — | ✓ | 1-of-5 (DA CRITICAL) |
| AI disclosure scope | ✓ | — | — | — | — | 1-of-5 (MINOR) |
| LLM model pinning / reproducibility | — | ✓ | — | — | — | 1-of-5 (MINOR) |
| Cross-disciplinary AI-red-team citations | — | — | — | ✓ | — | 1-of-5 (MINOR) |
| STRIDE claim orphan | — | — | ✓ | — | — | 1-of-5 (MINOR) |
| PII hashing algorithm unspecified | — | — | — | — | ✓ | 1-of-5 (MAJOR) |
| Detection-vector missing from blind red-team | — | — | — | — | ✓ | 1-of-5 (MAJOR) |

### Devil's Advocate CRITICAL Adjudication (Iron Rule #4)

**D1 — Circular ablation logic.** Adjudicated by EIC. **Partially validated.** The ablation changes *both* the retrieval layer and the prompt-mediated citation pathway. The 5-vs-0 finding is *consistent with* retrieval's contribution but does not exclude the prompt-citation pathway. **Action:** the paper must add a prompt-controlled ablation. **Decision impact:** does not block Accept pending revision; the empirical claim will be re-scoped to "RAG + prompted citation" if the ablation is not added.

**D2 — n=6 Cowrie headline.** Adjudicated by EIC. **Validated.** The paper itself acknowledges under-powering. The headline framing is too strong. **Decision impact:** re-frame the Cowrie comparison as indicative, not as a primary result.

**D4 — Internal-vs-external surface gap.** Adjudicated by EIC. **Validated.** The blind red-team finding is genuinely a fatal deployment-stage observation. **Decision impact:** the contribution must be re-framed as "internally validated, externally pending" architecture. This is not a v3.6.2-Accept veto because the paper self-discloses the gap; it is a *scope* clarification.

---

# Editorial Decision Letter

**Manuscript ID:** ESWA-S-26-45224 (RAGIN)
**Journal:** Expert Systems with Applications (Elsevier)
**Decision:** **Major Revision**
**Decision Date:** 2026-08-04

---

**Dear Authors,**

Thank you for submitting "RAGIN: Retrieval-Augmented Honeypot Intelligence: Measuring Adaptive Deception Against Real and Simulated Adversaries" to Expert Systems with Applications. The paper reports a three-component (Chrollo/Don/Hisoka) adaptive cyber-deception system that combines a 150-feature Random Forest classifier, a 780,600-document hybrid RAG engine, and a skill-stratified adaptive-deception layer, deployed on a live AWS EC2 honeypot, with a candid blind red-team finding that the deception did not yet hold external attackers.

The panel's overall assessment is positive. The empirical honesty (publishing both the 91.9% content-pass and the 10.1% deployment Truthfulness numbers), the open-source artifact, the reproducibility harness, and the threat-model completeness are exemplary for the field. The editorial decision is **Major Revision** because the paper's strongest empirical claim — that RAG grounding is the *determinant* of TTP discovery — rests on an ablation that conflates the retrieval layer with the prompt-mediated citation pathway, and the headline Cowrie comparison is based on n=6 sessions that the paper itself acknowledges is underpowered. Both can be addressed within a reasonable revision window.

### Major Issues (must address)

**M1. Ablation circularity (Devil's Advocate D1, methodology adjacency).** The 5-vs-0 RAG ablation holds the LLM prompt constant, but the prompt template is *constructed to use retrieved documents*. The 5-vs-0 result is therefore consistent with both a retrieval contribution and a prompt-citation contribution. **Action:** add an ablation arm where retrieved documents are semantically replaced with unrelated documents (or removed and the prompt rewritten to be neutral), and re-run the 5-vs-0 measurement. If the effect survives, the paper's claim strengthens. If it does not, re-scope the claim to "RAG-augmented, citation-prompted TTP discovery."

**M2. Headline abstract framing (EIC-1, DA-D2).** The abstract leans on the 0.697 composite effectiveness. The 10.1% deployment Truthfulness number is the more honest operational figure. **Action:** lead the abstract with the deployment metric and demote the composite to secondary. Add the n=6 Cowrie caveat inline. ESWA's abstract policy requires the most operationally honest number to be the first one cited.

**M3. Statistical power on the Cowrie head-to-head (Methodology Reviewer, DA-D2).** The +0.380 composite delta is based on n=6 Cowrie sessions. **Action:** report a bootstrap confidence interval on the 0.697 vs. 0.317 delta, or move the Cowrie comparison to supplementary material and reorder the headline around the 5-vs-0 RAG ablation (which is on n=30 sessions).

**M4. IQS composite weight sensitivity (Methodology Reviewer).** The 0.4 / 0.35 / 0.25 weights are asserted without justification. **Action:** add a sensitivity table showing how the composite ranking changes when each weight is varied ±0.15. If the ranking is robust, the composite is well-specified; if not, report the three component scores individually.

**M5. LLM-judge artifact-safety bias (Devil's Advocate D5, Methodology +1).** The paper identifies a scoring-rubric artifact (LLM judges penalize plausible fabricated credentials) but does not correct for it. **Action:** report the deception-quality consensus *with and without* the artifact-safety dimension, or apply a deterministic regex/human rubric for that dimension and re-aggregate. The 2.51/5 mean cannot be a headline number if the scoring bias is uncorrected.

**M6. Internal-vs-external surface gap (Devil's Advocate D4, perspective review adjacent).** The blind red-team finding is currently in §6.5 (Results) and §7.5 (Limitations), but the contribution framing does not reflect it. **Action:** in the Abstract and §1.7, frame the contribution as "internally validated architecture, externally pending deployment" — not as a deployed deception system. This is a scope re-framing, not a denial of the contribution.

**M7. MITRE ATT&CK tactic-level breakdown (Domain Reviewer).** The 31 unique ATT&CK techniques is presented as a count. A tactic-level distribution (TA0001, TA0007, etc.) is the unit analysts actually need. **Action:** add a tactic-level breakdown for the 31 surfaced TTPs and the 5 Cowrie TTPs.

**M8. Persona taxonomy citation (Domain Reviewer).** The Novice / Intermediate / Expert-APT taxonomy in Table 5 is presented without a theoretical citation. **Action:** either cite the cognitive-load or engagement-yield theory that motivates the three-tier partitioning, or justify the bins empirically (e.g., from Chrollo's feature-importance ranking).

**M9. PII hashing algorithm (Devil's Advocate, OPSEC).** The paper claims "PII hashing at ingestion" without specifying the algorithm. **Action:** name the hash function (e.g., HMAC-SHA256), the key-management regime, and whether attacker IPs are erased or retained in hashed form.

**M10. Blind red-team detection vector (Devil's Advocate).** The paper reports that the blind red-team *did* detect the honeypot but does not report *what they detected*. **Action:** add a paragraph on the detection vector (LLM-style response patterns, timing, static file paths, or another tell). This is the most actionable finding for red-team-defenders and is currently missing.

**M11. STRIDE-pattern threat-modelling claim (Domain Reviewer).** §1.5 mentions STRIDE-pattern threat modelling in the loop. **Action:** describe how STRIDE maps to Chrollo's escalation, or remove the claim.

### Minor Issues (recommended)

- **m1.** LLM model identifier should be pinned in the artifact for reproducibility.
- **m2.** Reference list is thin (40 entries). Add at least one AI-red-team reference (Ganguli 2022 / Perez 2022) and one constitutional-AI / RLHF reference that motivates the 86.7% safety-alignment ceiling.
- **m3.** The Generative-AI declaration covers writing assistance only — ESWA policy requires disclosure of AI assistance in technical work too.
- **m4.** The 30 RAGIN vs. 6 Cowrie session imbalance is acknowledged but should be more prominent.
- **m5.** The "k=5 k-NN degenerate fallback" in Algorithm 1 should report how often it triggered in the live 30 sessions.
- **m6.** The IQS weights cite three prior works but do not perform a sensitivity analysis.

### Strengths (acknowledged, do not weaken)

- Genuinely honest reporting of the deployment-fidelity gap (10.1% vs. 91.9%).
- The blind red-team finding is unusually candid.
- The RAG-poisoning defense in Algorithm 2 is a real contribution.
- Open-source artifact + reproducible build.
- The §2.6 threat model is thorough and the §7.6 jurisdictional note is appropriate.
- The narrative voice — "we don't claim any single primitive is novel on its own" — is honest and well-suited to ESWA.

### Panel

| Reviewer | Profile | Score |
|---|---|---|
| EIC (cybersecurity track) | ESWA Editor-in-Chief | Major Revision |
| Methodology | Senior ML/security systems researcher | Major Revision |
| Domain | Cyber-deception researcher | Major Revision |
| Perspective | AI safety / RAG-security researcher | Major Revision |
| Devil's Advocate | Adversarial reviewer / former red-team operator | Major Revision |

### Decision Authority

Under ESWA's editorial policy, the Major Revision decision is grounded in the *aggregation* of three unanimous reviewer assessments plus the panel's consensus on the deployment-fidelity framing. The Devil's Advocate CRITICAL findings (D1, D2, D4) have been **adjudicated explicitly** above: D1 is **partially validated** (requires prompt-controlled ablation), D2 is **validated** (requires n=6 caveat), D4 is **validated** (requires scope re-framing). None of these are silently bypassed.

**Editorial Decision:** **Major Revision**. Revise and resubmit with point-by-point responses to M1–M11. We expect a revision round that adds the prompt-controlled ablation (M1), re-frames the abstract (M2), and provides the MITRE-tactic breakdown (M7). Other major issues can be addressed in supplementary material where appropriate.

**Yours sincerely,**
ESWA Editorial Office

---

# Revision Roadmap (priority-ordered)

Ready to feed directly into `academic-paper` revision mode.

## P0 — Without these, the paper cannot be accepted

1. **R1.1** Add a prompt-controlled RAG ablation arm (M1). The "5 vs 0" result must be tested against a prompt-citation-only baseline.
2. **R1.2** Re-frame the abstract to lead with the 10.1% deployment Truthfulness number, not the 0.697 composite. Add the n=6 Cowrie caveat inline (M2).
3. **R1.3** Add bootstrap 95% CI on the 0.697 vs. 0.317 headline (M3). If the CI is wide, re-order the headline.
4. **R1.4** Re-frame the contribution as "internally validated, externally pending" in Abstract and §1.7 (M6).

## P1 — Required for the paper to deliver on its claims

5. **R1.5** Add a weight-sensitivity table for the IQS composite (M4). If the ranking is robust, the composite is well-specified; if not, demote the composite and report the three component scores.
6. **R1.6** Re-score the LLM-judge consensus with the artifact-safety dimension either removed or deterministically corrected (M5).
7. **R1.7** Add a tactic-level breakdown of the 31 surfaced MITRE ATT&CK techniques (M7).
8. **R1.8** Cite a theoretical anchor for the Novice/Intermediate/Expert-APT taxonomy, or derive the bins empirically from Chrollo's feature importance (M8).
9. **R1.9** Specify the PII hashing algorithm, key-management regime, and retention posture (M9).
10. **R1.10** Describe the blind red-team detection vector — what did the attackers detect? (M10).
11. **R1.11** Describe the STRIDE-pattern threat-modelling mapping or remove the claim (M11).

## P2 — Recommended polish

12. **R2.1** Pin the LLM model identifier in the artifact (m1).
13. **R2.2** Add AI-red-team and constitutional-AI references (m2).
14. **R2.3** Expand the Generative-AI declaration to cover technical work (m3).
15. **R2.4** Report the trigger rate of the k=5 degenerate fallback in the live 30 sessions (m5).
16. **R2.5** Expand the reference list by 5–10 entries (m6).

## P3 — Optional

17. **R3.1** Add a session-level TTP overlap measure (Jaccard) to the ablation to distinguish "RAGIN discovers 5 TTPs" from "RAGIN enumerates 5 TTPs from the same index."
18. **R3.2** Add a sensitivity analysis on the Algorithm 3 persona-gating thresholds (precision ≥ 0.5, speed ≥ 1.0 cmd/s).
19. **R3.3** Add a defensive argument for the LLM provider's use-of-service posture.

---

# Summary

| Item | Value |
|---|---|
| Decision | **Major Revision** |
| Path to Accept | All P0 + P1 items addressed |
| Strengths | Honest reporting, open-source, threat-model completeness, RAG-poisoning defense |
| Critical DA findings | D1 (partial), D2 (validated), D4 (validated) — all adjudicated, none silently bypassed |
| Headline risk | The 0.697 vs. 0.317 number is on n=6 Cowrie; the paper must lead with the 10.1% deployment figure |
| Underlying contribution | Real, but the paper's strongest claim (RAG determines TTP discovery) is on shakier ground than presented |

---

*Review generated 2026-08-04 by ARS `academic-paper-reviewer` v1.10.0 in `full` mode (5-seat panel + Devil's Advocate + editorial synthesis).*
