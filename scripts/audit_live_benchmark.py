#!/usr/bin/env python3
"""
Quality-aware re-scoring of live_benchmark.json.

Adds three deployment-quality gates on top of the existing content scorer:
  1. NON-EMPTY  : response_preview has substantive content
  2. NON-REFUSAL: response does not contain safety-refusal signals
  3. TIMELY     : latency_ms < 90000 (below OpenRouter SDK read-timeout)

A record is `quality_passed` only if all three gates pass AND the original
content scorer returned >= 0.3. This separates "content fidelity" from
"deployment readiness" -- the former is what RAGIN's architecture delivers;
the latter is the live latency contract that the current OpenRouter path
fails to meet.

Output: live_benchmark_audited.json with the same schema plus:
  - quality_class  : GROUNDED | EMPTY | REFUSAL | TIMEOUT
  - quality_passed : bool (gates + content score)
  - audit_notes    : list[str] of which gates failed
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "results" / "live_benchmark.json"
DST = ROOT / "results" / "live_benchmark_audited.json"

LATENCY_TIMEOUT_MS = 90_000
MIN_CONTENT_CHARS = 80

REFUSAL_SIGNALS = [
    "i can't roleplay",
    "i cannot roleplay",
    "i won't roleplay",
    "i'm not able to roleplay",
    "i can't assist with that",
    "i can't help with that",
    "i won't provide",
    "i can't provide",
    "i cannot provide",
    "as an ai assistant",
    "i'm unable to",
    "i won't generate",
    "i can't generate",
    "i don't think i should",
    "i'm not going to",
    "i won't engage",
    "as a language model",
    "ethical concerns",
    "safety guidelines",
    "responsible ai",
]

EMPTY_SIGNALS = [
    "(no output)",
    "looking for something in particular?",
]


def classify(record: dict) -> tuple[str, list[str]]:
    preview = (record.get("details") or {}).get("response_preview", "") or ""
    latency_ms = record.get("latency_ms") or 0
    notes: list[str] = []

    if latency_ms >= LATENCY_TIMEOUT_MS:
        notes.append(f"timeout({latency_ms:.0f}ms)")
        return "TIMEOUT", notes

    preview_stripped = preview.strip()
    if not preview_stripped:
        notes.append("empty:no_response")
        return "EMPTY", notes
    if len(preview_stripped) < MIN_CONTENT_CHARS:
        notes.append(f"empty:short({len(preview_stripped)}c)")
        return "EMPTY", notes
    lowered = preview_stripped.lower()
    if any(sig in lowered for sig in EMPTY_SIGNALS):
        notes.append("empty:fallback_signal")
        return "EMPTY", notes
    if any(sig in lowered for sig in REFUSAL_SIGNALS):
        notes.append("refusal:safety_aligned")
        return "REFUSAL", notes

    return "GROUNDED", notes


def audit(data: dict) -> dict:
    by_suite: dict[str, list[dict]] = {}
    for suite_key in ("technique_results", "actor_results", "persona_results"):
        records = data.get(suite_key, [])
        for rec in records:
            qclass, qnotes = classify(rec)
            content_passed = bool(rec.get("passed"))
            rec["quality_class"] = qclass
            rec["quality_passed"] = (qclass == "GROUNDED") and content_passed
            rec["audit_notes"] = qnotes
            by_suite.setdefault(suite_key, []).append(rec)

    new_metrics = dict(data.get("metrics", {}))
    flat = [r for v in by_suite.values() for r in v]
    total = len(flat)
    classes = {"GROUNDED": 0, "EMPTY": 0, "REFUSAL": 0, "TIMEOUT": 0}
    for r in flat:
        classes[r["quality_class"]] += 1
    qp = sum(1 for r in flat if r["quality_passed"])
    new_metrics["audit"] = {
        "total_records": total,
        "quality_passed": qp,
        "quality_pass_rate": round(qp / max(total, 1), 4),
        "class_breakdown": classes,
        "grounded_rate": round(classes["GROUNDED"] / max(total, 1), 4),
        "refusal_rate": round(classes["REFUSAL"] / max(total, 1), 4),
        "empty_rate": round(classes["EMPTY"] / max(total, 1), 4),
        "timeout_rate": round(classes["TIMEOUT"] / max(total, 1), 4),
        "latency_threshold_ms": LATENCY_TIMEOUT_MS,
        "min_content_chars": MIN_CONTENT_CHARS,
    }
    data["metrics"] = new_metrics
    return data


def main() -> int:
    if not SRC.exists():
        print(f"missing source: {SRC}", file=sys.stderr)
        return 1
    with open(SRC) as fh:
        data = json.load(fh)
    audited = audit(data)
    DST.write_text(json.dumps(audited, indent=2))
    a = audited["metrics"]["audit"]
    print(f"audited -> {DST}")
    print(f"  total:               {a['total_records']}")
    print(f"  quality_passed:      {a['quality_passed']}  ({100*a['quality_pass_rate']:.1f}%)")
    for k in ("grounded", "refusal", "empty", "timeout"):
        v = a[f"{k}_rate"]
        n = a["class_breakdown"][k.upper()]
        print(f"  {k:8s}: {100*v:5.1f}%  ({n})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
