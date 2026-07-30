#!/usr/bin/env python3
"""Validate Phase 1 output integrity on a real Cowrie session."""

import hashlib
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SRC_IP_SALT = "ragin-ip-v1"
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8080")


def hash_ip(ip: str) -> str:
    return hashlib.sha256(f"{ip}{SRC_IP_SALT}".encode()).hexdigest()


def main():
    cowrie_path = "/tmp/cowrie_vps.json"
    print(f"[*] Loading cowrie events from: {cowrie_path}")
    events = []
    with open(cowrie_path) as f:
        events = [json.loads(line) for line in f if line.strip()]
    print(f"[*] Total events: {len(events)}")

    by_session = defaultdict(list)
    for e in events:
        by_session[e.get("session", "?")].append(e)

    input_eid = "cowrie.command.input"
    best_sid = max(
        by_session,
        key=lambda s: sum(1 for e in by_session[s] if e.get("eventid") == input_eid),
    )
    sess_events = by_session[best_sid]

    src_ip = next((e["src_ip"] for e in sess_events if "src_ip" in e), "unknown")
    ssh_version = next(
        (e["version"] for e in sess_events if e.get("eventid") == "cowrie.client.version"),
        "unknown",
    )
    login = next(
        (
            {"username": e["username"], "password": e["password"]}
            for e in sess_events
            if e.get("eventid") == "cowrie.login.success"
        ),
        None,
    )
    commands = [e["input"] for e in sess_events if e.get("eventid") == input_eid]
    start_time = next(
        (e["timestamp"] for e in sess_events if e.get("eventid") == "cowrie.session.connect"),
        "",
    )

    print(f"[*] Session: {best_sid}")
    print(f"[*] Source IP: {src_ip}")
    print(f"[*] SSH: {ssh_version}")
    print(f"[*] Login: {login}")
    print(f"[*] Commands ({len(commands)}): {commands}")
    print()

    hashed_src = hash_ip(src_ip)
    session_id = hashed_src
    session_context = {
        "session_id": session_id,
        "attacker_inputs": commands,
        "start_time": start_time,
        "features": {
            "ssh_version": ssh_version,
            "login_attempts": 0,
            "login_success": bool(login),
            "source_ip": src_ip,
            "hashed_ip": hashed_src,
            "commands": commands,
            "description": "; ".join(commands),
        },
    }

    # === ChrolloAdapter ===
    print("=" * 60)
    print("STEP 1: ChrolloAdapter.classify()")
    print("=" * 60)

    from ragin.cycle.adapters import ChrolloAdapter

    classify_result = ChrolloAdapter().classify(commands[0] if commands else "", session_context)

    print(f"  skill_level: {classify_result['skill_level']}")
    print(f"  confidence: {classify_result['confidence']}")
    print(f"  features_used: {classify_result.get('features_used', [])}")
    print(f"  error: {classify_result.get('error', '')}")
    print(f"  keys: {sorted(classify_result.keys())}")
    print()

    # === DonAdapter ===
    print("=" * 60)
    print("STEP 2: DonAdapter.analyze()")
    print("=" * 60)

    from ragin.cycle.adapters import DonAdapter

    session_context["classification"] = {
        "skill_level": classify_result["skill_level"],
        "confidence": classify_result["confidence"],
    }

    da = DonAdapter(gateway_url=GATEWAY_URL, api_key=None)
    analyze_result = da.analyze(commands[0] if commands else "", session_context)

    print(f"  analysis_id: {analyze_result.get('analysis_id', 'MISSING')}")
    print(f"  severity: {analyze_result.get('severity', 'MISSING')}")
    print(f"  classification: {analyze_result.get('classification', 'MISSING')}")
    print(f"  confidence: {analyze_result.get('confidence', 'MISSING')}")
    print(f"  error: {analyze_result.get('error', 'MISSING')}")
    print()

    actors = analyze_result.get("candidate_actors", analyze_result.get("threat_actors", []))
    print(f"  candidate_actors ({len(actors)}):")
    for a in actors:
        print(f"    - {a.get('name')} (conf={a.get('confidence')}, basis={a.get('basis', 'MISSING')})")
    print()

    for field in ["evasion_techniques", "tools_used", "credential_access"]:
        val = analyze_result.get(field, [])
        print(f"  {field}: {val}")
    tactics = analyze_result.get("tactics", [])
    print(f"  tactics: {[t.get('name') for t in tactics]}")
    print()
    print(f"  keys: {sorted(analyze_result.keys())}")
    print()

    # === Summary ===
    print("=" * 60)
    print("PHASE 1 VALIDATION SUMMARY")
    print("=" * 60)
    checks = []

    actors_ok = "candidate_actors" in analyze_result and all("basis" in a for a in actors)
    checks.append((actors_ok, "candidate_actors with basis"))

    for field in ["evasion_techniques", "tools_used", "credential_access", "tactics"]:
        checks.append((field in analyze_result, f"{field} present"))

    for ok, msg in checks:
        print(f"  [{'✓' if ok else '✗'}] {msg}")

    passed = sum(1 for ok, _ in checks if ok)
    print(f"\n  Result: {passed}/{len(checks)} checks passed")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
