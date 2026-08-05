#!/usr/bin/env python3
"""Cowrie -> RAGIN Pipeline Bridge.

Watches cowrie.json for completed sessions and feeds them through
the Chrollo (classify) -> Don (analyze) pipeline via nginx.
"""

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

COWRIE_LOG = Path("/home/ubuntu/cowrie_logs/cowrie.json")
STATE_FILE = Path("/home/ubuntu/cowrie_logs/.bridge_offset")
RESULTS_DIR = Path("/home/ubuntu/cowrie_logs/results")
PIPELINE_URL = "http://localhost"
API_KEY = "27290c841436f1c10fc309d21b484a06378353dc2a80bcb3316478f82254e899"
POLL_INTERVAL = 2.0
STALE_TIMEOUT = 300  # 5 min — process partial sessions that never saw a close event
SRC_IP_SALT = "ragin-ip-v1"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def hash_ip(ip: str) -> str:
    import hashlib

    return hashlib.sha256(f"{ip}{SRC_IP_SALT}".encode()).hexdigest()


def read_offset() -> int:
    if STATE_FILE.exists():
        return int(STATE_FILE.read_text().strip())
    return 0


def write_offset(offset: int):
    STATE_FILE.write_text(str(offset))


def send_classify(payload: dict) -> dict | None:
    try:
        resp = httpx.post(
            f"{PIPELINE_URL}/api/classify",
            json=payload,
            headers={"X-API-Key": API_KEY},
            timeout=30.0,
        )
        if resp.status_code == 200:
            return resp.json()
        print(f"  [!] classify {resp.status_code}: {resp.text[:120]}")
        return None
    except Exception as e:
        print(f"  [!] classify error: {e}")
        return None


def send_analyze(payload: dict) -> dict | None:
    try:
        resp = httpx.post(
            f"{PIPELINE_URL}/api/analyze",
            json=payload,
            headers={"X-API-Key": API_KEY},
            timeout=30.0,
        )
        if resp.status_code == 200:
            return resp.json()
        print(f"  [!] analyze {resp.status_code}: {resp.text[:120]}")
        return None
    except Exception as e:
        print(f"  [!] analyze error: {e}")
        return None


def save_result(session_id: str, classify_r: dict | None, analyze_r: dict | None):
    record = {
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "classify_result": classify_r,
        "analyze_result": analyze_r,
    }
    (RESULTS_DIR / f"{session_id[:32]}.json").write_text(json.dumps(record, indent=2, default=str))


def assemble_session(events: list[dict]) -> dict | None:
    if not events:
        return None
    src_ip = None
    ssh_version = None
    duration_ms = None
    connect_time = None
    login_attempts = []
    login_success = None
    commands = []

    for ev in events:
        eid = ev.get("eventid", "")
        if eid == "cowrie.session.connect":
            src_ip = ev.get("src_ip", "unknown")
            connect_time = ev.get("timestamp")
        elif eid == "cowrie.client.version":
            ssh_version = ev.get("version", "")
        elif eid == "cowrie.login.failed":
            login_attempts.append(
                {
                    "username": ev.get("username", ""),
                    "password": ev.get("password", ""),
                }
            )
        elif eid == "cowrie.login.success":
            login_success = {
                "username": ev.get("username", ""),
                "password": ev.get("password", ""),
            }
        elif eid == "cowrie.command.input":
            commands.append(
                {
                    "command": ev.get("input", ev.get("message", "")),
                    "timestamp": ev.get("timestamp", ""),
                }
            )
        elif eid == "cowrie.session.closed":
            duration_ms = ev.get("duration_ms", 0)

    if not src_ip or src_ip == "172.17.0.1":
        return None

    hashed_src = hash_ip(src_ip)

    classify_payload = {
        "session_id": hashed_src,
        "start_time": connect_time or "",
        "commands": commands,
        "duration_seconds": (duration_ms or 0) / 1000.0,
        "features": {
            "ssh_version": ssh_version or "unknown",
            "login_attempts": len(login_attempts),
            "login_success": bool(login_success),
            "source_ip": src_ip,
            "hashed_ip": hashed_src,
        },
    }

    session_log = []
    for cmd in commands:
        session_log.append({"command": cmd["command"], "timestamp": cmd["timestamp"]})

    return {
        "classify_payload": classify_payload,
        "session_log": session_log,
        "has_commands": len(commands) > 0,
        "has_login_attempts": len(login_attempts) > 0,
        "has_login_success": login_success is not None,
        "login_attempts_list": login_attempts,
        "login_success": login_success,
        "ssh_version": ssh_version,
        "duration_ms": duration_ms,
        "src_ip": src_ip,
        "hashed_ip": hashed_src,
        "raw_session_id": events[0].get("session", "unknown"),
    }


def poll_cowrie():
    print("[*] Cowrie Pipeline Bridge")
    print(f"[*] Watching: {COWRIE_LOG}")
    print(f"[*] Pipeline: {PIPELINE_URL}")
    print(f"[*] Results:  {RESULTS_DIR}/")

    buffers: dict[str, list[dict]] = {}
    # Track last event timestamp per session for stale detection
    last_event: dict[str, float] = {}

    while True:
        now = time.time()

        if not COWRIE_LOG.exists():
            time.sleep(POLL_INTERVAL * 5)
            continue

        offset = read_offset()
        file_size = COWRIE_LOG.stat().st_size

        if file_size < offset:
            write_offset(0)
            print(f"[*] Log rotated/shrunk ({file_size}B < offset {offset}B) — resetting offset")
            offset = 0

        if file_size <= offset:
            # Check for stale sessions even when no new logs
            stale_found = False
            for sid in list(buffers.keys()):
                age = now - last_event.get(sid, now)
                if age > STALE_TIMEOUT:
                    print(f"\n  [*] Stale session {sid[:12]} (idle {age:.0f}s) — processing partial")
                    assembled = assemble_session(buffers[sid])
                    if assembled:
                        process_session(assembled)
                    del buffers[sid]
                    del last_event[sid]
                    stale_found = True
            if stale_found:
                continue
            time.sleep(POLL_INTERVAL)
            continue

        try:
            with open(COWRIE_LOG) as f:
                f.seek(offset)
                new_lines = f.readlines()
                new_offset = f.tell()
        except Exception as e:
            print(f"[!] read error: {e}")
            time.sleep(POLL_INTERVAL)
            continue

        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            session_id = event.get("session")
            eid = event.get("eventid", "")

            if not session_id:
                continue
            if session_id not in buffers:
                buffers[session_id] = []
            buffers[session_id].append(event)
            last_event[session_id] = now

            if eid == "cowrie.session.closed":
                assembled = assemble_session(buffers[session_id])
                if assembled:
                    process_session(assembled)
                del buffers[session_id]
                if session_id in last_event:
                    del last_event[session_id]

        write_offset(new_offset)
        time.sleep(POLL_INTERVAL)


def process_session(a: dict):
    now = datetime.now(timezone.utc).strftime("%H:%M:%S")
    src = a["src_ip"]
    hid = a["hashed_ip"][:12]
    ver = a["ssh_version"] or "?"
    dur = a["duration_ms"]
    cmds = a["classify_payload"]["commands"]

    print(f"\n[{now}] {src} ({hid}...) SSH={ver} dur={dur}ms", end="")

    if a["login_success"]:
        ls = a["login_success"]
        print(f"\n  LOGIN OK: {ls['username']}:{ls['password']}")
    if a["login_attempts_list"]:
        for la in a["login_attempts_list"][:3]:
            print(f"  LOGIN FAIL: {la['username']}:{la['password']}")
    if cmds:
        print(f"  Commands ({len(cmds)}):")
        for c in cmds[:8]:
            print(f"    > {c['command']}")

    if cmds or a["has_login_attempts"]:
        print("  -> Classify...", end=" ", flush=True)
        cr = send_classify(a["classify_payload"])
        if cr:
            sl = cr.get("skill_level", "?")
            cf = cr.get("confidence", 0)
            print(f"skill={sl} conf={cf}", end="")
            if sl != "novice" or cf >= 0.5:
                print(" -> Analyze...", end=" ", flush=True)
                enriched = dict(a["classify_payload"])
                clean_id = "".join(c for c in enriched["session_id"] if c.isalnum())[:128]
                # Add commands in both formats Don expects:
                #   "commands" -> list of strings (heuristic keyword matching)
                #   "description" -> text blob (name/phrase scanning)
                cmd_strs = [c["command"] for c in enriched.get("commands", [])]
                don_features = dict(enriched["features"])
                don_features["commands"] = cmd_strs
                don_features["description"] = "; ".join(cmd_strs)
                ar = send_analyze(
                    {
                        "session_id": clean_id,
                        "classification": sl,
                        "confidence": cf,
                        "features": don_features,
                        "session_log": a["session_log"],
                    }
                )
                if ar:
                    sev = ar.get("severity", "?")
                    tac = ar.get("tactics", [])
                    act = ar.get("candidate_actors", [])
                    print(f"severity={sev}", end="")
                    if tac:
                        print(f" tactics={[t['name'] for t in tac[:3]]}", end="")
                    if act:
                        print(f" actors={[x['name'] for x in act[:2]]}", end="")
                else:
                    print("FAIL", end="")
                save_result(a["hashed_ip"], cr, ar)
            else:
                save_result(a["hashed_ip"], cr, None)
            print()
        else:
            print("FAIL")
    else:
        print("  (probe — no login/commands)")


if __name__ == "__main__":
    try:
        poll_cowrie()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
        sys.exit(0)
