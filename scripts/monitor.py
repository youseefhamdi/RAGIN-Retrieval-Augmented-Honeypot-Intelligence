#!/usr/bin/env python3
"""RAGIN Network Monitor — captures and analyzes traffic on honeypot ports using tcpdump."""

import json
import os
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "logs"
PCAP_DIR = ROOT / "data" / "pcaps"

PORTS = [8081, 8082, 8083]  # Chrollo, Don, Hisoka


def start_capture(
    interface: str = "lo", ports: list[int] | None = None, outfile: str | None = None
) -> subprocess.Popen:
    """Start tcpdump capture on specified ports."""
    PCAP_DIR.mkdir(parents=True, exist_ok=True)

    if not ports:
        ports = PORTS
    if not outfile:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        outfile = str(PCAP_DIR / f"ragin_{ts}.pcap")

    # Build port filter
    port_filters = " or ".join(f"port {p}" for p in ports)
    bpf = f"({port_filters}) and not port 22 and not port 53"

    # Use dumpcap (has cap_net_raw, no root needed) if available, else tcpdump
    import shutil

    cap_bin = shutil.which("dumpcap") or "tcpdump"

    if cap_bin.endswith("dumpcap"):
        # dumpcap doesn't support BPF natively in the same way; write pcap then tshark filter
        cmd = [
            "dumpcap",
            "-i",
            interface,
            "-w",
            outfile,
            "-f",
            bpf,
        ]
    else:
        cmd = [
            "tcpdump",
            "-i",
            interface,
            "-w",
            outfile,
            "-s",
            "0",  # full packets
            "-v",
            bpf,
        ]

    print(f"[*] Starting capture: {' '.join(cmd)}")
    print(f"[*] Output: {outfile}")
    print(f"[*] Ports: {ports}")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    print(f"[*] tcpdump PID: {proc.pid}")
    return proc, outfile


def analyze_pcap(pcap_path: str) -> dict:
    """Analyze a pcap file with tshark."""
    if not os.path.exists(pcap_path):
        return {"error": f"File not found: {pcap_path}"}

    # Basic stats
    cmd_stats = [
        "tshark",
        "-r",
        pcap_path,
        "-q",
        "-z",
        "io,stat,1",
    ]
    result = subprocess.run(cmd_stats, capture_output=True, text=True, timeout=30)

    # Protocol hierarchy
    cmd_proto = [
        "tshark",
        "-r",
        pcap_path,
        "-q",
        "-z",
        "io,phs",
    ]
    proto_result = subprocess.run(cmd_proto, capture_output=True, text=True, timeout=30)

    # Conversation stats
    cmd_conv = [
        "tshark",
        "-r",
        pcap_path,
        "-q",
        "-z",
        "conv,ip",
    ]
    conv_result = subprocess.run(cmd_conv, capture_output=True, text=True, timeout=30)

    # Extract HTTP requests
    cmd_http = [
        "tshark",
        "-r",
        pcap_path,
        "-Y",
        "http.request",
        "-T",
        "fields",
        "-e",
        "frame.time",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "http.request.method",
        "-e",
        "http.request.uri",
        "-e",
        "http.host",
    ]
    http_result = subprocess.run(cmd_http, capture_output=True, text=True, timeout=30)

    http_requests = []
    for line in http_result.stdout.strip().split("\n"):
        if line:
            fields = line.split("\t")
            if len(fields) >= 5:
                http_requests.append(
                    {
                        "time": fields[0],
                        "src": fields[1],
                        "dst": fields[2],
                        "method": fields[3],
                        "uri": fields[4],
                        "host": fields[5] if len(fields) > 5 else "",
                    }
                )

    return {
        "pcap_file": pcap_path,
        "io_stats": result.stdout[:2000],
        "protocol_hierarchy": proto_result.stdout[:2000],
        "conversations": conv_result.stdout[:2000],
        "http_requests": http_requests,
        "total_http": len(http_requests),
    }


def continuous_monitor(interface: str = "lo", interval: int = 60, ports: list[int] | None = None):
    """Run continuous monitoring with periodic pcap rotation."""
    if not ports:
        ports = PORTS

    print(f"[*] Continuous monitor — rotating every {interval}s")
    print(f"[*] Ports: {ports}")
    print("[*] Press Ctrl+C to stop")

    running = True

    def handle_signal(sig, frame):
        nonlocal running
        print("\n[*] Stopping monitor...")
        running = False

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    rotation = 0
    while running:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        pcap = str(PCAP_DIR / f"ragin_rot{rotation:03d}_{ts}.pcap")

        proc, _ = start_capture(interface, ports, pcap)

        # Wait for interval or signal
        start = time.monotonic()
        while running and (time.monotonic() - start) < interval:
            time.sleep(1)

        # Stop capture
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        # Analyze
        print(f"\n[*] Rotation {rotation} — Analyzing {pcap}")
        stats = analyze_pcap(pcap)
        if stats.get("total_http", 0) > 0:
            print(f"    HTTP requests captured: {stats['total_http']}")
            for req in stats["http_requests"][:10]:
                print(f"    {req['method']} {req['uri']} from {req['src']}")

        rotation += 1

    print(f"[*] Monitor stopped. {rotation} rotations captured.")


def query_health(ports: list[int] | None = None) -> dict:
    """Query health of all RAGIN services."""
    if not ports:
        ports = PORTS
    results = {}
    for port in ports:
        name = {8081: "chrollo", 8082: "don", 8083: "hisoka"}.get(port, f"port_{port}")
        try:
            resp = httpx.get(f"http://127.0.0.1:{port}/health", timeout=3.0)
            results[name] = resp.json()
        except Exception as e:
            results[name] = {"error": str(e), "healthy": False}
    return results


def main():
    import argparse

    parser = argparse.ArgumentParser(description="RAGIN Network Monitor")
    sub = parser.add_subparsers(dest="command")

    cap = sub.add_parser("capture", help="Start packet capture")
    cap.add_argument("--interface", "-i", default="lo")
    cap.add_argument("--ports", "-p", nargs="+", type=int, default=PORTS)
    cap.add_argument("--output", "-o")

    mon = sub.add_parser("monitor", help="Continuous monitoring")
    mon.add_argument("--interface", "-i", default="lo")
    mon.add_argument("--interval", type=int, default=60)
    mon.add_argument("--ports", "-p", nargs="+", type=int, default=PORTS)

    ana = sub.add_parser("analyze", help="Analyze pcap file")
    ana.add_argument("pcap")

    hp = sub.add_parser("health", help="Query service health")

    args = parser.parse_args()

    if args.command == "capture":
        proc, outfile = start_capture(args.interface, args.ports, args.output)
        try:
            proc.wait()
        except KeyboardInterrupt:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=5)
        print(f"[*] Capture saved: {outfile}")

    elif args.command == "monitor":
        continuous_monitor(args.interface, args.interval, args.ports)

    elif args.command == "analyze":
        stats = analyze_pcap(args.pcap)
        print(json.dumps(stats, indent=2))

    elif args.command == "health":
        results = query_health()
        for name, info in results.items():
            s = "✓" if info.get("status") == "healthy" else "✗"
            print(f"  {s} {name}: {json.dumps(info, indent=2)}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
