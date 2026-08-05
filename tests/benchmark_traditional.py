"""
Traditional Honeypot Benchmark Harness
--------------------------------------
Deploys Dionaea, Conpot, and Kippo via Docker, sends the same 500-session
corpus used for RAGIN evaluation, and records detection metrics.

Usage:
    docker compose -f docker-compose-traditional.yml up -d
    python tests/benchmark_traditional.py --results traditional_results.json
    docker compose -f docker-compose-traditional.yml down
"""

import argparse
import json
import socket
import statistics
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

# ── Targets ──────────────────────────────────────────────────────────────
TRADITIONAL_TARGETS = {
    "dionaea": {
        "image": "dionaea/dionaea:latest",
        "ports": {"ftp": 21, "smb": 445, "http": 80, "sip": 5060},
        "description": "Malware capture honeypot (FTP/HTTP/SMB)",
    },
    "conpot": {
        "image": "conpot/conpot:latest",
        "ports": {"modbus": 502, "http": 81, "s7comm": 102},
        "description": "ICS/SCADA honeypot",
    },
    "kippo": {
        "image": "kwart/kippo:latest",
        "ports": {"ssh": 2223},
        "description": "SSH honeypot",
    },
}


@dataclass
class SessionResult:
    target: str
    port: int
    connection_success: bool
    interaction_captured: bool
    response_time_ms: float
    session_type: str  # "attack" or "benign"
    technique: str = ""
    error: str | None = None


@dataclass
class BenchmarkResults:
    target: str
    total_sessions: int = 0
    attack_sessions: int = 0
    benign_sessions: int = 0
    detected_attacks: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    missed_attacks: int = 0
    detection_accuracy: float = 0.0
    false_positive_rate: float = 0.0
    avg_response_time_ms: float = 0.0
    sessions: list = field(default_factory=list)


def probe_port(host: str, port: int, timeout: float = 5.0) -> tuple[bool, float]:
    """Probe a port and return (is_open, response_time_ms)."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.monotonic() - start) * 1000
            return True, elapsed
    except (TimeoutError, ConnectionRefusedError, OSError):
        elapsed = (time.monotonic() - start) * 1000
        return False, elapsed


def send_ssh_session(host: str, port: int) -> bool:
    """Attempt SSH connection and check for banner (honeypot interaction)."""
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            banner = sock.recv(1024)
            return len(banner) > 0 and b"SSH" in banner
    except Exception:
        return False


def send_http_session(host: str, port: int, path: str = "/") -> bool:
    """Send HTTP GET and check for response."""
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
            sock.send(req.encode())
            resp = sock.recv(4096)
            return len(resp) > 0
    except Exception:
        return False


def run_benchmark(
    target_name: str,
    target_config: dict,
    attack_sessions: list[dict],
    benign_sessions: list[dict],
    host: str = "127.0.0.1",
) -> BenchmarkResults:
    """Run benchmark against a single traditional honeypot."""
    results = BenchmarkResults(target=target_name)

    # Check which ports are actually open
    open_ports = {}
    for svc, port in target_config["ports"].items():
        is_open, resp_time = probe_port(host, port)
        if is_open:
            open_ports[svc] = port
            print(f"  [+] {target_name}:{svc} (port {port}) is OPEN ({resp_time:.1f}ms)")
        else:
            print(f"  [-] {target_name}:{svc} (port {port}) is CLOSED")

    if not open_ports:
        print(f"  [!] No open ports for {target_name} — skipping benchmark")
        return results

    all_sessions = [(s, "attack") for s in attack_sessions] + [(s, "benign") for s in benign_sessions]

    response_times = []

    for session, stype in all_sessions:
        port = session.get("port") or list(open_ports.values())[0]
        detected = False
        resp_time = 0.0
        error = None

        try:
            if "ssh" in open_ports and port == open_ports.get("ssh", -1):
                detected = send_ssh_session(host, port)
            elif "http" in open_ports and (port == open_ports.get("http", -1) or port == 80):
                detected = send_http_session(host, port)
            else:
                is_open, resp_time = probe_port(host, port)
                detected = is_open

            response_times.append(resp_time)
        except Exception as e:
            error = str(e)

        results.total_sessions += 1
        results.sessions.append(
            SessionResult(
                target=target_name,
                port=port,
                connection_success=detected,
                interaction_captured=detected,
                response_time_ms=resp_time,
                session_type=stype,
                technique=session.get("technique", ""),
                error=error,
            )
        )

        if stype == "attack":
            results.attack_sessions += 1
            if detected:
                results.detected_attacks += 1
            else:
                results.missed_attacks += 1
        else:
            results.benign_sessions += 1
            if detected:
                results.false_positives += 1
            else:
                results.true_negatives += 1

    # Compute metrics
    if results.attack_sessions > 0:
        results.detection_accuracy = results.detected_attacks / results.attack_sessions * 100
    tp_fn = results.false_positives + results.true_negatives
    if tp_fn > 0:
        results.false_positive_rate = results.false_positives / tp_fn * 100
    if response_times:
        results.avg_response_time_ms = statistics.mean(response_times)

    return results


def load_sessions(path: str) -> tuple[list[dict], list[dict]]:
    """Load attack and benign sessions from the RAGIN corpus."""
    with open(path) as f:
        corpus = json.load(f)
    attacks = [s for s in corpus if s.get("label") == "attack"]
    benigns = [s for s in corpus if s.get("label") == "benign"]
    return attacks, benigns


def main():
    parser = argparse.ArgumentParser(description="Benchmark traditional honeypots against RAGIN corpus")
    parser.add_argument("--corpus", default="data/session_corpus.json", help="Session corpus path")
    parser.add_argument("--results", default="results/traditional_benchmark.json", help="Output path")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    args = parser.parse_args()

    corpus_path = Path(args.corpus)
    if not corpus_path.exists():
        print(f"[!] Corpus not found: {corpus_path}")
        print("    Generate with: python tests/generate_corpus.py")
        return

    attacks, benigns = load_sessions(str(corpus_path))
    print(f"[*] Loaded {len(attacks)} attack + {len(benigns)} benign sessions")

    all_results = {}
    for name, config in TRADITIONAL_TARGETS.items():
        print(f"\n[*] Benchmarking {name}: {config['description']}")
        result = run_benchmark(name, config, attacks, benigns, args.host)
        all_results[name] = asdict(result)
        print(
            f"    Detection: {result.detection_accuracy:.1f}%  "
            f"FPR: {result.false_positive_rate:.1f}%  "
            f"Sessions: {result.total_sessions}"
        )

    # Save results
    output_path = Path(args.results)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n[*] Results saved to {output_path}")

    # Print comparison table
    print("\n" + "=" * 60)
    print(f"{'System':<20} {'Det. Acc.':<12} {'FPR':<12} {'Sessions':<10}")
    print("=" * 60)
    for name, r in all_results.items():
        print(
            f"{name:<20} {r['detection_accuracy']:<12.1f} "
            f"{r['false_positive_rate']:<12.1f} {r['total_sessions']:<10}"
        )
    print("=" * 60)


if __name__ == "__main__":
    main()
