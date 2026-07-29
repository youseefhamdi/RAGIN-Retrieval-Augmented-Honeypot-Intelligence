#!/usr/bin/env python3
"""RAGIN Field Data Collector — exports and analyzes session data from the deployed honeypot."""

import argparse
import json
import logging
import sys
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
LOG_DIR = ROOT / "logs"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ragin.collector")


# ─── Redis Session Export ────────────────────────────────────────────────────


def export_redis_sessions(days: int = 30, output_dir: Path = DATA_DIR / "exports") -> Path:
    """Export session data from Redis for analysis."""
    try:
        import redis
    except ImportError:
        logger.error("redis-py not installed: pip install redis")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    export_file = output_dir / f"sessions_{ts}.jsonl"

    r = redis.Redis()
    logger.info("Connected to Redis — exporting sessions from last %d days", days)

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    exported = 0

    # Scan for session keys
    cursor = 0
    with open(export_file, "w") as f:
        while True:
            cursor, keys = r.scan(cursor=cursor, match="ragin:session:*", count=100)
            for key in keys:
                try:
                    data = r.hgetall(key)
                    if not data:
                        continue

                    # Parse session data
                    session = {}
                    for k, v in data.items():
                        k_str = k.decode() if isinstance(k, bytes) else k
                        v_str = v.decode() if isinstance(v, bytes) else v
                        # Try to parse JSON values
                        try:
                            session[k_str] = json.loads(v_str)
                        except (json.JSONDecodeError, TypeError):
                            session[k_str] = v_str

                    # Check timestamp
                    created = session.get("created_at", session.get("timestamp", ""))
                    if created:
                        try:
                            sess_time = datetime.fromisoformat(created.replace("Z", "+00:00"))
                            if sess_time < cutoff:
                                continue
                        except (ValueError, TypeError):
                            pass

                    f.write(json.dumps(session, default=str) + "\n")
                    exported += 1

                except Exception as e:
                    logger.warning("Failed to export key %s: %s", key, e)

            if cursor == 0:
                break

    logger.info("Exported %d sessions to %s", exported, export_file)
    return export_file


# ─── Log File Export ─────────────────────────────────────────────────────────


def export_logs(days: int = 30, output_dir: Path = DATA_DIR / "exports") -> Path:
    """Export and consolidate log files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    export_file = output_dir / f"logs_{ts}.jsonl"

    log_files = [
        LOG_DIR / "gateway.log",
        LOG_DIR / "chrollo.log",
        LOG_DIR / "don.log",
        LOG_DIR / "hisoka.log",
    ]

    exported = 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    with open(export_file, "w") as f:
        for log_file in log_files:
            if not log_file.exists():
                continue

            logger.info("Processing %s", log_file.name)
            with open(log_file) as lf:
                for line in lf:
                    line = line.strip()
                    if not line:
                        continue
                    # Try to parse as JSON log entry
                    try:
                        entry = json.loads(line)
                        entry["_source_file"] = log_file.name
                        f.write(json.dumps(entry, default=str) + "\n")
                        exported += 1
                    except json.JSONDecodeError:
                        # Plain text log line
                        f.write(
                            json.dumps(
                                {
                                    "message": line,
                                    "_source_file": log_file.name,
                                }
                            )
                            + "\n"
                        )
                        exported += 1

    logger.info("Exported %d log entries to %s", exported, export_file)
    return export_file


# ─── Prometheus Metrics Export ────────────────────────────────────────────────


def export_prometheus_metrics(output_dir: Path = DATA_DIR / "exports") -> Path | None:
    """Export current Prometheus metrics snapshot."""
    import httpx

    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    export_file = output_dir / f"metrics_{ts}.json"

    try:
        resp = httpx.get("http://127.0.0.1:9090/api/v1/query?query=up", timeout=10.0)
        data = resp.json()

        metrics = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "query": "up",
            "results": data.get("data", {}).get("result", []),
        }

        with open(export_file, "w") as f:
            json.dump(metrics, f, indent=2)

        logger.info("Exported Prometheus metrics to %s", export_file)
        return export_file
    except Exception as e:
        logger.warning("Failed to export Prometheus metrics: %s", e)
        return None


# ─── Analysis ────────────────────────────────────────────────────────────────


def analyze_sessions(export_file: Path) -> dict:
    """Analyze exported session data and produce summary statistics."""
    sessions = []
    with open(export_file) as f:
        for line in f:
            try:
                sessions.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not sessions:
        return {"error": "No sessions found"}

    # Aggregate stats
    total = len(sessions)
    classifications = {}
    ttps = {}
    honeypots_hit = {}
    attacker_ips = set()

    for s in sessions:
        # Classification distribution
        cls = s.get("classification", s.get("chrollo_classification", "unknown"))
        classifications[cls] = classifications.get(cls, 0) + 1

        # TTP collection
        session_ttps = s.get("ttps", s.get("detected_ttps", []))
        if isinstance(session_ttps, list):
            for ttp in session_ttps:
                ttps[ttp] = ttps.get(ttp, 0) + 1

        # Honeypot interaction
        hp = s.get("honeypot_type", s.get("target_honeypot", "unknown"))
        honeypots_hit[hp] = honeypots_hit.get(hp, 0) + 1

        # Attacker IPs
        ip = s.get("attacker_ip", s.get("src_ip", s.get("ip", "")))
        if ip:
            attacker_ips.add(ip)

    # Sort by frequency
    top_ttps = sorted(ttps.items(), key=lambda x: x[1], reverse=True)[:20]
    top_ips = sorted(attacker_ips)[:100]  # First 100 unique IPs

    analysis = {
        "summary": {
            "total_sessions": total,
            "unique_attackers": len(attacker_ips),
            "analysis_date": datetime.now(timezone.utc).isoformat(),
        },
        "classifications": classifications,
        "top_ttps": [{"ttp": t, "count": c} for t, c in top_ttps],
        "honeypot_distribution": honeypots_hit,
        "unique_attacker_ips": len(attacker_ips),
        "sample_ips": top_ips[:20],
    }

    return analysis


# ─── Archive ─────────────────────────────────────────────────────────────────


def archive_exports(output_dir: Path = DATA_DIR / "exports") -> Path:
    """Create a tarball of all exports for archival."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    archive_file = DATA_DIR / f"ragin_export_{ts}.tar.gz"

    with tarfile.open(archive_file, "w:gz") as tar:
        for f in output_dir.iterdir():
            if f.is_file():
                tar.add(f, arcname=f.name)

    logger.info("Archived exports to %s", archive_file)
    return archive_file


# ─── CLI ──────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="RAGIN Field Data Collector")
    sub = parser.add_subparsers(dest="command", required=True)

    # Export sessions
    exp = sub.add_parser("export", help="Export session data from Redis")
    exp.add_argument("--days", "-d", type=int, default=30, help="Lookback period in days")
    exp.add_argument("--output", "-o", type=Path, default=DATA_DIR / "exports")

    # Export logs
    log_exp = sub.add_parser("logs", help="Export and consolidate log files")
    log_exp.add_argument("--days", "-d", type=int, default=30)
    log_exp.add_argument("--output", "-o", type=Path, default=DATA_DIR / "exports")

    # Export metrics
    met = sub.add_parser("metrics", help="Export Prometheus metrics snapshot")
    met.add_argument("--output", "-o", type=Path, default=DATA_DIR / "exports")

    # Analyze
    ana = sub.add_parser("analyze", help="Analyze exported session data")
    ana.add_argument("file", type=Path, help="Path to sessions JSONL export")
    ana.add_argument("--output", "-o", type=Path, default=DATA_DIR / "exports")

    # Archive
    arc = sub.add_parser("archive", help="Create tarball of all exports")
    arc.add_argument("--output", "-o", type=Path, default=DATA_DIR / "exports")

    # Full pipeline
    full = sub.add_parser("full", help="Run full export + analysis pipeline")
    full.add_argument("--days", "-d", type=int, default=30)
    full.add_argument("--output", "-o", type=Path, default=DATA_DIR / "exports")

    args = parser.parse_args()

    if args.command == "export":
        export_redis_sessions(args.days, args.output)

    elif args.command == "logs":
        export_logs(args.days, args.output)

    elif args.command == "metrics":
        export_prometheus_metrics(args.output)

    elif args.command == "analyze":
        analysis = analyze_sessions(args.file)
        out_file = args.output / f"analysis_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        with open(out_file, "w") as f:
            json.dump(analysis, f, indent=2)
        logger.info("Analysis saved to %s", out_file)
        print(json.dumps(analysis, indent=2))

    elif args.command == "archive":
        archive_exports(args.output)

    elif args.command == "full":
        logger.info("Running full export pipeline...")
        session_file = export_redis_sessions(args.days, args.output)
        log_file = export_logs(args.days, args.output)
        metrics_file = export_prometheus_metrics(args.output)

        # Analyze sessions
        analysis = analyze_sessions(session_file)
        analysis_file = args.output / f"analysis_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        with open(analysis_file, "w") as f:
            json.dump(analysis, f, indent=2)

        # Archive everything
        archive_file = archive_exports(args.output)

        print(f"\n{'='*60}")
        print(" Export Complete")
        print(f"{'='*60}")
        print(f" Sessions:   {session_file}")
        print(f" Logs:       {log_file}")
        print(f" Metrics:    {metrics_file}")
        print(f" Analysis:   {analysis_file}")
        print(f" Archive:    {archive_file}")
        print(f"{'='*60}\n")

        # Print summary
        print(json.dumps(analysis.get("summary", {}), indent=2))


if __name__ == "__main__":
    main()
