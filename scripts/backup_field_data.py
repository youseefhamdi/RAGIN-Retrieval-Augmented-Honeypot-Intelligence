#!/usr/bin/env python3
"""RAGIN Field Data Backup — automated backup of sessions, logs, configs, and Redis data."""

import argparse
import json
import logging
import shutil
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
LOG_DIR = ROOT / "logs"
BACKUP_DIR = DATA_DIR / "backups"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ragin.backup")


# ─── Redis Backup ────────────────────────────────────────────────────────────


def backup_redis(backup_path: Path) -> bool:
    """Dump Redis data using BGSAVE."""
    try:
        import redis

        r = redis.Redis()
        r.bgsave()
        # Wait for save to complete
        import time

        for _ in range(30):
            if r.lastsave() > 0:
                break
            time.sleep(1)

        # Copy RDB file
        rdb_src = Path("/var/lib/redis/dump.rdb")
        if not rdb_src.exists():
            # Try Docker volume location
            rdb_src = Path("/data/dump.rdb")

        if rdb_src.exists():
            shutil.copy2(rdb_src, backup_path / "redis_dump.rdb")
            logger.info("Redis RDB dump saved")
            return True
        else:
            logger.warning("Redis RDB file not found at expected locations")
            return False
    except Exception as e:
        logger.error("Redis backup failed: %s", e)
        return False


# ─── Log Backup ──────────────────────────────────────────────────────────────


def backup_logs(backup_path: Path) -> int:
    """Copy log files to backup directory."""
    log_backup = backup_path / "logs"
    log_backup.mkdir(exist_ok=True)

    count = 0
    for log_file in LOG_DIR.glob("*.log"):
        shutil.copy2(log_file, log_backup / log_file.name)
        count += 1

    logger.info("Backed up %d log files", count)
    return count


# ─── Config Backup ───────────────────────────────────────────────────────────


def backup_configs(backup_path: Path) -> int:
    """Backup configuration files."""
    config_backup = backup_path / "config"
    config_backup.mkdir(exist_ok=True)

    config_files = [
        ROOT / ".env",
        ROOT / "docker-compose.yml",
        ROOT / "docker-compose.prod.yml",
        ROOT / "ragin" / "config" / "settings.yaml",
        ROOT / "ragin" / "config" / "prometheus.yml",
        ROOT / "ragin" / "config" / "alert_rules.yml",
        ROOT / "ragin" / "config" / "nginx.conf.template",
    ]

    count = 0
    for cf in config_files:
        if cf.exists():
            shutil.copy2(cf, config_backup / cf.name)
            count += 1

    logger.info("Backed up %d config files", count)
    return count


# ─── Data Backup ─────────────────────────────────────────────────────────────


def backup_data(backup_path: Path) -> int:
    """Backup data directory (sessions, exports, pcaps)."""
    data_backup = backup_path / "data"
    data_backup.mkdir(exist_ok=True)

    count = 0
    for item in DATA_DIR.iterdir():
        if item.is_file():
            shutil.copy2(item, data_backup / item.name)
            count += 1
        elif item.is_dir() and item.name != "backups":
            shutil.copytree(item, data_backup / item.name, dirs_exist_ok=True)
            count += 1

    logger.info("Backed up %d data items", count)
    return count


# ─── Docker State ────────────────────────────────────────────────────────────


def backup_docker_state(backup_path: Path) -> bool:
    """Export Docker container states and compose config."""
    try:
        proc = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(ROOT),
        )

        containers = []
        for line in proc.stdout.strip().split("\n"):
            if line:
                try:
                    containers.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        state_file = backup_path / "docker_state.json"
        with open(state_file, "w") as f:
            json.dump(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "containers": containers,
                },
                f,
                indent=2,
            )

        logger.info("Docker state exported (%d containers)", len(containers))
        return True
    except Exception as e:
        logger.warning("Docker state export failed: %s", e)
        return False


# ─── Create Archive ──────────────────────────────────────────────────────────


def create_archive(backup_path: Path) -> Path:
    """Create a compressed tarball of the backup."""
    archive = backup_path.with_suffix(".tar.gz")
    with tarfile.open(archive, "w:gz") as tar:
        for item in backup_path.iterdir():
            tar.add(item, arcname=item.name)

    logger.info("Archive created: %s", archive)
    return archive


# ─── Cleanup Old Backups ─────────────────────────────────────────────────────


def cleanup_old_backups(keep_days: int = 90):
    """Remove backups older than keep_days."""
    cutoff = datetime.now(timezone.utc).timestamp() - (keep_days * 86400)
    removed = 0

    for item in BACKUP_DIR.iterdir():
        if item.is_file() and item.stat().st_mtime < cutoff:
            item.unlink()
            removed += 1
        elif item.is_dir() and item.stat().st_mtime < cutoff:
            shutil.rmtree(item)
            removed += 1

    if removed:
        logger.info("Cleaned up %d old backups (>%d days)", removed, keep_days)


# ─── Full Backup ─────────────────────────────────────────────────────────────


def full_backup(output_dir: Path = BACKUP_DIR, keep_days: int = 90) -> Path:
    """Run full backup pipeline."""
    output_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = output_dir / f"backup_{ts}"
    backup_path.mkdir(parents=True, exist_ok=True)

    logger.info("Starting full backup to %s", backup_path)

    # Run all backup steps
    backup_redis(backup_path)
    backup_logs(backup_path)
    backup_configs(backup_path)
    backup_data(backup_path)
    backup_docker_state(backup_path)

    # Create archive
    archive = create_archive(backup_path)

    # Write backup manifest
    manifest = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "backup_path": str(backup_path),
        "archive": str(archive),
        "size_bytes": sum(f.stat().st_size for f in backup_path.rglob("*") if f.is_file()),
    }
    with open(backup_path / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    # Cleanup old backups
    cleanup_old_backups(keep_days)

    logger.info("Full backup complete: %s (%.1f MB)", archive, manifest["size_bytes"] / (1024 * 1024))
    return archive


# ─── CLI ──────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="RAGIN Field Data Backup")
    parser.add_argument("--output", "-o", type=Path, default=BACKUP_DIR, help="Backup output directory")
    parser.add_argument("--keep-days", type=int, default=90, help="Days to retain backups (default: 90)")
    parser.add_argument("--redis-only", action="store_true", help="Backup Redis only")
    parser.add_argument("--logs-only", action="store_true", help="Backup logs only")
    parser.add_argument("--cleanup", action="store_true", help="Run cleanup only")
    args = parser.parse_args()

    if args.cleanup:
        cleanup_old_backups(args.keep_days)
        return

    if args.redis_only:
        backup_redis(args.output)
    elif args.logs_only:
        backup_logs(args.output)
    else:
        full_backup(args.output, args.keep_days)


if __name__ == "__main__":
    main()
