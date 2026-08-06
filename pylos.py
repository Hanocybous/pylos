#!/usr/bin/env python3
"""
Pylos: Production SSH Intrusion Autoblocker & CLI Tool
Copyright (c) 2026 - Charilaos Chatzidimitriou
"""

import argparse
import ipaddress
import json
import os
import re
import signal
import sqlite3
import subprocess  # nosec B404
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional

# System Paths
CONFIG_PATH = "/etc/pylos/config.json"
DB_PATH = "/var/lib/pylos/pylos.db"
CHAIN_NAME = "PYLOS"

# Default Configuration Values
DEFAULT_CONFIG = {
    "max_attempts": 5,
    "window_seconds": 600,      # 10 minutes sliding window
    "ban_duration_seconds": 3600, # 1 hour ban duration
    "whitelist": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128"]
}

# Regex to capture SSH authentication failures
FAIL_REGEX = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?\S+ from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def ensure_environment():
    """Ensure required system directories
	and configurations exist.
    """
    os.makedirs("/etc/pylos", exist_ok=True)
    os.makedirs("/var/lib/pylos", exist_ok=True)

    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)


def load_config() -> dict:
    """Load JSON config or
	return defaults on failure.
    """
    ensure_environment()
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            # Fill missing keys from default config
            for k, v in DEFAULT_CONFIG.items():
                cfg.setdefault(k, v)
            return cfg
    except (OSError, json.JSONDecodeError) as e:
        print(f"[WARN] Failed to load {CONFIG_PATH}: {e}. Using defaults.", file=sys.stderr)
        return DEFAULT_CONFIG


def validate_ip(ip_str: str) -> Optional[str]:
    """Validate and normalize an IP address string."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return str(ip_obj)
    except ValueError:
        return None


def is_whitelisted(ip_str: str, whitelist_networks: List[str]) -> bool:
    """Check if an IP falls within any whitelisted IP or CIDR network."""
    try:
        target = ipaddress.ip_address(ip_str)
        for net in whitelist_networks:
            try:
                if target in ipaddress.ip_network(net, strict=False):
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False


class DatabaseManager:
    """Manages SQLite storage for ban history, active bans, and analytics."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS active_bans (
                    ip TEXT PRIMARY KEY,
                    banned_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    reason TEXT DEFAULT 'SSH brute force'
                );

                CREATE TABLE IF NOT EXISTS attack_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    attempt_timestamp REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ban_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    banned_at REAL NOT NULL,
                    unbanned_at REAL,
                    reason TEXT
                );
            """)

    def record_attack(self, ip: str, timestamp: float):
        with self._get_connection() as conn:
            conn.execute("INSERT INTO attack_logs (ip, attempt_timestamp) VALUES (?, ?)", (ip, timestamp))

    def add_ban(self, ip: str, banned_at: float, duration: int, reason: str = "SSH brute force"):
        expires_at = banned_at + duration
        with self._get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO active_bans (ip, banned_at, expires_at, reason) VALUES (?, ?, ?, ?)",
                (ip, banned_at, expires_at, reason)
            )
            conn.execute(
                "INSERT INTO ban_history (ip, banned_at, reason) VALUES (?, ?, ?)",
                (ip, banned_at, reason)
            )

    def remove_ban(self, ip: str):
        now = time.time()
        with self._get_connection() as conn:
            conn.execute("DELETE FROM active_bans WHERE ip = ?", (ip,))
            conn.execute(
                "UPDATE ban_history SET unbanned_at = ? WHERE ip = ? AND unbanned_at IS NULL",
                (now, ip)
            )

    def get_active_bans(self) -> List[sqlite3.Row]:
        with self._get_connection() as conn:
            return conn.execute("SELECT * FROM active_bans ORDER BY banned_at DESC").fetchall()

    def get_stats(self) -> dict:
        with self._get_connection() as conn:
            total_attacks = conn.execute("SELECT COUNT(*) FROM attack_logs").fetchone()[0]
            total_bans = conn.execute("SELECT COUNT(*) FROM ban_history").fetchone()[0]
            active_count = conn.execute("SELECT COUNT(*) FROM active_bans").fetchone()[0]
            return {
                "total_attacks_logged": total_attacks,
                "total_historical_bans": total_bans,
                "currently_banned": active_count
            }

    def prune_old_logs(self, retention_days: int = 7):
        """Prevents database bloat by deleting logs older than X days."""
        cutoff_time = time.time() - (retention_days * 86400)
        with self._get_connection() as conn:
            conn.execute("DELETE FROM attack_logs WHERE attempt_timestamp < ?", (cutoff_time,))
            # Vacuum the database to reclaim physical disk space
            conn.execute("VACUUM")

class FirewallController:
    def __init__(self):
        self._init_chain()

    def _run_cmd(self, cmd: List[str]) -> subprocess.CompletedProcess:
        # Input is strictly validated and passed as a safe list
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def _init_chain(self):
        self._run_cmd(["/usr/sbin/iptables", "-N", CHAIN_NAME])
        check = self._run_cmd(["/usr/sbin/iptables", "-C", "INPUT", "-j", CHAIN_NAME])
        if check.returncode != 0:
            self._run_cmd(["/usr/sbin/iptables", "-I", "INPUT", "1", "-j", CHAIN_NAME])

    def ban_ip(self, ip: str) -> bool:
        if not validate_ip(ip):
            return False
        check = self._run_cmd(["/usr/sbin/iptables", "-C", CHAIN_NAME, "-s", ip, "-j", "DROP"])
        if check.returncode != 0:
            res = self._run_cmd(["/usr/sbin/iptables", "-A", CHAIN_NAME, "-s", ip, "-j", "DROP"])
            return res.returncode == 0
        return True

    def unban_ip(self, ip: str) -> bool:
        if not validate_ip(ip):
            return False
        res = self._run_cmd(["/usr/sbin/iptables", "-D", CHAIN_NAME, "-s", ip, "-j", "DROP"])
        return res.returncode == 0

class SSHLogMonitor:
    """Tails systemd journal for SSH authentication failures."""

    def __init__(self):
        # Execution is safe; arguments are static system commands
        self.process = subprocess.Popen(
            ["/usr/bin/journalctl", "-t", "sshd", "-u", "ssh", "-u", "sshd", "-f", "-n", "0", "-o", "cat"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

    def read_line(self) -> str:
        return self.process.stdout.readline()

    def terminate(self):
        if self.process:
            self.process.terminate()


def run_daemon():
    """Background service execution loop."""
    if os.geteuid() != 0:
        print("[FATAL] Daemon mode requires root privileges.", file=sys.stderr)
        sys.exit(1)

    print("[SYSTEM] Starting Pylos Daemon...")
    cfg = load_config()
    db = DatabaseManager()
    fw = FirewallController()
    monitor = SSHLogMonitor()

    # Re-enforce existing active bans from database upon startup
    active_db_bans = db.get_active_bans()
    now = time.time()
    for row in active_db_bans:
        if row["expires_at"] > now:
            fw.ban_ip(row["ip"])
        else:
            fw.unban_ip(row["ip"])
            db.remove_ban(row["ip"])

    def handle_shutdown(_signum, _frame):
        print("\n[SYSTEM] Daemon shutting down...")
        monitor.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    failures: Dict[str, List[float]] = defaultdict(list)
    last_prune_check = time.time()
    last_db_prune = time.time()

    while True:
        line = monitor.read_line()
        now = time.time()

        if line:
            match = FAIL_REGEX.search(line)
            if match:
                ip = match.group("ip")
                if is_whitelisted(ip, cfg["whitelist"]):
                    print(f"[LOG] Ignored failed attempt from whitelisted IP: {ip}")
                    continue

                print(f"[ATTACK] Failed SSH login attempt from: {ip}")
                db.record_attack(ip, now)

                failures[ip].append(now)
                # Prune timestamps outside window
                failures[ip] = [t for t in failures[ip] if (now - t) <= cfg["window_seconds"]]

                if len(failures[ip]) >= cfg["max_attempts"]:
                    print(f"[BAN] Threshold reached! Banning IP: {ip}")
                    if fw.ban_ip(ip):
                        db.add_ban(ip, now, cfg["ban_duration_seconds"])
                    failures[ip].clear()

        # Check for expired bans every 15 seconds
        if now - last_prune_check > 15:
            active_bans = db.get_active_bans()
            for row in active_bans:
                if now >= row["expires_at"]:
                    print(f"[UNBAN] Ban expired for IP: {row['ip']}")
                    fw.unban_ip(row["ip"])
                    db.remove_ban(row["ip"])
            last_prune_check = now

	# Prune old database logs once every 24 hours to prevent disk exhaustion
        if now - last_db_prune > 86400:
            print("[SYSTEM] Executing daily database maintenance and pruning...")
            db.prune_old_logs(retention_days=7)
            last_db_prune = now

# --- CLI Subcommands ---

def cli_status():
    db = DatabaseManager()
    stats = db.get_stats()
    cfg = load_config()

    print("==================================================")
    print("           PYLOS SYSTEM STATUS             ")
    print("==================================================")
    print(f"Max Attempts Allowed : {cfg['max_attempts']}")
    print(f"Sliding Window      : {cfg['window_seconds']}s")
    print(f"Ban Duration        : {cfg['ban_duration_seconds']}s")
    print("--------------------------------------------------")
    print(f"Active Bans         : {stats['currently_banned']}")
    print(f"Total Attacks Logged: {stats['total_attacks_logged']}")
    print(f"Total Bans Issued   : {stats['total_historical_bans']}")
    print("==================================================")


def cli_list():
    db = DatabaseManager()
    bans = db.get_active_bans()
    now = time.time()

    if not bans:
        print("No active IP bans.")
        return

    print(f"{'IP ADDRESS':<18} {'BANNED AT':<20} {'REMAINING (MIN)':<16} {'REASON'}")
    print("-" * 70)
    for row in bans:
        banned_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["banned_at"]))
        rem_min = max(0, int((row["expires_at"] - now) / 60))
        print(f"{row['ip']:<18} {banned_str:<20} {rem_min:<16} {row['reason']}")


def cli_ban(ip: str, duration: Optional[int]):
    if os.geteuid() != 0:
        print("[FATAL] Manual ban requires root privileges.", file=sys.stderr)
        sys.exit(1)

    ip_valid = validate_ip(ip)
    if not ip_valid:
        print(f"[ERROR] '{ip}' is not a valid IPv4 address.", file=sys.stderr)
        sys.exit(1)

    cfg = load_config()
    ban_dur = duration if duration else cfg["ban_duration_seconds"]

    fw = FirewallController()
    db = DatabaseManager()

    if fw.ban_ip(ip_valid):
        db.add_ban(ip_valid, time.time(), ban_dur, reason="Manual CLI Ban")
        print(f"[SUCCESS] Successfully banned {ip_valid} for {ban_dur} seconds.")
    else:
        print(f"[ERROR] Failed to apply firewall rule for {ip_valid}.", file=sys.stderr)


def cli_unban(ip: str):
    if os.geteuid() != 0:
        print("[FATAL] Manual unban requires root privileges.", file=sys.stderr)
        sys.exit(1)

    ip_valid = validate_ip(ip)
    if not ip_valid:
        print(f"[ERROR] '{ip}' is not a valid IPv4 address.", file=sys.stderr)
        sys.exit(1)

    fw = FirewallController()
    db = DatabaseManager()

    fw.unban_ip(ip_valid)
    db.remove_ban(ip_valid)
    print(f"[SUCCESS] Unbanned {ip_valid}.")


def main():
    ensure_environment()

    parser = argparse.ArgumentParser(
        description="Pylos: Production SSH Intrusion Autoblocker & Security CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Subcommand: daemon
    subparsers.add_parser("daemon", help="Run the background intrusion detection daemon")

    # Subcommand: status
    subparsers.add_parser("status", help="Show system status and overall analytics")

    # Subcommand: list
    subparsers.add_parser("list", help="List all currently banned IP addresses")

    # Subcommand: ban
    parser_ban = subparsers.add_parser("ban", help="Manually ban an IP address")
    parser_ban.add_argument("ip", help="IP address to ban")
    parser_ban.add_argument("-d", "--duration", type=int, help="Ban duration in seconds")

    # Subcommand: unban
    parser_unban = subparsers.add_parser("unban", help="Manually unban an IP address")
    parser_unban.add_argument("ip", help="IP address to unban")

    args = parser.parse_args()

    if args.command == "daemon":
        run_daemon()
    elif args.command == "status":
        cli_status()
    elif args.command == "list":
        cli_list()
    elif args.command == "ban":
        cli_ban(args.ip, args.duration)
    elif args.command == "unban":
        cli_unban(args.ip)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
