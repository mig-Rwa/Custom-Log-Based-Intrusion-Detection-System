"""
Log Generator / Simulator
=========================
Generates realistic Linux auth.log and syslog entries for testing the IDS.
Simulates: SSH brute-force, invalid users, sudo abuse, port scans,
root login attempts, and normal traffic.
"""

import random
import os
from datetime import datetime, timedelta
from pathlib import Path


class LogGenerator:
    """Generates realistic sample log files for IDS testing."""

    # ── Attacker IPs (non-routable / documentation ranges) ──
    ATTACKER_IPS = [
        "203.0.113.50",     # Brute-forcer
        "198.51.100.23",    # Password sprayer
        "45.33.32.156",     # Root attacker
        "192.0.2.100",      # Port scanner
        "203.0.113.99",     # Generic attacker
        "198.51.100.77",    # Distributed attacker
    ]

    INTERNAL_IPS = ["10.0.0.5", "10.0.0.10", "10.0.0.20", "192.168.1.100"]

    # ── Common usernames attackers try ──
    ATTACK_USERS = [
        "admin", "root", "test", "guest", "oracle", "postgres",
        "mysql", "ftpuser", "ubuntu", "pi", "deploy", "www-data",
        "backup", "nagios", "tomcat", "jenkins", "git"
    ]

    LEGIT_USERS = ["admin", "deployer", "jdoe", "ubuntu"]

    def __init__(self, output_dir: str = "logs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_all(self):
        """Generate all sample log files."""
        print("\n[*] Generating sample log files for IDS testing...")
        self.generate_auth_log()
        self.generate_syslog()
        print("[*] Done! Sample logs are ready.\n")

    def generate_auth_log(self, filename: str = "sample_auth.log", num_hours: int = 12):
        """
        Generate a realistic auth.log with attack scenarios embedded.

        Scenarios:
        1. SSH brute-force (many failed logins from one IP)
        2. Password spraying (many users from one IP)
        3. Root login attempts
        4. Sudo abuse
        5. Port scan indicators
        6. Normal legitimate traffic
        """
        filepath = self.output_dir / filename
        lines = []
        base_time = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

        pid_counter = 10000

        # ── Scenario 1: SSH Brute-Force Attack (~02:14) ──
        print(f"    Generating SSH brute-force scenario...")
        attacker_ip = "203.0.113.50"
        t = base_time + timedelta(hours=2, minutes=14)
        for i in range(15):
            pid_counter += 1
            port = 49820 + i
            lines.append(self._syslog_line(
                t + timedelta(seconds=i*2),
                f"sshd[{pid_counter}]",
                f"Failed password for admin from {attacker_ip} port {port} ssh2"
            ))
        # Auth failure
        lines.append(self._syslog_line(
            t + timedelta(seconds=32),
            f"sshd[{pid_counter}]",
            f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
            f"tty=ssh ruser= rhost={attacker_ip}  user=admin"
        ))

        # ── Scenario 2: Password Spraying (~03:22) ──
        print(f"    Generating password spraying scenario...")
        sprayer_ip = "198.51.100.23"
        t = base_time + timedelta(hours=3, minutes=22)
        for i, user in enumerate(self.ATTACK_USERS[:10]):
            pid_counter += 1
            port = 44000 + i
            lines.append(self._syslog_line(
                t + timedelta(seconds=i*2),
                f"sshd[{pid_counter}]",
                f"Invalid user {user} from {sprayer_ip} port {port} ssh2"
            ))
            lines.append(self._syslog_line(
                t + timedelta(seconds=i*2 + 1),
                f"sshd[{pid_counter}]",
                f"Failed password for invalid user {user} from {sprayer_ip} port {port} ssh2"
            ))

        # ── Scenario 3: Root Login Attempts (~04:00) ──
        print(f"    Generating root login attack scenario...")
        root_attacker = "45.33.32.156"
        t = base_time + timedelta(hours=4)
        for i in range(8):
            pid_counter += 1
            port = 55010 + i
            lines.append(self._syslog_line(
                t + timedelta(seconds=i*2),
                f"sshd[{pid_counter}]",
                f"Failed password for root from {root_attacker} port {port} ssh2"
            ))
        lines.append(self._syslog_line(
            t + timedelta(seconds=18),
            f"sshd[{pid_counter}]",
            f"ROOT LOGIN REFUSED from {root_attacker}"
        ))

        # ── Scenario 4: Sudo Abuse (~05:10) ──
        print(f"    Generating sudo abuse scenario...")
        t = base_time + timedelta(hours=5, minutes=10)
        for i in range(4):
            pid_counter += 1
            lines.append(self._syslog_line(
                t + timedelta(seconds=i*5),
                f"sudo[{pid_counter}]",
                f"pam_unix(sudo:auth): authentication failure; logname=jdoe uid=1001 "
                f"euid=0 tty=/dev/pts/0 ruser=jdoe rhost=  user=jdoe"
            ))
            lines.append(self._syslog_line(
                t + timedelta(seconds=i*5 + 2),
                f"sudo[{pid_counter}]",
                f"    jdoe : 3 incorrect password attempts ; TTY=pts/0 ; "
                f"PWD=/home/jdoe ; USER=root ; COMMAND=/bin/bash"
            ))
        lines.append(self._syslog_line(
            t + timedelta(seconds=25),
            f"sudo[{pid_counter}]",
            f"    jdoe : user NOT in sudoers ; TTY=pts/0 ; "
            f"PWD=/home/jdoe ; USER=root ; COMMAND=/bin/su -"
        ))

        # ── Scenario 5: Port Scan Indicators (~06:30) ──
        print(f"    Generating port scan indicators...")
        scanner_ip = "192.0.2.100"
        t = base_time + timedelta(hours=6, minutes=30)
        for i in range(15):
            pid_counter += 1
            port = 60000 + i
            lines.append(self._syslog_line(
                t + timedelta(milliseconds=i*200),
                f"sshd[{pid_counter}]",
                f"Connection closed by {scanner_ip} port {port} [preauth]"
            ))
        lines.append(self._syslog_line(
            t + timedelta(seconds=4),
            f"sshd[{pid_counter}]",
            f"Did not receive identification string from {scanner_ip} port 60020"
        ))
        lines.append(self._syslog_line(
            t + timedelta(seconds=5),
            f"sshd[{pid_counter}]",
            f"refused connect from {scanner_ip} ({scanner_ip})"
        ))

        # ── Scenario 6: Normal Traffic ──
        print(f"    Generating normal/legitimate traffic...")
        for hour in range(num_hours):
            t = base_time + timedelta(hours=hour)
            user = random.choice(self.LEGIT_USERS)
            ip = random.choice(self.INTERNAL_IPS)
            pid_counter += 1
            port = random.randint(50000, 60000)

            # Successful login
            lines.append(self._syslog_line(
                t + timedelta(minutes=random.randint(0, 59)),
                f"sshd[{pid_counter}]",
                f"Accepted publickey for {user} from {ip} port {port} ssh2"
            ))
            lines.append(self._syslog_line(
                t + timedelta(minutes=random.randint(0, 59), seconds=1),
                f"sshd[{pid_counter}]",
                f"pam_unix(sshd:session): session opened for user {user} by (uid=0)"
            ))
            # Session close
            lines.append(self._syslog_line(
                t + timedelta(minutes=random.randint(0, 59), seconds=random.randint(60, 3600)),
                f"sshd[{pid_counter}]",
                f"pam_unix(sshd:session): session closed for user {user}"
            ))

        # Sort by timestamp and write
        lines.sort()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        print(f"    ✓ Generated {filepath} ({len(lines)} lines)")

    def generate_syslog(self, filename: str = "sample_syslog.log"):
        """Generate a realistic syslog with firewall blocks and system events."""
        filepath = self.output_dir / filename
        lines = []
        base_time = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

        # Firewall blocks from attackers
        for ip in self.ATTACKER_IPS[:3]:
            t = base_time + timedelta(hours=random.randint(1, 6), minutes=random.randint(0, 59))
            for i in range(random.randint(3, 8)):
                dport = random.choice([22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080, 8443])
                lines.append(self._syslog_line(
                    t + timedelta(seconds=i),
                    "kernel",
                    f"[UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 "
                    f"SRC={ip} DST=10.0.0.1 LEN=44 TOS=0x00 PREC=0x00 TTL={random.randint(40,64)} "
                    f"ID={random.randint(10000,65000)} DF PROTO=TCP "
                    f"SPT={random.randint(40000,65000)} DPT={dport} "
                    f"WINDOW=1024 RES=0x00 SYN URGP=0"
                ))

        # Normal system events
        for hour in range(12):
            t = base_time + timedelta(hours=hour)
            lines.append(self._syslog_line(
                t, "CRON[9001]",
                "(root) CMD (/usr/local/bin/backup.sh)"
            ))
            lines.append(self._syslog_line(
                t + timedelta(minutes=30), "systemd[1]",
                "Starting Daily apt download activities..."
            ))

        lines.sort()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        print(f"    ✓ Generated {filepath} ({len(lines)} lines)")

    @staticmethod
    def _syslog_line(timestamp: datetime, process: str, message: str) -> str:
        """Format a standard syslog line."""
        ts = timestamp.strftime("%b %e %H:%M:%S").replace("  ", " ")
        return f"{ts} webserver {process}: {message}"


# Allow running standalone
if __name__ == "__main__":
    gen = LogGenerator()
    gen.generate_all()
