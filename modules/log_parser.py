"""
Log Parser Module
=================
Parses Linux log files (auth.log, syslog) into structured event dictionaries.
Supports reading from position for continuous monitoring.
Handles multiple log formats: syslog (RFC 3164), auth.log, and custom.
"""

import re
import os
from datetime import datetime
from typing import List, Dict, Tuple, Optional


class LogParser:
    """Parses raw Linux log lines into structured event dictionaries."""

    # ── Regex patterns for common log formats ──

    # Standard syslog: "Mar  1 10:23:45 hostname process[pid]: message"
    SYSLOG_PATTERN = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s+"
        r"(?P<message>.+)$"
    )

    # Extract source IP from common patterns
    IP_PATTERNS = [
        re.compile(r"from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
        re.compile(r"SRC=(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
        re.compile(r"rhost=(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
    ]

    # Extract username from common patterns
    USER_PATTERNS = [
        re.compile(r"for\s+(?:invalid\s+user\s+)?(?P<user>\S+)"),
        re.compile(r"user[=:\s]+(?P<user>\S+)"),
        re.compile(r"USER=(?P<user>\S+)"),
    ]

    # Extract port
    PORT_PATTERN = re.compile(r"port\s+(?P<port>\d+)")

    def __init__(self, config):
        self.config = config
        self.whitelist = config.get_whitelist()
        self._current_year = datetime.now().year

    def parse_file(self, filepath: str, source_name: str) -> List[Dict]:
        """
        Parse an entire log file into structured events.

        Args:
            filepath: Path to the log file
            source_name: Identifier for the log source (e.g., 'auth_log')

        Returns:
            List of parsed event dictionaries
        """
        events = []
        if not os.path.exists(filepath):
            return events

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                event = self._parse_line(line, source_name, line_num)
                if event and not self._is_whitelisted(event):
                    events.append(event)

        return events

    def parse_file_from_position(
        self, filepath: str, source_name: str, start_pos: int
    ) -> Tuple[List[Dict], int]:
        """
        Parse a log file from a specific byte position (for tail-mode monitoring).

        Args:
            filepath: Path to the log file
            source_name: Identifier for the log source
            start_pos: Byte position to start reading from

        Returns:
            Tuple of (parsed_events, new_position)
        """
        events = []
        new_pos = start_pos

        if not os.path.exists(filepath):
            return events, new_pos

        file_size = os.path.getsize(filepath)

        # Handle log rotation: if file got smaller, start from beginning
        if file_size < start_pos:
            start_pos = 0

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            f.seek(start_pos)
            line_num = 0
            for line in f:
                line_num += 1
                line = line.strip()
                if not line:
                    continue
                event = self._parse_line(line, source_name, line_num)
                if event and not self._is_whitelisted(event):
                    events.append(event)

            new_pos = f.tell()

        return events, new_pos

    def _parse_line(self, line: str, source_name: str, line_num: int) -> Optional[Dict]:
        """
        Parse a single log line into a structured event dict.

        Returns:
            Dict with keys: timestamp, hostname, process, pid, message,
                           source_ip, username, port, raw_line, source, line_num
            None if line couldn't be parsed
        """
        match = self.SYSLOG_PATTERN.match(line)
        if not match:
            # Return a minimal event for unrecognized formats
            return {
                "timestamp": datetime.now().isoformat(),
                "hostname": "unknown",
                "process": "unknown",
                "pid": None,
                "message": line,
                "source_ip": self._extract_ip(line),
                "username": self._extract_user(line),
                "port": self._extract_port(line),
                "raw_line": line,
                "source": source_name,
                "line_num": line_num
            }

        # Build timestamp (syslog doesn't include year)
        try:
            ts_str = f"{match.group('month')} {match.group('day')} {match.group('time')} {self._current_year}"
            timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
        except ValueError:
            timestamp = datetime.now()

        message = match.group("message")

        return {
            "timestamp": timestamp.isoformat(),
            "hostname": match.group("hostname"),
            "process": match.group("process"),
            "pid": match.group("pid"),
            "message": message,
            "source_ip": self._extract_ip(message),
            "username": self._extract_user(message),
            "port": self._extract_port(message),
            "raw_line": line,
            "source": source_name,
            "line_num": line_num
        }

    def _extract_ip(self, text: str) -> Optional[str]:
        """Extract source IP address from log message."""
        for pattern in self.IP_PATTERNS:
            match = pattern.search(text)
            if match:
                return match.group("ip")
        return None

    def _extract_user(self, text: str) -> Optional[str]:
        """Extract username from log message."""
        for pattern in self.USER_PATTERNS:
            match = pattern.search(text)
            if match:
                user = match.group("user")
                # Filter out non-usernames
                if user not in ("from", "on", "for", "port", "(", ")"):
                    return user
        return None

    def _extract_port(self, text: str) -> Optional[int]:
        """Extract port number from log message."""
        match = self.PORT_PATTERN.search(text)
        if match:
            return int(match.group("port"))
        return None

    def _is_whitelisted(self, event: Dict) -> bool:
        """Check if event should be skipped due to whitelist."""
        if event.get("source_ip") in self.whitelist.get("ips", []):
            return True
        if event.get("username") in self.whitelist.get("users", []):
            return True
        return False
