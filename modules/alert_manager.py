"""
Alert Manager
=============
Handles alert output — console display, JSON file writing, and log file output.
Supports multiple alert formats: JSON, CEF (Common Event Format), LEEF.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List


# ── Severity color codes (ANSI) ──
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m\033[1m",  # Bold Red
    "HIGH":     "\033[91m",          # Red
    "MEDIUM":   "\033[93m",          # Yellow
    "LOW":      "\033[94m",          # Blue
    "INFO":     "\033[90m",          # Grey
}
RESET = "\033[0m"


class AlertManager:
    """Manages alert output to console, JSON files, and log files."""

    def __init__(self, config):
        self.config = config
        self.alerts: List[Dict] = []

        # Output settings
        self.output_file = config.get("alerting.output_file", "alerts/ids_alerts.json")
        self.log_file = config.get("alerting.log_file", "alerts/ids_events.log")
        self.console_output = config.get("alerting.console_output", True)
        self.alert_format = config.get("alerting.alert_format", "json")

        # Create output directories
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

        print(f"    ✓ Alert output: {self.output_file}")

    def process_alert(self, alert: Dict):
        """
        Process a single alert: store it and display on console.

        Args:
            alert: Alert dictionary from DetectionEngine
        """
        self.alerts.append(alert)

        if self.console_output:
            self._print_alert(alert)

        # Append to log file immediately
        self._append_to_log(alert)

    def _print_alert(self, alert: Dict):
        """Print a formatted alert to the console."""
        severity = alert.get("severity", "MEDIUM")
        color = SEVERITY_COLORS.get(severity, "")

        print(f"\n{color}{'━'*60}")
        print(f"  🚨 ALERT: {alert.get('rule_name', 'Unknown Rule')}")
        print(f"{'━'*60}{RESET}")
        print(f"  Severity    : {color}{severity}{RESET}")
        print(f"  Alert ID    : {alert.get('alert_id', 'N/A')}")
        print(f"  Description : {alert.get('description', 'N/A')}")
        print(f"  Source IP   : {alert.get('source_ip', 'N/A')}")
        print(f"  Target Users: {', '.join(alert.get('target_users', [])) or 'N/A'}")
        print(f"  Event Count : {alert.get('event_count', 0)} "
              f"(threshold: {alert.get('threshold', 'N/A')})")
        print(f"  Time Window : {alert.get('time_window', 'N/A')}s")
        print(f"  First Seen  : {alert.get('first_seen', 'N/A')}")
        print(f"  Last Seen   : {alert.get('last_seen', 'N/A')}")
        print(f"  Hostname    : {alert.get('hostname', 'N/A')}")

        mitre = alert.get("mitre_attack", {})
        print(f"\n  MITRE ATT&CK:")
        print(f"    Tactic    : {mitre.get('tactic', 'N/A')}")
        print(f"    Technique : {mitre.get('technique_id', 'N/A')} — "
              f"{mitre.get('technique_name', 'N/A')}")

        evidence = alert.get("evidence", [])
        if evidence:
            print(f"\n  Evidence (sample):")
            for i, line in enumerate(evidence[:3], 1):
                print(f"    [{i}] {line[:120]}")

        print(f"{color}{'━'*60}{RESET}\n")

    def _append_to_log(self, alert: Dict):
        """Append a one-line log entry for the alert."""
        try:
            log_line = (
                f"[{alert.get('timestamp', '')}] "
                f"[{alert.get('severity', 'MEDIUM')}] "
                f"rule={alert.get('rule_name', '')} "
                f"src_ip={alert.get('source_ip', '')} "
                f"users={','.join(alert.get('target_users', []))} "
                f"count={alert.get('event_count', 0)} "
                f"mitre={alert.get('mitre_attack', {}).get('technique_id', 'N/A')} "
                f"alert_id={alert.get('alert_id', '')}"
            )
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")
        except IOError as e:
            print(f"[WARN] Could not write to log file: {e}")

    def flush(self):
        """Write all accumulated alerts to the JSON output file."""
        if not self.alerts:
            return

        # Load existing alerts if file exists
        existing = []
        if os.path.exists(self.output_file):
            try:
                with open(self.output_file, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except (json.JSONDecodeError, IOError):
                existing = []

        # Merge and write
        all_alerts = existing + self.alerts
        try:
            with open(self.output_file, "w", encoding="utf-8") as f:
                json.dump(all_alerts, f, indent=2, default=str)
        except IOError as e:
            print(f"[ERROR] Could not write alerts file: {e}")

        count = len(self.alerts)
        self.alerts = []  # Clear buffer
        return count

    def to_cef(self, alert: Dict) -> str:
        """Convert alert to ArcSight CEF (Common Event Format) string."""
        mitre = alert.get("mitre_attack", {})
        severity_map = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3, "INFO": 1}
        sev = severity_map.get(alert.get("severity", "MEDIUM"), 5)

        return (
            f"CEF:0|CustomIDS|LogIDS|1.0|{alert.get('rule_name', '')}|"
            f"{alert.get('description', '')}|{sev}|"
            f"src={alert.get('source_ip', '')} "
            f"duser={','.join(alert.get('target_users', []))} "
            f"cnt={alert.get('event_count', 0)} "
            f"cs1={mitre.get('technique_id', '')} "
            f"cs1Label=MITRE_Technique"
        )

    def get_summary(self) -> Dict:
        """Get a summary of alerts by severity and rule."""
        summary = {
            "total_alerts": len(self.alerts),
            "by_severity": {},
            "by_rule": {},
            "unique_source_ips": set()
        }
        for alert in self.alerts:
            sev = alert.get("severity", "MEDIUM")
            rule = alert.get("rule_name", "unknown")
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
            summary["by_rule"][rule] = summary["by_rule"].get(rule, 0) + 1
            summary["unique_source_ips"].add(alert.get("source_ip", ""))

        summary["unique_source_ips"] = list(summary["unique_source_ips"])
        return summary
