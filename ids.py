"""
Custom Log-Based Intrusion Detection System (IDS)
==================================================
Main detection engine that monitors Linux logs for brute-force patterns,
privilege escalation attempts, and suspicious activity, then generates
structured alerts and optionally forwards them to a SIEM.

Author: SOC Analyst Lab Project
Date: March 2026
MITRE ATT&CK Mapped Detections
"""

import time
import signal
import sys
import os
import argparse
from pathlib import Path
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

# Ensure UTF-8 console output so banners, checkmarks, and emoji render
# correctly even when stdout/stderr are redirected to a file or pipe
# (Windows defaults to cp1252, which crashes on these characters).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

from modules.config_loader import ConfigLoader
from modules.log_parser import LogParser
from modules.detection_engine import DetectionEngine
from modules.alert_manager import AlertManager
from modules.siem_forwarder import SIEMForwarder

# ── Banner ──────────────────────────────────────────────
BANNER = r"""
  ╔══════════════════════════════════════════════════╗
  ║   CUSTOM LOG-BASED INTRUSION DETECTION SYSTEM    ║
  ║          Brute-Force & Threat Detector            ║
  ║         MITRE ATT&CK Mapped Alerts               ║
  ╚══════════════════════════════════════════════════╝
"""

class IntrusionDetectionSystem:
    """Main IDS orchestrator — ties all modules together."""

    def __init__(self, config_path: str, overrides: dict = None):
        self.running = False
        self.stats = {
            "start_time": None,
            "lines_processed": 0,
            "alerts_generated": 0,
            "detection_cycles": 0
        }

        # Load configuration
        print("[*] Loading configuration...")
        self.config = ConfigLoader(config_path)

        # Apply CLI flag overrides before modules read the config
        if overrides:
            for key, value in overrides.items():
                self.config.set(key, value)
                print(f"[*] Config override: {key} = {value}")

        # Initialize modules
        print("[*] Initializing log parser...")
        self.parser = LogParser(self.config)

        print("[*] Initializing detection engine...")
        self.detection = DetectionEngine(self.config)

        print("[*] Initializing alert manager...")
        self.alert_manager = AlertManager(self.config)

        # Initialize SIEM forwarder if enabled
        self.siem = None
        if self.config.get("siem.enabled", False):
            print("[*] Initializing SIEM forwarder...")
            self.siem = SIEMForwarder(self.config)
        else:
            print("[*] SIEM forwarding disabled (enable in config)")

        # Register signal handlers for graceful shutdown.
        # SIGTERM is not available on all platforms (e.g. Windows), so
        # register each handler defensively to stay cross-platform.
        for sig_name in ("SIGINT", "SIGTERM"):
            sig = getattr(signal, sig_name, None)
            if sig is not None:
                try:
                    signal.signal(sig, self._shutdown_handler)
                except (ValueError, OSError):
                    # Not supported in this context (e.g. non-main thread)
                    pass

    def _shutdown_handler(self, signum, frame):
        """Handle graceful shutdown on CTRL+C."""
        print("\n[!] Shutdown signal received. Stopping IDS...")
        self.running = False

    def _print_stats(self):
        """Print detection statistics."""
        elapsed = (datetime.now() - self.stats["start_time"]).total_seconds()
        print(f"\n{'='*55}")
        print(f"  IDS SESSION STATISTICS")
        print(f"{'='*55}")
        print(f"  Runtime           : {elapsed:.1f} seconds")
        print(f"  Lines Processed   : {self.stats['lines_processed']}")
        print(f"  Alerts Generated  : {self.stats['alerts_generated']}")
        print(f"  Detection Cycles  : {self.stats['detection_cycles']}")
        print(f"{'='*55}\n")

    def run_once(self):
        """Run a single detection pass on all configured log files.

        Returns an exit code: 0 on success, 2 if no configured log
        source could be found (useful for scripting/automation).
        """
        print(BANNER)
        print(f"[*] Running single detection pass at {datetime.now().isoformat()}")
        self.stats["start_time"] = datetime.now()

        log_sources = self.config.get("log_sources", {})
        sources_found = 0

        for source_name, log_path in log_sources.items():
            if not os.path.exists(log_path):
                print(f"[!] Log file not found: {log_path} — skipping")
                continue
            sources_found += 1

            print(f"\n[*] Parsing {source_name}: {log_path}")
            parsed_events = self.parser.parse_file(log_path, source_name)
            self.stats["lines_processed"] += len(parsed_events)
            print(f"    → Parsed {len(parsed_events)} log events")

            # Run detection rules
            alerts = self.detection.analyze(parsed_events)
            self.stats["alerts_generated"] += len(alerts)

            if alerts:
                print(f"    → 🚨 {len(alerts)} ALERTS triggered!")
                for alert in alerts:
                    self.alert_manager.process_alert(alert)
                    if self.siem:
                        self.siem.forward(alert)
            else:
                print(f"    → ✅ No threats detected")

        self.stats["detection_cycles"] += 1
        self._print_stats()

        # Write alerts to file
        self.alert_manager.flush()
        print(f"[*] Alerts saved to: {self.config.get('alerting.output_file')}")

        if sources_found == 0:
            print("[!] No log sources were found — check your config or --source path.")
            return 2
        return 0

    def run_continuous(self):
        """Run IDS in continuous monitoring mode."""
        print(BANNER)
        interval = self.config.get("general.monitor_interval", 5)
        print(f"[*] Starting continuous monitoring (interval: {interval}s)")
        print(f"[*] Press CTRL+C to stop\n")

        self.running = True
        self.stats["start_time"] = datetime.now()

        # Track file positions for tail-mode reading
        file_positions = {}
        log_sources = self.config.get("log_sources", {})

        for source_name, log_path in log_sources.items():
            if os.path.exists(log_path):
                file_positions[source_name] = 0  # start from beginning first time
            else:
                print(f"[!] Log file not found: {log_path}")

        while self.running:
            cycle_alerts = 0

            for source_name, log_path in log_sources.items():
                if not os.path.exists(log_path):
                    continue

                # Pick up log files that appeared after startup
                if source_name not in file_positions:
                    print(f"[*] Log file now available: {log_path}")
                    file_positions[source_name] = 0

                # Read new lines since last position
                current_pos = file_positions.get(source_name, 0)
                parsed_events, new_pos = self.parser.parse_file_from_position(
                    log_path, source_name, current_pos
                )
                file_positions[source_name] = new_pos
                self.stats["lines_processed"] += len(parsed_events)

                if parsed_events:
                    alerts = self.detection.analyze(parsed_events)
                    self.stats["alerts_generated"] += len(alerts)
                    cycle_alerts += len(alerts)

                    for alert in alerts:
                        self.alert_manager.process_alert(alert)
                        if self.siem:
                            self.siem.forward(alert)

            self.stats["detection_cycles"] += 1

            if cycle_alerts > 0:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 {cycle_alerts} alerts | "
                      f"Cycle #{self.stats['detection_cycles']}")
                self.alert_manager.flush()
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Clear | "
                      f"Cycle #{self.stats['detection_cycles']}", end='\r')

            time.sleep(interval)

        # Shutdown
        self.alert_manager.flush()
        self._print_stats()
        print("[*] IDS stopped. Goodbye.")


def main():
    parser = argparse.ArgumentParser(
        description="Custom Log-Based Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ids.py                          # Single pass with default config
  python ids.py --continuous             # Continuous monitoring mode
  python ids.py --config custom.yaml     # Use custom config file
  python ids.py --generate-logs          # Generate sample logs for testing
  python ids.py --source /var/log/auth.log   # Scan one ad-hoc log file
  python ids.py --interval 10 -m         # Continuous mode, poll every 10s
  python ids.py --output alerts/run1.json    # Redirect alert output file
        """
    )
    parser.add_argument(
        "--config", "-c",
        default=os.path.join(PROJECT_ROOT, "config", "ids_config.yaml"),
        help="Path to IDS configuration file"
    )
    parser.add_argument(
        "--continuous", "-m",
        action="store_true",
        help="Run in continuous monitoring mode"
    )
    parser.add_argument(
        "--generate-logs", "-g",
        action="store_true",
        help="Generate sample log files for testing"
    )
    parser.add_argument(
        "--interval", "-i",
        type=int,
        default=None,
        help="Polling interval in seconds for continuous mode (overrides config)"
    )
    parser.add_argument(
        "--source", "-s",
        default=None,
        help="Scan a single ad-hoc log file instead of the configured sources"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Path to write alert output (overrides config alerting.output_file)"
    )

    args = parser.parse_args()

    # Generate sample logs if requested
    if args.generate_logs:
        from modules.log_generator import LogGenerator
        generator = LogGenerator()
        generator.generate_all()
        print("[*] Sample logs generated in logs/ directory")
        return

    # Build CLI overrides so they apply before modules read the config
    overrides = {}
    if args.interval is not None:
        overrides["general.monitor_interval"] = args.interval
    if args.output is not None:
        overrides["alerting.output_file"] = args.output
    if args.source is not None:
        # Replace configured sources with the single ad-hoc file
        overrides["log_sources"] = {"adhoc": args.source}

    # Run IDS
    ids = IntrusionDetectionSystem(args.config, overrides=overrides)

    if args.continuous:
        ids.run_continuous()
        return 0
    else:
        return ids.run_once()


if __name__ == "__main__":
    sys.exit(main())
