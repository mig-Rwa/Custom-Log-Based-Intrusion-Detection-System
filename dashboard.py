"""
IDS Web Dashboard
=================
Flask-based browser dashboard for the Custom Log-Based IDS.
Serves a real-time SOC-style interface at http://localhost:5000

Features:
  - Live alert feed with severity color-coding
  - Stats cards: Total, Critical, High, Medium, Low
  - Charts: Severity distribution, Top attacking IPs, Alerts over time
  - Searchable & filterable alert table
  - Run a fresh IDS scan from the browser
  - Auto-refreshes every 5 seconds
"""

import csv
import io
import json
import os
import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter, defaultdict

from flask import Flask, render_template, jsonify, request, Response

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from modules.config_loader import ConfigLoader
from modules.log_parser import LogParser
from modules.detection_engine import DetectionEngine
from modules.alert_manager import AlertManager

# ── App setup ────────────────────────────────────────────────
app = Flask(__name__)

CONFIG_PATH = PROJECT_ROOT / "config" / "ids_config.yaml"
ALERTS_FILE = PROJECT_ROOT / "alerts" / "ids_alerts.json"

# Global scan lock so multiple browser clicks don't run scans simultaneously
scan_lock = threading.Lock()
last_scan_time = None


# ── Helpers ──────────────────────────────────────────────────

def load_alerts():
    """Load all alerts from the JSON output file."""
    if not ALERTS_FILE.exists():
        return []
    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []


def compute_stats(alerts):
    """Compute summary statistics from alert list."""
    severity_counts = Counter(a.get("severity", "UNKNOWN") for a in alerts)
    rule_counts = Counter(a.get("rule_name", "unknown") for a in alerts)
    ip_counts = Counter(
        a.get("source_ip", "unknown") for a in alerts
        if a.get("source_ip") and a.get("source_ip") != "unknown"
    )

    # Alerts over time — group by hour
    time_buckets = defaultdict(int)
    for alert in alerts:
        try:
            ts = datetime.fromisoformat(alert["timestamp"])
            bucket = ts.strftime("%Y-%m-%d %H:00")
            time_buckets[bucket] += 1
        except (KeyError, ValueError):
            pass

    # Sort time buckets and take last 24
    sorted_buckets = sorted(time_buckets.items())[-24:]

    return {
        "total": len(alerts),
        "critical": severity_counts.get("CRITICAL", 0),
        "high": severity_counts.get("HIGH", 0),
        "medium": severity_counts.get("MEDIUM", 0),
        "low": severity_counts.get("LOW", 0),
        "by_severity": dict(severity_counts),
        "top_ips": dict(ip_counts.most_common(8)),
        "top_rules": dict(rule_counts.most_common(6)),
        "over_time_labels": [b[0] for b in sorted_buckets],
        "over_time_values": [b[1] for b in sorted_buckets],
    }


def run_ids_scan():
    """Run a full IDS scan and return number of new alerts generated."""
    global last_scan_time
    config = ConfigLoader(str(CONFIG_PATH))
    parser = LogParser(config)
    engine = DetectionEngine(config)
    alert_mgr = AlertManager(config)

    log_sources = config.get("log_sources", {})
    total_new = 0

    for source_name, log_path in log_sources.items():
        if not os.path.exists(log_path):
            continue
        events = parser.parse_file(log_path, source_name)
        alerts = engine.analyze(events)
        total_new += len(alerts)
        for alert in alerts:
            alert_mgr.process_alert(alert)

    alert_mgr.flush()
    last_scan_time = datetime.now().isoformat()
    return total_new


# ── Routes ───────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    """Return all alerts, optionally filtered by severity or rule."""
    alerts = load_alerts()

    severity_filter = request.args.get("severity", "").upper()
    rule_filter = request.args.get("rule", "")
    search = request.args.get("search", "").lower()
    limit = int(request.args.get("limit", 200))

    if severity_filter:
        alerts = [a for a in alerts if a.get("severity") == severity_filter]
    if rule_filter:
        alerts = [a for a in alerts if a.get("rule_name") == rule_filter]
    if search:
        alerts = [
            a for a in alerts
            if search in json.dumps(a).lower()
        ]

    # Most recent first
    alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
    return jsonify(alerts[:limit])


@app.route("/api/stats")
def api_stats():
    """Return summary statistics for dashboard cards and charts."""
    alerts = load_alerts()
    stats = compute_stats(alerts)
    stats["last_scan"] = last_scan_time
    return jsonify(stats)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Trigger a fresh IDS scan. Returns number of new alerts."""
    if not scan_lock.acquire(blocking=False):
        return jsonify({"status": "busy", "message": "Scan already running"}), 429

    try:
        new_alerts = run_ids_scan()
        return jsonify({
            "status": "ok",
            "new_alerts": new_alerts,
            "scanned_at": last_scan_time
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        scan_lock.release()


@app.route("/api/rules")
def api_rules():
    """Return list of all enabled rule names."""
    config = ConfigLoader(str(CONFIG_PATH))
    rules = config.get_rules()
    return jsonify(list(rules.keys()))


@app.route("/api/alerts/clear", methods=["POST"])
def api_clear():
    """Clear all saved alerts (reset for a clean run)."""
    try:
        with open(ALERTS_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)
        return jsonify({"status": "ok", "message": "All alerts cleared"})
    except IOError as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/alerts/export")
def api_export():
    """Export alerts as a downloadable CSV file (optionally filtered)."""
    alerts = load_alerts()

    severity_filter = request.args.get("severity", "").upper()
    rule_filter = request.args.get("rule", "")
    search = request.args.get("search", "").lower()

    if severity_filter:
        alerts = [a for a in alerts if a.get("severity") == severity_filter]
    if rule_filter:
        alerts = [a for a in alerts if a.get("rule_name") == rule_filter]
    if search:
        alerts = [a for a in alerts if search in json.dumps(a).lower()]

    alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)

    columns = [
        "timestamp", "severity", "rule_name", "description",
        "source_ip", "event_count", "mitre_tactic",
        "mitre_technique_id", "mitre_technique_name",
    ]

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    for a in alerts:
        mitre = a.get("mitre_attack", {}) or {}
        writer.writerow([
            a.get("timestamp", ""),
            a.get("severity", ""),
            a.get("rule_name", ""),
            a.get("description", ""),
            a.get("source_ip", ""),
            a.get("event_count", ""),
            mitre.get("tactic", ""),
            mitre.get("technique_id", ""),
            mitre.get("technique_name", ""),
        ])

    filename = f"ids_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── Entry point ──────────────────────────────────────────────

def run_dashboard(host: str = "127.0.0.1", port: int = 5000, initial_scan: bool = True):
    """Start the web dashboard.

    Args:
        host: Interface to bind to. Defaults to 127.0.0.1 (localhost only)
              for safety. Use "0.0.0.0" to expose it on your network.
        port: TCP port to serve on.
        initial_scan: Run a scan on startup so the dashboard isn't empty.
    """
    if initial_scan:
        print("\n[*] Running initial IDS scan...")
        try:
            count = run_ids_scan()
            print(f"[*] Initial scan complete — {count} alerts detected")
        except Exception as e:
            print(f"[!] Initial scan failed: {e}")

    display_host = "localhost" if host in ("127.0.0.1", "0.0.0.0") else host
    print(f"\n[*] Starting dashboard at http://{display_host}:{port}")
    if host == "0.0.0.0":
        print("[!] Warning: bound to 0.0.0.0 — reachable by other devices on your network")
    print("[*] Press CTRL+C to stop\n")
    app.run(debug=False, host=host, port=port)


if __name__ == "__main__":
    import argparse

    cli = argparse.ArgumentParser(description="IDS Web Dashboard")
    cli.add_argument("--host", default="127.0.0.1",
                     help="Interface to bind to (default: 127.0.0.1; use 0.0.0.0 to expose)")
    cli.add_argument("--port", type=int, default=5000, help="Port to serve on (default: 5000)")
    cli.add_argument("--no-scan", action="store_true",
                     help="Skip the initial scan on startup")
    dash_args = cli.parse_args()

    run_dashboard(host=dash_args.host, port=dash_args.port,
                  initial_scan=not dash_args.no_scan)
