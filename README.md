# 🛡️ Custom Log-Based Intrusion Detection System (IDS)

A lightweight, Python-based Intrusion Detection System that monitors Linux authentication logs and syslogs for brute-force attacks, privilege escalation attempts, and reconnaissance activity. Generates structured, MITRE ATT&CK-mapped alerts with optional SIEM forwarding to Splunk, ELK, or Syslog.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Detection Rules](#detection-rules)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Alert Output](#alert-output)
- [SIEM Integration](#siem-integration)
- [Configuration](#configuration)
- [Sample Output](#sample-output)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

Security Operations Centers (SOCs) rely on detection engineering to identify threats in real time. This project implements a **custom IDS** that:

1. **Parses** Linux log files (`auth.log`, `syslog`) into structured events
2. **Correlates** events using configurable threshold and time-window logic
3. **Detects** brute-force, credential stuffing, privilege escalation, and reconnaissance patterns
4. **Generates** structured JSON alerts mapped to the MITRE ATT&CK framework
5. **Forwards** alerts to a SIEM (Splunk HEC, Elasticsearch, or Syslog)

It ships with realistic sample logs containing embedded attack scenarios, making it ready to run out of the box for learning, testing, or demonstration purposes.

---

## Features

| Feature | Description |
|---------|-------------|
| **6 Detection Rules** | SSH brute-force, password spraying, root login, sudo abuse, port scan indicators, session anomalies |
| **MITRE ATT&CK Mapping** | Every alert includes tactic, technique ID, and technique name |
| **Threshold + Time-Window Correlation** | Sliding window engine groups events by source IP and applies configurable thresholds |
| **IP & User Whitelisting** | Reduce false positives by whitelisting trusted IPs and service accounts |
| **Multiple Output Formats** | JSON, CEF (ArcSight), and flat log files |
| **SIEM Forwarding** | Built-in connectors for Splunk (HEC), Elasticsearch, and generic Syslog (UDP/TCP) |
| **Continuous Monitoring Mode** | Tail-mode file monitoring with configurable polling intervals |
| **Log Generator** | Built-in simulator generates realistic attack and benign traffic logs |
| **Log Rotation Handling** | Detects and recovers from log rotation during continuous monitoring |
| **Zero External Dependencies for Core** | Only `PyYAML` required; `requests` optional for HTTP-based SIEM forwarding |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        ids.py (Main)                         │
│              Orchestrator & CLI Entry Point                   │
└──────────┬───────────────┬──────────────────┬────────────────┘
           │               │                  │
           ▼               ▼                  ▼
   ┌──────────────┐ ┌─────────────┐  ┌───────────────┐
   │  Log Parser   │ │  Detection  │  │    Alert      │
   │              │ │   Engine    │  │   Manager     │
   │ • Syslog     │ │             │  │               │
   │ • auth.log   │ │ • Pattern   │  │ • Console     │
   │ • IP extract │ │   matching  │  │ • JSON file   │
   │ • User       │ │ • Threshold │  │ • Log file    │
   │   extract    │ │ • Time-     │  │ • CEF format  │
   │ • Whitelist  │ │   window    │  │               │
   │   filtering  │ │ • MITRE     │  │               │
   │              │ │   tagging   │  │               │
   └──────────────┘ └─────────────┘  └───────┬───────┘
                                              │
                                              ▼
                                     ┌───────────────┐
                                     │     SIEM      │
                                     │   Forwarder   │
                                     │               │
                                     │ • Splunk HEC  │
                                     │ • Elastic API │
                                     │ • Syslog UDP  │
                                     └───────────────┘
```

---

## Detection Rules

| # | Rule | Severity | Threshold | Window | MITRE ATT&CK |
|---|------|----------|-----------|--------|---------------|
| 1 | SSH Brute-Force | HIGH | 5 failed logins | 60s | T1110.001 — Password Guessing |
| 2 | Invalid User / Password Spraying | MEDIUM | 3 attempts | 120s | T1110.003 — Password Spraying |
| 3 | Sudo Abuse / Privilege Escalation | HIGH | 3 failures | 300s | T1548.003 — Sudo Caching |
| 4 | Port Scan Indicators | MEDIUM | 10 connections | 30s | T1046 — Network Service Discovery |
| 5 | Direct Root Login Attempts | CRITICAL | 1 attempt | 60s | T1078.003 — Local Accounts |
| 6 | Rapid Session Anomalies | LOW | 10 sessions | 60s | T1078 — Valid Accounts |

All rules are configurable in `config/ids_config.yaml`. Thresholds, time windows, severity, and patterns can be tuned without modifying code.

---

## Project Structure

```
Custom-Log-Based-Intrusion-Detection-System/
│
├── ids.py                          # Main entry point & CLI
├── requirements.txt                # Python dependencies
├── .gitignore
│
├── config/
│   └── ids_config.yaml             # Detection rules, SIEM settings, whitelists
│
├── modules/
│   ├── __init__.py
│   ├── config_loader.py            # YAML config parser with dot-notation access
│   ├── log_parser.py               # Parses auth.log/syslog into structured events
│   ├── detection_engine.py         # Threshold + time-window correlation engine
│   ├── alert_manager.py            # Console, JSON, CEF, and log output
│   ├── siem_forwarder.py           # Splunk HEC, ELK, Syslog connectors
│   └── log_generator.py            # Realistic attack log simulator
│
├── logs/
│   ├── sample_auth.log             # Pre-built auth.log with 6 attack scenarios
│   └── sample_syslog.log           # Firewall blocks + system events
│
└── alerts/
    └── .gitkeep                    # Alert output directory (JSON + logs)
```

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup

```bash
# Clone the repository
git clone https://github.com/mig-Rwa/Custom-Log-Based-Intrusion-Detection-System.git
cd Custom-Log-Based-Intrusion-Detection-System

# Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Linux/Mac
# .venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Single Pass Analysis (Default)

Analyzes the sample log files and prints all detected alerts:

```bash
python ids.py
```

### Continuous Monitoring Mode

Monitors log files in real time, checking for new entries at a configurable interval:

```bash
python ids.py --continuous
```

### Generate Fresh Sample Logs

Regenerate randomized attack + benign log data for testing:

```bash
python ids.py --generate-logs
```

### Custom Configuration

Point to a different config file:

```bash
python ids.py --config /path/to/custom_config.yaml
```

### All Options

```
usage: ids.py [-h] [--config CONFIG] [--continuous] [--generate-logs]

Custom Log-Based Intrusion Detection System

optional arguments:
  -h, --help            show this help message and exit
  --config, -c          Path to IDS configuration file
  --continuous, -m      Run in continuous monitoring mode
  --generate-logs, -g   Generate sample log files for testing
```

---

## Alert Output

### Console Output

Alerts are printed with ANSI color-coded severity:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🚨 ALERT: ssh_brute_force
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Severity    : HIGH
  Alert ID    : 4a22ee71-ca0
  Description : Detect SSH brute-force attempts (multiple failed logins)
  Source IP   : 203.0.113.50
  Target Users: admin
  Event Count : 8 (threshold: 5)
  Time Window : 60s
  First Seen  : 2026-03-01T02:14:01
  Last Seen   : 2026-03-01T02:14:15
  Hostname    : webserver

  MITRE ATT&CK:
    Tactic    : Credential Access
    Technique : T1110.001 — Brute Force: Password Guessing

  Evidence (sample):
    [1] Mar  1 02:14:01 webserver sshd[12001]: Failed password for admin...
    [2] Mar  1 02:14:03 webserver sshd[12001]: Failed password for admin...
    [3] Mar  1 02:14:05 webserver sshd[12002]: Failed password for admin...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### JSON File (`alerts/ids_alerts.json`)

```json
{
  "alert_id": "4a22ee71-ca0",
  "timestamp": "2026-03-01T20:03:22.544",
  "rule_name": "ssh_brute_force",
  "severity": "HIGH",
  "source_ip": "203.0.113.50",
  "target_users": ["admin"],
  "event_count": 8,
  "mitre_attack": {
    "tactic": "Credential Access",
    "technique_id": "T1110.001",
    "technique_name": "Brute Force: Password Guessing"
  },
  "evidence": ["..."]
}
```

### Event Log (`alerts/ids_events.log`)

One-line-per-alert format for easy `grep` and log aggregation:

```
[2026-03-01T20:03:22] [HIGH] rule=ssh_brute_force src_ip=203.0.113.50 users=admin count=8 mitre=T1110.001
```

---

## SIEM Integration

### Splunk (HTTP Event Collector)

1. In Splunk, go to **Settings → Data Inputs → HTTP Event Collector**
2. Create a new token with index `security`
3. Update `config/ids_config.yaml`:

```yaml
siem:
  enabled: true
  type: "splunk"
  splunk:
    hec_url: "https://YOUR-SPLUNK:8088/services/collector/event"
    hec_token: "YOUR-HEC-TOKEN"
    index: "security"
    sourcetype: "custom_ids"
```

### Elasticsearch (ELK Stack)

```yaml
siem:
  enabled: true
  type: "elk"
  elk:
    elasticsearch_url: "http://YOUR-ELK:9200"
    index: "ids-alerts"
    api_key: "YOUR-API-KEY"
```

### Generic Syslog (UDP/TCP)

```yaml
siem:
  enabled: true
  type: "generic_syslog"
  generic_syslog:
    host: "YOUR-SYSLOG-SERVER"
    port: 514
    protocol: "udp"
```

---

## Configuration

All configuration lives in `config/ids_config.yaml`. Key sections:

| Section | Purpose |
|---------|---------|
| `general` | Monitor interval, log format, timezone |
| `log_sources` | Paths to log files (sample or live) |
| `detection_rules` | Rule definitions: patterns, thresholds, time windows, severity, MITRE mapping |
| `alerting` | Output file paths, console toggle, alert format |
| `siem` | SIEM type, connection details, credentials |
| `whitelist` | Trusted IPs and usernames to exclude from detection |

### Pointing to Live Logs (Linux)

```yaml
log_sources:
  auth_log: "/var/log/auth.log"
  syslog: "/var/log/syslog"
```

### Adding a Custom Detection Rule

```yaml
detection_rules:
  my_custom_rule:
    enabled: true
    description: "Detect something suspicious"
    threshold: 3
    time_window: 120
    severity: "HIGH"
    patterns:
      - "your regex pattern here"
    mitre_attack:
      tactic: "Initial Access"
      technique: "T1190"
      name: "Exploit Public-Facing Application"
```

---

## Sample Output

Running `python ids.py` against the included sample logs produces:

| Severity | Rule | Source IP | MITRE Technique |
|----------|------|-----------|-----------------|
| 🔴 CRITICAL | Root Login Attempts | 45.33.32.156 | T1078.003 |
| 🟠 HIGH | SSH Brute-Force (admin) | 203.0.113.50 | T1110.001 |
| 🟠 HIGH | SSH Brute-Force (root) | 45.33.32.156 | T1110.001 |
| 🟡 MEDIUM | Password Spraying | 198.51.100.23 | T1110.003 |
| 🟡 MEDIUM | Port Scan Indicators | 192.0.2.100 | T1046 |
| 🔵 LOW | Session Anomaly | — | T1078 |

---

## Roadmap

- [ ] GeoIP enrichment for source IP addresses
- [ ] Email / Slack / Webhook alert notifications
- [ ] Dashboard (Flask/Streamlit) for alert visualization
- [ ] PCAP / Zeek log parsing support
- [ ] Sigma rule format import
- [ ] Automated threat intelligence feed integration
- [ ] Docker container deployment

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- [MITRE ATT&CK Framework](https://attack.mitre.org/) for threat classification
- Linux `auth.log` and `syslog` standards
- The open-source cybersecurity community

---

> **Built for learning, testing, and detection engineering practice.**
> Deploy responsibly and only monitor systems you own or have authorization to monitor.
