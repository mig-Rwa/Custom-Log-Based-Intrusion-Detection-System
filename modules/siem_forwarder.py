"""
SIEM Forwarder
==============
Forwards IDS alerts to a SIEM platform.
Supports: Splunk (HEC), ELK (Elasticsearch), and generic Syslog.
"""

import json
import socket
import ssl
from datetime import datetime
from typing import Dict, Optional

# Optional imports — graceful degradation if not installed
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class SIEMForwarder:
    """Forwards structured alerts to a SIEM (Splunk, ELK, or Syslog)."""

    def __init__(self, config):
        self.config = config
        self.siem_type = config.get("siem.type", "splunk")
        self.stats = {"sent": 0, "failed": 0}

        if self.siem_type in ("splunk", "elk") and not HAS_REQUESTS:
            print("    [WARN] 'requests' package not installed. SIEM HTTP forwarding disabled.")
            print("           Install with: pip install requests")
            self.enabled = False
        else:
            self.enabled = True
            print(f"    ✓ SIEM forwarder ready ({self.siem_type})")

    def forward(self, alert: Dict) -> bool:
        """
        Forward an alert to the configured SIEM.

        Args:
            alert: Alert dictionary from DetectionEngine

        Returns:
            True if successfully forwarded, False otherwise
        """
        if not self.enabled:
            return False

        try:
            if self.siem_type == "splunk":
                return self._forward_splunk(alert)
            elif self.siem_type == "elk":
                return self._forward_elk(alert)
            elif self.siem_type == "generic_syslog":
                return self._forward_syslog(alert)
            else:
                print(f"[WARN] Unknown SIEM type: {self.siem_type}")
                return False
        except Exception as e:
            self.stats["failed"] += 1
            print(f"[WARN] SIEM forward failed: {e}")
            return False

    # ── Splunk HEC ──────────────────────────────────────

    def _forward_splunk(self, alert: Dict) -> bool:
        """
        Forward alert to Splunk via HTTP Event Collector (HEC).

        HEC Endpoint: POST /services/collector/event
        Payload: {"event": alert_data, "sourcetype": "custom_ids", "index": "security"}
        """
        hec_url = self.config.get("siem.splunk.hec_url")
        hec_token = self.config.get("siem.splunk.hec_token")
        index = self.config.get("siem.splunk.index", "main")
        sourcetype = self.config.get("siem.splunk.sourcetype", "custom_ids")
        verify_ssl = self.config.get("siem.splunk.verify_ssl", False)

        if not hec_url or not hec_token:
            print("[WARN] Splunk HEC URL or token not configured")
            return False

        payload = {
            "event": alert,
            "sourcetype": sourcetype,
            "index": index,
            "time": datetime.now().timestamp(),
            "host": alert.get("hostname", "ids-sensor")
        }

        headers = {
            "Authorization": f"Splunk {hec_token}",
            "Content-Type": "application/json"
        }

        resp = requests.post(
            hec_url,
            headers=headers,
            data=json.dumps(payload, default=str),
            verify=verify_ssl,
            timeout=10
        )

        if resp.status_code == 200:
            self.stats["sent"] += 1
            return True
        else:
            self.stats["failed"] += 1
            print(f"[WARN] Splunk HEC returned {resp.status_code}: {resp.text}")
            return False

    # ── Elasticsearch (ELK) ─────────────────────────────

    def _forward_elk(self, alert: Dict) -> bool:
        """
        Forward alert to Elasticsearch.

        Endpoint: POST /<index>/_doc
        """
        es_url = self.config.get("siem.elk.elasticsearch_url")
        index = self.config.get("siem.elk.index", "ids-alerts")
        api_key = self.config.get("siem.elk.api_key", "")

        if not es_url:
            print("[WARN] Elasticsearch URL not configured")
            return False

        url = f"{es_url}/{index}/_doc"

        # Add @timestamp for Kibana
        alert_payload = {**alert, "@timestamp": datetime.now().isoformat()}

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"

        resp = requests.post(
            url,
            headers=headers,
            data=json.dumps(alert_payload, default=str),
            timeout=10
        )

        if resp.status_code in (200, 201):
            self.stats["sent"] += 1
            return True
        else:
            self.stats["failed"] += 1
            print(f"[WARN] Elasticsearch returned {resp.status_code}: {resp.text}")
            return False

    # ── Generic Syslog (UDP/TCP) ────────────────────────

    def _forward_syslog(self, alert: Dict) -> bool:
        """
        Forward alert as a syslog message (RFC 5424 format).
        Supports UDP and TCP.
        """
        host = self.config.get("siem.generic_syslog.host", "localhost")
        port = self.config.get("siem.generic_syslog.port", 514)
        protocol = self.config.get("siem.generic_syslog.protocol", "udp")

        # Map severity to syslog priority
        severity_map = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 5, "INFO": 6}
        sev = severity_map.get(alert.get("severity", "MEDIUM"), 4)
        facility = 10  # security/auth
        priority = facility * 8 + sev

        mitre = alert.get("mitre_attack", {})
        syslog_msg = (
            f"<{priority}>1 {datetime.now().isoformat()} "
            f"{alert.get('hostname', 'ids-sensor')} CustomIDS - - - "
            f"rule=\"{alert.get('rule_name', '')}\" "
            f"severity=\"{alert.get('severity', '')}\" "
            f"src_ip=\"{alert.get('source_ip', '')}\" "
            f"users=\"{','.join(alert.get('target_users', []))}\" "
            f"count={alert.get('event_count', 0)} "
            f"mitre_technique=\"{mitre.get('technique_id', '')}\" "
            f"alert_id=\"{alert.get('alert_id', '')}\""
        )

        if protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(syslog_msg.encode("utf-8"), (host, port))
            sock.close()
        elif protocol == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            sock.sendall(syslog_msg.encode("utf-8") + b"\n")
            sock.close()

        self.stats["sent"] += 1
        return True

    def get_stats(self) -> Dict:
        """Return forwarding statistics."""
        return {
            "siem_type": self.siem_type,
            "enabled": self.enabled,
            "sent": self.stats["sent"],
            "failed": self.stats["failed"]
        }
