"""
Detection Engine
================
Core rule-matching engine that analyzes parsed log events against
configured detection rules. Implements threshold-based correlation,
time-window grouping, and MITRE ATT&CK tagging.
"""

import re
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict
import uuid


class DetectionEngine:
    """
    Analyzes parsed log events against detection rules.
    Groups events by source IP, applies thresholds over time windows,
    and generates structured alerts with MITRE ATT&CK mappings.
    """

    def __init__(self, config):
        self.config = config
        self.rules = config.get_rules()
        self._compile_patterns()

        # Correlation state: tracks event counts per (rule, source_ip)
        # Format: { "rule_name:source_ip": [list of timestamps] }
        self.correlation_state = defaultdict(list)

        print(f"    ✓ Detection engine loaded with {len(self.rules)} rules")

    def _compile_patterns(self):
        """Pre-compile regex patterns for all rules for performance."""
        self._compiled_rules = {}
        for rule_name, rule in self.rules.items():
            patterns = rule.get("patterns", [])
            compiled = []
            for pattern in patterns:
                try:
                    compiled.append(re.compile(pattern, re.IGNORECASE))
                except re.error as e:
                    print(f"    [WARN] Invalid regex in rule '{rule_name}': {pattern} ({e})")
            self._compiled_rules[rule_name] = compiled

    def analyze(self, events: List[Dict]) -> List[Dict]:
        """
        Analyze a batch of parsed events against all detection rules.

        Args:
            events: List of parsed event dictionaries from LogParser

        Returns:
            List of alert dictionaries for events exceeding thresholds
        """
        # Step 1: Match events against rule patterns
        matched = self._match_events(events)

        # Step 2: Apply threshold/time-window correlation
        alerts = self._correlate(matched)

        return alerts

    def _match_events(self, events: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Match each event against all rule patterns.

        Returns:
            Dict mapping rule_name -> list of matching events
        """
        matches = defaultdict(list)

        for event in events:
            message = event.get("message", "")
            raw_line = event.get("raw_line", "")

            for rule_name, compiled_patterns in self._compiled_rules.items():
                for pattern in compiled_patterns:
                    if pattern.search(message) or pattern.search(raw_line):
                        matches[rule_name].append(event)
                        break  # one pattern match per rule per event is enough

        return dict(matches)

    def _correlate(self, matched: Dict[str, List[Dict]]) -> List[Dict]:
        """
        Apply threshold and time-window correlation to matched events.
        Groups by (rule, source_ip) and triggers alerts when thresholds are met.

        Uses a sliding window based on the events' OWN timestamps so that
        batch/file analysis works correctly (not just real-time).

        Returns:
            List of alert dicts
        """
        alerts = []

        for rule_name, events in matched.items():
            rule = self.rules[rule_name]
            threshold = rule.get("threshold", 1)
            time_window = rule.get("time_window", 60)  # seconds

            # Group events by source IP (or "unknown" if no IP)
            ip_groups = defaultdict(list)
            for event in events:
                source_ip = event.get("source_ip") or "unknown"
                ip_groups[source_ip].append(event)

            for source_ip, ip_events in ip_groups.items():
                # Parse timestamps from the events themselves
                timed_events = []
                for event in ip_events:
                    try:
                        ts = datetime.fromisoformat(event["timestamp"])
                    except (ValueError, KeyError):
                        ts = datetime.now()
                    timed_events.append((ts, event))

                # Sort by timestamp
                timed_events.sort(key=lambda x: x[0])

                # Sliding window: check if enough events fall within
                # any time_window-length window
                if len(timed_events) >= threshold:
                    # Simple approach: group all events and check total count
                    # For batch analysis, if we have >= threshold events for
                    # the same rule+IP, that's a detection
                    window_groups = self._find_window_clusters(
                        timed_events, time_window, threshold
                    )

                    for cluster_events in window_groups:
                        alert = self._build_alert(
                            rule_name, rule, source_ip,
                            [e for _, e in cluster_events],
                            len(cluster_events)
                        )
                        alerts.append(alert)

        return alerts

    def _find_window_clusters(self, timed_events, time_window, threshold):
        """
        Find clusters of events that exceed the threshold within a time window.
        Uses a sliding window approach over sorted timestamped events.

        Returns:
            List of event clusters (each cluster is a list of (timestamp, event) tuples)
        """
        clusters = []
        used = set()

        for i in range(len(timed_events)):
            if i in used:
                continue

            window_start = timed_events[i][0]
            window_end = window_start + timedelta(seconds=time_window)

            # Collect all events in this window
            cluster = []
            for j in range(i, len(timed_events)):
                if timed_events[j][0] <= window_end:
                    cluster.append(timed_events[j])
                else:
                    break

            if len(cluster) >= threshold:
                clusters.append(cluster)
                # Mark events as used so we don't double-count
                for j in range(i, i + len(cluster)):
                    if j < len(timed_events):
                        used.add(j)

        return clusters

    def _build_alert(
        self,
        rule_name: str,
        rule: Dict,
        source_ip: str,
        events: List[Dict],
        event_count: int
    ) -> Dict:
        """
        Build a structured alert dictionary.

        Returns:
            Alert dict with detection details, MITRE mapping, and evidence
        """
        mitre = rule.get("mitre_attack", {})

        # Collect unique usernames targeted
        target_users = list(set(
            e.get("username") for e in events if e.get("username")
        ))

        # Collect unique ports
        target_ports = list(set(
            e.get("port") for e in events if e.get("port")
        ))

        # Get first and last event timestamps
        timestamps = []
        for e in events:
            try:
                timestamps.append(datetime.fromisoformat(e["timestamp"]))
            except (ValueError, KeyError):
                pass

        first_seen = min(timestamps).isoformat() if timestamps else None
        last_seen = max(timestamps).isoformat() if timestamps else None

        # Collect sample evidence lines (max 5)
        evidence = [e.get("raw_line", "") for e in events[:5]]

        return {
            "alert_id": str(uuid.uuid4())[:12],
            "timestamp": datetime.now().isoformat(),
            "rule_name": rule_name,
            "description": rule.get("description", ""),
            "severity": rule.get("severity", "MEDIUM"),
            "source_ip": source_ip,
            "target_users": target_users,
            "target_ports": target_ports,
            "event_count": event_count,
            "threshold": rule.get("threshold", 1),
            "time_window": rule.get("time_window", 60),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "hostname": events[0].get("hostname", "unknown") if events else "unknown",
            "log_source": events[0].get("source", "unknown") if events else "unknown",
            "mitre_attack": {
                "tactic": mitre.get("tactic", "Unknown"),
                "technique_id": mitre.get("technique", "N/A"),
                "technique_name": mitre.get("name", "Unknown")
            },
            "evidence": evidence,
            "status": "NEW"
        }
