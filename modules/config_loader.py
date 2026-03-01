"""
Configuration Loader
====================
Loads and validates the YAML configuration file.
Provides dot-notation access to nested config values.
"""

import yaml
import sys
from pathlib import Path


class ConfigLoader:
    """Loads YAML configuration and provides dot-notation access."""

    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self._data = {}
        self._load()

    def _load(self):
        """Load and validate the YAML config file."""
        if not self.config_path.exists():
            print(f"[ERROR] Config file not found: {self.config_path}")
            sys.exit(1)

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                self._data = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            print(f"[ERROR] Invalid YAML in config: {e}")
            sys.exit(1)

        # Validate required sections
        required_sections = ["log_sources", "detection_rules", "alerting"]
        for section in required_sections:
            if section not in self._data:
                print(f"[ERROR] Missing required config section: '{section}'")
                sys.exit(1)

        print(f"    ✓ Loaded config from {self.config_path}")
        rules = self._data.get("detection_rules", {})
        enabled = sum(1 for r in rules.values() if r.get("enabled", False))
        print(f"    ✓ {enabled}/{len(rules)} detection rules enabled")

    def get(self, key: str, default=None):
        """
        Get a config value using dot notation.
        Example: config.get("siem.splunk.hec_url")
        """
        keys = key.split(".")
        value = self._data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value

    def get_rules(self):
        """Return all enabled detection rules."""
        rules = self._data.get("detection_rules", {})
        return {
            name: rule for name, rule in rules.items()
            if rule.get("enabled", False)
        }

    def get_whitelist(self):
        """Return whitelisted IPs and users."""
        return self._data.get("whitelist", {"ips": [], "users": []})

    @property
    def data(self):
        return self._data
