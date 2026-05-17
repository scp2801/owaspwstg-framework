"""
Config Loader Module
====================
Loads and manages YAML-based configuration for the framework.
Supports scan profiles, custom overrides, and environment-specific settings.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any


DEFAULT_CONFIG = {
    "framework": {
        "name": "OWASP WSTG Bug Bounty Framework",
        "version": "1.0.0",
        "author": "scp2801",
    },
    "scan": {
        "profile": "default",
        "threads": 10,
        "timeout": 30,
        "rate_limit": 50,
        "delay": 0.1,
        "retries": 3,
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 WSTG-Framework/1.0",
        "verify_ssl": False,
        "follow_redirects": True,
        "max_redirects": 5,
        "vuln_scan": True,
        "no_crawl": False,
        "screenshots": True,
        "mode": "full",
    },
    "output": {
        "dir": "reports",
        "format": "all",
        "timestamp_dirs": True,
    },
    "recon": {
        "sources": ["crtsh", "alienvault", "rapiddns", "webarchive"],
        "dns_types": ["A", "AAAA", "MX", "TXT", "CNAME", "NS"],
        "max_subdomains": 5000,
        "live_host_threads": 20,
    },
    "crawling": {
        "max_depth": 3,
        "max_pages": 500,
        "extract_js": True,
        "check_robots": True,
        "check_sitemap": True,
        "include_external": False,
    },
    "vulnerabilities": {
        "xss": True,
        "sqli": True,
        "ssrf": True,
        "open_redirect": True,
        "idor": True,
        "cors": True,
        "jwt": True,
        "file_upload": True,
        "security_headers": True,
        "clickjacking": True,
        "subdomain_takeover": True,
        "sensitive_files": True,
    },
    "tools": {
        "nuclei": {"enabled": True, "templates": ""},
        "subfinder": {"enabled": True},
        "httpx": {"enabled": True},
        "ffuf": {"enabled": True, "wordlist": "wordlists/common.txt"},
        "sqlmap": {"enabled": False, "risk": 1, "level": 1},
    },
    "reporting": {
        "company": "Bug Bounty Report",
        "analyst": "scp2801",
        "include_evidence": True,
        "include_screenshots": True,
        "cvss_scoring": True,
    },
}

SCAN_PROFILES = {
    "fast": {
        "scan": {
            "threads": 25,
            "timeout": 10,
            "rate_limit": 100,
            "delay": 0,
        },
        "crawling": {"max_depth": 1, "max_pages": 100},
        "recon": {"max_subdomains": 500},
    },
    "deep": {
        "scan": {
            "threads": 5,
            "timeout": 60,
            "rate_limit": 10,
            "delay": 0.5,
        },
        "crawling": {"max_depth": 5, "max_pages": 2000},
        "recon": {"max_subdomains": 10000, "sources": ["crtsh", "alienvault", "rapiddns", "webarchive", "chaos"]},
    },
    "stealth": {
        "scan": {
            "threads": 2,
            "timeout": 45,
            "rate_limit": 5,
            "delay": 2.0,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
        "crawling": {"max_depth": 2, "max_pages": 200},
    },
    "default": {},
}


class ConfigLoader:
    """
    Loads configuration from YAML file with fallback to defaults.
    Merges scan profiles and supports runtime overrides.
    """

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path

    def load(self) -> Dict[str, Any]:
        """
        Load configuration from file, merging with defaults.

        Returns:
            Merged configuration dictionary
        """
        config = self._deep_copy(DEFAULT_CONFIG)

        # Load from file if exists
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    file_config = yaml.safe_load(f) or {}
                config = self._deep_merge(config, file_config)
            except Exception as e:
                print(f"[!] Warning: Could not load config file: {e}. Using defaults.")

        # Apply scan profile
        profile = config.get("scan", {}).get("profile", "default")
        profile_config = SCAN_PROFILES.get(profile, {})
        if profile_config:
            config = self._deep_merge(config, profile_config)

        return config

    def _deep_merge(self, base: dict, override: dict) -> dict:
        """Recursively merge two dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def _deep_copy(self, d: dict) -> dict:
        """Deep copy a dictionary."""
        import copy
        return copy.deepcopy(d)

    def save_default(self, path: str = "config.yaml"):
        """Save default configuration to YAML file."""
        with open(path, "w") as f:
            yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, allow_unicode=True, indent=2)
        print(f"[+] Default config saved to {path}")
