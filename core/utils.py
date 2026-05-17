"""
Utilities Module
================
Common helper functions used across the framework.
URL normalization, validation, file helpers, and data processing.
"""

import re
import os
import json
import hashlib
import ipaddress
import urllib.parse
from datetime import datetime
from typing import List, Optional, Set, Dict, Any
from pathlib import Path


def normalize_url(url: str) -> str:
    """
    Normalize a URL to a consistent format.

    Args:
        url: Raw URL string

    Returns:
        Normalized URL with scheme
    """
    url = url.strip()
    if not url:
        return ""

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Parse and reconstruct
    parsed = urllib.parse.urlparse(url)

    # Lowercase scheme and host
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Remove default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    if netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    # Reconstruct
    normalized = urllib.parse.urlunparse((
        scheme,
        netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        "",  # Remove fragments
    ))

    return normalized


def extract_domain(url: str) -> str:
    """
    Extract base domain from URL or domain string.

    Args:
        url: URL or domain string

    Returns:
        Base domain (e.g., 'example.com')
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    return parsed.netloc.lower().split(":")[0]


def is_valid_domain(domain: str) -> bool:
    """
    Validate if a string is a valid domain name.

    Args:
        domain: Domain string to validate

    Returns:
        True if valid domain
    """
    domain = domain.strip().lower()

    # Remove scheme if present
    if "://" in domain:
        domain = urllib.parse.urlparse(domain if "://" in domain else "https://" + domain).netloc

    # IP address check
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        pass

    # Domain regex validation
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        r"\.)+[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(domain))


def is_valid_url(url: str) -> bool:
    """Check if a string is a valid HTTP/HTTPS URL."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def deduplicate_list(items: List[str]) -> List[str]:
    """Remove duplicates while preserving order."""
    seen: Set[str] = set()
    result = []
    for item in items:
        normalized = item.strip().lower()
        if normalized not in seen and normalized:
            seen.add(normalized)
            result.append(item.strip())
    return result


def deduplicate_urls(urls: List[str]) -> List[str]:
    """Remove duplicate URLs, ignoring fragments and trailing slashes."""
    seen: Set[str] = set()
    result = []
    for url in urls:
        clean = url.strip().rstrip("/").split("#")[0]
        clean_lower = clean.lower()
        if clean_lower not in seen and clean_lower:
            seen.add(clean_lower)
            result.append(url.strip())
    return result


def sanitize_filename(name: str) -> str:
    """
    Sanitize a string for use as a filename.

    Args:
        name: Raw filename string

    Returns:
        Safe filename string
    """
    # Replace unsafe chars
    name = re.sub(r'[<>:"/\\|?*]', '_', name)
    name = re.sub(r'\s+', '_', name)
    name = name.strip('._')
    return name[:200]  # Limit length


def create_output_dir(base_dir: str, target: str) -> str:
    """
    Create organized output directory for a scan target.

    Args:
        base_dir: Base output directory
        target: Target domain/URL

    Returns:
        Path to created directory
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = sanitize_filename(extract_domain(target) or target)
    scan_dir = os.path.join(base_dir, f"{domain}_{timestamp}")

    # Create subdirectories
    subdirs = ["screenshots", "evidence", "raw", "js_analysis"]
    Path(scan_dir).mkdir(parents=True, exist_ok=True)
    for sub in subdirs:
        Path(os.path.join(scan_dir, sub)).mkdir(exist_ok=True)

    return scan_dir


def load_wordlist(path: str) -> List[str]:
    """Load a wordlist from file, skipping comments and blank lines."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception:
        return []


def save_json(data: Any, path: str):
    """Save data to JSON file with pretty formatting."""
    Path(os.path.dirname(path) or ".").mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def load_json(path: str) -> Any:
    """Load JSON from file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def hash_url(url: str) -> str:
    """Generate short hash for a URL (for deduplication keys)."""
    return hashlib.md5(url.encode()).hexdigest()[:12]


def chunk_list(lst: List, size: int) -> List[List]:
    """Split list into chunks of given size."""
    return [lst[i:i + size] for i in range(0, len(lst), size)]


def extract_urls_from_text(text: str) -> List[str]:
    """Extract all URLs from a block of text."""
    url_pattern = re.compile(
        r'https?://[^\s<>"\'`\(\)\[\]\{\}]+',
        re.IGNORECASE
    )
    return list(set(url_pattern.findall(text)))


def extract_emails(text: str) -> List[str]:
    """Extract email addresses from text."""
    pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    return list(set(pattern.findall(text)))


def extract_ips(text: str) -> List[str]:
    """Extract IP addresses from text."""
    pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    candidates = pattern.findall(text)
    valid = []
    for ip in candidates:
        try:
            ipaddress.ip_address(ip)
            valid.append(ip)
        except ValueError:
            pass
    return list(set(valid))


def format_timestamp() -> str:
    """Return formatted current timestamp."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def severity_to_color(severity: str) -> str:
    """Map severity level to rich color string."""
    mapping = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "cyan",
        "pass": "green",
        "fail": "red",
        "review": "yellow",
    }
    return mapping.get(severity.lower(), "white")


def parse_scope_file(path: str) -> List[str]:
    """
    Parse a scope file containing domains/URLs.
    Supports comments (#), blank lines, and wildcards.

    Args:
        path: Path to scope file

    Returns:
        List of normalized targets
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Scope file not found: {path}")

    targets = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Handle wildcard domains
            if line.startswith("*."):
                line = line[2:]  # Strip wildcard prefix
            if is_valid_domain(line) or is_valid_url(line):
                targets.append(line)

    return deduplicate_list(targets)
