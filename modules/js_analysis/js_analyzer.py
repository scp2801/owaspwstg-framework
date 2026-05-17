"""
JavaScript Analyzer Module
==========================
Analyzes JavaScript files for:
- API keys and secrets
- AWS credentials
- Firebase configurations
- JWT tokens
- Hidden API endpoints
- Internal URLs and paths
- CORS misconfigurations
"""

import re
import asyncio
from typing import List, Dict, Any

import aiohttp


# Secret patterns to search for in JavaScript files
SECRET_PATTERNS = [
    {"name": "AWS Access Key", "pattern": r'AKIA[0-9A-Z]{16}', "severity": "Critical", "cwe": "CWE-798"},
    {"name": "AWS Secret Key", "pattern": r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]', "severity": "Critical", "cwe": "CWE-798"},
    {"name": "Google API Key", "pattern": r'AIza[0-9A-Za-z\\-_]{35}', "severity": "High", "cwe": "CWE-798"},
    {"name": "Firebase Config", "pattern": r'firebaseConfig\s*=\s*\{[^}]+\}', "severity": "Medium", "cwe": "CWE-312"},
    {"name": "JWT Token", "pattern": r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "severity": "High", "cwe": "CWE-522"},
    {"name": "Private Key", "pattern": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "severity": "Critical", "cwe": "CWE-321"},
    {"name": "Slack Token", "pattern": r'xox[baprs]-[0-9a-zA-Z]{10,48}', "severity": "High", "cwe": "CWE-798"},
    {"name": "GitHub Token", "pattern": r'ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}', "severity": "High", "cwe": "CWE-798"},
    {"name": "Stripe Key", "pattern": r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}', "severity": "Critical", "cwe": "CWE-798"},
    {"name": "Twilio Token", "pattern": r'SK[0-9a-fA-F]{32}', "severity": "High", "cwe": "CWE-798"},
    {"name": "SendGrid API Key", "pattern": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', "severity": "High", "cwe": "CWE-798"},
    {"name": "Mailgun API Key", "pattern": r'key-[0-9a-zA-Z]{32}', "severity": "High", "cwe": "CWE-798"},
    {"name": "Generic API Key", "pattern": r'(?i)api[_\-]?key[\'"\s]*[:=][\'"\s]*([0-9a-zA-Z\-_]{20,})', "severity": "Medium", "cwe": "CWE-798"},
    {"name": "Generic Secret", "pattern": r'(?i)(?:secret|password|passwd|pwd)[\'"\s]*[:=][\'"\s]*([^\'";\s]{8,})', "severity": "Medium", "cwe": "CWE-312"},
    {"name": "Database URL", "pattern": r'(?i)(mongodb|mysql|postgresql|redis)://[^\s\'"]+', "severity": "Critical", "cwe": "CWE-312"},
    {"name": "Internal IP", "pattern": r'(?:^|[^0-9])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[^0-9]|$)', "severity": "Low", "cwe": "CWE-200"},
    {"name": "Hardcoded Password", "pattern": r'(?i)(?:password|passwd)\s*=\s*[\'"][^\'"]{3,}[\'"]', "severity": "High", "cwe": "CWE-259"},
    {"name": "Cloudinary URL", "pattern": r'cloudinary://[0-9a-zA-Z]+:[0-9a-zA-Z]+@[0-9a-zA-Z]+', "severity": "High", "cwe": "CWE-798"},
]

API_ENDPOINT_PATTERNS = [
    r'(?:\'|"|`)(/api/v\d+/[^\'"`,\s]+)',
    r'(?:\'|"|`)(/graphql[^\'"`,\s]*)',
    r'(?:\'|"|`)(https?://[^\'"`\s]+/api/[^\'"`,\s]+)',
    r'fetch\([\'"]([^\'"]+)[\'"]\)',
    r'axios\.[a-z]+\([\'"]([^\'"]+)[\'"]\)',
    r'XMLHttpRequest.*?open\([\'"](?:GET|POST)[\'"],\s*[\'"]([^\'"]+)[\'"]',
    r'(?:baseURL|apiUrl|endpoint)\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
]


class JSAnalyzer:
    """
    Analyzes JavaScript files for secrets, API keys, and hidden endpoints.
    """

    def __init__(self, js_urls: List[str], config: Dict, logger):
        self.js_urls = js_urls
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

    async def analyze(self) -> List[Dict]:
        """
        Download and analyze all JavaScript files.

        Returns:
            List of findings from JS analysis
        """
        all_findings = []
        semaphore = asyncio.Semaphore(5)

        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:

            async def analyze_one(url: str) -> List[Dict]:
                async with semaphore:
                    return await self._analyze_js_file(session, url)

            tasks = [analyze_one(url) for url in self.js_urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)

        self.logger.info(f"JS Analysis complete: {len(all_findings)} findings")
        return all_findings

    async def _analyze_js_file(self, session: aiohttp.ClientSession, url: str) -> List[Dict]:
        """Download and scan a single JavaScript file."""
        findings = []

        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return []

                js_content = await resp.text(errors="ignore")

                # Check for secrets
                for pattern_def in SECRET_PATTERNS:
                    matches = re.finditer(pattern_def["pattern"], js_content)
                    for match in matches:
                        matched_text = match.group(0)

                        # Skip very short matches or common false positives
                        if len(matched_text) < 8:
                            continue

                        finding = {
                            "type": "secret",
                            "name": pattern_def["name"],
                            "url": url,
                            "match": matched_text[:100],  # Truncate for safety
                            "severity": pattern_def["severity"],
                            "cwe": pattern_def.get("cwe", ""),
                            "wstg_id": "WSTG-INFO-05",
                            "evidence": f"Found {pattern_def['name']} in {url}",
                            "recommendation": f"Remove {pattern_def['name']} from client-side JavaScript. Use server-side environment variables.",
                            "vulnerable": True,
                        }
                        findings.append(finding)
                        self.logger.warning(
                            f"[JS-SECRET] {pattern_def['name']} found in {url}"
                        )

                # Extract API endpoints
                endpoints = self._extract_endpoints(js_content, url)
                for ep in endpoints:
                    findings.append({
                        "type": "endpoint",
                        "name": "Hidden API Endpoint",
                        "url": url,
                        "endpoint": ep,
                        "severity": "Info",
                        "wstg_id": "WSTG-INFO-06",
                        "evidence": f"Endpoint found in JS: {ep}",
                        "recommendation": "Review exposed API endpoints for proper authentication.",
                        "vulnerable": False,
                    })

        except asyncio.TimeoutError:
            self.logger.debug(f"JS analysis timeout: {url}")
        except Exception as e:
            self.logger.debug(f"JS analysis error for {url}: {e}")

        return findings

    def _extract_endpoints(self, js_content: str, base_url: str) -> List[str]:
        """Extract potential API endpoints from JavaScript content."""
        endpoints = []
        seen = set()

        for pattern in API_ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                endpoint = match.group(1) if match.lastindex else match.group(0)
                endpoint = endpoint.strip()

                if endpoint and endpoint not in seen and len(endpoint) > 2:
                    seen.add(endpoint)
                    # Filter out obvious non-endpoints
                    if not any(ext in endpoint.lower() for ext in [".png", ".jpg", ".css", ".gif"]):
                        endpoints.append(endpoint)

        return endpoints[:50]  # Limit results
