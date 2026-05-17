"""
SSRF Checker Module
===================
Tests for Server-Side Request Forgery vulnerabilities.
WSTG-INPV-19

Safe detection methods:
- Tests redirect to external domains
- Checks for internal IP addresses in responses
- Uses Canary tokens / safe callback URLs
- Checks common SSRF-prone parameters
"""

import asyncio
import re
from typing import List, Dict, Any

import aiohttp


# Safe SSRF test URLs (non-destructive, just checking if requests are made)
SSRF_TEST_URLS = [
    "http://169.254.169.254/latest/meta-data/",   # AWS metadata
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/v1/",  # DigitalOcean
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://2130706433/",  # 127.0.0.1 in decimal
    "http://0177.0.0.1/",  # 127.0.0.1 in octal
]

# Response indicators that suggest SSRF worked
SSRF_SUCCESS_INDICATORS = [
    r"ami-id",
    r"instance-id",
    r"local-hostname",
    r"public-ipv4",
    r"security-credentials",
    r"computeMetadata",
    r"digitalocean",
    r"127\.0\.0\.1",
    r"<title>Welcome to nginx",
    r"root:x:0:0",
    r"AWS_ACCESS_KEY",
]

# Parameters commonly vulnerable to SSRF
SSRF_PRONE_PARAMS = {
    "url", "uri", "u", "path", "dest", "destination", "redirect",
    "next", "return", "link", "src", "source", "ref", "redir",
    "target", "site", "page", "fetch", "host", "server",
    "endpoint", "api", "webhook", "callback", "proxy", "load",
    "open", "file", "img", "image", "pdf", "document",
}


class SSRFChecker:
    """
    Detects SSRF vulnerabilities in web applications.
    """

    def __init__(self, urls_with_params: List[Dict], config: Dict, logger):
        self.urls_with_params = urls_with_params
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=min(config["scan"].get("timeout", 30), 15))
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

    async def check(self) -> List[Dict]:
        """
        Test SSRF-prone parameters.

        Returns:
            List of SSRF findings
        """
        findings = []
        semaphore = asyncio.Semaphore(3)

        # Filter to SSRF-prone parameters
        ssrf_candidates = [
            p for p in self.urls_with_params
            if p.get("param", "").lower() in SSRF_PRONE_PARAMS
            or p.get("type") == "SSRF_CANDIDATE"
        ]

        if not ssrf_candidates:
            return []

        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:

            async def check_one(param_info: Dict) -> List[Dict]:
                async with semaphore:
                    return await self._test_param(session, param_info)

            tasks = [check_one(p) for p in ssrf_candidates[:30]]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return findings

    async def _test_param(self, session: aiohttp.ClientSession, param_info: Dict) -> List[Dict]:
        """Test a parameter for SSRF."""
        findings = []
        base_url = param_info.get("base_url", "")
        param_name = param_info.get("param", "")

        if not base_url or not param_name:
            return []

        for ssrf_url in SSRF_TEST_URLS[:4]:  # Limit for speed
            try:
                from urllib.parse import quote
                test_url = f"{base_url}?{param_name}={quote(ssrf_url, safe='')}"

                async with session.get(test_url, allow_redirects=False) as resp:
                    body = await resp.text(errors="ignore")
                    body_lower = body.lower()

                    # Check for SSRF success indicators
                    for indicator in SSRF_SUCCESS_INDICATORS:
                        if re.search(indicator, body, re.IGNORECASE):
                            findings.append({
                                "type": "ssrf",
                                "name": "Server-Side Request Forgery (SSRF)",
                                "url": test_url,
                                "wstg_id": "WSTG-INPV-19",
                                "severity": "Critical",
                                "cwe": "CWE-918",
                                "cvss": "9.8",
                                "description": (
                                    f"Parameter '{param_name}' may allow SSRF. "
                                    f"Internal service response indicators found when requesting {ssrf_url}."
                                ),
                                "evidence": (
                                    f"SSRF Payload URL: {ssrf_url}\n"
                                    f"Test URL: {test_url}\n"
                                    f"Response snippet: {body[:300]}"
                                ),
                                "recommendation": (
                                    "Validate and whitelist allowed URLs/domains. "
                                    "Block requests to private/internal IP ranges. "
                                    "Use an allowlist of permitted schemes (https only). "
                                    "Disable unnecessary URL fetching features."
                                ),
                                "vulnerable": True,
                                "status": "FAIL",
                                "param": param_name,
                            })
                            self.logger.warning(f"[SSRF] Possible SSRF in {test_url}")
                            return findings

                    # Check for redirect to internal (SSRF via redirect)
                    if resp.status in (301, 302, 307, 308):
                        location = resp.headers.get("Location", "")
                        if any(internal in location for internal in ["127.", "192.168.", "10.", "169.254."]):
                            findings.append({
                                "type": "ssrf_redirect",
                                "name": "SSRF via Open Redirect to Internal",
                                "url": test_url,
                                "wstg_id": "WSTG-INPV-19",
                                "severity": "High",
                                "cwe": "CWE-918",
                                "cvss": "8.1",
                                "description": f"Parameter '{param_name}' redirects to internal address: {location}",
                                "evidence": f"Redirect Location: {location}",
                                "recommendation": "Block redirects to private IP ranges. Validate destination URLs.",
                                "vulnerable": True,
                                "status": "REVIEW",
                                "param": param_name,
                            })

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.debug(f"SSRF test error: {e}")

        return findings
