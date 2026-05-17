"""
Open Redirect Checker
=====================
Tests for Open Redirect vulnerabilities.
WSTG-CLNT-04

Safe detection: checks if response redirects to external domain.
"""

import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import quote

import aiohttp


REDIRECT_PARAMS = {
    "url", "redirect", "next", "return", "goto", "redir", "target",
    "dest", "destination", "return_url", "returnurl", "redirect_uri",
    "redirect_url", "callback", "continue", "to", "link", "forward",
    "location", "r", "u", "ref", "referer", "site",
}

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/%2F..",
    "/\\evil.com",
    "https://evil.com?trusted.com",
    "%0ahttps://evil.com",
]

EXTERNAL_INDICATORS = [
    "evil.com",
    "Location: https://evil.com",
    "Location: //evil.com",
]


class OpenRedirectChecker:
    """
    Detects open redirect vulnerabilities in web applications.
    """

    def __init__(self, urls_with_params: List[Dict], config: Dict, logger):
        self.urls_with_params = urls_with_params
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

    async def check(self) -> List[Dict]:
        """Test for open redirect vulnerabilities."""
        findings = []
        semaphore = asyncio.Semaphore(5)

        candidates = [
            p for p in self.urls_with_params
            if p.get("param", "").lower() in REDIRECT_PARAMS
            or p.get("type") == "REDIRECT_CANDIDATE"
        ]

        if not candidates:
            return []

        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:

            async def check_one(param_info: Dict) -> List[Dict]:
                async with semaphore:
                    return await self._test_param(session, param_info)

            tasks = [check_one(p) for p in candidates[:50]]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return findings

    async def _test_param(self, session: aiohttp.ClientSession, param_info: Dict) -> List[Dict]:
        """Test a parameter for open redirect."""
        findings = []
        base_url = param_info.get("base_url", "")
        param_name = param_info.get("param", "")

        if not base_url or not param_name:
            return []

        for payload in REDIRECT_PAYLOADS[:3]:
            try:
                test_url = f"{base_url}?{param_name}={quote(payload, safe='://')}"

                async with session.get(test_url, allow_redirects=False) as resp:
                    if resp.status in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")

                        # Check if redirecting to external domain
                        if "evil.com" in location or (
                            location.startswith("http") and
                            not any(trusted in location for trusted in [base_url.split("/")[2]])
                        ):
                            findings.append({
                                "type": "open_redirect",
                                "name": "Open Redirect",
                                "url": test_url,
                                "wstg_id": "WSTG-CLNT-04",
                                "severity": "Medium",
                                "cwe": "CWE-601",
                                "cvss": "6.1",
                                "description": (
                                    f"Parameter '{param_name}' redirects to attacker-controlled URL. "
                                    "Can be used in phishing attacks."
                                ),
                                "evidence": (
                                    f"Payload: {payload}\n"
                                    f"Test URL: {test_url}\n"
                                    f"Redirect Location: {location}"
                                ),
                                "recommendation": (
                                    "Validate redirect destinations against a whitelist. "
                                    "Use relative URLs for internal redirects. "
                                    "Warn users before redirecting to external domains."
                                ),
                                "vulnerable": True,
                                "status": "FAIL",
                                "param": param_name,
                            })
                            self.logger.warning(f"[REDIRECT] Open redirect in {test_url}")
                            return findings

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.debug(f"Redirect test error: {e}")

        return findings
