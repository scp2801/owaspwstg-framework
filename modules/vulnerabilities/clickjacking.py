"""
Clickjacking Checker
====================
Tests for clickjacking vulnerabilities.
WSTG-CLNT-09

Checks:
- X-Frame-Options header (DENY/SAMEORIGIN)
- Content-Security-Policy frame-ancestors
- Framing protection completeness
"""

import asyncio
from typing import List, Dict, Any

import aiohttp


class ClickjackingChecker:
    """Detects clickjacking vulnerabilities via header analysis."""

    def __init__(self, urls: List[str], config: Dict, logger):
        self.urls = urls
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

    async def check(self) -> List[Dict]:
        """Check URLs for clickjacking protection."""
        findings = []
        semaphore = asyncio.Semaphore(10)

        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:

            async def check_one(url: str) -> List[Dict]:
                async with semaphore:
                    return await self._check_url(session, url)

            tasks = [check_one(url) for url in self.urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return findings

    async def _check_url(self, session: aiohttp.ClientSession, url: str) -> List[Dict]:
        """Check a single URL for clickjacking protection."""
        findings = []

        try:
            async with session.get(url, allow_redirects=True) as resp:
                if resp.status != 200:
                    return []

                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                xfo = headers_lower.get("x-frame-options", "")
                csp = headers_lower.get("content-security-policy", "")

                has_xfo = bool(xfo and xfo.upper() in ("DENY", "SAMEORIGIN"))
                has_csp_frame = "frame-ancestors" in csp.lower()

                if not has_xfo and not has_csp_frame:
                    # Fully vulnerable
                    findings.append({
                        "type": "clickjacking",
                        "name": "Clickjacking: No Framing Protection",
                        "url": url,
                        "wstg_id": "WSTG-CLNT-09",
                        "severity": "Medium",
                        "cwe": "CWE-1021",
                        "cvss": "4.3",
                        "description": (
                            "The page has no X-Frame-Options or CSP frame-ancestors protection. "
                            "It can be embedded in an iframe by any attacker."
                        ),
                        "evidence": (
                            f"X-Frame-Options: {xfo or 'MISSING'}\n"
                            f"CSP frame-ancestors: {'Present' if has_csp_frame else 'MISSING'}"
                        ),
                        "recommendation": (
                            "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header. "
                            "Alternatively, use CSP: 'Content-Security-Policy: frame-ancestors none' "
                            "for more granular control."
                        ),
                        "vulnerable": True,
                        "status": "FAIL",
                    })

                elif xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
                    # Weak XFO value
                    findings.append({
                        "type": "clickjacking_weak",
                        "name": "Clickjacking: Weak X-Frame-Options Value",
                        "url": url,
                        "wstg_id": "WSTG-CLNT-09",
                        "severity": "Low",
                        "cwe": "CWE-1021",
                        "cvss": "3.1",
                        "description": f"X-Frame-Options has non-standard value: '{xfo}'",
                        "evidence": f"X-Frame-Options: {xfo}",
                        "recommendation": "Use X-Frame-Options: DENY or SAMEORIGIN only.",
                        "vulnerable": True,
                        "status": "REVIEW",
                    })

                else:
                    findings.append({
                        "type": "clickjacking_protected",
                        "name": "Clickjacking: Protected",
                        "url": url,
                        "wstg_id": "WSTG-CLNT-09",
                        "severity": "Info",
                        "vulnerable": False,
                        "status": "PASS",
                        "evidence": f"X-Frame-Options: {xfo or 'via CSP frame-ancestors'}",
                    })

        except Exception as e:
            self.logger.debug(f"Clickjacking check error for {url}: {e}")

        return findings
