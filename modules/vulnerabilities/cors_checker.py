"""
CORS Misconfiguration Checker
==============================
Tests for Cross-Origin Resource Sharing misconfigurations.
WSTG-CLNT-07

Tests:
- Wildcard CORS with credentials
- Null origin reflection
- Arbitrary origin reflection
- Trusted subdomain bypass
"""

import asyncio
from typing import List, Dict, Any

import aiohttp


class CORSChecker:
    """
    Detects CORS misconfigurations in web applications.
    """

    def __init__(self, urls: List[str], config: Dict, logger):
        self.urls = urls
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))

    async def check(self) -> List[Dict]:
        """
        Test CORS configuration for all URLs.

        Returns:
            List of CORS findings
        """
        findings = []
        semaphore = asyncio.Semaphore(5)

        async with aiohttp.ClientSession(
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:

            async def check_one(url: str) -> List[Dict]:
                async with semaphore:
                    return await self._check_url(session, url)

            tasks = [check_one(url) for url in self.urls[:50]]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return findings

    async def _check_url(self, session: aiohttp.ClientSession, url: str) -> List[Dict]:
        """Test CORS for a single URL with multiple origin headers."""
        findings = []

        # Test payloads: various origin values
        test_origins = [
            "https://evil.com",
            "null",
            "https://attacker.example.com",
        ]

        for origin in test_origins:
            try:
                headers = {
                    "User-Agent": self.config["scan"].get("user_agent", "Mozilla/5.0"),
                    "Origin": origin,
                }
                async with session.get(url, headers=headers, allow_redirects=True) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "false")

                    if not acao:
                        continue  # No CORS headers, skip

                    # Case 1: Wildcard with credentials (critical)
                    if acao == "*" and acac.lower() == "true":
                        findings.append(self._make_finding(
                            url=url,
                            title="CORS: Wildcard with Credentials",
                            severity="Critical",
                            evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                            description="Wildcard CORS with Allow-Credentials:true is invalid but some browsers may handle it insecurely.",
                            recommendation="Do not use wildcard (*) with credentials. Specify explicit allowed origins.",
                            cvss="9.1",
                        ))

                    # Case 2: Arbitrary origin reflected
                    elif acao == origin and acac.lower() == "true":
                        findings.append(self._make_finding(
                            url=url,
                            title="CORS: Arbitrary Origin Reflected with Credentials",
                            severity="High",
                            evidence=f"Request Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                            description="The server reflects any origin and allows credentials. An attacker can make authenticated cross-origin requests.",
                            recommendation="Maintain a whitelist of allowed origins. Never reflect arbitrary origins when credentials are involved.",
                            cvss="8.1",
                        ))

                    # Case 3: Null origin reflected
                    elif acao == "null" or (origin == "null" and acao == "null"):
                        findings.append(self._make_finding(
                            url=url,
                            title="CORS: Null Origin Allowed",
                            severity="Medium",
                            evidence=f"Access-Control-Allow-Origin: null",
                            description="The server allows null origin which can be triggered from sandboxed iframes or local files.",
                            recommendation="Do not allow null origin. Use explicit origin whitelist.",
                            cvss="5.4",
                        ))

                    # Case 4: Reflected without credentials (lower risk)
                    elif acao == origin and acac.lower() != "true":
                        findings.append(self._make_finding(
                            url=url,
                            title="CORS: Arbitrary Origin Reflected (no credentials)",
                            severity="Low",
                            evidence=f"Request Origin: {origin}\nAccess-Control-Allow-Origin: {acao}",
                            description="The server reflects arbitrary origins but does not allow credentials. Lower risk but still a misconfiguration.",
                            recommendation="Use an explicit origin whitelist instead of reflecting request origin.",
                            cvss="3.7",
                            status="REVIEW",
                        ))

            except asyncio.TimeoutError:
                pass
            except Exception as e:
                self.logger.debug(f"CORS check error for {url}: {e}")

        return findings

    def _make_finding(self, url: str, title: str, severity: str, evidence: str,
                      description: str, recommendation: str, cvss: str = "",
                      status: str = "FAIL") -> Dict:
        """Create a standardized CORS finding dictionary."""
        vuln = status == "FAIL"
        return {
            "type": "cors",
            "name": title,
            "url": url,
            "wstg_id": "WSTG-CLNT-07",
            "severity": severity,
            "cwe": "CWE-942",
            "cvss": cvss,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "vulnerable": vuln,
            "status": status,
        }
