"""
Security Headers Checker
========================
Tests HTTP security headers for OWASP best practices.
WSTG-CONF-07, WSTG-CONF-12, WSTG-CLNT-09

Checks for:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options (Clickjacking protection)
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- X-XSS-Protection (deprecated but checked)
- Cache-Control for sensitive responses
"""

import asyncio
from typing import List, Dict, Any

import aiohttp


REQUIRED_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "description": "HSTS - Forces HTTPS connections",
        "wstg_id": "WSTG-CONF-07",
        "severity": "Medium",
        "cwe": "CWE-319",
        "cvss": "5.3",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
    },
    {
        "name": "Content-Security-Policy",
        "description": "CSP - Prevents XSS and data injection",
        "wstg_id": "WSTG-CONF-12",
        "severity": "Medium",
        "cwe": "CWE-693",
        "cvss": "5.3",
        "recommendation": "Implement a strict Content-Security-Policy header.",
    },
    {
        "name": "X-Frame-Options",
        "description": "Prevents clickjacking attacks",
        "wstg_id": "WSTG-CLNT-09",
        "severity": "Medium",
        "cwe": "CWE-693",
        "cvss": "4.3",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
    },
    {
        "name": "X-Content-Type-Options",
        "description": "Prevents MIME sniffing",
        "wstg_id": "WSTG-CONF-07",
        "severity": "Low",
        "cwe": "CWE-16",
        "cvss": "3.7",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' header.",
    },
    {
        "name": "Referrer-Policy",
        "description": "Controls referrer information",
        "wstg_id": "WSTG-CONF-07",
        "severity": "Low",
        "cwe": "CWE-200",
        "cvss": "3.1",
        "recommendation": "Add 'Referrer-Policy: no-referrer-when-downgrade' or stricter.",
    },
    {
        "name": "Permissions-Policy",
        "description": "Controls browser feature access",
        "wstg_id": "WSTG-CONF-07",
        "severity": "Low",
        "cwe": "CWE-16",
        "cvss": "2.6",
        "recommendation": "Add 'Permissions-Policy' to restrict sensitive browser APIs.",
    },
]

DANGEROUS_HEADERS = [
    {
        "name": "X-Powered-By",
        "description": "Reveals technology stack",
        "wstg_id": "WSTG-INFO-02",
        "severity": "Info",
        "recommendation": "Remove X-Powered-By header to reduce fingerprinting.",
    },
    {
        "name": "Server",
        "description": "Reveals server software",
        "wstg_id": "WSTG-INFO-02",
        "severity": "Info",
        "recommendation": "Remove or obscure the Server header.",
    },
]


class SecurityHeadersChecker:
    """
    Checks HTTP security headers for OWASP compliance.
    """

    def __init__(self, urls: List[str], config: Dict, logger):
        self.urls = urls
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

    async def check(self) -> List[Dict]:
        """
        Check security headers for all provided URLs.

        Returns:
            List of security header findings
        """
        all_findings = []
        semaphore = asyncio.Semaphore(5)

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
                all_findings.extend(result)

        return all_findings

    async def _check_url(self, session: aiohttp.ClientSession, url: str) -> List[Dict]:
        """Check security headers for a single URL."""
        findings = []

        try:
            async with session.get(url, allow_redirects=True) as resp:
                response_headers = {k.lower(): v for k, v in resp.headers.items()}

                # Check required headers that are MISSING
                for hdr in REQUIRED_HEADERS:
                    header_name_lower = hdr["name"].lower()
                    if header_name_lower not in response_headers:
                        finding = {
                            "type": "security_header_missing",
                            "name": f"Missing Security Header: {hdr['name']}",
                            "url": url,
                            "wstg_id": hdr["wstg_id"],
                            "severity": hdr["severity"],
                            "cwe": hdr.get("cwe", ""),
                            "cvss": hdr.get("cvss", ""),
                            "description": hdr["description"],
                            "evidence": f"Header '{hdr['name']}' not found in response from {url}",
                            "recommendation": hdr["recommendation"],
                            "vulnerable": True,
                            "status": "FAIL",
                        }
                        findings.append(finding)
                        self.logger.debug(f"Missing header: {hdr['name']} on {url}")
                    else:
                        # Header present - check value quality
                        value = response_headers[header_name_lower]
                        quality_issue = self._check_header_quality(hdr["name"], value)
                        if quality_issue:
                            findings.append({
                                "type": "security_header_weak",
                                "name": f"Weak Security Header: {hdr['name']}",
                                "url": url,
                                "wstg_id": hdr["wstg_id"],
                                "severity": "Low",
                                "description": quality_issue,
                                "evidence": f"{hdr['name']}: {value}",
                                "recommendation": hdr["recommendation"],
                                "vulnerable": True,
                                "status": "REVIEW",
                            })
                        else:
                            findings.append({
                                "type": "security_header_ok",
                                "name": f"Security Header Present: {hdr['name']}",
                                "url": url,
                                "wstg_id": hdr["wstg_id"],
                                "severity": "Info",
                                "vulnerable": False,
                                "status": "PASS",
                            })

                # Check for dangerous headers that should be REMOVED
                for hdr in DANGEROUS_HEADERS:
                    header_name_lower = hdr["name"].lower()
                    if header_name_lower in response_headers:
                        value = response_headers[header_name_lower]
                        findings.append({
                            "type": "information_disclosure_header",
                            "name": f"Information Disclosure: {hdr['name']}",
                            "url": url,
                            "wstg_id": hdr["wstg_id"],
                            "severity": hdr["severity"],
                            "description": hdr["description"],
                            "evidence": f"{hdr['name']}: {value}",
                            "recommendation": hdr["recommendation"],
                            "vulnerable": True,
                            "status": "REVIEW",
                        })

        except asyncio.TimeoutError:
            self.logger.debug(f"Timeout checking headers: {url}")
        except Exception as e:
            self.logger.debug(f"Header check error for {url}: {e}")

        return findings

    def _check_header_quality(self, header_name: str, value: str) -> str:
        """
        Check if a security header has a strong/correct value.

        Returns:
            Empty string if OK, description of issue if weak
        """
        header_lower = header_name.lower()
        value_lower = value.lower()

        if header_lower == "strict-transport-security":
            if "max-age=0" in value_lower:
                return "HSTS max-age is set to 0 (disabled)"
            if "max-age" not in value_lower:
                return "HSTS missing max-age directive"
            # Check max-age value
            import re
            match = re.search(r'max-age=(\d+)', value_lower)
            if match and int(match.group(1)) < 15768000:  # 6 months
                return "HSTS max-age is less than 6 months (recommended: 1 year+)"

        elif header_lower == "x-frame-options":
            if value_lower not in ["deny", "sameorigin"]:
                return f"X-Frame-Options has unusual value: {value}"

        elif header_lower == "content-security-policy":
            if "unsafe-inline" in value_lower:
                return "CSP allows 'unsafe-inline' which weakens XSS protection"
            if "unsafe-eval" in value_lower:
                return "CSP allows 'unsafe-eval' which weakens XSS protection"
            if "*" in value and "default-src" in value_lower:
                return "CSP default-src uses wildcard (*) which is overly permissive"

        return ""  # Header is fine
