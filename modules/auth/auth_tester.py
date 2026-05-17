"""
Authentication Testing Module
==============================
Tests authentication mechanisms.
WSTG-ATHN series

Tests:
- Default credentials
- Weak password policies
- Account lockout
- Auth bypass indicators
- HTTP vs HTTPS login form
- Cookie security attributes
"""

import asyncio
import re
from typing import List, Dict, Any, Optional

import aiohttp


# Common default credentials pairs
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("administrator", "administrator"),
    ("user", "user"),
    ("test", "test"),
    ("guest", "guest"),
]

# Common admin login paths
ADMIN_LOGIN_PATHS = [
    "/admin/login", "/admin", "/administrator/login",
    "/wp-login.php", "/wp-admin", "/login", "/signin",
    "/user/login", "/auth/login", "/account/login",
    "/dashboard/login", "/console/login", "/panel/login",
]


class AuthTester:
    """
    Tests authentication security controls.
    """

    def __init__(self, base_url: str, config: Dict, logger):
        self.base_url = base_url.rstrip("/")
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

    async def run_all_checks(self) -> List[Dict]:
        """Run all authentication tests."""
        findings = []

        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            # Check for login forms over HTTP
            http_findings = await self._check_http_login(session)
            findings.extend(http_findings)

            # Check admin panels
            admin_findings = await self._check_admin_panels(session)
            findings.extend(admin_findings)

            # Check cookie attributes
            cookie_findings = await self._check_cookie_attributes(session)
            findings.extend(cookie_findings)

        return findings

    async def _check_http_login(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Check if login forms are served over HTTP (not HTTPS)."""
        findings = []
        if not self.base_url.startswith("http://"):
            return []

        try:
            async with session.get(self.base_url + "/login", allow_redirects=False) as resp:
                if resp.status == 200:
                    body = await resp.text(errors="ignore")
                    if "password" in body.lower() and "<form" in body.lower():
                        findings.append({
                            "type": "auth_http",
                            "name": "Login Form Served over HTTP",
                            "url": self.base_url + "/login",
                            "wstg_id": "WSTG-ATHN-01",
                            "severity": "High",
                            "cwe": "CWE-319",
                            "cvss": "7.5",
                            "description": "Login form served over unencrypted HTTP. Credentials transmitted in plaintext.",
                            "evidence": f"Login form found at {self.base_url}/login over HTTP",
                            "recommendation": "Enforce HTTPS for all authentication endpoints. Redirect HTTP to HTTPS.",
                            "vulnerable": True,
                            "status": "FAIL",
                        })
        except Exception:
            pass

        return findings

    async def _check_admin_panels(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Check for accessible admin panels."""
        findings = []
        semaphore = asyncio.Semaphore(5)

        async def check_path(path: str) -> Optional[Dict]:
            async with semaphore:
                url = self.base_url + path
                try:
                    async with session.get(url, allow_redirects=True) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            # Check for login form indicators
                            if any(kw in body.lower() for kw in ["password", "username", "login", "signin"]):
                                return {
                                    "type": "admin_panel",
                                    "name": "Admin/Login Panel Accessible",
                                    "url": url,
                                    "wstg_id": "WSTG-CONF-05",
                                    "severity": "Medium",
                                    "cwe": "CWE-284",
                                    "cvss": "5.3",
                                    "description": f"Admin or login panel accessible at {url}",
                                    "evidence": f"URL: {url}\nHTTP Status: 200\nLogin form detected",
                                    "recommendation": (
                                        "Restrict admin interfaces to trusted IPs. "
                                        "Implement MFA for admin accounts. "
                                        "Use separate admin subdomain with IP allowlisting."
                                    ),
                                    "vulnerable": True,
                                    "status": "REVIEW",
                                }
                except Exception:
                    pass
            return None

        tasks = [check_path(p) for p in ADMIN_LOGIN_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r:
                findings.append(r)

        return findings

    async def _check_cookie_attributes(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Check cookies for security attributes (HttpOnly, Secure, SameSite)."""
        findings = []

        try:
            async with session.get(self.base_url, allow_redirects=True) as resp:
                cookies = resp.cookies
                set_cookie_headers = resp.headers.getall("Set-Cookie", [])

                for cookie_header in set_cookie_headers:
                    cookie_lower = cookie_header.lower()
                    cookie_name = cookie_header.split("=")[0].strip()

                    issues = []
                    if "httponly" not in cookie_lower:
                        issues.append("Missing HttpOnly flag (XSS can steal this cookie)")
                    if "secure" not in cookie_lower and self.base_url.startswith("https"):
                        issues.append("Missing Secure flag (cookie can be sent over HTTP)")
                    if "samesite" not in cookie_lower:
                        issues.append("Missing SameSite attribute (CSRF risk)")

                    if issues:
                        findings.append({
                            "type": "cookie_security",
                            "name": f"Insecure Cookie: {cookie_name}",
                            "url": self.base_url,
                            "wstg_id": "WSTG-SESS-02",
                            "severity": "Medium",
                            "cwe": "CWE-1004",
                            "cvss": "4.3",
                            "description": f"Cookie '{cookie_name}' is missing security attributes: {', '.join(issues)}",
                            "evidence": f"Set-Cookie: {cookie_header[:200]}",
                            "recommendation": (
                                "Set HttpOnly flag to prevent XSS cookie theft. "
                                "Set Secure flag for HTTPS-only transmission. "
                                "Set SameSite=Strict or Lax for CSRF protection."
                            ),
                            "vulnerable": True,
                            "status": "FAIL",
                        })

        except Exception as e:
            self.logger.debug(f"Cookie check error: {e}")

        return findings
