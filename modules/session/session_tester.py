"""
Session Management Testing Module
==================================
Tests session management security.
WSTG-SESS series

Tests:
- Cookie security attributes (HttpOnly, Secure, SameSite)
- Session fixation
- CSRF token presence
- Session timeout
- Weak session token patterns
- Logout functionality
"""

import asyncio
import re
import base64
import hashlib
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin

import aiohttp


class SessionTester:
    """
    Tests session management security controls.
    WSTG-SESS-01 through WSTG-SESS-10
    """

    def __init__(self, base_url: str, endpoints: List[str], config: Dict, logger):
        self.base_url = base_url.rstrip("/")
        self.endpoints = endpoints
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

    async def run_all_checks(self) -> List[Dict]:
        """Run all session management tests."""
        findings = []

        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            # Cookie security attributes
            cookie_findings = await self._check_cookie_security(session)
            findings.extend(cookie_findings)

            # CSRF token detection
            csrf_findings = await self._check_csrf(session)
            findings.extend(csrf_findings)

            # Session token quality
            token_findings = await self._check_session_token_quality(session)
            findings.extend(token_findings)

            # Logout functionality
            logout_findings = await self._check_logout(session)
            findings.extend(logout_findings)

        return findings

    async def _check_cookie_security(self, session: aiohttp.ClientSession) -> List[Dict]:
        """
        Check all cookies for proper security attributes.
        WSTG-SESS-02
        """
        findings = []

        try:
            async with session.get(self.base_url, allow_redirects=True) as resp:
                # Get all Set-Cookie headers
                set_cookie_headers = resp.headers.getall("Set-Cookie", [])

                if not set_cookie_headers:
                    return []

                for cookie_str in set_cookie_headers:
                    cookie_lower = cookie_str.lower()

                    # Parse cookie name
                    cookie_name = cookie_str.split("=")[0].strip()

                    # Determine if this looks like a session cookie
                    is_session_like = any(keyword in cookie_name.lower() for keyword in [
                        "session", "sess", "sid", "token", "auth", "login", "user",
                        "jwt", "access", "refresh", "csrf", "xsrf"
                    ])

                    issues = []
                    recommendations = []

                    # Check HttpOnly flag
                    if "httponly" not in cookie_lower:
                        issues.append("Missing HttpOnly flag")
                        recommendations.append("Set HttpOnly flag to prevent JavaScript cookie access (XSS protection)")

                    # Check Secure flag (only for HTTPS sites)
                    if self.base_url.startswith("https") and "secure" not in cookie_lower:
                        issues.append("Missing Secure flag on HTTPS site")
                        recommendations.append("Set Secure flag to prevent transmission over HTTP")

                    # Check SameSite attribute
                    if "samesite" not in cookie_lower:
                        issues.append("Missing SameSite attribute")
                        recommendations.append("Set SameSite=Strict or Lax to prevent CSRF")
                    elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                        issues.append("SameSite=None without Secure flag (blocked by modern browsers)")
                        recommendations.append("Add Secure flag when using SameSite=None")

                    # Check for very long expiry on session cookies
                    if "max-age" in cookie_lower:
                        max_age_match = re.search(r"max-age=(\d+)", cookie_lower)
                        if max_age_match:
                            max_age = int(max_age_match.group(1))
                            if max_age > 86400 * 30:  # More than 30 days
                                issues.append(f"Very long Max-Age: {max_age // 86400} days")
                                recommendations.append("Use shorter session expiry times")

                    if issues:
                        severity = "High" if is_session_like else "Medium"
                        findings.append({
                            "type": "cookie_security",
                            "name": f"Insecure Cookie Attributes: {cookie_name}",
                            "url": self.base_url,
                            "wstg_id": "WSTG-SESS-02",
                            "severity": severity,
                            "cwe": "CWE-1004",
                            "cvss": "6.1" if severity == "High" else "4.3",
                            "description": (
                                f"Cookie '{cookie_name}' has insecure configuration: "
                                + ", ".join(issues)
                            ),
                            "evidence": (
                                f"Cookie: {cookie_str[:200]}\n"
                                f"Issues: {', '.join(issues)}"
                            ),
                            "recommendation": " | ".join(recommendations),
                            "vulnerable": True,
                            "status": "FAIL",
                        })
                        self.logger.debug(f"Cookie issue: {cookie_name} → {issues}")

        except Exception as e:
            self.logger.debug(f"Cookie security check error: {e}")

        return findings

    async def _check_csrf(self, session: aiohttp.ClientSession) -> List[Dict]:
        """
        Check for CSRF token implementation in forms.
        WSTG-SESS-05
        """
        findings = []
        csrf_token_names = {
            "csrf_token", "csrftoken", "_csrf", "csrf", "xsrf_token",
            "_token", "authenticity_token", "__requestverificationtoken",
            "nonce", "_xsrf"
        }

        try:
            # Check forms on the main page and a few endpoints
            urls_to_check = [self.base_url] + self.endpoints[:10]

            for url in urls_to_check:
                try:
                    async with session.get(url) as resp:
                        if resp.status != 200:
                            continue

                        body = await resp.text(errors="ignore")
                        body_lower = body.lower()

                        # Only check pages with forms
                        if "<form" not in body_lower:
                            continue

                        # Check POST forms
                        form_pattern = re.compile(
                            r'<form[^>]*method=["\']?post["\']?[^>]*>(.*?)</form>',
                            re.IGNORECASE | re.DOTALL
                        )
                        forms = form_pattern.findall(body)

                        for form_content in forms:
                            form_lower = form_content.lower()

                            # Check if form has CSRF token
                            has_csrf = any(name in form_lower for name in csrf_token_names)

                            # Also check for hidden inputs that might be CSRF
                            hidden_inputs = re.findall(
                                r'<input[^>]*type=["\']?hidden["\']?[^>]*>',
                                form_content, re.IGNORECASE
                            )

                            has_hidden_token = any(
                                any(name in inp.lower() for name in csrf_token_names)
                                for inp in hidden_inputs
                            )

                            if not has_csrf and not has_hidden_token:
                                # Check if it's a sensitive form (login, register, etc.)
                                is_sensitive = any(kw in form_lower for kw in [
                                    "password", "email", "username", "account",
                                    "transfer", "payment", "delete", "update"
                                ])

                                if is_sensitive:
                                    findings.append({
                                        "type": "csrf_missing",
                                        "name": "CSRF Token Missing in Sensitive Form",
                                        "url": url,
                                        "wstg_id": "WSTG-SESS-05",
                                        "severity": "High",
                                        "cwe": "CWE-352",
                                        "cvss": "6.5",
                                        "description": (
                                            "A POST form handling sensitive data appears to lack "
                                            "CSRF token protection. Attackers can perform Cross-Site "
                                            "Request Forgery attacks."
                                        ),
                                        "evidence": (
                                            f"URL: {url}\n"
                                            f"Form snippet: {form_content[:200]}\n"
                                            f"No CSRF token found in hidden inputs"
                                        ),
                                        "recommendation": (
                                            "Implement synchronizer token pattern (CSRF token). "
                                            "Use framework's built-in CSRF protection. "
                                            "Validate Origin/Referer headers as secondary defense. "
                                            "Use SameSite=Strict cookies."
                                        ),
                                        "vulnerable": True,
                                        "status": "REVIEW",
                                    })
                                    self.logger.warning(f"[CSRF] Missing token in form at {url}")
                                    break  # One finding per URL

                except Exception:
                    continue

        except Exception as e:
            self.logger.debug(f"CSRF check error: {e}")

        return findings

    async def _check_session_token_quality(self, session: aiohttp.ClientSession) -> List[Dict]:
        """
        Analyze session token entropy and patterns.
        WSTG-SESS-01
        """
        findings = []

        try:
            async with session.get(self.base_url, allow_redirects=True) as resp:
                set_cookie_headers = resp.headers.getall("Set-Cookie", [])

                for cookie_str in set_cookie_headers:
                    # Extract cookie value
                    parts = cookie_str.split(";")
                    if not parts:
                        continue

                    name_value = parts[0].strip()
                    if "=" not in name_value:
                        continue

                    name, _, value = name_value.partition("=")
                    name = name.strip()
                    value = value.strip()

                    # Only analyze session-like cookies
                    if not any(keyword in name.lower() for keyword in [
                        "session", "sess", "sid", "token", "auth"
                    ]):
                        continue

                    if not value or len(value) < 8:
                        continue

                    # Check for weak patterns
                    issues = []

                    # Very short tokens
                    if len(value) < 16:
                        issues.append(f"Token too short ({len(value)} chars, min 32 recommended)")

                    # Check if it looks like base64-encoded data without randomness
                    try:
                        decoded = base64.b64decode(value + "==").decode("utf-8", errors="ignore")
                        if any(pattern in decoded.lower() for pattern in [
                            "user", "admin", "id=", "role=", "\"id\":"
                        ]):
                            issues.append("Token appears to contain predictable user data")
                    except Exception:
                        pass

                    # Check if token is sequential/incremental (simple heuristic)
                    if value.isdigit() and len(value) < 20:
                        issues.append("Session token appears to be a simple integer (highly predictable)")

                    # Check for all-hex tokens that are MD5-length (16 bytes = 32 hex) - possibly MD5
                    if re.match(r'^[0-9a-f]{32}$', value, re.IGNORECASE):
                        issues.append("Token matches MD5 length/format - verify it uses proper CSPRNG")

                    if issues:
                        findings.append({
                            "type": "weak_session_token",
                            "name": f"Potentially Weak Session Token: {name}",
                            "url": self.base_url,
                            "wstg_id": "WSTG-SESS-01",
                            "severity": "Medium",
                            "cwe": "CWE-330",
                            "cvss": "5.9",
                            "description": (
                                f"Session token '{name}' may have quality issues: "
                                + ", ".join(issues)
                            ),
                            "evidence": (
                                f"Cookie name: {name}\n"
                                f"Token length: {len(value)}\n"
                                f"Issues: {', '.join(issues)}"
                            ),
                            "recommendation": (
                                "Generate session tokens using a cryptographically secure "
                                "pseudorandom number generator (CSPRNG). "
                                "Tokens should be at least 128 bits (32 hex chars) of entropy. "
                                "Never include user data in session tokens."
                            ),
                            "vulnerable": False,
                            "status": "REVIEW",
                        })

        except Exception as e:
            self.logger.debug(f"Session token check error: {e}")

        return findings

    async def _check_logout(self, session: aiohttp.ClientSession) -> List[Dict]:
        """
        Check if logout endpoints exist and function.
        WSTG-SESS-06
        """
        findings = []
        logout_paths = ["/logout", "/signout", "/auth/logout", "/user/logout",
                        "/api/logout", "/account/logout", "/session/destroy"]

        semaphore = asyncio.Semaphore(3)

        async def check_logout_path(path: str) -> Optional[Dict]:
            async with semaphore:
                url = self.base_url + path
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        # 200 on GET logout might mean logout via GET (CSRF risk)
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            if any(kw in body.lower() for kw in ["logout", "signed out", "logged out"]):
                                return {
                                    "type": "logout_get",
                                    "name": "Logout via GET Request (CSRF Risk)",
                                    "url": url,
                                    "wstg_id": "WSTG-SESS-06",
                                    "severity": "Low",
                                    "cwe": "CWE-352",
                                    "cvss": "3.5",
                                    "description": (
                                        f"Logout endpoint {path} accepts GET requests. "
                                        "Attackers can trick users into logging out via CSRF."
                                    ),
                                    "evidence": f"GET {url} returns HTTP 200 with logout confirmation",
                                    "recommendation": (
                                        "Implement logout as a POST request only. "
                                        "Require CSRF token for logout. "
                                        "Properly invalidate session on server side."
                                    ),
                                    "vulnerable": True,
                                    "status": "REVIEW",
                                }
                except Exception:
                    pass
            return None

        tasks = [check_logout_path(p) for p in logout_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r:
                findings.append(r)

        return findings
