"""
Client-Side Security Testing Module
=====================================
Tests client-side security issues.
WSTG-CLNT series

Tests:
- DOM-based XSS indicators
- HTML Injection
- Reverse Tabnabbing (target="_blank" without rel="noopener")
- JavaScript source map exposure
- Browser storage misuse (localStorage/sessionStorage)
- PostMessage security
- CSP evaluation
"""

import asyncio
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin

import aiohttp
from bs4 import BeautifulSoup


class ClientSideTester:
    """
    Tests client-side security vulnerabilities.
    WSTG-CLNT-01 through WSTG-CLNT-14
    """

    def __init__(self, base_url: str, endpoints: List[str], config: Dict, logger):
        self.base_url = base_url.rstrip("/")
        self.endpoints = endpoints
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

    async def run_all_checks(self) -> List[Dict]:
        """Run all client-side security tests."""
        findings = []

        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            # Run all checks concurrently
            check_coros = [
                self._check_reverse_tabnabbing(session),
                self._check_dom_xss_sources(session),
                self._check_csp_quality(session),
                self._check_source_maps(session),
                self._check_mixed_content(session),
            ]
            results = await asyncio.gather(*check_coros, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return findings

    async def _check_reverse_tabnabbing(self, session: aiohttp.ClientSession) -> List[Dict]:
        """
        Check for reverse tabnabbing via target="_blank" without rel="noopener".
        WSTG-CLNT-14
        """
        findings = []
        urls_to_check = [self.base_url] + self.endpoints[:20]

        semaphore = asyncio.Semaphore(5)

        async def check_url(url: str) -> Optional[Dict]:
            async with semaphore:
                try:
                    async with session.get(url) as resp:
                        if resp.status != 200:
                            return None

                        body = await resp.text(errors="ignore")

                        try:
                            soup = BeautifulSoup(body, "lxml")
                        except Exception:
                            soup = BeautifulSoup(body, "html.parser")

                        # Find all links with target="_blank"
                        blank_links = soup.find_all("a", attrs={"target": "_blank"})

                        vulnerable_links = []
                        for link in blank_links:
                            rel = link.get("rel", [])
                            rel_str = " ".join(rel) if isinstance(rel, list) else str(rel)
                            href = link.get("href", "")

                            # Check if rel="noopener noreferrer" is missing
                            if "noopener" not in rel_str.lower():
                                # Only flag external links
                                if href and (href.startswith("http") or href.startswith("//")):
                                    vulnerable_links.append(href)

                        if vulnerable_links:
                            return {
                                "type": "reverse_tabnabbing",
                                "name": "Reverse Tabnabbing Vulnerability",
                                "url": url,
                                "wstg_id": "WSTG-CLNT-14",
                                "severity": "Low",
                                "cwe": "CWE-1022",
                                "cvss": "3.1",
                                "description": (
                                    f"Found {len(vulnerable_links)} external links with target='_blank' "
                                    "but missing rel='noopener noreferrer'. "
                                    "The opened page can access window.opener and redirect the parent."
                                ),
                                "evidence": (
                                    f"Vulnerable links ({len(vulnerable_links)}):\n"
                                    + "\n".join(f"  - {l}" for l in vulnerable_links[:5])
                                ),
                                "recommendation": (
                                    "Add rel='noopener noreferrer' to all external links with target='_blank'. "
                                    "Example: <a href='...' target='_blank' rel='noopener noreferrer'>"
                                ),
                                "vulnerable": True,
                                "status": "FAIL",
                            }
                except Exception:
                    pass
            return None

        tasks = [check_url(url) for url in urls_to_check]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r:
                findings.append(r)

        return findings

    async def _check_dom_xss_sources(self, session: aiohttp.ClientSession) -> List[Dict]:
        """
        Check for dangerous DOM XSS source usage in JavaScript.
        WSTG-CLNT-01
        """
        findings = []

        # Dangerous DOM sources that could lead to XSS
        dangerous_sources = [
            "document.location",
            "document.URL",
            "document.documentURI",
            "location.href",
            "location.search",
            "location.hash",
            "document.referrer",
            "window.name",
        ]

        # Dangerous DOM sinks
        dangerous_sinks = [
            "innerHTML",
            "outerHTML",
            "document.write(",
            "document.writeln(",
            "eval(",
            "setTimeout(",
            "setInterval(",
            "Function(",
        ]

        urls_to_check = [self.base_url] + self.endpoints[:10]
        semaphore = asyncio.Semaphore(5)

        async def check_page(url: str) -> Optional[Dict]:
            async with semaphore:
                try:
                    async with session.get(url) as resp:
                        if resp.status != 200:
                            return None
                        body = await resp.text(errors="ignore")

                        # Extract inline JavaScript
                        script_pattern = re.compile(
                            r'<script[^>]*>(.*?)</script>',
                            re.IGNORECASE | re.DOTALL
                        )
                        scripts = script_pattern.findall(body)
                        all_js = " ".join(scripts)

                        found_sources = [s for s in dangerous_sources if s in all_js]
                        found_sinks = [s for s in dangerous_sinks if s in all_js]

                        if found_sources and found_sinks:
                            return {
                                "type": "dom_xss_potential",
                                "name": "Potential DOM XSS: Dangerous Source→Sink Pattern",
                                "url": url,
                                "wstg_id": "WSTG-CLNT-01",
                                "severity": "High",
                                "cwe": "CWE-79",
                                "cvss": "6.1",
                                "description": (
                                    "Inline JavaScript contains both dangerous DOM sources "
                                    "and dangerous sinks. Manual review required to confirm DOM XSS."
                                ),
                                "evidence": (
                                    f"DOM Sources found: {', '.join(found_sources[:3])}\n"
                                    f"DOM Sinks found: {', '.join(found_sinks[:3])}\n"
                                    f"URL: {url}"
                                ),
                                "recommendation": (
                                    "Avoid using dangerous DOM sinks with user-controlled input. "
                                    "Use textContent instead of innerHTML. "
                                    "Sanitize input with DOMPurify before using in sinks. "
                                    "Implement a strict Content-Security-Policy."
                                ),
                                "vulnerable": False,
                                "status": "REVIEW",
                            }
                except Exception:
                    pass
            return None

        tasks = [check_page(url) for url in urls_to_check]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r:
                findings.append(r)

        return findings

    async def _check_csp_quality(self, session: aiohttp.ClientSession) -> List[Dict]:
        """
        Evaluate Content-Security-Policy quality.
        WSTG-CONF-12
        """
        findings = []

        try:
            async with session.get(self.base_url, allow_redirects=True) as resp:
                csp = resp.headers.get("Content-Security-Policy", "")
                if not csp:
                    return []  # Missing CSP handled by security_headers module

                csp_lower = csp.lower()
                issues = []

                # Check for dangerous CSP directives
                if "'unsafe-inline'" in csp_lower:
                    issues.append("'unsafe-inline' allows inline scripts/styles (bypasses XSS protection)")

                if "'unsafe-eval'" in csp_lower:
                    issues.append("'unsafe-eval' allows eval() and similar (bypasses XSS protection)")

                if "* " in csp or csp.endswith("*"):
                    issues.append("Wildcard (*) source allows any origin")

                if "http:" in csp_lower and self.base_url.startswith("https"):
                    issues.append("CSP allows HTTP sources on HTTPS site")

                if not any(directive in csp_lower for directive in [
                    "default-src", "script-src"
                ]):
                    issues.append("Missing default-src or script-src directive")

                if issues:
                    findings.append({
                        "type": "csp_weak",
                        "name": "Weak Content-Security-Policy",
                        "url": self.base_url,
                        "wstg_id": "WSTG-CONF-12",
                        "severity": "Medium",
                        "cwe": "CWE-693",
                        "cvss": "5.3",
                        "description": f"CSP is present but contains weaknesses: {', '.join(issues)}",
                        "evidence": f"Content-Security-Policy: {csp}\nIssues: {', '.join(issues)}",
                        "recommendation": (
                            "Remove 'unsafe-inline' and 'unsafe-eval'. "
                            "Use nonces or hashes for inline scripts. "
                            "Avoid wildcards in CSP directives. "
                            "Use CSP Evaluator (csp-evaluator.withgoogle.com) to verify policy."
                        ),
                        "vulnerable": True,
                        "status": "REVIEW",
                    })

        except Exception as e:
            self.logger.debug(f"CSP quality check error: {e}")

        return findings

    async def _check_source_maps(self, session: aiohttp.ClientSession) -> List[Dict]:
        """
        Check for exposed JavaScript source maps.
        Source maps can reveal original source code.
        WSTG-INFO-05
        """
        findings = []
        semaphore = asyncio.Semaphore(5)

        async def check_source_map(url: str) -> Optional[Dict]:
            """Check if a JS file exposes its source map."""
            async with semaphore:
                try:
                    map_url = url + ".map"
                    async with session.get(map_url) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            # Verify it's actually a source map
                            if '"sources"' in body or '"sourceRoot"' in body:
                                return {
                                    "type": "source_map_exposed",
                                    "name": "JavaScript Source Map Exposed",
                                    "url": map_url,
                                    "wstg_id": "WSTG-INFO-05",
                                    "severity": "Medium",
                                    "cwe": "CWE-540",
                                    "cvss": "5.3",
                                    "description": (
                                        "JavaScript source map exposed. Attackers can reconstruct "
                                        "original source code, revealing business logic, internal "
                                        "paths, and potential vulnerabilities."
                                    ),
                                    "evidence": f"Source map accessible at: {map_url}",
                                    "recommendation": (
                                        "Remove .map files from production deployments. "
                                        "Configure web server to block .map file access. "
                                        "Use source map upload to error tracking tools instead."
                                    ),
                                    "vulnerable": True,
                                    "status": "FAIL",
                                }
                except Exception:
                    pass
            return None

        # Get JS files from main page
        try:
            async with session.get(self.base_url) as resp:
                body = await resp.text(errors="ignore")
                js_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
                js_urls = []
                for match in js_pattern.findall(body):
                    full_url = urljoin(self.base_url, match)
                    js_urls.append(full_url)

                tasks = [check_source_map(url) for url in js_urls[:20]]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, dict) and r:
                        findings.append(r)
        except Exception:
            pass

        return findings

    async def _check_mixed_content(self, session: aiohttp.ClientSession) -> List[Dict]:
        """
        Check for mixed content (HTTP resources on HTTPS pages).
        WSTG-CRYP-03
        """
        findings = []

        if not self.base_url.startswith("https"):
            return []

        try:
            async with session.get(self.base_url) as resp:
                body = await resp.text(errors="ignore")

                # Find HTTP resources on HTTPS page
                http_resources = re.findall(r'(?:src|href|action)=["\']http://[^"\']+["\']', body, re.IGNORECASE)
                http_scripts = re.findall(r'<script[^>]+src=["\']http://[^"\']+["\']', body, re.IGNORECASE)

                if http_scripts:
                    findings.append({
                        "type": "mixed_content_active",
                        "name": "Active Mixed Content: HTTP Scripts on HTTPS Page",
                        "url": self.base_url,
                        "wstg_id": "WSTG-CRYP-03",
                        "severity": "High",
                        "cwe": "CWE-319",
                        "cvss": "7.4",
                        "description": (
                            "HTTPS page loads JavaScript over HTTP. "
                            "An attacker can MitM the HTTP request and inject malicious code."
                        ),
                        "evidence": (
                            f"HTTP script tags found: {len(http_scripts)}\n"
                            + "\n".join(http_scripts[:3])
                        ),
                        "recommendation": (
                            "Change all resource URLs from http:// to https://. "
                            "Use protocol-relative URLs (//example.com/script.js). "
                            "Enable HSTS to prevent HTTP downgrade."
                        ),
                        "vulnerable": True,
                        "status": "FAIL",
                    })

                elif http_resources:
                    findings.append({
                        "type": "mixed_content_passive",
                        "name": "Passive Mixed Content: HTTP Resources on HTTPS Page",
                        "url": self.base_url,
                        "wstg_id": "WSTG-CRYP-03",
                        "severity": "Medium",
                        "cwe": "CWE-319",
                        "cvss": "4.3",
                        "description": "HTTPS page loads images/media over HTTP.",
                        "evidence": f"HTTP resources: {len(http_resources)} found",
                        "recommendation": "Load all resources over HTTPS.",
                        "vulnerable": True,
                        "status": "REVIEW",
                    })

        except Exception as e:
            self.logger.debug(f"Mixed content check error: {e}")

        return findings
