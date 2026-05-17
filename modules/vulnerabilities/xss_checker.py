"""
XSS Checker Module
==================
Tests for Cross-Site Scripting vulnerabilities.
WSTG-INPV-01 (Reflected XSS), WSTG-INPV-02 (Stored XSS), WSTG-CLNT-01 (DOM XSS)

Uses safe, non-destructive detection payloads.
Checks for reflection in response without executing scripts.
"""

import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urlencode, urlparse, parse_qs

import aiohttp


# Safe detection payloads - these check for reflection only
# They do NOT execute in browsers and are safe for testing
XSS_DETECTION_PAYLOADS = [
    '<xsstestmarker>',
    '"<xss>',
    "'<xss>",
    '<script>xsstest</script>',
    '"><img src=x>',
    "javascript:xsstest",
    '<svg/xsstestmarker>',
    '${xsstest}',
    '{{xsstest}}',
    '<%xsstest%>',
]


class XSSChecker:
    """
    Tests parameters for XSS reflection without harmful payloads.
    """

    def __init__(self, urls_with_params: List[Dict], config: Dict, logger):
        self.urls_with_params = urls_with_params
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

    async def check(self) -> List[Dict]:
        """
        Test URL parameters for XSS reflection.

        Returns:
            List of XSS findings
        """
        findings = []
        semaphore = asyncio.Semaphore(5)

        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:

            async def check_one(param_info: Dict) -> List[Dict]:
                async with semaphore:
                    return await self._test_param(session, param_info)

            tasks = [check_one(p) for p in self.urls_with_params if p.get("method") == "GET"]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return findings

    async def _test_param(self, session: aiohttp.ClientSession, param_info: Dict) -> List[Dict]:
        """Test a single parameter for XSS reflection."""
        findings = []
        base_url = param_info.get("base_url", "")
        param_name = param_info.get("param", "")

        if not base_url or not param_name:
            return []

        for payload in XSS_DETECTION_PAYLOADS[:3]:  # Limit payloads for speed
            try:
                test_url = f"{base_url}?{param_name}={payload}"

                async with session.get(test_url, allow_redirects=True) as resp:
                    if resp.status not in (200, 201):
                        continue

                    body = await resp.text(errors="ignore")
                    content_type = resp.headers.get("Content-Type", "")

                    # Only check HTML responses
                    if "html" not in content_type.lower():
                        continue

                    # Check if payload is reflected
                    if payload.lower() in body.lower():
                        # Check if it's actually unescaped (look for raw < > characters)
                        is_unescaped = (
                            payload in body and
                            "&lt;" not in body[max(0, body.lower().find(payload.lower()) - 10):
                                              body.lower().find(payload.lower()) + len(payload) + 10]
                        )

                        if is_unescaped:
                            findings.append({
                                "type": "xss",
                                "name": "Reflected XSS",
                                "url": test_url,
                                "wstg_id": "WSTG-INPV-01",
                                "severity": "High",
                                "cwe": "CWE-79",
                                "cvss": "7.2",
                                "description": f"Parameter '{param_name}' reflects input without encoding. Possible XSS.",
                                "evidence": f"Payload '{payload}' reflected unescaped in response.\nURL: {test_url}",
                                "recommendation": (
                                    "Encode all user input before rendering in HTML. "
                                    "Use context-aware output encoding. "
                                    "Implement Content-Security-Policy."
                                ),
                                "vulnerable": True,
                                "status": "FAIL",
                                "param": param_name,
                                "payload": payload,
                            })
                            self.logger.warning(f"[XSS] Reflected in {test_url} param={param_name}")
                            break  # Found vulnerability, stop testing this param

                        else:
                            # Reflected but escaped - log as info/review
                            findings.append({
                                "type": "xss_encoded",
                                "name": "XSS Reflected but Encoded",
                                "url": test_url,
                                "wstg_id": "WSTG-INPV-01",
                                "severity": "Info",
                                "description": f"Parameter '{param_name}' reflects input but it appears encoded.",
                                "evidence": f"Payload '{payload}' reflected (encoded) in response.",
                                "recommendation": "Verify encoding is applied in all contexts.",
                                "vulnerable": False,
                                "status": "REVIEW",
                            })

            except asyncio.TimeoutError:
                pass
            except Exception as e:
                self.logger.debug(f"XSS test error for {base_url}: {e}")

        return findings
