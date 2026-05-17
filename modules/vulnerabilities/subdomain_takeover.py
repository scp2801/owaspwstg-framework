"""
Subdomain Takeover Checker
==========================
Detects subdomains vulnerable to takeover.
WSTG-CONF-10

Checks DNS CNAME records pointing to:
- Unclaimed GitHub Pages
- Unclaimed Heroku apps
- Unclaimed S3 buckets
- Unclaimed Azure resources
- Other dead third-party services
"""

import asyncio
import re
from typing import List, Dict, Any, Optional

import aiohttp


# Fingerprints for vulnerable services
# Format: service_name, cname_patterns, response_fingerprints
TAKEOVER_SIGNATURES = [
    {
        "service": "GitHub Pages",
        "cname": [".github.io", "github.io"],
        "fingerprint": ["there isn't a github pages site here", "for root url"],
        "severity": "High",
    },
    {
        "service": "Heroku",
        "cname": [".herokudns.com", ".heroku.com"],
        "fingerprint": ["no such app", "heroku | no such app", "there is no app"],
        "severity": "High",
    },
    {
        "service": "AWS S3",
        "cname": [".s3.amazonaws.com", "s3-website"],
        "fingerprint": ["nosuchbucket", "the specified bucket does not exist", "noSuchBucket"],
        "severity": "Critical",
    },
    {
        "service": "AWS CloudFront",
        "cname": [".cloudfront.net"],
        "fingerprint": ["bad request", "error 403", "the request could not be satisfied"],
        "severity": "Medium",
    },
    {
        "service": "Shopify",
        "cname": [".myshopify.com"],
        "fingerprint": ["sorry, this shop is currently unavailable", "only one step left"],
        "severity": "High",
    },
    {
        "service": "Netlify",
        "cname": [".netlify.app", ".netlify.com"],
        "fingerprint": ["not found - request id"],
        "severity": "High",
    },
    {
        "service": "Vercel",
        "cname": [".vercel.app", ".now.sh"],
        "fingerprint": ["the deployment you are looking for", "deployment not found"],
        "severity": "High",
    },
    {
        "service": "Azure",
        "cname": [".azurewebsites.net", ".cloudapp.net", ".azure.com"],
        "fingerprint": ["404 web site not found", "this microsoft azure web app is stopped"],
        "severity": "High",
    },
    {
        "service": "Zendesk",
        "cname": [".zendesk.com"],
        "fingerprint": ["help center closed", "this help center no longer exists"],
        "severity": "High",
    },
    {
        "service": "Tumblr",
        "cname": [".tumblr.com"],
        "fingerprint": ["whatever you were looking for doesn't currently exist", "not found."],
        "severity": "High",
    },
    {
        "service": "WordPress.com",
        "cname": [".wordpress.com"],
        "fingerprint": ["do you want to register"],
        "severity": "Medium",
    },
    {
        "service": "Pantheon",
        "cname": [".pantheonsite.io"],
        "fingerprint": ["the gods are wise", "404 error unknown site"],
        "severity": "High",
    },
    {
        "service": "Fastly",
        "cname": [".fastly.net"],
        "fingerprint": ["fastly error: unknown domain", "please check that this domain has been added"],
        "severity": "Medium",
    },
    {
        "service": "Surge.sh",
        "cname": [".surge.sh"],
        "fingerprint": ["project not found", "surge 404"],
        "severity": "High",
    },
    {
        "service": "Unbounce",
        "cname": [".unbouncepages.com"],
        "fingerprint": ["the requested url was not found on this server"],
        "severity": "Medium",
    },
]


class SubdomainTakeoverChecker:
    """
    Detects subdomain takeover vulnerabilities.
    """

    def __init__(self, subdomains: List[str], config: Dict, logger):
        self.subdomains = subdomains
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=15)
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

    async def check(self) -> List[Dict]:
        """
        Check all subdomains for takeover vulnerabilities.

        Returns:
            List of takeover findings
        """
        findings = []
        semaphore = asyncio.Semaphore(10)

        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:

            async def check_one(subdomain: str) -> Optional[Dict]:
                async with semaphore:
                    return await self._check_subdomain(session, subdomain)

            tasks = [check_one(sub) for sub in self.subdomains[:200]]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result:
                findings.append(result)

        self.logger.info(f"Subdomain takeover check: {len(findings)} potential takeovers found")
        return findings

    async def _check_subdomain(self, session: aiohttp.ClientSession, subdomain: str) -> Optional[Dict]:
        """Check a single subdomain for takeover."""
        # First, check DNS CNAME
        cname = await self._get_cname(subdomain)

        if not cname:
            return None

        # Match CNAME against known vulnerable services
        matched_service = None
        for sig in TAKEOVER_SIGNATURES:
            for cname_pattern in sig["cname"]:
                if cname_pattern in cname.lower():
                    matched_service = sig
                    break
            if matched_service:
                break

        if not matched_service:
            return None

        # Check HTTP response for vulnerability fingerprint
        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"
            try:
                async with session.get(url, allow_redirects=True) as resp:
                    body = await resp.text(errors="ignore")
                    body_lower = body.lower()

                    for fingerprint in matched_service["fingerprint"]:
                        if fingerprint.lower() in body_lower:
                            self.logger.warning(
                                f"[TAKEOVER] {subdomain} → {cname} ({matched_service['service']})"
                            )
                            return {
                                "type": "subdomain_takeover",
                                "name": f"Subdomain Takeover: {matched_service['service']}",
                                "url": url,
                                "subdomain": subdomain,
                                "wstg_id": "WSTG-CONF-10",
                                "severity": matched_service["severity"],
                                "cwe": "CWE-284",
                                "cvss": "9.1" if matched_service["severity"] == "Critical" else "7.5",
                                "description": (
                                    f"Subdomain '{subdomain}' has CNAME pointing to {cname} "
                                    f"({matched_service['service']}) which appears unclaimed. "
                                    "An attacker could claim this service and serve malicious content."
                                ),
                                "evidence": (
                                    f"Subdomain: {subdomain}\n"
                                    f"CNAME: {cname}\n"
                                    f"Service: {matched_service['service']}\n"
                                    f"Fingerprint matched: {fingerprint}\n"
                                    f"Response snippet: {body[:200]}"
                                ),
                                "recommendation": (
                                    f"Remove the DNS CNAME record for {subdomain} or "
                                    f"reclaim the {matched_service['service']} resource. "
                                    "Regularly audit DNS records for dangling entries."
                                ),
                                "vulnerable": True,
                                "status": "FAIL",
                            }
            except Exception:
                continue

        return None

    async def _get_cname(self, subdomain: str) -> str:
        """Get CNAME record for a subdomain."""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(subdomain, "CNAME")
            for rdata in answers:
                return str(rdata.target).rstrip(".")
        except Exception:
            pass

        # Fallback: try socket
        try:
            import socket
            result = socket.getfqdn(subdomain)
            if result != subdomain:
                return result
        except Exception:
            pass

        return ""
