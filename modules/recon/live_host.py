"""
Live Host Detector
==================
Probes discovered hosts to identify live HTTP/HTTPS services.
Captures: status codes, titles, technologies, redirects, headers.
"""

import asyncio
import re
from typing import List, Dict, Any, Optional

import aiohttp


class LiveHostDetector:
    """
    Detects live HTTP/HTTPS hosts from a list of hostnames/IPs.
    """

    def __init__(self, hosts: List[str], config: Dict, logger):
        self.hosts = hosts
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=self.config["scan"].get("timeout", 30))
        self.headers = {
            "User-Agent": self.config["scan"].get("user_agent", "Mozilla/5.0")
        }
        self.threads = self.config.get("recon", {}).get("live_host_threads", 20)

    async def detect(self) -> List[Dict]:
        """
        Probe all hosts for live HTTP/HTTPS services.

        Returns:
            List of live host info dictionaries
        """
        semaphore = asyncio.Semaphore(self.threads)
        live_hosts = []

        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False, limit=self.threads),
        ) as session:

            async def probe_host(host: str) -> Optional[Dict]:
                async with semaphore:
                    return await self._probe(session, host)

            tasks = [probe_host(h) for h in self.hosts]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result:
                live_hosts.append(result)

        self.logger.info(f"Live host detection: {len(live_hosts)}/{len(self.hosts)} hosts alive")
        return live_hosts

    async def _probe(self, session: aiohttp.ClientSession, host: str) -> Optional[Dict]:
        """Probe a single host on both HTTP and HTTPS."""
        host = host.strip()
        if not host:
            return None

        # Try HTTPS first, then HTTP
        for scheme in ["https", "http"]:
            url = f"{scheme}://{host}"
            try:
                async with session.get(
                    url,
                    allow_redirects=True,
                    max_redirects=5,
                ) as resp:
                    text = await resp.text(errors="ignore")
                    title = self._extract_title(text)
                    tech = self._detect_technologies(resp.headers, text)

                    return {
                        "host": host,
                        "url": str(resp.url),
                        "original_url": url,
                        "status_code": resp.status,
                        "title": title,
                        "technologies": tech,
                        "server": resp.headers.get("Server", ""),
                        "content_type": resp.headers.get("Content-Type", ""),
                        "content_length": resp.headers.get("Content-Length", ""),
                        "redirect_url": str(resp.url) if str(resp.url) != url else "",
                        "headers": dict(resp.headers),
                    }

            except asyncio.TimeoutError:
                continue
            except aiohttp.ClientConnectorError:
                continue
            except Exception as e:
                self.logger.debug(f"Probe error for {url}: {e}")
                continue

        return None

    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML."""
        match = re.search(r"<title[^>]*>([^<]{1,200})</title>", html, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return ""

    def _detect_technologies(self, headers: dict, body: str) -> List[str]:
        """Detect technologies from response headers and body."""
        tech = []
        header_str = str(headers).lower()
        body_lower = body.lower()

        # Server technologies
        server = headers.get("Server", "").lower()
        if "nginx" in server: tech.append("Nginx")
        if "apache" in server: tech.append("Apache")
        if "iis" in server: tech.append("IIS")
        if "cloudflare" in server: tech.append("Cloudflare")
        if "litespeed" in server: tech.append("LiteSpeed")

        # Frameworks/CMS
        if "x-powered-by" in header_str:
            xpb = headers.get("X-Powered-By", "")
            if xpb: tech.append(xpb)

        if "wp-content" in body_lower: tech.append("WordPress")
        if "drupal" in body_lower: tech.append("Drupal")
        if "joomla" in body_lower: tech.append("Joomla")
        if "django" in body_lower: tech.append("Django")
        if "laravel" in body_lower: tech.append("Laravel")
        if "react" in body_lower: tech.append("React")
        if "angular" in body_lower: tech.append("Angular")
        if "vue.js" in body_lower: tech.append("Vue.js")
        if "__next" in body_lower: tech.append("Next.js")

        # Security headers indicators
        if "strict-transport-security" in header_str: tech.append("HSTS")
        if "content-security-policy" in header_str: tech.append("CSP")

        return list(set(tech))
