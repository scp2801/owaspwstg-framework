"""
Web Crawler Module
==================
Recursively crawls web applications to discover:
- URLs and endpoints
- Forms and input fields
- JavaScript files
- API endpoints
- Hidden paths from robots.txt / sitemap.xml
- Archived URLs from Wayback Machine
"""

import asyncio
import re
from typing import List, Set, Dict, Any
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup


class WebCrawler:
    """
    Async recursive web application crawler.
    """

    def __init__(self, start_url: str, config: Dict, logger):
        self.start_url = start_url
        self.config = config
        self.logger = logger
        self.max_depth = config.get("crawling", {}).get("max_depth", 3)
        self.max_pages = config.get("crawling", {}).get("max_pages", 500)
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

        # State tracking
        self.visited: Set[str] = set()
        self.urls: Set[str] = set()
        self.forms: List[Dict] = []
        self.js_files: Set[str] = set()

        # Base domain for scoping
        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc

    async def crawl(self) -> Dict[str, Any]:
        """
        Start crawling from the start URL.

        Returns:
            Dictionary with discovered URLs, forms, and JS files
        """
        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=connector,
        ) as session:
            self._session = session

            # Check robots.txt
            if self.config.get("crawling", {}).get("check_robots", True):
                await self._parse_robots()

            # Check sitemap.xml
            if self.config.get("crawling", {}).get("check_sitemap", True):
                await self._parse_sitemap()

            # Start recursive crawl
            await self._crawl_url(self.start_url, depth=0)

        # Get archived URLs
        archived = await self._get_archived_urls()
        self.urls.update(archived)

        result = {
            "urls": list(self.urls),
            "forms": self.forms,
            "js_files": list(self.js_files),
            "total_pages": len(self.visited),
        }

        self.logger.info(
            f"Crawl complete: {len(self.urls)} URLs, "
            f"{len(self.forms)} forms, {len(self.js_files)} JS files"
        )

        return result

    async def _crawl_url(self, url: str, depth: int):
        """Recursively crawl a URL."""
        if depth > self.max_depth:
            return
        if len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return

        self.visited.add(url)
        self.urls.add(url)

        try:
            async with self._session.get(url, allow_redirects=True) as resp:
                if resp.status not in (200, 201):
                    return

                content_type = resp.headers.get("Content-Type", "")
                if "html" not in content_type and "javascript" not in content_type:
                    return

                html = await resp.text(errors="ignore")
                final_url = str(resp.url)
                self.urls.add(final_url)

                # Parse links
                links = self._extract_links(html, final_url)

                # Parse forms
                forms = self._extract_forms(html, final_url)
                self.forms.extend(forms)

                # Collect JS files
                js_urls = self._extract_js_files(html, final_url)
                self.js_files.update(js_urls)

                # Recursively crawl in-scope links
                tasks = []
                for link in links:
                    if self._is_in_scope(link) and link not in self.visited:
                        tasks.append(self._crawl_url(link, depth + 1))

                if tasks:
                    await asyncio.gather(*tasks[:20], return_exceptions=True)

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            self.logger.debug(f"Crawl error for {url}: {e}")

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML."""
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")

        links = []

        # href attributes
        for tag in soup.find_all(["a", "link", "area"], href=True):
            href = tag.get("href", "").strip()
            if href and not href.startswith(("#", "mailto:", "tel:", "javascript:")):
                full_url = urljoin(base_url, href).split("#")[0]
                links.append(full_url)

        # src attributes (for iframes, etc.)
        for tag in soup.find_all(["iframe", "frame"], src=True):
            src = tag.get("src", "").strip()
            if src and src.startswith("http"):
                links.append(src)

        # action attributes (forms)
        for tag in soup.find_all("form", action=True):
            action = tag.get("action", "").strip()
            if action and not action.startswith(("#", "javascript:")):
                full_url = urljoin(base_url, action)
                links.append(full_url)

        return links

    def _extract_forms(self, html: str, page_url: str) -> List[Dict]:
        """Extract form details from HTML."""
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")

        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "") or page_url
            method = form.get("method", "GET").upper()
            full_action = urljoin(page_url, action)

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })

            forms.append({
                "action": full_action,
                "method": method,
                "inputs": inputs,
                "page_url": page_url,
            })

        return forms

    def _extract_js_files(self, html: str, base_url: str) -> List[str]:
        """Extract JavaScript file URLs from HTML."""
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")

        js_files = []
        for script in soup.find_all("script", src=True):
            src = script.get("src", "").strip()
            if src:
                full_url = urljoin(base_url, src)
                js_files.append(full_url)

        return js_files

    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope (same domain)."""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.base_domain and \
                   parsed.scheme in ("http", "https")
        except Exception:
            return False

    async def _parse_robots(self):
        """Parse robots.txt for additional paths."""
        robots_url = f"{self.start_url.rstrip('/')}/robots.txt"
        try:
            async with self._session.get(robots_url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.splitlines():
                        line = line.strip()
                        if line.lower().startswith(("allow:", "disallow:")):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/":
                                full_url = urljoin(self.start_url, path)
                                if self._is_in_scope(full_url):
                                    self.urls.add(full_url)
        except Exception:
            pass

    async def _parse_sitemap(self):
        """Parse sitemap.xml for URLs."""
        sitemap_url = f"{self.start_url.rstrip('/')}/sitemap.xml"
        try:
            async with self._session.get(sitemap_url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    url_pattern = re.compile(r"<loc>(https?://[^<]+)</loc>", re.IGNORECASE)
                    for match in url_pattern.findall(text):
                        if self._is_in_scope(match):
                            self.urls.add(match)
        except Exception:
            pass

    async def _get_archived_urls(self) -> List[str]:
        """Get archived URLs from Wayback Machine CDX API."""
        archived = []
        domain = urlparse(self.start_url).netloc
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
        )
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(cdx_url, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for row in data[1:]:  # Skip header
                            if row and self._is_in_scope(row[0]):
                                archived.append(row[0])
        except Exception as e:
            self.logger.debug(f"Wayback Machine error: {e}")

        return archived
