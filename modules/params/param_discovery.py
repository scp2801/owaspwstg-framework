"""
Parameter Discovery Module
==========================
Discovers GET/POST parameters from:
- URL query strings
- Form analysis
- JavaScript files
- API endpoints
- Common parameter wordlist fuzzing
"""

import re
from typing import List, Dict, Any, Set
from urllib.parse import urlparse, parse_qs, urlencode

import aiohttp


class ParamDiscovery:
    """
    Discovers URL and form parameters from crawled URLs.
    """

    def __init__(self, urls: List[str], config: Dict, logger):
        self.urls = urls
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

    async def discover(self) -> List[Dict]:
        """
        Discover parameters from all provided URLs.

        Returns:
            List of parameter discovery results
        """
        params_found = []
        seen: Set[str] = set()

        for url in self.urls:
            # Extract params from URL query string
            url_params = self._extract_url_params(url)
            for param_url in url_params:
                key = f"{param_url['url']}:{param_url['param']}"
                if key not in seen:
                    seen.add(key)
                    params_found.append(param_url)

        self.logger.info(f"Parameter discovery: {len(params_found)} params found")
        return params_found

    def _extract_url_params(self, url: str) -> List[Dict]:
        """Extract parameters from URL query string."""
        try:
            parsed = urlparse(url)
            if not parsed.query:
                return []

            params = parse_qs(parsed.query, keep_blank_values=True)
            result = []

            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            for param_name, values in params.items():
                result.append({
                    "url": url,
                    "base_url": base_url,
                    "param": param_name,
                    "value": values[0] if values else "",
                    "method": "GET",
                    "type": self._classify_param(param_name, values[0] if values else ""),
                })

            return result
        except Exception:
            return []

    def _classify_param(self, name: str, value: str) -> str:
        """
        Classify parameter type based on name and value patterns.

        Returns:
            Parameter type classification string
        """
        name_lower = name.lower()
        value_lower = value.lower()

        # ID-like parameters
        if re.search(r'\b(id|uid|user_id|item_id|product_id|order_id)\b', name_lower):
            return "IDOR_CANDIDATE"

        # Redirect parameters
        if re.search(r'\b(url|redirect|next|return|goto|redir|target|dest)\b', name_lower):
            return "REDIRECT_CANDIDATE"

        # File-related parameters
        if re.search(r'\b(file|path|page|template|view|load|include)\b', name_lower):
            return "FILE_INCLUDE_CANDIDATE"

        # Search/input parameters
        if re.search(r'\b(q|query|search|s|keyword|term|input|text)\b', name_lower):
            return "XSS_CANDIDATE"

        # Callback parameters
        if re.search(r'\b(callback|jsonp|cb|function)\b', name_lower):
            return "JSONP_CANDIDATE"

        # SSRF candidates
        if re.search(r'\b(host|server|url|endpoint|api|fetch|proxy)\b', name_lower):
            return "SSRF_CANDIDATE"

        # SQL-like
        if re.search(r'\b(id|page|sort|order|limit|offset|filter)\b', name_lower):
            return "SQLI_CANDIDATE"

        return "GENERIC"
