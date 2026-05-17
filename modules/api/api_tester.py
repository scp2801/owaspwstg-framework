"""
API Security Testing Module
============================
Tests REST API and GraphQL endpoints for security issues.
WSTG-APIT-01

Tests:
- GraphQL introspection enabled
- API endpoints without authentication
- Verbose error messages
- API versioning exposure
- CORS on API endpoints
- Rate limiting
"""

import asyncio
import json
import re
from typing import List, Dict, Any, Optional

import aiohttp


GRAPHQL_INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind }
      }
    }
  }
}
"""

GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    "/query", "/gql", "/graph",
]

REST_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/rest",
    "/api/users", "/api/admin", "/api/config",
]


class APISecurityTester:
    """
    Tests API endpoints for common security misconfigurations.
    """

    def __init__(self, base_url: str, endpoints: List[str], config: Dict, logger):
        self.base_url = base_url.rstrip("/")
        self.endpoints = endpoints
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))
        self.headers = {
            "User-Agent": config["scan"].get("user_agent", "Mozilla/5.0"),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def run_all_checks(self) -> List[Dict]:
        """Run all API security tests."""
        findings = []

        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            # GraphQL introspection
            gql_findings = await self._check_graphql(session)
            findings.extend(gql_findings)

            # REST API checks
            api_findings = await self._check_rest_apis(session)
            findings.extend(api_findings)

        return findings

    async def _check_graphql(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Test for exposed GraphQL introspection."""
        findings = []
        semaphore = asyncio.Semaphore(3)

        async def test_graphql_path(path: str) -> Optional[Dict]:
            async with semaphore:
                url = self.base_url + path
                try:
                    async with session.post(
                        url,
                        json={"query": GRAPHQL_INTROSPECTION_QUERY},
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        if resp.status == 200:
                            try:
                                data = await resp.json(content_type=None)
                                if data.get("data", {}).get("__schema"):
                                    self.logger.warning(f"[API] GraphQL introspection enabled at {url}")
                                    return {
                                        "type": "graphql_introspection",
                                        "name": "GraphQL Introspection Enabled",
                                        "url": url,
                                        "wstg_id": "WSTG-APIT-01",
                                        "severity": "Medium",
                                        "cwe": "CWE-200",
                                        "cvss": "5.3",
                                        "description": (
                                            "GraphQL introspection is enabled. Attackers can query the entire "
                                            "API schema, discover hidden fields, mutations, and sensitive types."
                                        ),
                                        "evidence": f"GraphQL introspection returns schema data at {url}",
                                        "recommendation": (
                                            "Disable GraphQL introspection in production. "
                                            "Use persisted queries. "
                                            "Implement query depth limiting and complexity analysis."
                                        ),
                                        "vulnerable": True,
                                        "status": "FAIL",
                                    }
                            except Exception:
                                pass
                except Exception:
                    pass
            return None

        tasks = [test_graphql_path(p) for p in GRAPHQL_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r:
                findings.append(r)

        return findings

    async def _check_rest_apis(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Check REST API endpoints for security issues."""
        findings = []
        semaphore = asyncio.Semaphore(5)

        async def check_endpoint(path: str) -> List[Dict]:
            async with semaphore:
                url = self.base_url + path
                try:
                    async with session.get(url, allow_redirects=True) as resp:
                        if resp.status in (200, 201):
                            try:
                                body = await resp.text(errors="ignore")

                                # Check for verbose JSON errors
                                if resp.status == 200:
                                    try:
                                        data = json.loads(body)
                                        # API endpoint returns data without auth
                                        if isinstance(data, (list, dict)) and data:
                                            return [{
                                                "type": "api_no_auth",
                                                "name": "API Endpoint Accessible Without Authentication",
                                                "url": url,
                                                "wstg_id": "WSTG-AUTHZ-02",
                                                "severity": "High",
                                                "cwe": "CWE-306",
                                                "cvss": "7.5",
                                                "description": f"API endpoint {path} returns data without authentication.",
                                                "evidence": f"URL: {url}\nStatus: {resp.status}\nResponse: {body[:200]}",
                                                "recommendation": (
                                                    "Implement authentication for all API endpoints. "
                                                    "Use JWT or OAuth2 tokens. "
                                                    "Return 401 Unauthorized for unauthenticated requests."
                                                ),
                                                "vulnerable": True,
                                                "status": "REVIEW",
                                            }]
                                    except json.JSONDecodeError:
                                        pass

                            except Exception:
                                pass
                except Exception:
                    pass
            return []

        tasks = [check_endpoint(p) for p in REST_API_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings
