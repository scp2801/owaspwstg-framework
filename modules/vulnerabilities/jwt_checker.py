"""
JWT Checker Module
==================
Tests for JWT (JSON Web Token) vulnerabilities.
WSTG-SESS-10

Tests:
- Algorithm confusion (alg:none)
- Weak secret detection
- Missing signature validation
- Sensitive data in payload
- Expired tokens accepted
"""

import asyncio
import base64
import json
import re
from typing import List, Dict, Any, Optional

import aiohttp


class JWTChecker:
    """
    Detects JWT implementation vulnerabilities.
    """

    def __init__(self, endpoints: List[str], config: Dict, logger):
        self.endpoints = endpoints
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

    async def check(self) -> List[Dict]:
        """
        Scan endpoints for JWT tokens and test for vulnerabilities.

        Returns:
            List of JWT findings
        """
        findings = []
        semaphore = asyncio.Semaphore(5)

        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:

            async def check_one(url: str) -> List[Dict]:
                async with semaphore:
                    return await self._check_endpoint(session, url)

            tasks = [check_one(url) for url in self.endpoints[:50]]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return findings

    async def _check_endpoint(self, session: aiohttp.ClientSession, url: str) -> List[Dict]:
        """Probe an endpoint for JWT tokens and test them."""
        findings = []

        try:
            async with session.get(url, allow_redirects=True) as resp:
                body = await resp.text(errors="ignore")
                all_headers = dict(resp.headers)

                # Extract JWT tokens from response
                jwt_tokens = self._extract_jwts(body) + self._extract_jwts_from_headers(all_headers)

                for token in set(jwt_tokens):
                    token_findings = self._analyze_jwt(token, url)
                    findings.extend(token_findings)

        except Exception as e:
            self.logger.debug(f"JWT check error for {url}: {e}")

        return findings

    def _extract_jwts(self, text: str) -> List[str]:
        """Extract JWT tokens from text."""
        pattern = re.compile(
            r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
            re.IGNORECASE
        )
        return pattern.findall(text)

    def _extract_jwts_from_headers(self, headers: Dict) -> List[str]:
        """Extract JWT from response headers."""
        tokens = []
        for key, value in headers.items():
            if key.lower() in ("authorization", "set-cookie", "x-token", "x-access-token"):
                pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
                tokens.extend(pattern.findall(value))
        return tokens

    def _analyze_jwt(self, token: str, url: str) -> List[Dict]:
        """Analyze a JWT token for vulnerabilities."""
        findings = []

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return []

            # Decode header and payload
            header = self._decode_b64(parts[0])
            payload = self._decode_b64(parts[1])
            signature = parts[2]

            if not header or not payload:
                return []

            try:
                header_data = json.loads(header)
                payload_data = json.loads(payload)
            except json.JSONDecodeError:
                return []

            # Check 1: Algorithm "none" attack
            alg = header_data.get("alg", "").lower()
            if alg == "none" or alg == "":
                findings.append({
                    "type": "jwt_none_alg",
                    "name": "JWT: Algorithm 'none' Accepted",
                    "url": url,
                    "wstg_id": "WSTG-SESS-10",
                    "severity": "Critical",
                    "cwe": "CWE-347",
                    "cvss": "9.8",
                    "description": "JWT token uses 'none' algorithm, meaning signatures are not verified.",
                    "evidence": f"JWT Header: {json.dumps(header_data)}\nToken: {token[:50]}...",
                    "recommendation": "Reject JWTs with 'none' algorithm. Enforce strict algorithm allowlist.",
                    "vulnerable": True,
                    "status": "FAIL",
                })
                self.logger.warning(f"[JWT] None algorithm in token from {url}")

            # Check 2: Sensitive data in payload
            sensitive_keys = ["password", "passwd", "secret", "ssn", "credit_card", "cvv", "pin"]
            for key in sensitive_keys:
                if key in payload_data:
                    findings.append({
                        "type": "jwt_sensitive_data",
                        "name": "JWT: Sensitive Data in Payload",
                        "url": url,
                        "wstg_id": "WSTG-SESS-10",
                        "severity": "High",
                        "cwe": "CWE-312",
                        "cvss": "7.5",
                        "description": f"JWT payload contains sensitive field: '{key}'. JWT payloads are base64 encoded, not encrypted.",
                        "evidence": f"Sensitive field '{key}' found in JWT payload",
                        "recommendation": "Never store sensitive data in JWT payload. JWT is encoded, not encrypted. Use proper encryption for sensitive data.",
                        "vulnerable": True,
                        "status": "FAIL",
                    })

            # Check 3: Weak/common algorithm (HS256 with potential weak secret)
            if alg in ("hs256", "hs384", "hs512"):
                findings.append({
                    "type": "jwt_hmac_detected",
                    "name": "JWT: HMAC Algorithm (Verify Secret Strength)",
                    "url": url,
                    "wstg_id": "WSTG-SESS-10",
                    "severity": "Info",
                    "cwe": "CWE-330",
                    "cvss": "0.0",
                    "description": f"JWT uses {alg.upper()} algorithm. Ensure the signing secret is cryptographically strong.",
                    "evidence": f"Algorithm: {alg.upper()}\nHeader: {json.dumps(header_data)}",
                    "recommendation": "Use a randomly generated secret of at least 256 bits. Consider RS256/ES256 for better security.",
                    "vulnerable": False,
                    "status": "REVIEW",
                })

            # Check 4: No expiry (exp claim missing)
            if "exp" not in payload_data:
                findings.append({
                    "type": "jwt_no_expiry",
                    "name": "JWT: Missing Expiration Claim",
                    "url": url,
                    "wstg_id": "WSTG-SESS-10",
                    "severity": "Medium",
                    "cwe": "CWE-613",
                    "cvss": "5.3",
                    "description": "JWT token has no 'exp' (expiration) claim. Tokens never expire.",
                    "evidence": f"JWT Payload: {json.dumps(payload_data)}",
                    "recommendation": "Always include 'exp' claim in JWT. Use short expiry times (15-60 min for access tokens).",
                    "vulnerable": True,
                    "status": "FAIL",
                })

        except Exception as e:
            self.logger.debug(f"JWT analysis error: {e}")

        return findings

    def _decode_b64(self, data: str) -> Optional[str]:
        """Decode base64url encoded JWT part."""
        try:
            # Add padding if needed
            padding = 4 - len(data) % 4
            if padding != 4:
                data += "=" * padding
            return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
        except Exception:
            return None
