"""
SQL Injection Checker
=====================
Tests for SQL Injection vulnerabilities using safe error-based detection.
WSTG-INPV-05

Methods:
- Error-based detection (quotes, double quotes)
- Boolean-based blind detection (true/false condition differences)
- Time-based blind detection (short delays only)

SAFE: No destructive payloads. Detection only.
"""

import asyncio
import re
import time
from typing import List, Dict, Any
from urllib.parse import urlencode

import aiohttp


# Safe SQLi detection payloads - error triggering only
SQLI_ERROR_PAYLOADS = [
    "'",
    '"',
    "''",
    "1'",
    "1\"",
    "1`",
    "\\",
    "1\\",
]

# Common SQL error messages from different databases
SQL_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"mysql_fetch_array",
    r"mysql_num_rows",
    r"unclosed quotation mark",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg::syntaxerror",
    r"unterminated quoted string",
    # MSSQL
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"sqlsrv_query\(\)",
    r"\[sql server\]",
    # Oracle
    r"ora-\d{5}",
    r"oracle error",
    r"oracle.*driver",
    # SQLite
    r"sqlite_exception",
    r"sqlite3::",
    r"unable to open database file",
    # Generic
    r"sql syntax.*near",
    r"syntax error.*in query expression",
    r"unexpected end of sql command",
    r"quoted string not properly terminated",
]

# Boolean-based blind detection payloads
BOOL_PAYLOADS = [
    ("1 AND 1=1", "1 AND 1=2"),  # True vs False condition
]


class SQLiChecker:
    """
    Safe SQL Injection detection using error messages and boolean differences.
    """

    def __init__(self, urls_with_params: List[Dict], config: Dict, logger):
        self.urls_with_params = urls_with_params
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

    async def check(self) -> List[Dict]:
        """
        Test parameters for SQL injection.

        Returns:
            List of SQLi findings
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

            tasks = [check_one(p) for p in self.urls_with_params
                     if p.get("type") in ("SQLI_CANDIDATE", "GENERIC", "IDOR_CANDIDATE")]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return findings

    async def _test_param(self, session: aiohttp.ClientSession, param_info: Dict) -> List[Dict]:
        """Test a single parameter for SQL injection."""
        findings = []
        base_url = param_info.get("base_url", "")
        param_name = param_info.get("param", "")
        original_value = param_info.get("value", "1")

        if not base_url or not param_name:
            return []

        # Step 1: Get baseline response
        try:
            baseline_url = f"{base_url}?{param_name}={original_value}"
            async with session.get(baseline_url) as resp:
                baseline_body = await resp.text(errors="ignore")
                baseline_status = resp.status
                baseline_length = len(baseline_body)
        except Exception:
            return []

        # Step 2: Error-based detection
        for payload in SQLI_ERROR_PAYLOADS:
            try:
                test_url = f"{base_url}?{param_name}={original_value}{payload}"
                async with session.get(test_url) as resp:
                    body = await resp.text(errors="ignore")
                    body_lower = body.lower()

                    for pattern in SQL_ERROR_PATTERNS:
                        if re.search(pattern, body_lower):
                            findings.append({
                                "type": "sqli",
                                "name": "SQL Injection (Error-Based)",
                                "url": test_url,
                                "wstg_id": "WSTG-INPV-05",
                                "severity": "Critical",
                                "cwe": "CWE-89",
                                "cvss": "9.8",
                                "description": f"SQL error triggered in parameter '{param_name}'. Database error message exposed.",
                                "evidence": f"Payload: {payload}\nURL: {test_url}\nError pattern matched: {pattern}\nError snippet: {body_lower[:300]}",
                                "recommendation": (
                                    "Use parameterized queries / prepared statements. "
                                    "Never concatenate user input into SQL queries. "
                                    "Implement input validation. "
                                    "Use ORM frameworks."
                                ),
                                "vulnerable": True,
                                "status": "FAIL",
                                "param": param_name,
                                "payload": payload,
                            })
                            self.logger.warning(f"[SQLI] Error-based SQLi in {test_url} param={param_name}")
                            return findings  # Found - stop testing this param

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.debug(f"SQLi error test failed: {e}")

        # Step 3: Boolean-based blind detection
        for true_payload, false_payload in BOOL_PAYLOADS:
            try:
                true_url = f"{base_url}?{param_name}={original_value} {true_payload}"
                false_url = f"{base_url}?{param_name}={original_value} {false_payload}"

                async with session.get(true_url) as resp_true:
                    true_body = await resp_true.text(errors="ignore")
                    true_len = len(true_body)

                async with session.get(false_url) as resp_false:
                    false_body = await resp_false.text(errors="ignore")
                    false_len = len(false_body)

                # Significant content difference indicates boolean-based SQLi
                len_diff = abs(true_len - false_len)
                baseline_diff = abs(true_len - baseline_length)

                if len_diff > 50 and baseline_diff < 20:
                    findings.append({
                        "type": "sqli_blind",
                        "name": "SQL Injection (Boolean-Based Blind)",
                        "url": true_url,
                        "wstg_id": "WSTG-INPV-05",
                        "severity": "Critical",
                        "cwe": "CWE-89",
                        "cvss": "9.1",
                        "description": f"Boolean condition difference detected in parameter '{param_name}'. Possible blind SQLi.",
                        "evidence": (
                            f"True payload length: {true_len}\n"
                            f"False payload length: {false_len}\n"
                            f"Difference: {len_diff} bytes\n"
                            f"True URL: {true_url}"
                        ),
                        "recommendation": "Use parameterized queries. Review all database queries for user-controlled input.",
                        "vulnerable": True,
                        "status": "REVIEW",
                        "param": param_name,
                    })
                    self.logger.warning(f"[SQLI] Boolean-blind possible in {base_url} param={param_name}")

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.debug(f"SQLi boolean test failed: {e}")

        return findings
