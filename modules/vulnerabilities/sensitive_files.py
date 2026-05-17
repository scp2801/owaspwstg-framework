"""
Sensitive Files Checker
========================
Checks for exposed sensitive files and directories.
WSTG-CONF-04, WSTG-INFO-03

Checks for:
- .git exposure
- .env files
- backup files
- config files
- admin panels
- debug endpoints
- API documentation
"""

import asyncio
from typing import List, Dict, Any

import aiohttp


SENSITIVE_PATHS = [
    # Version Control
    {"path": "/.git/config", "name": "Git Configuration Exposed", "severity": "Critical", "cwe": "CWE-538"},
    {"path": "/.git/HEAD", "name": "Git Repository Exposed", "severity": "Critical", "cwe": "CWE-538"},
    {"path": "/.svn/entries", "name": "SVN Repository Exposed", "severity": "High", "cwe": "CWE-538"},
    {"path": "/.hg/hgrc", "name": "Mercurial Repository Exposed", "severity": "High", "cwe": "CWE-538"},

    # Environment & Config
    {"path": "/.env", "name": ".env File Exposed", "severity": "Critical", "cwe": "CWE-312"},
    {"path": "/.env.local", "name": ".env.local Exposed", "severity": "Critical", "cwe": "CWE-312"},
    {"path": "/.env.production", "name": ".env.production Exposed", "severity": "Critical", "cwe": "CWE-312"},
    {"path": "/.env.backup", "name": ".env.backup Exposed", "severity": "Critical", "cwe": "CWE-312"},
    {"path": "/config.php", "name": "PHP Config Exposed", "severity": "High", "cwe": "CWE-312"},
    {"path": "/configuration.php", "name": "Joomla Config Exposed", "severity": "High", "cwe": "CWE-312"},
    {"path": "/wp-config.php", "name": "WordPress Config Exposed", "severity": "Critical", "cwe": "CWE-312"},
    {"path": "/config.yml", "name": "YAML Config Exposed", "severity": "High", "cwe": "CWE-312"},
    {"path": "/config.yaml", "name": "YAML Config Exposed", "severity": "High", "cwe": "CWE-312"},
    {"path": "/settings.py", "name": "Django Settings Exposed", "severity": "High", "cwe": "CWE-312"},
    {"path": "/application.yml", "name": "Spring Config Exposed", "severity": "High", "cwe": "CWE-312"},
    {"path": "/application.properties", "name": "Java App Config Exposed", "severity": "High", "cwe": "CWE-312"},

    # Backup Files
    {"path": "/backup.zip", "name": "Backup Archive Exposed", "severity": "Critical", "cwe": "CWE-530"},
    {"path": "/backup.tar.gz", "name": "Backup Archive Exposed", "severity": "Critical", "cwe": "CWE-530"},
    {"path": "/backup.sql", "name": "Database Backup Exposed", "severity": "Critical", "cwe": "CWE-530"},
    {"path": "/db.sql", "name": "Database Dump Exposed", "severity": "Critical", "cwe": "CWE-530"},
    {"path": "/database.sql", "name": "Database Dump Exposed", "severity": "Critical", "cwe": "CWE-530"},
    {"path": "/dump.sql", "name": "Database Dump Exposed", "severity": "Critical", "cwe": "CWE-530"},
    {"path": "/site.zip", "name": "Site Archive Exposed", "severity": "Critical", "cwe": "CWE-530"},

    # Admin Interfaces
    {"path": "/admin", "name": "Admin Panel Accessible", "severity": "High", "cwe": "CWE-284"},
    {"path": "/admin/", "name": "Admin Panel Accessible", "severity": "High", "cwe": "CWE-284"},
    {"path": "/administrator", "name": "Admin Panel Accessible", "severity": "High", "cwe": "CWE-284"},
    {"path": "/wp-admin/", "name": "WordPress Admin Accessible", "severity": "Medium", "cwe": "CWE-284"},
    {"path": "/phpmyadmin/", "name": "phpMyAdmin Accessible", "severity": "Critical", "cwe": "CWE-284"},
    {"path": "/phpmyadmin", "name": "phpMyAdmin Accessible", "severity": "Critical", "cwe": "CWE-284"},
    {"path": "/adminer.php", "name": "Adminer DB Panel Accessible", "severity": "Critical", "cwe": "CWE-284"},
    {"path": "/panel", "name": "Control Panel Accessible", "severity": "Medium", "cwe": "CWE-284"},
    {"path": "/cpanel", "name": "cPanel Accessible", "severity": "High", "cwe": "CWE-284"},

    # Debug & Development
    {"path": "/debug", "name": "Debug Endpoint Exposed", "severity": "Medium", "cwe": "CWE-215"},
    {"path": "/.debug", "name": "Debug File Exposed", "severity": "Medium", "cwe": "CWE-215"},
    {"path": "/test", "name": "Test Endpoint Exposed", "severity": "Low", "cwe": "CWE-215"},
    {"path": "/phpinfo.php", "name": "PHP Info Exposed", "severity": "High", "cwe": "CWE-200"},
    {"path": "/info.php", "name": "PHP Info Exposed", "severity": "High", "cwe": "CWE-200"},
    {"path": "/server-status", "name": "Apache Server Status Exposed", "severity": "Medium", "cwe": "CWE-200"},
    {"path": "/server-info", "name": "Apache Server Info Exposed", "severity": "Medium", "cwe": "CWE-200"},
    {"path": "/.DS_Store", "name": ".DS_Store File Exposed", "severity": "Low", "cwe": "CWE-538"},

    # API Documentation
    {"path": "/swagger-ui.html", "name": "Swagger UI Exposed", "severity": "Medium", "cwe": "CWE-200"},
    {"path": "/swagger.json", "name": "Swagger JSON Exposed", "severity": "Medium", "cwe": "CWE-200"},
    {"path": "/api-docs", "name": "API Docs Exposed", "severity": "Medium", "cwe": "CWE-200"},
    {"path": "/api/swagger.json", "name": "API Swagger Exposed", "severity": "Medium", "cwe": "CWE-200"},
    {"path": "/openapi.json", "name": "OpenAPI Spec Exposed", "severity": "Medium", "cwe": "CWE-200"},
    {"path": "/graphql", "name": "GraphQL Endpoint Accessible", "severity": "Medium", "cwe": "CWE-200"},
    {"path": "/graphiql", "name": "GraphiQL UI Exposed", "severity": "Medium", "cwe": "CWE-200"},

    # Logs & Sensitive Data
    {"path": "/error.log", "name": "Error Log Exposed", "severity": "High", "cwe": "CWE-532"},
    {"path": "/access.log", "name": "Access Log Exposed", "severity": "High", "cwe": "CWE-532"},
    {"path": "/debug.log", "name": "Debug Log Exposed", "severity": "High", "cwe": "CWE-532"},
    {"path": "/logs/error.log", "name": "Error Log Exposed", "severity": "High", "cwe": "CWE-532"},
    {"path": "/.htaccess", "name": ".htaccess Exposed", "severity": "Medium", "cwe": "CWE-538"},
    {"path": "/.htpasswd", "name": ".htpasswd Exposed", "severity": "Critical", "cwe": "CWE-256"},

    # Cloud & DevOps
    {"path": "/.aws/credentials", "name": "AWS Credentials Exposed", "severity": "Critical", "cwe": "CWE-798"},
    {"path": "/docker-compose.yml", "name": "Docker Compose Exposed", "severity": "Medium", "cwe": "CWE-538"},
    {"path": "/Dockerfile", "name": "Dockerfile Exposed", "severity": "Low", "cwe": "CWE-538"},
    {"path": "/.travis.yml", "name": "CI Config Exposed", "severity": "Low", "cwe": "CWE-538"},
    {"path": "/.github/workflows/", "name": "GitHub Actions Exposed", "severity": "Low", "cwe": "CWE-538"},
    {"path": "/package.json", "name": "Package.json Exposed", "severity": "Info", "cwe": "CWE-200"},
    {"path": "/composer.json", "name": "Composer.json Exposed", "severity": "Info", "cwe": "CWE-200"},
    {"path": "/requirements.txt", "name": "Requirements.txt Exposed", "severity": "Info", "cwe": "CWE-200"},
]

# Content signatures to confirm sensitive exposure
CONTENT_SIGNATURES = {
    ".env": ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY=", "API_KEY=", "DATABASE_URL="],
    ".git": ["[core]", "[remote", "ref: refs/"],
    "sql": ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "--", "/*"],
    "credentials": ["aws_access_key_id", "aws_secret_access_key"],
    "phpinfo": ["PHP Version", "php.ini", "php_flag"],
}


class SensitiveFilesChecker:
    """
    Checks for exposed sensitive files and misconfigured directories.
    """

    def __init__(self, base_urls: List[str], config: Dict, logger):
        self.base_urls = base_urls
        self.config = config
        self.logger = logger
        self.timeout = aiohttp.ClientTimeout(total=config["scan"].get("timeout", 30))
        self.headers = {"User-Agent": config["scan"].get("user_agent", "Mozilla/5.0")}

    async def check(self) -> List[Dict]:
        """
        Check all base URLs for sensitive file exposure.

        Returns:
            List of sensitive file findings
        """
        findings = []
        semaphore = asyncio.Semaphore(10)

        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:

            tasks = []
            for base_url in self.base_urls[:10]:
                for path_info in SENSITIVE_PATHS:
                    tasks.append(self._check_path(session, semaphore, base_url, path_info))

            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result:
                findings.append(result)

        self.logger.info(f"Sensitive files check: {len(findings)} exposures found")
        return findings

    async def _check_path(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore,
                          base_url: str, path_info: Dict) -> Dict:
        """Check a single sensitive path."""
        async with semaphore:
            url = base_url.rstrip("/") + path_info["path"]
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="ignore")

                        # Confirm it's actually sensitive content
                        if self._is_false_positive(body, path_info["path"]):
                            return {}

                        self.logger.warning(
                            f"[SENSITIVE-FILE] {path_info['name']} at {url} [{resp.status}]"
                        )

                        return {
                            "type": "sensitive_file",
                            "name": path_info["name"],
                            "url": url,
                            "wstg_id": "WSTG-CONF-04",
                            "severity": path_info["severity"],
                            "cwe": path_info.get("cwe", "CWE-200"),
                            "cvss": self._severity_to_cvss(path_info["severity"]),
                            "description": f"Sensitive file exposed at: {url}",
                            "evidence": (
                                f"URL: {url}\n"
                                f"HTTP Status: {resp.status}\n"
                                f"Response snippet: {body[:200]}"
                            ),
                            "recommendation": (
                                f"Restrict access to {path_info['path']}. "
                                "Add server-side access controls. "
                                "Remove sensitive files from web root. "
                                "Configure web server to deny access."
                            ),
                            "vulnerable": True,
                            "status": "FAIL",
                        }

            except asyncio.TimeoutError:
                pass
            except Exception as e:
                self.logger.debug(f"Sensitive file check error for {url}: {e}")

        return {}

    def _is_false_positive(self, body: str, path: str) -> bool:
        """Detect false positives (custom 200 pages, etc.)."""
        body_lower = body.lower()

        # Generic 404/error pages that return 200
        false_positive_indicators = [
            "page not found",
            "404 not found",
            "file not found",
            "error 404",
            "does not exist",
        ]

        # If it looks like a 404 page, it's a false positive
        if any(indicator in body_lower for indicator in false_positive_indicators):
            return True

        # If body is very short (< 20 chars), likely false positive
        if len(body.strip()) < 20:
            return True

        return False

    def _severity_to_cvss(self, severity: str) -> str:
        """Map severity to approximate CVSS score."""
        mapping = {
            "Critical": "9.8",
            "High": "7.5",
            "Medium": "5.3",
            "Low": "3.1",
            "Info": "0.0",
        }
        return mapping.get(severity, "5.0")
