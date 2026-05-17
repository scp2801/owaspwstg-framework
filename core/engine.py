"""
Core Scan Engine
================
Orchestrates all scanning modules:
- Reconnaissance
- Web Crawling
- Parameter Discovery
- JavaScript Analysis
- Vulnerability Detection
- Report Generation

Uses asyncio for concurrent scanning.
"""

import asyncio
import os
import json
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from core.checklist_engine import ChecklistEngine, ChecklistStatus
from core.utils import create_output_dir, save_json, normalize_url, extract_domain
from modules.recon.subdomain_enum import SubdomainEnumerator
from modules.recon.dns_enum import DNSEnumerator
from modules.recon.live_host import LiveHostDetector
from modules.crawling.web_crawler import WebCrawler
from modules.params.param_discovery import ParamDiscovery
from modules.js_analysis.js_analyzer import JSAnalyzer
from modules.vulnerabilities.security_headers import SecurityHeadersChecker
from modules.vulnerabilities.cors_checker import CORSChecker
from modules.vulnerabilities.xss_checker import XSSChecker
from modules.vulnerabilities.sqli_checker import SQLiChecker
from modules.vulnerabilities.ssrf_checker import SSRFChecker
from modules.vulnerabilities.open_redirect import OpenRedirectChecker
from modules.vulnerabilities.sensitive_files import SensitiveFilesChecker
from modules.vulnerabilities.subdomain_takeover import SubdomainTakeoverChecker
from modules.vulnerabilities.jwt_checker import JWTChecker
from modules.vulnerabilities.clickjacking import ClickjackingChecker

console = Console()


class ScanEngine:
    """
    Main orchestration engine for OWASP WSTG-based scanning.
    Coordinates all modules and aggregates results.
    """

    def __init__(self, config: Dict, logger, os_info: Dict):
        self.config = config
        self.logger = logger
        self.os_info = os_info
        self.scan_id = str(uuid.uuid4())[:8].upper()
        self.checklist = ChecklistEngine()
        self.results: Dict[str, Any] = {}

    async def run(self, targets: List[str]) -> Dict[str, Any]:
        """
        Run full OWASP WSTG scan against all targets.

        Args:
            targets: List of target domains/URLs

        Returns:
            Complete scan results dictionary
        """
        start_time = datetime.now()
        all_results = {
            "scan_id": self.scan_id,
            "scan_start": start_time.isoformat(),
            "targets": targets,
            "config": {
                "profile": self.config["scan"]["profile"],
                "threads": self.config["scan"]["threads"],
            },
            "targets_results": [],
            "checklist": [],
            "summary": {},
        }

        console.print(f"\n[bold cyan]═══════════ SCAN ID: {self.scan_id} ═══════════[/bold cyan]")
        console.print(f"[cyan]Targets: {len(targets)} | Profile: {self.config['scan']['profile']}[/cyan]\n")

        # Create output directory
        output_dir = self.config["output"]["dir"]
        scan_dir = create_output_dir(output_dir, targets[0])
        all_results["scan_dir"] = scan_dir

        # Run each target
        for target in targets:
            console.print(f"\n[bold green]▶ Scanning: {target}[/bold green]")
            target_result = await self._scan_target(target, scan_dir)
            all_results["targets_results"].append(target_result)

        # Compile checklist
        all_results["checklist"] = self.checklist.get_all()
        all_results["checklist_summary"] = self.checklist.get_summary()

        # Final summary
        end_time = datetime.now()
        duration = (end_time - start_time).seconds
        all_results["scan_end"] = end_time.isoformat()
        all_results["duration_seconds"] = duration

        # Save raw results
        results_path = os.path.join(scan_dir, "scan_results.json")
        save_json(all_results, results_path)
        self.logger.info(f"Raw results saved: {results_path}")

        # Print summary
        self._print_summary(all_results)

        return all_results

    async def _scan_target(self, target: str, scan_dir: str) -> Dict[str, Any]:
        """
        Run all scan phases for a single target.

        Args:
            target: Target domain/URL
            scan_dir: Output directory path

        Returns:
            Per-target results dictionary
        """
        domain = extract_domain(target) if "://" not in target else extract_domain("https://" + target)
        target_url = normalize_url(target)

        result = {
            "target": target,
            "domain": domain,
            "url": target_url,
            "subdomains": [],
            "live_hosts": [],
            "dns_records": {},
            "endpoints": [],
            "parameters": [],
            "js_findings": [],
            "vulnerabilities": [],
            "screenshots": [],
        }

        threads = self.config["scan"]["threads"]
        timeout = self.config["scan"]["timeout"]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:

            # ── PHASE 1: Reconnaissance ──────────────────────────────
            task = progress.add_task("[cyan]Phase 1: Reconnaissance...", total=3)

            # Subdomain enumeration
            progress.update(task, description="[cyan]Enumerating subdomains...")
            sub_enum = SubdomainEnumerator(domain=domain, config=self.config, logger=self.logger)
            subdomains = await sub_enum.enumerate()
            result["subdomains"] = subdomains
            self.logger.info(f"Found {len(subdomains)} subdomains for {domain}")
            progress.advance(task)

            # DNS enumeration
            progress.update(task, description="[cyan]Enumerating DNS records...")
            dns_enum = DNSEnumerator(domain=domain, config=self.config, logger=self.logger)
            dns_records = await dns_enum.enumerate()
            result["dns_records"] = dns_records
            progress.advance(task)

            # Live host detection
            progress.update(task, description="[cyan]Detecting live hosts...")
            live_detector = LiveHostDetector(
                hosts=[domain] + subdomains,
                config=self.config,
                logger=self.logger,
            )
            live_hosts = await live_detector.detect()
            result["live_hosts"] = live_hosts
            self.logger.info(f"Found {len(live_hosts)} live hosts")
            progress.advance(task)

            # Update WSTG checklist - Recon phase
            self.checklist.mark_pass("WSTG-INFO-01", url=target_url, notes=f"Found {len(subdomains)} subdomains")
            self.checklist.mark_pass("WSTG-INFO-02", url=target_url)
            self.checklist.mark_pass("WSTG-INFO-04", url=target_url, notes=f"Found {len(live_hosts)} live hosts")
            self.checklist.mark_pass("WSTG-INFO-10", url=target_url)

            # ── PHASE 2: Web Crawling ────────────────────────────────
            if not self.config["scan"].get("no_crawl"):
                task2 = progress.add_task("[yellow]Phase 2: Web Crawling...", total=1)
                progress.update(task2, description="[yellow]Crawling web application...")

                crawler = WebCrawler(
                    start_url=target_url,
                    config=self.config,
                    logger=self.logger,
                )
                crawl_result = await crawler.crawl()
                result["endpoints"] = crawl_result.get("urls", [])
                result["forms"] = crawl_result.get("forms", [])
                result["js_files"] = crawl_result.get("js_files", [])

                self.checklist.mark_pass("WSTG-INFO-06", url=target_url,
                    notes=f"Found {len(result['endpoints'])} endpoints")
                self.checklist.mark_pass("WSTG-INFO-07", url=target_url)
                progress.advance(task2)

            # ── PHASE 3: Parameter Discovery ─────────────────────────
            task3 = progress.add_task("[magenta]Phase 3: Parameter Discovery...", total=1)
            param_disc = ParamDiscovery(
                urls=result["endpoints"][:200],  # Limit for performance
                config=self.config,
                logger=self.logger,
            )
            parameters = await param_disc.discover()
            result["parameters"] = parameters
            progress.advance(task3)

            # ── PHASE 4: JavaScript Analysis ──────────────────────────
            task4 = progress.add_task("[blue]Phase 4: JavaScript Analysis...", total=1)
            if result.get("js_files"):
                js_analyzer = JSAnalyzer(
                    js_urls=result["js_files"][:50],
                    config=self.config,
                    logger=self.logger,
                )
                js_findings = await js_analyzer.analyze()
                result["js_findings"] = js_findings
                if js_findings:
                    self.checklist.mark_fail(
                        "WSTG-INFO-05",
                        evidence=f"Found {len(js_findings)} secrets/endpoints in JS files",
                        url=target_url,
                        recommendation="Remove sensitive data from JavaScript files. Use server-side configurations.",
                    )
                else:
                    self.checklist.mark_pass("WSTG-INFO-05", url=target_url)
            progress.advance(task4)

            # ── PHASE 5: Vulnerability Scanning ──────────────────────
            if self.config["scan"].get("vuln_scan", True):
                task5 = progress.add_task("[red]Phase 5: Vulnerability Scanning...", total=10)
                vulnerabilities = []

                # Security Headers
                progress.update(task5, description="[red]Checking security headers...")
                hdr_checker = SecurityHeadersChecker(
                    urls=[target_url] + [h["url"] for h in live_hosts[:5]],
                    config=self.config, logger=self.logger,
                )
                hdr_findings = await hdr_checker.check()
                vulnerabilities.extend(hdr_findings)
                self._update_checklist_from_findings(hdr_findings)
                progress.advance(task5)

                # CORS
                progress.update(task5, description="[red]Testing CORS...")
                cors_checker = CORSChecker(
                    urls=[target_url] + result["endpoints"][:30],
                    config=self.config, logger=self.logger,
                )
                cors_findings = await cors_checker.check()
                vulnerabilities.extend(cors_findings)
                self._update_checklist_from_findings(cors_findings)
                progress.advance(task5)

                # XSS
                progress.update(task5, description="[red]Testing for XSS...")
                xss_checker = XSSChecker(
                    urls_with_params=result["parameters"][:50],
                    config=self.config, logger=self.logger,
                )
                xss_findings = await xss_checker.check()
                vulnerabilities.extend(xss_findings)
                self._update_checklist_from_findings(xss_findings)
                progress.advance(task5)

                # SQLi
                progress.update(task5, description="[red]Testing for SQL Injection...")
                sqli_checker = SQLiChecker(
                    urls_with_params=result["parameters"][:50],
                    config=self.config, logger=self.logger,
                )
                sqli_findings = await sqli_checker.check()
                vulnerabilities.extend(sqli_findings)
                self._update_checklist_from_findings(sqli_findings)
                progress.advance(task5)

                # SSRF
                progress.update(task5, description="[red]Testing for SSRF...")
                ssrf_checker = SSRFChecker(
                    urls_with_params=result["parameters"][:50],
                    config=self.config, logger=self.logger,
                )
                ssrf_findings = await ssrf_checker.check()
                vulnerabilities.extend(ssrf_findings)
                self._update_checklist_from_findings(ssrf_findings)
                progress.advance(task5)

                # Open Redirect
                progress.update(task5, description="[red]Testing for Open Redirect...")
                redirect_checker = OpenRedirectChecker(
                    urls_with_params=result["parameters"][:50],
                    config=self.config, logger=self.logger,
                )
                redirect_findings = await redirect_checker.check()
                vulnerabilities.extend(redirect_findings)
                self._update_checklist_from_findings(redirect_findings)
                progress.advance(task5)

                # Sensitive Files
                progress.update(task5, description="[red]Checking sensitive files...")
                sf_checker = SensitiveFilesChecker(
                    base_urls=[target_url] + [h["url"] for h in live_hosts[:5]],
                    config=self.config, logger=self.logger,
                )
                sf_findings = await sf_checker.check()
                vulnerabilities.extend(sf_findings)
                self._update_checklist_from_findings(sf_findings)
                progress.advance(task5)

                # Subdomain Takeover
                progress.update(task5, description="[red]Testing for subdomain takeover...")
                takeover_checker = SubdomainTakeoverChecker(
                    subdomains=subdomains[:100],
                    config=self.config, logger=self.logger,
                )
                takeover_findings = await takeover_checker.check()
                vulnerabilities.extend(takeover_findings)
                self._update_checklist_from_findings(takeover_findings)
                progress.advance(task5)

                # JWT
                progress.update(task5, description="[red]Analyzing JWT tokens...")
                jwt_checker = JWTChecker(
                    endpoints=result["endpoints"][:50],
                    config=self.config, logger=self.logger,
                )
                jwt_findings = await jwt_checker.check()
                vulnerabilities.extend(jwt_findings)
                self._update_checklist_from_findings(jwt_findings)
                progress.advance(task5)

                # Clickjacking
                progress.update(task5, description="[red]Testing for Clickjacking...")
                cj_checker = ClickjackingChecker(
                    urls=[target_url] + [h["url"] for h in live_hosts[:10]],
                    config=self.config, logger=self.logger,
                )
                cj_findings = await cj_checker.check()
                vulnerabilities.extend(cj_findings)
                self._update_checklist_from_findings(cj_findings)
                progress.advance(task5)

                result["vulnerabilities"] = vulnerabilities

            # ── PHASE 6: Screenshots ─────────────────────────────────
            if self.config["scan"].get("screenshots") and self.os_info.get("supports_playwright"):
                task6 = progress.add_task("[white]Phase 6: Screenshots...", total=1)
                progress.update(task6, description="[white]Capturing screenshots...")
                try:
                    from core.screenshot_engine import ScreenshotEngine
                    screenshot_engine = ScreenshotEngine(
                        urls=[h["url"] for h in live_hosts[:20]],
                        scan_dir=scan_dir,
                        config=self.config,
                        logger=self.logger,
                    )
                    screenshots = await screenshot_engine.capture_all()
                    result["screenshots"] = screenshots
                except Exception as e:
                    self.logger.warning(f"Screenshots failed: {e}. Continuing without screenshots.")
                progress.advance(task6)

        return result

    async def run_recon_only(self, target: str) -> Dict[str, Any]:
        """Run only the reconnaissance phase."""
        domain = extract_domain(target) if "://" in target else target
        target_url = normalize_url(target)

        sub_enum = SubdomainEnumerator(domain=domain, config=self.config, logger=self.logger)
        subdomains = await sub_enum.enumerate()

        dns_enum = DNSEnumerator(domain=domain, config=self.config, logger=self.logger)
        dns_records = await dns_enum.enumerate()

        live_detector = LiveHostDetector(
            hosts=[domain] + subdomains,
            config=self.config, logger=self.logger,
        )
        live_hosts = await live_detector.detect()

        return {
            "target": target,
            "domain": domain,
            "subdomains": subdomains,
            "live_hosts": live_hosts,
            "dns_records": dns_records,
        }

    def _update_checklist_from_findings(self, findings: List[Dict]):
        """Update WSTG checklist based on vulnerability findings."""
        for finding in findings:
            wstg_id = finding.get("wstg_id")
            if not wstg_id:
                continue

            if finding.get("status") == "FAIL" or finding.get("vulnerable", False):
                self.checklist.mark_fail(
                    wstg_id,
                    evidence=finding.get("evidence", ""),
                    url=finding.get("url", ""),
                    notes=finding.get("description", ""),
                    recommendation=finding.get("recommendation", ""),
                    cwe=finding.get("cwe", ""),
                    cvss=finding.get("cvss", ""),
                )
            elif finding.get("status") == "REVIEW":
                self.checklist.mark_review(
                    wstg_id,
                    evidence=finding.get("evidence", ""),
                    url=finding.get("url", ""),
                )
            else:
                self.checklist.mark_pass(wstg_id, url=finding.get("url", ""))

    def _print_summary(self, results: Dict):
        """Print scan summary to console."""
        summary = results.get("checklist_summary", {})
        console.print("\n[bold cyan]═══════════════════════ SCAN SUMMARY ═══════════════════════[/bold cyan]")
        console.print(f"  Scan ID:       [yellow]{results['scan_id']}[/yellow]")
        console.print(f"  Duration:      [yellow]{results.get('duration_seconds', 0)}s[/yellow]")
        console.print(f"  Targets:       [yellow]{len(results['targets'])}[/yellow]")

        if results.get("targets_results"):
            tr = results["targets_results"][0]
            console.print(f"  Subdomains:    [green]{len(tr.get('subdomains', []))}[/green]")
            console.print(f"  Live Hosts:    [green]{len(tr.get('live_hosts', []))}[/green]")
            console.print(f"  Endpoints:     [green]{len(tr.get('endpoints', []))}[/green]")
            console.print(f"  Vulns Found:   [red]{len(tr.get('vulnerabilities', []))}[/red]")

        sc = summary.get("status_counts", {})
        console.print(f"\n  WSTG Tests:")
        console.print(f"    ✓ PASS:        [green]{sc.get('PASS', 0)}[/green]")
        console.print(f"    ✗ FAIL:        [red]{sc.get('FAIL', 0)}[/red]")
        console.print(f"    ⚠ REVIEW:      [yellow]{sc.get('REVIEW', 0)}[/yellow]")
        console.print(f"    - NOT_TESTED:  [dim]{sc.get('NOT_TESTED', 0)}[/dim]")

        sev = summary.get("severity_counts", {})
        if any(v > 0 for v in sev.values()):
            console.print(f"\n  Severity Breakdown:")
            if sev.get("Critical", 0): console.print(f"    Critical: [bold red]{sev['Critical']}[/bold red]")
            if sev.get("High", 0):     console.print(f"    High:     [red]{sev['High']}[/red]")
            if sev.get("Medium", 0):   console.print(f"    Medium:   [yellow]{sev['Medium']}[/yellow]")
            if sev.get("Low", 0):      console.print(f"    Low:      [blue]{sev['Low']}[/blue]")

        console.print("[bold cyan]═════════════════════════════════════════════════════════════[/bold cyan]\n")
