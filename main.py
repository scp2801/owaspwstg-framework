#!/usr/bin/env python3
"""
OWASP WSTG Bug Bounty Automation Framework
==========================================
Author: scp2801
GitHub: https://github.com/scp2801
License: MIT

Main entry point for the framework.
"""

import sys
import os
import asyncio
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent))

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

from core.os_detector import OSDetector
from core.config_loader import ConfigLoader
from core.logger import setup_logger
from core.engine import ScanEngine
from core.dependency_checker import DependencyChecker
from core.report_engine import ReportEngine

app = typer.Typer(
    name="owaspwstg",
    help="OWASP WSTG Bug Bounty Automation Framework",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()


BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║          OWASP WSTG Bug Bounty Automation Framework             ║
║                  Version 1.0.0 | by scp2801                     ║
║         https://github.com/scp2801/owaspwstg-framework          ║
╠══════════════════════════════════════════════════════════════════╣
║  [*] OWASP Web Security Testing Guide - Full Automation          ║
║  [*] Reconnaissance | Vulnerability Discovery | Reporting        ║
║  [*] For authorized testing and bug bounty programs ONLY         ║
╚══════════════════════════════════════════════════════════════════╝
"""


def show_banner():
    """Display the framework banner."""
    console.print(Panel(
        Text(BANNER, style="bold green"),
        border_style="bright_green",
        padding=(0, 2),
    ))


@app.command("scan")
def scan(
    target: str = typer.Argument(..., help="Target domain or URL (e.g., example.com)"),
    scope_file: str = typer.Option(None, "--scope-file", "-s", help="Path to scope file (one target per line)"),
    output_dir: str = typer.Option("reports", "--output", "-o", help="Output directory for reports"),
    profile: str = typer.Option("default", "--profile", "-p", help="Scan profile: default, fast, deep, stealth"),
    threads: int = typer.Option(10, "--threads", "-t", help="Number of concurrent threads"),
    timeout: int = typer.Option(30, "--timeout", help="Request timeout in seconds"),
    no_screenshots: bool = typer.Option(False, "--no-screenshots", help="Disable screenshot capture"),
    no_crawl: bool = typer.Option(False, "--no-crawl", help="Skip web crawling"),
    vuln_scan: bool = typer.Option(True, "--vuln-scan/--no-vuln-scan", help="Enable/disable vulnerability scanning"),
    report_format: str = typer.Option("all", "--format", "-f", help="Report format: html, json, excel, txt, md, all"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    config_file: str = typer.Option("config.yaml", "--config", "-c", help="Path to config file"),
):
    """
    [bold green]Run a full OWASP WSTG scan against a target.[/bold green]

    Example:
        owaspwstg scan example.com
        owaspwstg scan example.com --profile deep --threads 20
        owaspwstg scan example.com --scope-file scope.txt --format excel
    """
    show_banner()

    # Load configuration
    config = ConfigLoader(config_file).load()

    # Setup logger
    logger = setup_logger(verbose=verbose, log_dir="logs")
    logger.info(f"Starting scan for target: {target}")

    # Detect OS/Environment
    os_info = OSDetector().detect()
    console.print(f"[cyan][*] Environment: {os_info['name']} | Screenshots: {'Enabled' if not os_info['is_termux'] and not no_screenshots else 'Disabled'}[/cyan]")

    # Check dependencies
    dep_checker = DependencyChecker(os_info)
    dep_checker.check_and_report()

    # Override config with CLI options
    config["scan"]["threads"] = threads
    config["scan"]["timeout"] = timeout
    config["scan"]["profile"] = profile
    config["scan"]["vuln_scan"] = vuln_scan
    config["scan"]["no_crawl"] = no_crawl
    config["scan"]["screenshots"] = not no_screenshots and not os_info["is_termux"]
    config["output"]["dir"] = output_dir
    config["output"]["format"] = report_format

    # Build target list
    targets = []
    if scope_file and os.path.exists(scope_file):
        with open(scope_file, "r") as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        console.print(f"[green][+] Loaded {len(targets)} targets from scope file[/green]")
    else:
        targets = [target]

    # Run engine
    engine = ScanEngine(config=config, logger=logger, os_info=os_info)

    try:
        results = asyncio.run(engine.run(targets=targets))
        console.print(f"\n[bold green][✓] Scan completed! Generating reports...[/bold green]")

        # Generate reports
        report_engine = ReportEngine(config=config, logger=logger)
        report_paths = report_engine.generate_all(results, output_dir=output_dir, formats=report_format)

        console.print("\n[bold cyan]═══════════════════════════ REPORTS GENERATED ═══════════════════════════[/bold cyan]")
        for fmt, path in report_paths.items():
            console.print(f"  [green]✓[/green] {fmt.upper():10} → {path}")
        console.print("[bold cyan]═══════════════════════════════════════════════════════════════════════[/bold cyan]\n")

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Scan interrupted by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        console.print(f"[red][✗] Scan failed: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@app.command("recon")
def recon(
    target: str = typer.Argument(..., help="Target domain"),
    output_dir: str = typer.Option("reports", "--output", "-o", help="Output directory"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """
    [bold yellow]Run reconnaissance only (subdomain enum, DNS, live host detection).[/bold yellow]
    """
    show_banner()
    config = ConfigLoader("config.yaml").load()
    logger = setup_logger(verbose=verbose, log_dir="logs")
    os_info = OSDetector().detect()

    config["output"]["dir"] = output_dir
    config["scan"]["mode"] = "recon_only"

    engine = ScanEngine(config=config, logger=logger, os_info=os_info)

    try:
        results = asyncio.run(engine.run_recon_only(target=target))
        console.print(f"\n[bold green][✓] Recon completed for {target}[/bold green]")
        console.print(f"  Subdomains found: [cyan]{len(results.get('subdomains', []))}[/cyan]")
        console.print(f"  Live hosts:       [cyan]{len(results.get('live_hosts', []))}[/cyan]")
        console.print(f"  DNS records:      [cyan]{len(results.get('dns_records', {}))}[/cyan]")
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted.[/yellow]")


@app.command("report")
def generate_report(
    results_file: str = typer.Argument(..., help="Path to scan results JSON file"),
    output_dir: str = typer.Option("reports", "--output", "-o", help="Output directory"),
    report_format: str = typer.Option("all", "--format", "-f", help="Report format: html, json, excel, txt, md, all"),
):
    """
    [bold blue]Generate reports from existing scan results JSON.[/bold blue]
    """
    show_banner()
    import json

    if not os.path.exists(results_file):
        console.print(f"[red][✗] Results file not found: {results_file}[/red]")
        raise typer.Exit(1)

    config = ConfigLoader("config.yaml").load()
    logger = setup_logger(verbose=False, log_dir="logs")

    with open(results_file, "r") as f:
        results = json.load(f)

    report_engine = ReportEngine(config=config, logger=logger)
    report_paths = report_engine.generate_all(results, output_dir=output_dir, formats=report_format)

    for fmt, path in report_paths.items():
        console.print(f"[green]✓[/green] {fmt.upper():10} → {path}")


@app.command("check")
def check_deps():
    """
    [bold magenta]Check dependencies and tool availability.[/bold magenta]
    """
    show_banner()
    os_info = OSDetector().detect()
    dep_checker = DependencyChecker(os_info)
    dep_checker.full_report()


@app.command("version")
def version():
    """Show framework version."""
    console.print("[bold green]OWASP WSTG Framework v1.0.0[/bold green]")
    console.print("Author: scp2801")
    console.print("GitHub: https://github.com/scp2801/owaspwstg-framework")


if __name__ == "__main__":
    app()
