"""
Dependency Checker Module
=========================
Checks for required Python packages and external tools.
Provides installation guidance and graceful handling of missing deps.
"""

import sys
import shutil
import subprocess
from typing import Dict, Any, List, Tuple

from rich.console import Console
from rich.table import Table

console = Console()


REQUIRED_PYTHON_PACKAGES = [
    ("aiohttp", "aiohttp"),
    ("typer", "typer[all]"),
    ("rich", "rich"),
    ("loguru", "loguru"),
    ("pyyaml", "PyYAML"),
    ("jinja2", "Jinja2"),
    ("openpyxl", "openpyxl"),
    ("pandas", "pandas"),
    ("dnspython", "dnspython"),
    ("requests", "requests"),
    ("beautifulsoup4", "beautifulsoup4"),
    ("lxml", "lxml"),
]

OPTIONAL_PYTHON_PACKAGES = [
    ("playwright", "playwright"),
    ("Crypto", "pycryptodome"),
]

EXTERNAL_TOOLS = {
    "subfinder": {
        "required": False,
        "description": "Subdomain enumeration",
        "install_kali": "apt install subfinder",
        "install_go": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "httpx": {
        "required": False,
        "description": "HTTP probing",
        "install_kali": "apt install httpx-toolkit",
        "install_go": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    },
    "nuclei": {
        "required": False,
        "description": "Vulnerability scanner",
        "install_kali": "apt install nuclei",
        "install_go": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    },
    "katana": {
        "required": False,
        "description": "Web crawler",
        "install_go": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    },
    "ffuf": {
        "required": False,
        "description": "Web fuzzer",
        "install_kali": "apt install ffuf",
        "install_go": "go install github.com/ffuf/ffuf/v2@latest",
    },
    "naabu": {
        "required": False,
        "description": "Port scanner",
        "install_go": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    },
    "nmap": {
        "required": False,
        "description": "Network scanner",
        "install_kali": "apt install nmap",
    },
}


class DependencyChecker:
    """
    Checks Python and system dependencies.
    Provides installation hints and graceful degradation.
    """

    def __init__(self, os_info: Dict[str, Any]):
        self.os_info = os_info
        self.missing_required = []
        self.missing_optional = []
        self.available_tools = {}

    def check_python_packages(self) -> Tuple[List, List]:
        """Check required and optional Python packages."""
        missing_req = []
        missing_opt = []

        for import_name, pip_name in REQUIRED_PYTHON_PACKAGES:
            try:
                __import__(import_name)
            except ImportError:
                missing_req.append((import_name, pip_name))

        for import_name, pip_name in OPTIONAL_PYTHON_PACKAGES:
            if self.os_info.get("is_termux") and import_name == "playwright":
                continue  # Skip playwright on Termux
            try:
                __import__(import_name)
            except ImportError:
                missing_opt.append((import_name, pip_name))

        return missing_req, missing_opt

    def check_external_tools(self) -> Dict[str, bool]:
        """Check availability of external security tools."""
        results = {}
        for tool in EXTERNAL_TOOLS:
            results[tool] = shutil.which(tool) is not None
        self.available_tools = results
        return results

    def check_and_report(self):
        """Quick check and print summary."""
        missing_req, _ = self.check_python_packages()
        tools = self.check_external_tools()

        if missing_req:
            console.print(f"[red][!] Missing required packages: {', '.join(p for _, p in missing_req)}[/red]")
            console.print("[yellow]    Run: pip install -r requirements.txt[/yellow]")

        available_count = sum(1 for v in tools.values() if v)
        console.print(f"[cyan][*] External tools: {available_count}/{len(tools)} available[/cyan]")

    def full_report(self):
        """Display full dependency report in a rich table."""
        console.print("\n[bold cyan]═══════════════ DEPENDENCY CHECK ═══════════════[/bold cyan]\n")

        # Python packages
        table = Table(title="Python Packages", show_header=True, header_style="bold magenta")
        table.add_column("Package", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Type")

        for import_name, pip_name in REQUIRED_PYTHON_PACKAGES:
            try:
                __import__(import_name)
                table.add_row(pip_name, "[green]✓ Installed[/green]", "Required")
            except ImportError:
                table.add_row(pip_name, "[red]✗ Missing[/red]", "Required")

        for import_name, pip_name in OPTIONAL_PYTHON_PACKAGES:
            try:
                __import__(import_name)
                table.add_row(pip_name, "[green]✓ Installed[/green]", "Optional")
            except ImportError:
                table.add_row(pip_name, "[yellow]⚠ Not installed[/yellow]", "Optional")

        console.print(table)

        # External tools
        tool_table = Table(title="\nExternal Tools", show_header=True, header_style="bold magenta")
        tool_table.add_column("Tool", style="cyan")
        tool_table.add_column("Status")
        tool_table.add_column("Description")

        for tool, info in EXTERNAL_TOOLS.items():
            available = shutil.which(tool) is not None
            status = "[green]✓ Available[/green]" if available else "[yellow]✗ Not found[/yellow]"
            tool_table.add_row(tool, status, info["description"])

        console.print(tool_table)
        console.print()

        # OS Info
        console.print(f"[bold]Environment:[/bold] {self.os_info.get('name', 'Unknown')}")
        console.print(f"[bold]Python:[/bold] {sys.version.split()[0]}")
        console.print(f"[bold]Screenshots:[/bold] {'Supported' if self.os_info.get('supports_screenshots') else 'Not supported (disabled)'}")
        console.print()
