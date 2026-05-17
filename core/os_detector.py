"""
OS Detector Module
==================
Detects the operating system and environment to enable
platform-specific features and graceful fallbacks.
"""

import os
import sys
import platform
import shutil
from typing import Dict, Any


class OSDetector:
    """
    Detects OS, environment, and available system tools.
    Provides platform-specific configuration for the framework.
    """

    def detect(self) -> Dict[str, Any]:
        """
        Detect current OS and environment.

        Returns:
            dict with OS info, capabilities, and flags
        """
        info = {
            "system": platform.system().lower(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
            "is_termux": self._is_termux(),
            "is_kali": self._is_kali(),
            "is_android": self._is_android(),
            "is_linux": platform.system().lower() == "linux",
            "is_windows": platform.system().lower() == "windows",
            "is_mac": platform.system().lower() == "darwin",
            "name": "",
            "home_dir": str(os.path.expanduser("~")),
            "supports_screenshots": True,
            "supports_playwright": True,
            "distro": self._get_distro(),
        }

        # Resolve friendly name
        if info["is_termux"]:
            info["name"] = "Termux (Android)"
            info["supports_screenshots"] = False
            info["supports_playwright"] = False
        elif info["is_kali"]:
            info["name"] = "Kali Linux"
        elif info["is_linux"]:
            info["name"] = f"Linux ({info['distro']})"
        elif info["is_mac"]:
            info["name"] = "macOS"
        elif info["is_windows"]:
            info["name"] = "Windows"
            info["supports_screenshots"] = False  # Limited support
        else:
            info["name"] = "Unknown"

        # Check playwright availability
        if not info["is_termux"]:
            info["supports_playwright"] = self._check_playwright()

        info["tools"] = self._detect_tools()
        info["storage_path"] = self._get_storage_path(info)

        return info

    def _is_termux(self) -> bool:
        """Check if running inside Termux on Android."""
        termux_indicators = [
            "/data/data/com.termux",
            os.environ.get("TERMUX_VERSION"),
            os.environ.get("PREFIX", "").startswith("/data/data/com.termux"),
        ]
        return any(bool(i) for i in termux_indicators) or \
               os.path.exists("/data/data/com.termux")

    def _is_kali(self) -> bool:
        """Check if running on Kali Linux."""
        try:
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release") as f:
                    content = f.read().lower()
                    return "kali" in content
        except Exception:
            pass
        return False

    def _is_android(self) -> bool:
        """Check if running on Android."""
        return os.path.exists("/system/build.prop") or \
               os.path.exists("/data/data/com.termux")

    def _get_distro(self) -> str:
        """Get Linux distribution name."""
        try:
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("NAME="):
                            return line.split("=")[1].strip().strip('"')
        except Exception:
            pass
        return "Unknown"

    def _check_playwright(self) -> bool:
        """Check if Playwright is installed and functional."""
        try:
            import playwright
            return True
        except ImportError:
            return False

    def _detect_tools(self) -> Dict[str, bool]:
        """Detect availability of external security tools."""
        tools = [
            "subfinder", "httpx", "nuclei", "katana",
            "ffuf", "sqlmap", "naabu", "nmap", "curl",
            "wget", "git", "python3", "pip3",
        ]
        return {tool: shutil.which(tool) is not None for tool in tools}

    def _get_storage_path(self, info: Dict) -> str:
        """Get appropriate storage path for the environment."""
        if info["is_termux"]:
            # Check if external storage is accessible
            external = "/sdcard/owaspwstg"
            if os.path.exists("/sdcard"):
                return external
            return os.path.join(os.environ.get("HOME", "/data/data/com.termux/files/home"), "owaspwstg")
        return os.path.join(info["home_dir"], "owaspwstg")
