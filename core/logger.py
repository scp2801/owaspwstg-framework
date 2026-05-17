"""
Logger Module
=============
Sets up loguru-based logging with file rotation, colored output,
and structured log management for the framework.
"""

import os
import sys
from pathlib import Path
from datetime import datetime

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger("owaspwstg")


def setup_logger(verbose: bool = False, log_dir: str = "logs"):
    """
    Configure and return the framework logger.

    Args:
        verbose: Enable verbose/debug output
        log_dir: Directory to store log files

    Returns:
        Configured logger instance
    """
    # Create log directory
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    # Generate log filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"scan_{timestamp}.log")

    try:
        from loguru import logger as loguru_logger

        # Remove default handler
        loguru_logger.remove()

        # Console handler - colored output
        log_level = "DEBUG" if verbose else "INFO"
        loguru_logger.add(
            sys.stdout,
            level=log_level,
            colorize=True,
            format=(
                "<green>{time:HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{name}</cyan>:<cyan>{function}</cyan> | "
                "<level>{message}</level>"
            ),
        )

        # File handler - full logs
        loguru_logger.add(
            log_file,
            level="DEBUG",
            rotation="50 MB",
            retention="30 days",
            compression="zip",
            format=(
                "{time:YYYY-MM-DD HH:mm:ss} | "
                "{level: <8} | "
                "{name}:{function}:{line} | "
                "{message}"
            ),
        )

        # Error log - separate file for errors only
        error_log = os.path.join(log_dir, f"errors_{timestamp}.log")
        loguru_logger.add(
            error_log,
            level="ERROR",
            rotation="10 MB",
            retention="30 days",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{line} | {message}",
        )

        loguru_logger.info(f"Logger initialized. Log file: {log_file}")
        return loguru_logger

    except ImportError:
        # Fallback to standard logging if loguru not available
        import logging

        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(log_file),
            ],
        )
        fallback_logger = logging.getLogger("owaspwstg")
        fallback_logger.info(f"Fallback logger initialized. Log file: {log_file}")
        return fallback_logger


class ScanLogger:
    """
    Wrapper around logger to provide scan-specific logging methods.
    Tracks findings, events, and scan progress.
    """

    def __init__(self, logger_instance, scan_id: str):
        self._logger = logger_instance
        self.scan_id = scan_id
        self.findings_log = []
        self.event_log = []

    def info(self, message: str):
        self._logger.info(f"[{self.scan_id}] {message}")
        self.event_log.append({"level": "INFO", "msg": message})

    def debug(self, message: str):
        self._logger.debug(f"[{self.scan_id}] {message}")

    def warning(self, message: str):
        self._logger.warning(f"[{self.scan_id}] {message}")
        self.event_log.append({"level": "WARNING", "msg": message})

    def error(self, message: str):
        self._logger.error(f"[{self.scan_id}] {message}")
        self.event_log.append({"level": "ERROR", "msg": message})

    def success(self, message: str):
        self._logger.success(f"[{self.scan_id}] {message}") if hasattr(self._logger, "success") else self._logger.info(f"[SUCCESS] [{self.scan_id}] {message}")
        self.event_log.append({"level": "SUCCESS", "msg": message})

    def finding(self, wstg_id: str, title: str, severity: str, url: str, evidence: str = ""):
        """Log a vulnerability finding."""
        entry = {
            "wstg_id": wstg_id,
            "title": title,
            "severity": severity,
            "url": url,
            "evidence": evidence,
        }
        self.findings_log.append(entry)
        self._logger.warning(
            f"[FINDING] [{self.scan_id}] [{wstg_id}] [{severity.upper()}] {title} | {url}"
        )
