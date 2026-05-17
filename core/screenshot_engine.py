"""
Screenshot Engine
=================
Captures screenshots of live web applications using Playwright.
Automatically disabled on Termux/Android or when Playwright is unavailable.
Provides graceful fallback with no crashes.
"""

import os
import asyncio
from typing import List, Dict, Any, Optional
from pathlib import Path


class ScreenshotEngine:
    """
    Playwright-based screenshot capture engine.
    Gracefully degrades when Playwright is unavailable.
    """

    def __init__(self, urls: List[str], scan_dir: str, config: Dict, logger):
        self.urls = urls
        self.scan_dir = scan_dir
        self.config = config
        self.logger = logger
        self.screenshot_dir = os.path.join(scan_dir, "screenshots")
        self.playwright_available = self._check_playwright()
        Path(self.screenshot_dir).mkdir(parents=True, exist_ok=True)

    def _check_playwright(self) -> bool:
        """Check if Playwright is available."""
        try:
            import playwright
            return True
        except ImportError:
            return False

    async def capture_all(self) -> List[Dict]:
        """
        Capture screenshots of all URLs.

        Returns:
            List of screenshot result dicts
        """
        if not self.playwright_available:
            self.logger.warning("Playwright not available. Skipping screenshots.")
            return []

        results = []
        timeout = self.config["scan"].get("timeout", 30) * 1000  # Convert to ms

        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                    ],
                )

                # Limit concurrent screenshots
                semaphore = asyncio.Semaphore(3)

                async def capture_one(url: str) -> Optional[Dict]:
                    async with semaphore:
                        return await self._capture_screenshot(browser, url, timeout)

                tasks = [capture_one(url) for url in self.urls[:50]]
                screenshot_results = await asyncio.gather(*tasks, return_exceptions=True)

                for res in screenshot_results:
                    if isinstance(res, dict) and res:
                        results.append(res)

                await browser.close()

        except Exception as e:
            self.logger.error(f"Screenshot engine failed: {e}")
            return []

        self.logger.info(f"Captured {len(results)} screenshots")
        return results

    async def _capture_screenshot(self, browser, url: str, timeout: int) -> Optional[Dict]:
        """Capture a single screenshot."""
        try:
            page = await browser.new_page(
                viewport={"width": 1280, "height": 800},
                user_agent=self.config["scan"].get("user_agent", "Mozilla/5.0"),
            )
            await page.set_extra_http_headers({"Accept-Language": "en-US,en;q=0.9"})

            response = await page.goto(
                url,
                timeout=timeout,
                wait_until="domcontentloaded",
            )

            # Generate filename
            from core.utils import sanitize_filename
            filename = sanitize_filename(url.replace("https://", "").replace("http://", "")) + ".png"
            filepath = os.path.join(self.screenshot_dir, filename)

            await page.screenshot(path=filepath, full_page=False)
            await page.close()

            return {
                "url": url,
                "file": filepath,
                "status_code": response.status if response else 0,
                "title": await page.title() if not page.is_closed() else "",
            }

        except Exception as e:
            self.logger.debug(f"Screenshot failed for {url}: {e}")
            return None
