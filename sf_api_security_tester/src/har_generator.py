"""HAR Generator — Phase -1: Live Traffic Capture via Playwright.

Uses Playwright's native HAR recording to capture live browser traffic
while simultaneously routing through an upstream proxy (ZAP/Caido/Burp).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from loguru import logger

from .models import AuditEvent


class HarGenerator:
    """Captures live browser traffic as HAR files using Playwright native recording."""

    def __init__(self, config: dict[str, Any]):
        har_cfg = config.get("har_generation", {})
        self.enabled: bool = har_cfg.get("enabled", True)
        self.default_output_path: str = har_cfg.get("default_output_path", "output/live_crawl.har")
        self.record_mode: str = har_cfg.get("record_mode", "full")
        self.headless: bool = har_cfg.get("headless", False)

        # Proxy config
        proxy_cfg = config.get("upstream_proxy", {})
        self.proxy_url: str | None = None
        if proxy_cfg.get("enabled", False):
            self.proxy_url = proxy_cfg.get("url", "http://127.0.0.1:8080")

        self._audit_log: list[AuditEvent] = []

    def generate(
        self,
        target_url: str,
        output_path: str | None = None,
        use_manual_auth: bool = False,
    ) -> str | None:
        """Generate a HAR file by recording live browser traffic.

        Args:
            target_url: The base URL to navigate to and record.
            output_path: Where to save the HAR file (default: output/live_crawl.har).
            use_manual_auth: If True, opens headed browser for manual login.

        Returns:
            Path to the generated HAR file, or None on failure.
        """
        if not self.enabled:
            logger.info("HAR generation disabled in config")
            return None

        output_path = output_path or self.default_output_path
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f"Starting HAR generation: {target_url} -> {output_path}")
        self._log("har_start", target_url, "started", f"output={output_path}")

        try:
            result = asyncio.run(
                self._generate_async(target_url, str(output_file), use_manual_auth)
            )
            if result:
                logger.info(f"HAR file saved: {result}")
                self._log("har_complete", result, "success")
            return result
        except Exception as e:
            logger.error(f"HAR generation failed: {e}")
            self._log("har_complete", target_url, "error", str(e))
            return None

    async def _generate_async(
        self, target_url: str, output_path: str, use_manual_auth: bool
    ) -> str | None:
        """Async HAR generation using Playwright native recording."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.error("Playwright not installed. Run: pip install playwright && playwright install chromium")
            return None

        pw = await async_playwright().start()

        try:
            # Launch headed browser (user must see it for manual auth)
            browser = await pw.chromium.launch(headless=self.headless)

            # Configure browser context with HAR recording
            context_kwargs: dict[str, Any] = {
                "viewport": {"width": 1920, "height": 1080},
                "record_har_path": output_path,
                "record_har_mode": self.record_mode,
                "record_har_content": "embed",  # Embed response bodies in HAR
            }

            # Add proxy if configured
            if self.proxy_url:
                context_kwargs["proxy"] = {"server": self.proxy_url}
                logger.info(f"HAR recording through proxy: {self.proxy_url}")

            context = await browser.new_context(**context_kwargs)
            page = await context.new_page()

            # Navigate to target
            logger.info(f"Navigating to: {target_url}")
            await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(2000)

            if use_manual_auth:
                # Manual mode: user browses interactively
                self._print_manual_instructions(target_url)
                await asyncio.get_event_loop().run_in_executor(None, input)
                logger.info("Manual browsing complete — saving HAR")
            else:
                # Auto mode: simple BFS to generate baseline traffic
                logger.info("Auto mode — generating baseline traffic...")
                await self._auto_browse(page, max_pages=5)
                await page.wait_for_timeout(5000)  # Wait for network to settle

            # Close context (this finalizes and saves the HAR file)
            await context.close()
            await browser.close()

            # Verify HAR file was created
            har_path = Path(output_path)
            if har_path.exists():
                size_kb = har_path.stat().st_size / 1024
                logger.info(f"HAR file saved: {output_path} ({size_kb:.1f} KB)")
                self._log("har_saved", output_path, "success", f"{size_kb:.1f} KB")
                return str(har_path)
            else:
                logger.error(f"HAR file not created at {output_path}")
                return None

        finally:
            await pw.stop()

    async def _auto_browse(self, page, max_pages: int = 5):
        """Simple auto-browsing to generate baseline traffic."""
        visited = set()
        queue = [page.url]

        for _ in range(max_pages):
            if not queue:
                break

            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                # Find and click navigation links
                links = await page.query_selector_all("a[href]")
                clicked = 0
                for link in links[:10]:
                    try:
                        href = await link.get_attribute("href")
                        if href and href.startswith("http") and clicked < 2:
                            await link.click()
                            await page.wait_for_timeout(2000)
                            new_url = page.url
                            if new_url not in visited:
                                queue.append(new_url)
                            clicked += 1
                    except Exception:
                        continue

                logger.debug(f"Browsed: {url[:80]} ({clicked} links clicked)")
            except Exception as e:
                logger.debug(f"Browse error: {e}")

    def _print_manual_instructions(self, target_url: str):
        """Print instructions for manual browsing."""
        from rich.console import Console
        console = Console()

        proxy_info = f" through proxy {self.proxy_url}" if self.proxy_url else ""
        console.print(
            f"\n[bold yellow]MANUAL HAR GENERATION[/bold yellow]\n"
            f"[yellow]A browser window has opened to: {target_url}[/yellow]\n"
            f"[yellow]Traffic is being recorded{proxy_info}.[/yellow]\n"
            f"[yellow]Please log in and click around the target website to generate traffic.[/yellow]\n"
            f"[yellow]Press ENTER in this terminal when finished.[/yellow]\n"
        )

    def _log(self, action: str, target: str, result: str, details: str = ""):
        self._audit_log.append(AuditEvent(
            action=action, target=target, result=result, details=details
        ))
