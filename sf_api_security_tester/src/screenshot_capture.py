"""Playwright-based screenshot capture for live evidence."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from loguru import logger

from .models import MutatedRequest


class ScreenshotCapture:
    """Captures screenshots of portal pages as live evidence."""

    def __init__(
        self,
        output_dir: str | Path,
        headless: bool = True,
        browser_type: str = "chromium",
        viewport_width: int = 1920,
        viewport_height: int = 1080,
        timeout: int = 15000,
        navigation_timeout: int = 30000,
        full_page: bool = False,
        user_agent: str | None = None,
        enabled: bool = True,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.headless = headless
        self.browser_type = browser_type
        self.viewport_width = viewport_width
        self.viewport_height = viewport_height
        self.timeout = timeout
        self.navigation_timeout = navigation_timeout
        self.full_page = full_page
        self.user_agent = user_agent
        self.enabled = enabled
        self._browser = None
        self._context = None

    async def _ensure_browser(self):
        """Ensure browser is launched and ready."""
        if self._browser is not None:
            return

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.error("Playwright not installed. Run: pip install playwright && playwright install")
            self.enabled = False
            return

        self._playwright = await async_playwright().start()

        browser_launcher = getattr(self._playwright, self.browser_type)
        self._browser = await browser_launcher.launch(headless=self.headless)

        context_options = {
            "viewport": {"width": self.viewport_width, "height": self.viewport_height},
        }
        if self.user_agent:
            context_options["user_agent"] = self.user_agent

        self._context = await self._browser.new_context(**context_options)

    async def close(self):
        """Close browser resources."""
        try:
            if self._context:
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if hasattr(self, "_playwright") and self._playwright:
                await self._playwright.stop()
        except Exception as e:
            logger.warning(f"Error closing browser: {e}")
        finally:
            self._browser = None
            self._context = None

    def capture_screenshot_sync(
        self,
        url: str,
        test_case_id: str,
        endpoint_id: str,
        mutated_request: MutatedRequest | None = None,
        label: str = "",
    ) -> str | None:
        """Synchronous wrapper for screenshot capture."""
        if not self.enabled:
            return None

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're inside an async context, use a new thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    result = pool.submit(
                        asyncio.run,
                        self._capture_screenshot(
                            url, test_case_id, endpoint_id, mutated_request, label
                        ),
                    ).result(timeout=self.timeout / 1000 + 10)
                return result
            else:
                return loop.run_until_complete(
                    self._capture_screenshot(
                        url, test_case_id, endpoint_id, mutated_request, label
                    )
                )
        except Exception as e:
            logger.error(f"Screenshot capture failed: {e}")
            return None

    async def capture_screenshot(
        self,
        url: str,
        test_case_id: str,
        endpoint_id: str,
        mutated_request: MutatedRequest | None = None,
        label: str = "",
    ) -> str | None:
        """Capture a screenshot of a URL."""
        return await self._capture_screenshot(
            url, test_case_id, endpoint_id, mutated_request, label
        )

    async def _capture_screenshot(
        self,
        url: str,
        test_case_id: str,
        endpoint_id: str,
        mutated_request: MutatedRequest | None = None,
        label: str = "",
    ) -> str | None:
        """Internal screenshot capture implementation."""
        if not self.enabled:
            return None

        try:
            await self._ensure_browser()
            if not self._context:
                return None

            page = await self._context.new_page()

            # Build screenshot filename
            safe_label = label.replace(" ", "_").replace("/", "_")[:30] if label else ""
            filename = f"{test_case_id}_{endpoint_id}_{safe_label}.png"
            screenshot_path = self.output_dir / filename

            try:
                # Navigate to URL
                response = await page.goto(
                    url,
                    timeout=self.navigation_timeout,
                    wait_until="domcontentloaded",
                )

                # Wait a moment for page to render
                await page.wait_for_timeout(2000)

                # If we have a mutated request, try to show the relevant info on page
                if mutated_request:
                    await self._inject_evidence_overlay(
                        page, mutated_request, response.status if response else 0
                    )

                # Take screenshot
                await page.screenshot(
                    path=str(screenshot_path),
                    full_page=self.full_page,
                )

                logger.debug(f"Screenshot saved: {screenshot_path}")
                return str(screenshot_path)

            except Exception as e:
                # Even if navigation fails, try to capture the error page
                try:
                    error_filename = f"{test_case_id}_{endpoint_id}_error.png"
                    error_path = self.output_dir / error_filename
                    await page.screenshot(path=str(error_path))
                    logger.debug(f"Error page screenshot saved: {error_path}")
                    return str(error_path)
                except Exception:
                    logger.warning(f"Could not capture error page screenshot: {e}")
                    return None
            finally:
                await page.close()

        except Exception as e:
            logger.error(f"Screenshot capture error: {e}")
            return None

    async def _inject_evidence_overlay(
        self, page, mutated_request: MutatedRequest, status_code: int
    ):
        """Inject a visual overlay showing test evidence on the page."""
        overlay_html = f"""
        <div id="security-test-overlay" style="
            position: fixed; top: 10px; right: 10px; z-index: 999999;
            background: rgba(0,0,0,0.85); color: #00ff41; padding: 15px;
            border: 2px solid #00ff41; border-radius: 8px; font-family: monospace;
            font-size: 12px; max-width: 400px; box-shadow: 0 0 20px rgba(0,255,65,0.3);
        ">
            <div style="font-size: 14px; font-weight: bold; margin-bottom: 8px; color: #ff6b6b;">
                ⚠ SECURITY TEST IN PROGRESS
            </div>
            <div><strong>Test:</strong> {mutated_request.test_case_id}</div>
            <div><strong>Method:</strong> {mutated_request.method.value}</div>
            <div><strong>URL:</strong> {mutated_request.url[:80]}...</div>
            <div><strong>Status:</strong> <span style="color: {'#ff6b6b' if status_code >= 400 else '#00ff41'}">{status_code}</span></div>
            <div><strong>Mutation:</strong> {mutated_request.mutation_description[:60]}</div>
        </div>
        """
        try:
            await page.evaluate(f"document.body.insertAdjacentHTML('beforeend', `{overlay_html}`)")
        except Exception:
            pass

    async def capture_api_response_screenshot(
        self,
        test_case_id: str,
        endpoint_id: str,
        request_url: str,
        method: str,
        status_code: int,
        response_body: str | None = None,
        label: str = "",
    ) -> str | None:
        """Capture a screenshot of an API response rendered in the browser."""
        if not self.enabled:
            return None

        try:
            await self._ensure_browser()
            if not self._context:
                return None

            page = await self._context.new_page()

            safe_label = label.replace(" ", "_").replace("/", "_")[:30] if label else ""
            filename = f"{test_case_id}_{endpoint_id}_api_{safe_label}.png"
            screenshot_path = self.output_dir / filename

            try:
                # Create a simple HTML page showing the API response
                body_escaped = (response_body or "No response body")[:2000]
                body_escaped = body_escaped.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

                html_content = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>API Response - {test_case_id}</title>
                    <style>
                        body {{ background: #1a1a2e; color: #e0e0e0; font-family: monospace; padding: 20px; }}
                        .header {{ background: #16213e; padding: 15px; border-radius: 8px; margin-bottom: 15px; }}
                        .status {{ color: {'#ff6b6b' if status_code >= 400 else '#00ff41'}; font-size: 24px; }}
                        .method {{ color: #ffd93d; font-weight: bold; }}
                        pre {{ background: #0f3460; padding: 15px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; }}
                        .finding-badge {{ background: #ff6b6b; color: white; padding: 5px 10px; border-radius: 4px; }}
                        .pass-badge {{ background: #00ff41; color: black; padding: 5px 10px; border-radius: 4px; }}
                    </style>
                </head>
                <body>
                    <div class="header">
                        <div class="status">Status: {status_code}</div>
                        <div><span class="method">{method}</span> {request_url[:120]}</div>
                        <div>Test: {test_case_id} | Endpoint: {endpoint_id}</div>
                    </div>
                    <h3>Response Body:</h3>
                    <pre>{body_escaped}</pre>
                </body>
                </html>
                """

                await page.set_content(html_content)
                await page.wait_for_timeout(500)

                await page.screenshot(path=str(screenshot_path))
                logger.debug(f"API response screenshot saved: {screenshot_path}")
                return str(screenshot_path)

            finally:
                await page.close()

        except Exception as e:
            logger.error(f"API response screenshot error: {e}")
            return None
