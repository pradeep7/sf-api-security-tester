"""Manual Auth Handoff — Cookie Harvesting for SSO/JIT/Azure AD flows.

Opens a headed browser for manual login, extracts session cookies,
and injects them into the httpx client for automated testing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from loguru import logger

from .models import AuditEvent


class AuthHandoff:
    """Manages manual authentication via headed Playwright browser.

    Used when SSO/JIT/Azure AD flows cannot be automated.
    """

    def __init__(self, config: dict[str, Any]):
        self.enabled: bool = False  # Set True by --manual-auth flag
        self.cookie_file: Path = Path("output/session_cookies.json")
        self._audit_log: list[AuditEvent] = []

    def harvest_cookies(
        self, login_url: str, credentials: dict[str, Any] | None = None
    ) -> dict[str, str]:
        """Open a headed browser for manual login, wait for user, extract cookies.

        Returns:
            Dict of cookie name -> value for session cookies.
        """
        if not self.enabled:
            return {}

        # Check for previously saved cookies
        if self.cookie_file.exists():
            logger.info(f"Found cached session cookies: {self.cookie_file}")
            cookies = self._load_cookies()
            if cookies:
                logger.info(f"Loaded {len(cookies)} cookies from cache")
                self._log("cookie_load", str(self.cookie_file), "success", f"{len(cookies)} cookies")
                return cookies

        console = self._get_console()
        console.print(
            "\n[bold yellow]MANUAL AUTH REQUIRED[/bold yellow]\n"
            f"[yellow]A browser window will open to: {login_url}[/yellow]\n"
            "[yellow]Please log in via Azure AD / SSO / JIT in the browser.[/yellow]\n"
            "[yellow]Press ENTER in this terminal when you reach the portal dashboard.[/yellow]\n"
        )

        try:
            cookies = asyncio.run(self._harvest_async(login_url))
            if cookies:
                self._save_cookies(cookies)
                self._log("cookie_harvest", login_url, "success", f"{len(cookies)} cookies")
                console.print(
                    f"[green]Harvested {len(cookies)} session cookies. "
                    f"Saved to {self.cookie_file}[/green]"
                )
            else:
                console.print("[red]No session cookies extracted. Login may have failed.[/red]")
            return cookies
        except Exception as e:
            logger.error(f"Manual auth handoff failed: {e}")
            self._log("cookie_harvest", login_url, "error", str(e))
            return {}

    async def _harvest_async(self, login_url: str) -> dict[str, str]:
        """Open headed browser, wait for user login, extract cookies."""
        from playwright.async_api import async_playwright

        pw = await async_playwright().start()
        browser = await pw.chromium.launch(
            headless=False,  # HEADED — user must see the browser
            args=["--start-maximized"],
        )
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
        )
        page = await context.new_page()

        try:
            # Navigate to login
            await page.goto(login_url, wait_until="domcontentloaded")
            logger.info(f"Opened browser to: {login_url}")

            # Wait for user to press Enter in terminal
            input("Press ENTER after you have logged in and reached the dashboard...")

            # Extract all cookies
            all_cookies = await context.cookies()

            # Filter to session-relevant cookies (skip static/analytics)
            session_cookies: dict[str, str] = {}
            for cookie in all_cookies:
                name = cookie.get("name", "")
                value = cookie.get("value", "")
                # Include SF session cookies and auth-related cookies
                if name and value and any(
                    kw in name.lower()
                    for kw in ["sid", "session", "token", "auth", "jwt", "access", "refresh", "cookie"]
                ):
                    session_cookies[name] = value

            # If no session cookies found, include all cookies
            if not session_cookies:
                session_cookies = {c["name"]: c["value"] for c in all_cookies if c.get("name")}

            logger.info(f"Extracted {len(session_cookies)} cookies from browser")
            return session_cookies

        finally:
            await browser.close()
            await pw.stop()

    def _save_cookies(self, cookies: dict[str, str]):
        """Save cookies to a JSON file."""
        self.cookie_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cookie_file, "w", encoding="utf-8") as f:
            json.dump(cookies, f, indent=2)

    def _load_cookies(self) -> dict[str, str]:
        """Load cookies from a JSON file."""
        try:
            with open(self.cookie_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def clear_cookies(self):
        """Clear cached cookies."""
        if self.cookie_file.exists():
            self.cookie_file.unlink()
            logger.info("Cleared cached session cookies")

    def _log(self, action: str, target: str, result: str, details: str = ""):
        self._audit_log.append(AuditEvent(
            action=action, target=target, result=result, details=details
        ))

    def _get_console(self):
        from rich.console import Console
        return Console()


# Needed for input() in async context
import asyncio
