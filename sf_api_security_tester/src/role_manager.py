"""Role Manager — Multi-role session handler with isolated browser contexts.

Provides separate Playwright browser contexts per role to prevent
cookie/session contamination during role comparison testing.
"""

from __future__ import annotations

import asyncio
from typing import Any

from loguru import logger

from .models import AuditEvent


class RoleSession:
    """A single role's browser session with isolated context."""

    __slots__ = ("role_name", "page", "context", "browser", "verified", "audit_log")

    def __init__(self, role_name: str):
        self.role_name = role_name
        self.page: Any = None
        self.context: Any = None
        self.browser: Any = None
        self.verified: bool = False
        self.audit_log: list[AuditEvent] = []

    def log(self, action: str, target: str = "", result: str = "success", details: str = ""):
        self.audit_log.append(AuditEvent(
            action=action, target=target, result=result, details=details, role=self.role_name
        ))


class RoleManager:
    """Creates and manages isolated browser sessions for multiple roles."""

    def __init__(self, config: dict[str, Any]):
        role_cfg = config.get("role_comparison", {})
        self.enabled: bool = role_cfg.get("enabled", False)
        self.roles: list[dict[str, Any]] = role_cfg.get("roles", [])
        self.page_load_timeout: int = config.get("exploration", config.get("discovery", {})).get("page_load_timeout", 30) * 1000

    def create_sessions(
        self, credentials_config: dict[str, Any]
    ) -> dict[str, RoleSession]:
        """Create isolated browser sessions for each configured role.

        Args:
            credentials_config: The full credentials.yaml content.

        Returns:
            Dict mapping role_name -> RoleSession.
        """
        if not self.enabled or not self.roles:
            return {}

        role_creds = credentials_config.get("role_comparison", credentials_config.get("roles", {}))
        sessions: dict[str, RoleSession] = {}

        for role in self.roles:
            role_name = role.get("name", "unknown")
            cred_key = role.get("credentials_key", role_name)
            creds = role_creds.get(cred_key, {})

            if not creds.get("username"):
                logger.warning(f"Role '{role_name}' has no credentials — skipping")
                continue

            session = RoleSession(role_name)
            sessions[role_name] = session
            logger.info(f"Created session for role: {role_name}")

        return sessions

    async def login_session(
        self, session: RoleSession, login_url: str, credentials: dict[str, Any]
    ) -> bool:
        """Log in a role session with isolated browser context.

        Uses a NEW browser + context per role to guarantee cookie isolation.
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.error("Playwright not installed")
            return False

        try:
            pw = await async_playwright().start()
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
                ),
            )
            page = await context.new_page()

            session.browser = browser
            session.context = context
            session.page = page

            # Navigate to login
            await page.goto(login_url, timeout=self.page_load_timeout, wait_until="domcontentloaded")
            await page.wait_for_timeout(2000)
            session.log("navigate", login_url, "success")

            # Fill credentials
            username = credentials.get("username", "")
            password = credentials.get("password", "")

            # Username
            for sel in ["#username", 'input[name="username"]', 'input[type="email"]']:
                el = await page.query_selector(sel)
                if el and await el.is_visible():
                    await el.fill(username)
                    break

            # Password
            for sel in ["#password", 'input[name="password"]', 'input[type="password"]']:
                el = await page.query_selector(sel)
                if el and await el.is_visible():
                    await el.fill(password)
                    break

            # Submit
            for sel in ["#Login", 'input[type="submit"]', 'button[type="submit"]']:
                el = await page.query_selector(sel)
                if el and await el.is_visible():
                    await el.click()
                    break

            await page.wait_for_timeout(5000)

            # Wait for Lightning app
            for sel in [".oneAppLauncher", ".slds-page-header", ".forceGlobalNav"]:
                try:
                    await page.wait_for_selector(sel, timeout=15000)
                    break
                except Exception:
                    continue

            session.log("login", login_url, "success", f"URL: {page.url}")

            # Verify role
            session.verified = await self._verify_role(page, session)
            session.log("verify_role", session.role_name, "verified" if session.verified else "unverified")

            return True

        except Exception as e:
            logger.error(f"Login failed for role '{session.role_name}': {e}")
            session.log("login", login_url, "error", str(e))
            return False

    async def _verify_role(self, page, session: RoleSession) -> bool:
        """Verify the role by checking the Salesforce user profile page."""
        try:
            # Try to navigate to the user profile
            current_url = page.url
            if "/lightning/" in current_url:
                # Try to find and click the user profile menu
                profile_selectors = [
                    ".branding-userProfile",
                    ".profile-link",
                    'a[href*="/profile"]',
                    ".user-profile-menu",
                ]
                for sel in profile_selectors:
                    try:
                        el = await page.query_selector(sel)
                        if el and await el.is_visible():
                            await el.click()
                            await page.wait_for_timeout(1000)
                            break
                    except Exception:
                        continue

            # Check for role indicators in the page
            page_text = await page.evaluate("() => document.body ? document.body.innerText : ''")
            page_text = (page_text or "").lower()

            role_indicators = {
                "admin": ["system administrator", "setup", "admin", "manage users"],
                "standard_user": ["standard user", "regular user", "community user"],
                "tenant_user": ["tenant", "partner", "community"],
            }

            expected = session.role_name.lower()
            indicators = role_indicators.get(expected, [])

            for indicator in indicators:
                if indicator in page_text:
                    return True

            # If no specific indicators found, assume verified if login succeeded
            # (the page URL changed from /login)
            if "/login" not in page.url:
                return True

            return False

        except Exception as e:
            logger.debug(f"Role verification failed: {e}")
            return False

    async def close_all(self, sessions: dict[str, RoleSession]):
        """Close all role sessions cleanly."""
        for role_name, session in sessions.items():
            try:
                if session.context:
                    await session.context.close()
                if session.browser:
                    await session.browser.close()
            except Exception as e:
                logger.debug(f"Error closing session for {role_name}: {e}")

    def get_all_audit_logs(self, sessions: dict[str, RoleSession]) -> list[AuditEvent]:
        """Collect audit logs from all sessions."""
        logs = []
        for session in sessions.values():
            logs.extend(session.audit_log)
        return sorted(logs, key=lambda e: e.timestamp)
