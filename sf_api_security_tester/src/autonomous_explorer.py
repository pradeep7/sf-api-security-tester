"""Autonomous AI Reconnaissance — Playwright BFS exploration + Vision LLM analysis.

Phase 0 of V3.0: Systematically explores a Salesforce Lightning portal,
captures page snapshots, and uses a Vision LLM to understand page purpose,
input fields, and sensitive data exposure.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from loguru import logger

from .models import AuditEvent, InputFieldInfo, PageSnapshot, SiteMap

# ---------------------------------------------------------------------------
# Vision LLM prompt for page analysis
# ---------------------------------------------------------------------------
_PAGE_ANALYSIS_PROMPT = """\
You are an expert Salesforce Security Reconnaissance Analyst. \
Analyse this screenshot and DOM snippet of a Salesforce Lightning page. \
Return a JSON object describing the page and its security-relevant characteristics:

{
  "page_purpose": "<1-sentence description of what this page does>",
  "page_category": "dashboard|list_view|record_detail|form|settings|admin|profile|file_upload|login|other",
  "features": ["list of functional capabilities on this page"],
  "input_fields": [
    {"name": "<field name or id>", "type": "text|select|file|richtext|search|textarea|checkbox|radio", "label": "<visible label>", "risk_type": "xss|sqli|ssrf|none"}
  ],
  "navigation_targets": ["list of visible links/tabs/buttons and where they go"],
  "sensitive_data_visible": <true/false>,
  "sensitive_data_description": "<what sensitive data is visible if any>",
  "role_indicators": "<describe any role/admin/user indicators visible>",
  "api_endpoints_inferred": ["any API calls you can infer from the page behavior"],
  "file_upload_detected": <true/false>,
  "comment_or_state_change_detected": <true/false>,
  "admin_or_settings_page": <true/false>,
  "profile_page": <true/false>,
  "destructive_actions": ["list of delete/archive/remove buttons visible"],
  "state_change_actions": ["list of save/submit/update buttons visible"],
  "confidence": <float 0.0-1.0, how confident you are in this analysis>
}

Rules:
- Include ALL visible input fields (text boxes, dropdowns, file uploads, search bars).
- risk_type: xss if field accepts free text, sqli if it's a search/query field, \
ssrf if it accepts URLs, none otherwise.
- sensitive_data_visible: true if PII, internal IDs, API keys, or emails are visible.
- features: list key capabilities (e.g. "Search contacts", "Create case", "Export data").
- navigation_targets: list visible navigation elements (e.g. "Tab: Cases", "Button: New Case").
- api_endpoints_inferred: infer from UI (e.g. "/services/data/v58.0/sobjects/Account").
- file_upload_detected: true if any file input or upload button is visible.
- comment_or_state_change_detected: true if any textarea, rich text editor, or comment box exists.
- admin_or_settings_page: true if this is an admin, setup, or configuration page.
- profile_page: true if this is a user profile or account settings page.
- destructive_actions: list buttons that delete, archive, or remove data.
- state_change_actions: list buttons that save, submit, or update data.
- Return ONLY the JSON, no markdown.
"""

_MAX_DOM_CHARS = 3000
_MAX_VISIBLE_TEXT = 3000
_MAX_IMG_B64 = 80_000


class AutonomousExplorer:
    """BFS page explorer for Salesforce Lightning portals.

    Uses Playwright to systematically click through the portal, capturing
    page snapshots and using Vision LLM to analyse each page.
    """

    def __init__(self, config: dict[str, Any]):
        expl_cfg = config.get("exploration", {})
        self.enabled: bool = expl_cfg.get("enabled", True)
        self.max_pages: int = expl_cfg.get("max_pages", 100)
        self.max_depth: int = expl_cfg.get("max_depth", 5)
        self.page_load_timeout: int = expl_cfg.get("page_load_timeout", 30) * 1000

        # Vision LLM config (reuse visual_audit settings)
        vis_cfg = config.get("visual_audit", {})
        self.llm_enabled: bool = vis_cfg.get("enabled", False) and self.enabled
        self.llm_provider: str = vis_cfg.get("provider", "openai")
        self.llm_model: str = vis_cfg.get("model", "gpt-4o")
        api_key_env: str = vis_cfg.get("api_key_env_var", "LLM_API_KEY")
        self.api_key: str = os.environ.get(api_key_env, "")
        if not self.api_key:
            self.api_key = os.environ.get("OPENAI_API_KEY", "")
        self.llm_client: Any = None

        # Playwright state
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None

        # Exploration state
        self._visited: set[str] = set()
        self._queue: list[tuple[str, int, str | None]] = []  # (url, depth, parent_url)
        self._snapshots: list[PageSnapshot] = []
        self._audit_log: list[AuditEvent] = []
        self._output_dir: Path = Path("output/evidence/exploration")
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def _log_audit(self, action: str, target: str = "", result: str = "success", details: str = "", role: str = ""):
        """Record a structured audit event."""
        event = AuditEvent(
            action=action, target=target, result=result, details=details, role=role
        )
        self._audit_log.append(event)
        logger.debug(f"AUDIT: [{action}] {target[:60]} -> {result}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def explore(
        self,
        portal_url: str,
        credentials: dict[str, Any] | None = None,
    ) -> SiteMap:
        """Run autonomous exploration on a Salesforce portal.

        Smart Recon Flow:
        1. Try automated login with provided credentials
        2. If SSO/MFA detected, fall back to manual login
        3. After login, BFS-crawl every page/tab
        4. If login fails entirely, explore as guest

        Args:
            portal_url: Base URL of the portal to explore.
            credentials: Optional dict with login_url, username, password.

        Returns:
            SiteMap with all discovered pages and their analysis.
        """
        if not self.enabled:
            logger.info("Autonomous exploration disabled — skipping")
            return SiteMap()

        logger.info(f"Starting autonomous exploration of {portal_url}")
        self._log_audit("explore_start", portal_url, "started")

        start_time = time.time()

        try:
            asyncio.run(self._run_exploration(portal_url, credentials))
        except Exception as e:
            logger.error(f"Exploration failed: {e}")
            self._log_audit("explore_error", portal_url, "error", str(e))

        duration = time.time() - start_time

        # Build SiteMap
        site_map = SiteMap(
            pages=self._snapshots,
            total_pages=len(self._snapshots),
            total_input_fields=sum(len(p.input_fields) for p in self._snapshots),
            categories=self._count_categories(),
            sensitive_pages=[p.url for p in self._snapshots if p.sensitive_data_visible],
            exploration_duration_seconds=round(duration, 1),
            audit_log=self._audit_log,
        )

        self._log_audit("explore_complete", portal_url, "success",
                        f"{site_map.total_pages} pages, {site_map.total_input_fields} inputs")

        logger.info(
            f"Exploration complete: {site_map.total_pages} pages, "
            f"{site_map.total_input_fields} input fields, "
            f"{len(site_map.sensitive_pages)} sensitive pages "
            f"({duration:.1f}s)"
        )

        return site_map

    # ------------------------------------------------------------------
    # Async exploration loop
    # ------------------------------------------------------------------
    async def _run_exploration(
        self, portal_url: str, credentials: dict[str, Any] | None
    ):
        """BFS exploration using Playwright with smart login flow.

        Smart Recon Flow:
        1. Launch browser
        2. Try automated login (if credentials provided)
        3. If automated login fails (SSO/MFA/error), offer manual login
        4. After login (auto or manual), BFS-crawl pages
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.error("Playwright not installed")
            return

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=True)
        self._context = await self._browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
            ),
        )

        try:
            # Smart login flow
            login_success = False
            if credentials and credentials.get("username"):
                login_success = await self._smart_login(portal_url, credentials)

            if not login_success and credentials:
                # Auto login failed — try manual login
                logger.info("Automated login failed — offering manual login")
                login_success = await self._manual_login(portal_url)

            if not login_success:
                logger.warning("Login failed — exploring as guest")
                self._log_audit("login", portal_url, "guest_mode")

            # Start BFS from portal URL
            self._queue.append((portal_url, 0, None))
            self._log_audit("navigate", portal_url, "queued", "BFS root")

            while self._queue and len(self._snapshots) < self.max_pages:
                url, depth, parent_url = self._queue.pop(0)

                if depth > self.max_depth:
                    self._log_audit("skip", url, "max_depth", f"depth={depth}")
                    continue
                if self._normalise_url(url) in self._visited:
                    self._log_audit("skip", url, "already_visited")
                    continue

                # Scope check: stay on same domain
                if not self._is_same_domain(portal_url, url):
                    self._log_audit("skip", url, "out_of_scope", "different domain")
                    continue

                snapshot = await self._explore_page(url, depth, parent_url)
                if snapshot:
                    self._snapshots.append(snapshot)
                    self._visited.add(self._normalise_url(url))
                    self._log_audit("navigate", url, "success", f"depth={depth}, category={snapshot.page_category}")

                    # Discover new links
                    if depth < self.max_depth:
                        new_urls = await self._discover_links(url)
                        self._log_audit("click", url, "links_found", f"{len(new_urls)} links")
                        for new_url in new_urls:
                            if self._normalise_url(new_url) not in self._visited:
                                self._queue.append((new_url, depth + 1, url))

        finally:
            await self._cleanup()

    async def _smart_login(self, portal_url: str, credentials: dict[str, Any]) -> bool:
        """Try automated login. Returns True if successful."""
        try:
            await self._login(portal_url, credentials)
            # Check if we're still on the login page
            page = await self._context.new_page()
            try:
                current_url = page.url
                is_logged_in = "/s/login" not in current_url and "/login" not in current_url
                if is_logged_in:
                    self._log_audit("login", portal_url, "success", role=credentials.get("username", ""))
                else:
                    self._log_audit("login", portal_url, "failed", "still on login page")
                return is_logged_in
            finally:
                await page.close()
        except Exception as e:
            logger.warning(f"Automated login failed: {e}")
            self._log_audit("login", portal_url, "failed", str(e))
            return False

    async def _manual_login(self, portal_url: str) -> bool:
        """Open a headed browser for manual SSO/MFA login.

        After user logs in and presses ENTER, we extract cookies
        and use them for the exploration session.
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return False

        console = self._get_console()
        console.print(
            f"\n[bold yellow]MANUAL LOGIN REQUIRED[/bold yellow]\n"
            f"[yellow]A browser window will open to: {portal_url}[/yellow]\n"
            f"[yellow]Please log in via SSO/MFA/JIT in the browser.[/yellow]\n"
            f"[yellow]Press ENTER in this terminal when you reach the dashboard.[/yellow]\n"
        )

        # Launch a SEPARATE headed browser for manual login
        pw = await async_playwright().start()
        browser = await pw.chromium.launch(headless=False)
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
        )
        page = await context.new_page()

        try:
            await page.goto(portal_url, timeout=self.page_load_timeout, wait_until="domcontentloaded")
            logger.info(f"Opened manual login browser to: {portal_url}")

            # Wait for user to log in
            await asyncio.get_event_loop().run_in_executor(None, input)

            # Extract cookies from the manual session
            all_cookies = await context.cookies()
            session_cookies = {c["name"]: c["value"] for c in all_cookies if c.get("name")}

            if session_cookies:
                logger.info(f"Extracted {len(session_cookies)} cookies from manual login")
                self._log_audit("manual_login", portal_url, "success", f"{len(session_cookies)} cookies")

                # Inject cookies into the main exploration context
                await self._context.add_cookies(all_cookies)

                # Verify we can access a page
                test_page = await self._context.new_page()
                try:
                    await test_page.goto(portal_url, timeout=self.page_load_timeout, wait_until="domcontentloaded")
                    await test_page.wait_for_timeout(3000)
                    current_url = test_page.url
                    is_logged_in = "/s/login" not in current_url and "/login" not in current_url
                    if is_logged_in:
                        logger.info(f"Manual login verified — exploring as authenticated user")
                        return True
                    else:
                        logger.warning("Manual login cookies did not work — exploring as guest")
                        return False
                finally:
                    await test_page.close()
            else:
                logger.warning("No cookies extracted from manual login")
                return False

        except Exception as e:
            logger.error(f"Manual login failed: {e}")
            return False
        finally:
            await context.close()
            await browser.close()
            await pw.stop()

    # ------------------------------------------------------------------
    # Page exploration
    # ------------------------------------------------------------------
    async def _explore_page(
        self, url: str, depth: int, parent_url: str | None
    ) -> PageSnapshot | None:
        """Navigate to a page, capture snapshot, and analyse with Vision LLM.

        V3.1: Now captures response headers, network requests, localStorage,
        iframe content, and SF metadata for deeper recon.
        """
        try:
            page = await self._context.new_page()

            # --- V3.1: Intercept network requests (XHR/Fetch) ---
            captured_requests: list[dict] = []
            async def on_request(request):
                if request.resource_type in ("xhr", "fetch", "document"):
                    captured_requests.append({
                        "url": request.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                    })
            page.on("request", on_request)

            try:
                await page.goto(url, timeout=self.page_load_timeout, wait_until="domcontentloaded")
                # Wait for Salesforce Lightning to settle
                await self._wait_for_lightning(page)
                await page.wait_for_timeout(1500)

                # Capture data
                title = await page.title()
                current_url = page.url
                dom_summary = await self._extract_dom_summary(page)
                visible_text = await self._extract_visible_text(page)
                input_fields = await self._extract_input_fields(page)

                # V3.1: Capture response headers
                response_headers = await self._extract_response_headers(page)

                # V3.1: Capture localStorage/sessionStorage
                storage_data = await self._extract_storage(page)

                # V3.1: Capture iframe content
                iframe_summary = await self._extract_iframe_content(page)

                # V3.1: Capture SF metadata (object types, field names, Aura components)
                sf_metadata = await self._extract_sf_metadata(page)

                # V3.1: Detect page characteristics
                page_chars = await self._detect_page_characteristics(page)

                # Screenshot
                safe_name = re.sub(r"[^\w\-]", "_", urlparse(current_url).path)[:40]
                screenshot_path = self._output_dir / f"page_{depth}_{safe_name}.png"
                await page.screenshot(path=str(screenshot_path))
                self._log_audit("screenshot", current_url, "success", str(screenshot_path))

                # Vision LLM analysis (if enabled)
                analysis = await self._analyse_page_with_llm(
                    str(screenshot_path), dom_summary, current_url
                )
                self._log_audit("llm_call", current_url, "success" if analysis else "skipped",
                                f"fields={len(analysis.get('input_fields', []))}" if analysis else "disabled")

                # Build enhanced DOM summary with V3.1 data
                enhanced_dom = self._build_enhanced_dom_summary(
                    dom_summary, response_headers, storage_data,
                    iframe_summary, sf_metadata, page_chars, captured_requests
                )

                # Determine category from LLM or heuristic
                category = analysis.get("page_category", "") if analysis else ""
                if not category:
                    category = page_chars.get("category", "other")

                # Determine sensitive data from LLM or heuristic
                sensitive = analysis.get("sensitive_data_visible", False) if analysis else False
                if not sensitive:
                    sensitive = page_chars.get("has_pii", False) or page_chars.get("has_financial", False)

                # Determine role indicators from LLM or heuristic
                role = analysis.get("role_indicators", "") if analysis else ""
                if not role:
                    role = page_chars.get("role_hint", "")

                snapshot = PageSnapshot(
                    url=current_url,
                    title=title,
                    page_purpose=analysis.get("page_purpose", "") if analysis else "",
                    page_category=category,
                    features=analysis.get("features", []) if analysis else [],
                    input_fields=[
                        InputFieldInfo(**f) for f in analysis.get("input_fields", [])
                    ] if analysis and analysis.get("input_fields") else input_fields,
                    navigation_targets=analysis.get("navigation_targets", []) if analysis else [],
                    sensitive_data_visible=sensitive,
                    sensitive_data_description=analysis.get("sensitive_data_description", "") if analysis else "",
                    role_indicators=role,
                    api_endpoints_inferred=analysis.get("api_endpoints_inferred", []) if analysis else [],
                    analysis_confidence=float(analysis.get("confidence", 0.5)) if analysis else 0.0,
                    screenshot_path=str(screenshot_path),
                    dom_summary=enhanced_dom[:_MAX_DOM_CHARS],
                    visible_text=visible_text[:_MAX_VISIBLE_TEXT],
                    depth=depth,
                    parent_url=parent_url,
                    navigation_method="link",
                )

                logger.info(
                    f"  [Depth {depth}] {snapshot.page_category}: "
                    f"{title[:50] or current_url[:50]} "
                    f"({len(snapshot.input_fields)} inputs, "
                    f"{len(captured_requests)} XHR/Fetch, "
                    f"{len(response_headers)} resp headers)"
                )

                return snapshot

            finally:
                await page.close()

        except Exception as e:
            logger.debug(f"Failed to explore {url[:80]}: {e}")
            return None

    async def _wait_for_lightning(self, page):
        """Wait for Salesforce Lightning SPA to finish loading.

        Uses specific Lightning selectors instead of generic networkidle
        to handle the SPA navigation properly.
        """
        # Primary: Wait for Lightning app shell elements
        app_selectors = [
            ".oneAppLauncher",
            ".slds-page-header",
            ".slds-grid",
            ".forceGlobalNav",
        ]

        for selector in app_selectors:
            try:
                await page.wait_for_selector(
                    selector, timeout=min(self.page_load_timeout, 10000)
                )
                break
            except Exception:
                continue

        # Wait for loading spinners to disappear
        try:
            await page.wait_for_function("""() => {
                const spinners = document.querySelectorAll(
                    '.slds-spinner, .loadingSpinner, [class*="spinner"]'
                );
                return spinners.length === 0;
            }""", timeout=8000)
        except Exception:
            pass

        # Final settle
        await page.wait_for_timeout(1000)

    # ------------------------------------------------------------------
    # DOM analysis
    # ------------------------------------------------------------------
    async def _extract_dom_summary(self, page) -> str:
        """Extract a summary of the page DOM structure."""
        try:
            return await page.evaluate("""() => {
                const inputs = document.querySelectorAll('input, select, textarea, [role="combobox"], [role="searchbox"]');
                const buttons = document.querySelectorAll('button, [role="button"], a.slds-button');
                const tables = document.querySelectorAll('table, .slds-table');
                const forms = document.querySelectorAll('form');

                let summary = `Inputs: ${inputs.length}, Buttons: ${buttons.length}, Tables: ${tables.length}, Forms: ${forms.length}\\n`;

                inputs.forEach((el, i) => {
                    if (i < 15) {
                        summary += `  [${el.tagName}] name="${el.name||''}" type="${el.type||''}" placeholder="${el.placeholder||''}"\\n`;
                    }
                });

                return summary;
            }""")
        except Exception:
            return ""

    async def _extract_visible_text(self, page) -> str:
        """Extract visible text content from the page."""
        try:
            return await page.evaluate("""() => {
                const body = document.body;
                if (!body) return '';
                return body.innerText.substring(0, 3000);
            }""")
        except Exception:
            return ""

    async def _extract_input_fields(self, page) -> list[InputFieldInfo]:
        """Extract input fields from the DOM (fallback when LLM is disabled)."""
        try:
            fields_raw = await page.evaluate("""() => {
                const inputs = document.querySelectorAll('input, select, textarea, [role="combobox"], [role="searchbox"]');
                const results = [];
                inputs.forEach(el => {
                    const label = el.labels && el.labels[0] ? el.labels[0].textContent.trim() : '';
                    const type = el.tagName === 'SELECT' ? 'select'
                        : el.tagName === 'TEXTAREA' ? 'textarea'
                        : el.type || 'text';
                    let riskType = 'none';
                    if (type === 'file') riskType = 'ssrf';
                    else if (type === 'search' || el.getAttribute('role') === 'searchbox') riskType = 'sqli';
                    else if (type === 'text' || type === 'email' || type === 'url') riskType = 'xss';

                    results.push({
                        name: el.name || el.id || '',
                        field_type: type,
                        label: label,
                        risk_type: riskType,
                        placeholder: el.placeholder || '',
                    });
                });
                return results;
            }""")
            return [InputFieldInfo(**f) for f in fields_raw if f.get("name") or f.get("label")]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # V3.1: Enhanced extraction methods
    # ------------------------------------------------------------------
    async def _extract_response_headers(self, page) -> dict[str, str]:
        """Extract response headers from the last navigation."""
        try:
            return await page.evaluate("""() => {
                // Performance API provides timing for last navigation
                const entries = performance.getEntriesByType('navigation');
                if (entries.length > 0) {
                    return { 'status': String(entries[0].responseStatus || 0) };
                }
                return {};
            }""")
        except Exception:
            return {}

    async def _extract_storage(self, page) -> dict[str, str]:
        """Extract localStorage and sessionStorage items."""
        try:
            return await page.evaluate("""() => {
                const storage = {};
                try {
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        const val = localStorage.getItem(key);
                        if (key && val && val.length < 200) {
                            storage['ls_' + key] = val;
                        }
                    }
                } catch(e) {}
                try {
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        const val = sessionStorage.getItem(key);
                        if (key && val && val.length < 200) {
                            storage['ss_' + key] = val;
                        }
                    }
                } catch(e) {}
                return storage;
            }""")
        except Exception:
            return {}

    async def _extract_iframe_content(self, page) -> str:
        """Extract summary of iframe content."""
        try:
            return await page.evaluate("""() => {
                const iframes = document.querySelectorAll('iframe');
                if (iframes.length === 0) return '';
                let summary = `Iframes: ${iframes.length}\\n`;
                iframes.forEach((iframe, i) => {
                    if (i < 5) {
                        const src = iframe.src || 'no-src';
                        const name = iframe.name || 'unnamed';
                        summary += `  [${i}] name="${name}" src="${src.substring(0, 100)}"\\n`;
                    }
                });
                return summary;
            }""")
        except Exception:
            return ""

    async def _extract_sf_metadata(self, page) -> dict[str, Any]:
        """Extract Salesforce-specific metadata from the page."""
        try:
            return await page.evaluate("""() => {
                const meta = {};

                // Extract SF object type from URL or data attributes
                const url = window.location.href;
                const objMatch = url.match(/\/lightning\\/o\\/([A-Za-z_]+)/);
                if (objMatch) meta.object_type = objMatch[1];

                // Extract record ID from URL
                const recMatch = url.match(/\/lightning\\/r\\/[^\\/]+\\/([A-Za-z0-9]{15,18})/);
                if (recMatch) meta.record_id = recMatch[1];

                // Extract from data attributes (Lightning components)
                document.querySelectorAll('[data-object-api-name], [data-record-id]').forEach(el => {
                    const obj = el.getAttribute('data-object-api-name');
                    const recId = el.getAttribute('data-record-id');
                    if (obj) meta.object_type = obj;
                    if (recId) meta.record_id = recId;
                });

                // Extract Aura component names
                const auraComponents = [];
                document.querySelectorAll('[data-aura-rendered-by], [aura-type]').forEach(el => {
                    const type = el.getAttribute('aura-type') || el.getAttribute('data-aura-rendered-by');
                    if (type && !auraComponents.includes(type)) auraComponents.push(type);
                });
                if (auraComponents.length > 0) meta.aura_components = auraComponents.slice(0, 10);

                // Extract field names from labels
                const fieldNames = [];
                document.querySelectorAll('label, .slds-form-element__label').forEach(el => {
                    const text = el.textContent.trim();
                    if (text && text.length < 50) fieldNames.push(text);
                });
                if (fieldNames.length > 0) meta.field_names = fieldNames.slice(0, 20);

                // Detect page type from SF patterns
                meta.is_setup = url.includes('/setup/') || url.includes('/lightning/setup');
                meta.is_admin = url.includes('/setup/') || url.includes('/admin');
                meta.is_record_detail = url.includes('/lightning/r/');
                meta.is_list_view = url.includes('/lightning/o/') && url.includes('/list');

                return meta;
            }""")
        except Exception:
            return {}

    async def _detect_page_characteristics(self, page) -> dict[str, Any]:
        """Detect page characteristics: file uploads, comments, state changes, profiles."""
        try:
            return await page.evaluate("""() => {
                const chars = {};

                // Detect file upload inputs
                const fileInputs = document.querySelectorAll('input[type="file"]');
                chars.has_file_upload = fileInputs.length > 0;
                chars.file_upload_count = fileInputs.length;

                // Detect comment/text areas (state change indicators)
                const textAreas = document.querySelectorAll('textarea, [contenteditable="true"]');
                chars.has_comment_box = textAreas.length > 0;
                chars.comment_count = textAreas.length;

                // Detect rich text editors (CKEditor, TinyMCE, etc.)
                const richText = document.querySelectorAll('[class*="editor"], [class*="richtext"], [class*="ck-"], .cke_editable, .tox-edit-area');
                chars.has_rich_text = richText.length > 0;

                // Detect delete/archive buttons
                const deleteButtons = document.querySelectorAll('button[title*="Delete"], button[title*="Archive"], [data-action*="delete"]');
                chars.has_delete_action = deleteButtons.length > 0;

                // Detect save/submit buttons (state change indicators)
                const saveButtons = document.querySelectorAll('button[title*="Save"], button[title*="Submit"], button[title*="Update"], button[name="save"]');
                chars.has_save_action = saveButtons.length > 0;

                // Detect profile/user settings pages
                const profileIndicators = document.querySelectorAll('[class*="profile"], [class*="settings"], [class*="preferences"], [class*="account"]');
                chars.is_profile_or_settings = profileIndicators.length > 0;

                // Detect admin indicators
                const adminIndicators = document.querySelectorAll('[class*="admin"], [class*="setup"], [class*="configuration"]');
                chars.is_admin_page = adminIndicators.length > 0;

                // Detect sensitive data patterns
                const bodyText = document.body ? document.body.innerText : '';
                chars.has_pii = /email|phone|address|ssn|password/i.test(bodyText);
                chars.has_financial = /price|amount|total|payment|invoice|budget/i.test(bodyText);
                chars.has_internal_ids = /[0-9A-Za-z]{15}|[0-9A-Za-z]{18}/.test(bodyText);

                // Detect role indicators
                const roleText = bodyText.toLowerCase();
                if (roleText.includes('admin') || roleText.includes('administrator')) chars.role_hint = 'admin';
                else if (roleText.includes('manager')) chars.role_hint = 'manager';
                else if (roleText.includes('user') || roleText.includes('member')) chars.role_hint = 'user';
                else chars.role_hint = '';

                // Detect page category from characteristics
                if (chars.has_file_upload) chars.category = 'file_upload';
                else if (chars.is_admin_page) chars.category = 'admin';
                else if (chars.is_profile_or_settings) chars.category = 'settings';
                else if (chars.has_comment_box && chars.has_save_action) chars.category = 'form';
                else if (chars.has_delete_action) chars.category = 'admin_operations';
                else chars.category = 'other';

                return chars;
            }""")
        except Exception:
            return {}

    def _build_enhanced_dom_summary(
        self, dom_summary: str, response_headers: dict,
        storage: dict, iframe_summary: str, sf_metadata: dict,
        page_chars: dict, network_requests: list
    ) -> str:
        """Build an enhanced DOM summary including V3.1 data."""
        parts = [dom_summary]

        if response_headers:
            parts.append(f"\nResponse Headers: {json.dumps(response_headers)}")

        if storage:
            items = list(storage.items())[:10]
            parts.append(f"\nStorage ({len(storage)} items): {json.dumps(dict(items))}")

        if iframe_summary:
            parts.append(f"\n{iframe_summary}")

        if sf_metadata:
            parts.append(f"\nSF Metadata: {json.dumps(sf_metadata)}")

        if page_chars:
            chars_summary = []
            if page_chars.get("has_file_upload"):
                chars_summary.append(f"File Uploads: {page_chars.get('file_upload_count', 0)}")
            if page_chars.get("has_comment_box"):
                chars_summary.append(f"Comment Boxes: {page_chars.get('comment_count', 0)}")
            if page_chars.get("has_rich_text"):
                chars_summary.append("Rich Text Editor: YES")
            if page_chars.get("has_delete_action"):
                chars_summary.append("Delete Actions: YES")
            if page_chars.get("has_save_action"):
                chars_summary.append("Save/Submit Actions: YES")
            if page_chars.get("is_profile_or_settings"):
                chars_summary.append("Profile/Settings Page: YES")
            if page_chars.get("is_admin_page"):
                chars_summary.append("Admin Page: YES")
            if page_chars.get("has_pii"):
                chars_summary.append("PII Detected: YES")
            if page_chars.get("has_financial"):
                chars_summary.append("Financial Data: YES")
            if page_chars.get("has_internal_ids"):
                chars_summary.append("Internal IDs: YES")
            if chars_summary:
                parts.append(f"\nPage Characteristics: {', '.join(chars_summary)}")

        if network_requests:
            unique_urls = list(set(r["url"] for r in network_requests))[:10]
            parts.append(f"\nNetwork Requests ({len(network_requests)} total): {json.dumps(unique_urls)}")

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Link discovery
    # ------------------------------------------------------------------
    async def _discover_links(self, current_url: str) -> list[str]:
        """Discover navigable links on the current page."""
        try:
            page = await self._context.new_page()
            try:
                await page.goto(current_url, timeout=self.page_load_timeout, wait_until="domcontentloaded")
                await self._wait_for_lightning(page)
                await page.wait_for_timeout(1000)

                links_raw = await page.evaluate("""() => {
                    const links = [];
                    // Standard links
                    document.querySelectorAll('a[href]').forEach(a => {
                        const href = a.href;
                        if (href && !href.startsWith('javascript:') && !href.includes('#')) {
                            links.push(href);
                        }
                    });
                    // Lightning buttons that navigate
                    document.querySelectorAll('[data-navi-target-href]').forEach(el => {
                        links.push(el.getAttribute('data-navi-target-href'));
                    });
                    return [...new Set(links)];
                }""")

                # Filter to same-origin links
                base_domain = urlparse(current_url).netloc
                filtered = []
                for link in links_raw:
                    try:
                        parsed = urlparse(link)
                        if parsed.netloc == base_domain and not any(
                            ext in parsed.path.lower()
                            for ext in [".js", ".css", ".png", ".jpg", ".pdf", ".zip"]
                        ):
                            filtered.append(link)
                    except Exception:
                        continue

                return filtered[:50]  # Cap link discovery

            finally:
                await page.close()
        except Exception as e:
            logger.debug(f"Link discovery failed: {e}")
            return []

    # ------------------------------------------------------------------
    # Vision LLM analysis
    # ------------------------------------------------------------------
    def _get_llm_client(self) -> Any:
        if self.llm_client:
            return self.llm_client
        if not self.llm_enabled or not self.api_key:
            return None
        try:
            from openai import OpenAI
            self.llm_client = OpenAI(api_key=self.api_key, timeout=30)
            return self.llm_client
        except Exception:
            return None

    async def _analyse_page_with_llm(
        self, screenshot_path: str, dom_summary: str, page_url: str
    ) -> dict[str, Any]:
        """Analyse a page using Vision LLM."""
        if not self.llm_enabled:
            return {}

        client = self._get_llm_client()
        if not client:
            return {}

        try:
            # Encode screenshot
            img_data = Path(screenshot_path).read_bytes()
            b64 = base64.b64encode(img_data).decode()
            if len(b64) > _MAX_IMG_B64:
                b64 = b64[:_MAX_IMG_B64]

            response = client.chat.completions.create(
                model=self.llm_model,
                max_tokens=600,
                temperature=0.1,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": _PAGE_ANALYSIS_PROMPT},
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": f"URL: {page_url}\nDOM:\n{dom_summary[:1500]}"},
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{b64}",
                                    "detail": "low",
                                },
                            },
                        ],
                    },
                ],
            )

            raw = response.choices[0].message.content or "{}"
            # Robust parse
            cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip(), flags=re.MULTILINE)
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                match = re.search(r"\{.*\}", cleaned, re.DOTALL)
                if match:
                    return json.loads(match.group(0))
                return {}

        except Exception as e:
            logger.debug(f"Vision LLM analysis failed: {e}")
            return {}

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------
    async def _login(self, portal_url: str, credentials: dict[str, Any]):
        """Handle Salesforce Lightning login with all edge cases.

        Handles:
        1. Standard username/password fields with SF-specific selectors
        2. 'Remember this browser' prompt
        3. Lightning loading spinner
        4. MFA / 2FA prompt (pauses for manual completion)
        """
        login_url = credentials.get("login_url", f"{portal_url}/s/login")
        username = credentials.get("username", "")
        password = credentials.get("password", "")

        if not username or not password:
            logger.warning("No login credentials — exploring as guest")
            return

        page = await self._context.new_page()

        try:
            # --- Step 1: Navigate to login page ---
            logger.info(f"Navigating to login: {login_url}")
            await page.goto(login_url, timeout=self.page_load_timeout, wait_until="domcontentloaded")
            await page.wait_for_timeout(2000)

            # --- Step 2: Wait for and fill username field ---
            username_selectors = [
                "#username",
                'input[name="username"]',
                'input[id="username"]',
                'input[type="email"]',
                'input[placeholder*="Username"]',
                'input[placeholder*="username"]',
                'input[aria-label*="Username"]',
            ]
            username_field = await self._wait_for_any_selector(page, username_selectors, timeout=15000)
            if not username_field:
                logger.error("Could not find username field on login page")
                return

            await username_field.click()
            await username_field.fill("")
            await username_field.type(username, delay=30)
            logger.debug("Username filled")

            # --- Step 3: Wait for and fill password field ---
            password_selectors = [
                "#password",
                'input[name="password"]',
                'input[id="password"]',
                'input[type="password"]',
                'input[aria-label*="Password"]',
            ]
            password_field = await self._wait_for_any_selector(page, password_selectors, timeout=10000)
            if not password_field:
                logger.error("Could not find password field on login page")
                return

            await password_field.click()
            await password_field.fill("")
            await password_field.type(password, delay=30)
            logger.debug("Password filled")

            # --- Step 4: Click login button ---
            login_selectors = [
                "#Login",
                "#login",
                'input[type="submit"]',
                'button[type="submit"]',
                'input[name="login"]',
                '.slds-button--brand',
                'button.login-button',
            ]
            login_btn = await self._wait_for_any_selector(page, login_selectors, timeout=5000)
            if not login_btn:
                logger.error("Could not find login button")
                return

            await login_btn.click()
            logger.info("Login button clicked — waiting for response...")
            await page.wait_for_timeout(3000)

            # --- Step 5: Handle 'Remember this browser' prompt ---
            await self._handle_remember_browser(page)

            # --- Step 6: Handle MFA / 2FA if present ---
            mfa_handled = await self._handle_mfa(page)
            if mfa_handled:
                logger.info("MFA completed — waiting for Lightning to load")

            # --- Step 7: Wait for Lightning app to fully load ---
            await self._wait_for_lightning_app(page)

            # --- Step 8: Verify login success ---
            current_url = page.url
            if "/s/login" in current_url or "/login" in current_url:
                logger.error(f"Login appears to have failed — still on login page: {current_url}")
            else:
                logger.info(f"Login successful — current URL: {current_url}")

        except Exception as e:
            logger.error(f"Login failed: {e}")
        finally:
            await page.close()

    async def _wait_for_any_selector(
        self, page, selectors: list[str], timeout: int = 10000
    ):
        """Try multiple selectors and return the first one found."""
        import asyncio
        deadline = asyncio.get_event_loop().time() + timeout / 1000

        while asyncio.get_event_loop().time() < deadline:
            for selector in selectors:
                try:
                    el = await page.query_selector(selector)
                    if el:
                        is_visible = await el.is_visible()
                        if is_visible:
                            return el
                except Exception:
                    continue
            await page.wait_for_timeout(200)

        return None

    async def _handle_remember_browser(self, page):
        """Handle the 'Remember this browser?' prompt if it appears."""
        try:
            # Salesforce shows this after login — look for common button text
            remember_selectors = [
                'button:has-text("Don\'t ask me again")',
                'button:has-text("Remember")',
                'button:has-text("Cancel")',
                'a:has-text("Don\'t ask me again")',
                'input[value="Don\'t ask me again"]',
            ]
            btn = await self._wait_for_any_selector(page, remember_selectors, timeout=3000)
            if btn:
                # Click "Don't ask me again" or "Cancel"
                text = await btn.text_content() or ""
                await btn.click()
                logger.debug(f"Handled 'Remember browser' prompt: clicked '{text.strip()}'")
                await page.wait_for_timeout(1000)
        except Exception:
            pass

    async def _handle_mfa(self, page) -> bool:
        """Handle MFA / 2FA if detected.

        If MFA is required, pauses the script and prints a console message
        asking the user to complete MFA manually.  Waits for a post-login
        selector before continuing.

        Returns True if MFA was detected and handled.
        """
        # Detect MFA by looking for common MFA indicators
        mfa_indicators = [
            'input[name="otp"]',
            'input[id="otp"]',
            'input[aria-label*="verification"]',
            'input[aria-label*="code"]',
            'input[placeholder*="verification"]',
            'input[placeholder*="code"]',
            'input[type="tel"]',
            '#challenge-form',
            '.verification-code',
            'h2:has-text("Verify")',
            'h2:has-text("Verification")',
            'h2:has-text("MFA")',
            'h2:has-text("Two-Factor")',
            'h2:has-text("Authenticity")',
            'label:has-text("Verification Code")',
        ]

        mfa_detected = False
        for selector in mfa_indicators:
            try:
                el = await page.query_selector(selector)
                if el and await el.is_visible():
                    mfa_detected = True
                    break
            except Exception:
                continue

        if not mfa_detected:
            return False

        # MFA detected — pause for manual completion
        console.print(
            "\n[bold yellow]MFA / 2FA DETECTED[/bold yellow]\n"
            "[yellow]Please complete the multi-factor authentication "
            "in the browser window.[/yellow]\n"
            "[dim]The script will continue automatically once you are "
            "logged in.[/dim]\n"
            "[dim]Waiting for post-login page...[/dim]\n"
        )

        # Wait for post-login selector (Lightning app loaded)
        post_login_selectors = [
            ".oneAppLauncher",
            ".slds-page-header",
            ".forceGlobalNav",
            ".navContainer",
            ".homeRightCard",
            "[data-aura-rendered-by]",
            ".slds-grid--align-spread",
            ".branding-userProfile",
        ]

        try:
            for selector in post_login_selectors:
                try:
                    await page.wait_for_selector(selector, timeout=60000)
                    logger.info(f"MFA completed — detected post-login element: {selector}")
                    return True
                except Exception:
                    continue

            # Fallback: just wait for URL to change from login
            await page.wait_for_function(
                "() => !window.location.href.includes('/login')",
                timeout=60000,
            )
            logger.info("MFA completed — URL changed from login page")
            return True

        except Exception as e:
            logger.warning(f"Timed out waiting for post-MFA login: {e}")
            return True  # Still return True so exploration continues

    async def _wait_for_lightning_app(self, page):
        """Wait for Salesforce Lightning app to fully load after login.

        Uses the specific app launcher selector instead of generic networkidle.
        """
        # Primary: Wait for the Lightning app shell
        app_selectors = [
            ".oneAppLauncher",
            ".slds-page-header",
            ".forceGlobalNav",
            ".navContainer",
            ".slds-grid--align-spread",
        ]

        for selector in app_selectors:
            try:
                await page.wait_for_selector(selector, timeout=15000)
                logger.debug(f"Lightning app loaded — detected: {selector}")
                break
            except Exception:
                continue

        # Secondary: Wait for any loading spinners to disappear
        try:
            # Salesforce uses .slds-spinner for loading indicators
            await page.wait_for_function("""() => {
                const spinners = document.querySelectorAll('.slds-spinner, .loadingSpinner, [class*="spinner"]');
                return spinners.length === 0;
            }""", timeout=10000)
        except Exception:
            pass

        # Final settle time
        await page.wait_for_timeout(2000)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _normalise_url(url: str) -> str:
        """Normalise URL for deduplication."""
        parsed = urlparse(url)
        # Remove trailing slash, fragment, and common tracking params
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    @staticmethod
    def _is_same_domain(base_url: str, target_url: str) -> bool:
        """Check if target_url is on the same domain as base_url."""
        try:
            base_domain = urlparse(base_url).netloc
            target_domain = urlparse(target_url).netloc
            # Allow subdomains of the base domain
            return target_domain == base_domain or target_domain.endswith("." + base_domain)
        except Exception:
            return False

    def _get_console(self):
        from rich.console import Console
        return Console()

    def _count_categories(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for p in self._snapshots:
            cat = p.page_category or "other"
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    async def _cleanup(self):
        try:
            if self._context:
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
        except Exception:
            pass
        self._browser = None
        self._context = None
