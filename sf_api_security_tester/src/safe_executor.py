"""Safe Payload Executor — Non-destructive probe execution via Playwright.

Phase 0.5 of V3.0: Executes safe probes (SF_XSS_PROBE_xxx, SF_SQLI_PROBE_xxx)
against discovered input fields using Playwright.  If the probe is reflected
in the DOM, flags it as POTENTIAL_FINDING for Phase 3 real mutations.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from loguru import logger

from .models import (
    FindingResult,
    FindingVerdict,
    ConfidenceLevel,
    PlannedTest,
    Severity,
    SiteMap,
    TestPlan,
)


class SafePayloadExecutor:
    """Executes safe, non-destructive probes via Playwright.

    NEVER sends real attack payloads — only identifiable probe strings.
    """

    def __init__(self, config: dict[str, Any]):
        expl_cfg = config.get("exploration", {})
        self.enabled: bool = expl_cfg.get("enabled", True)
        self.page_load_timeout: int = expl_cfg.get("page_load_timeout", 30) * 1000
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None

    def execute_probes(
        self,
        test_plan: TestPlan,
        site_map: SiteMap,
    ) -> list[FindingResult]:
        """Execute all safe probes in the test plan.

        Returns:
            List of FindingResults — POTENTIAL_FINDING if probe reflected,
            NOT_FINDING if not reflected.
        """
        if not self.enabled or not test_plan.planned_tests:
            return []

        probes = [t for t in test_plan.planned_tests if t.test_type == "safe_probe"]
        if not probes:
            return []

        logger.info(f"Executing {len(probes)} safe probes via Playwright")
        results: list[FindingResult] = []

        try:
            results = asyncio.run(self._run_probes(probes, site_map))
        except Exception as e:
            logger.error(f"Safe probe execution failed: {e}")

        reflected = sum(1 for r in results if r.verdict == FindingVerdict.POTENTIAL_FINDING)
        logger.info(
            f"Safe probes complete: {reflected}/{len(probes)} reflected"
        )

        return results

    async def _run_probes(
        self, probes: list[PlannedTest], site_map: SiteMap
    ) -> list[FindingResult]:
        """Run probes asynchronously."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.error("Playwright not installed")
            return []

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=True)
        self._context = await self._browser.new_context(
            viewport={"width": 1920, "height": 1080},
        )

        page_by_id = {p.id: p for p in site_map.pages}
        results: list[FindingResult] = []

        try:
            for probe in probes:
                result = await self._execute_single_probe(probe, page_by_id)
                if result:
                    results.append(result)
        finally:
            await self._cleanup()

        return results

    async def _execute_single_probe(
        self, probe: PlannedTest, page_by_id: dict[str, Any]
    ) -> FindingResult | None:
        """Execute a single safe probe against a page field."""
        page_info = page_by_id.get(probe.target_page_id)
        if not page_info:
            return None

        try:
            page = await self._context.new_page()

            try:
                # Navigate to target page
                await page.goto(
                    probe.target_url,
                    timeout=self.page_load_timeout,
                    wait_until="domcontentloaded",
                )
                await page.wait_for_timeout(2000)

                # Find and fill the target field
                field_found = await self._fill_field(
                    page, probe.target_field, probe.payload
                )

                if not field_found:
                    logger.debug(
                        f"Field '{probe.target_field}' not found on "
                        f"{probe.target_url[:60]}"
                    )
                    return self._make_result(probe, False, "Field not found on page")

                # Submit the form (if there's a submit button)
                await self._submit_form(page)
                await page.wait_for_timeout(2000)

                # Check if probe is reflected in DOM
                reflected = await self._check_reflection(page, probe.payload)

                # Screenshot
                screenshot_path = f"output/evidence/probes/{probe.test_id}.png"
                import os
                os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
                await page.screenshot(path=screenshot_path)

                # Extract DOM
                dom_html = await page.evaluate("""() => {
                    return document.body ? document.body.outerHTML.substring(0, 2000) : '';
                }""")

                result = self._make_result(
                    probe, reflected,
                    "Probe reflected in DOM" if reflected else "Probe not reflected",
                    screenshot_path,
                    dom_html,
                )

                return result

            finally:
                await page.close()

        except Exception as e:
            logger.debug(f"Probe execution failed: {e}")
            return self._make_result(probe, False, f"Execution error: {e}")

    async def _fill_field(self, page, field_name: str, value: str) -> bool:
        """Find a field by name/id/label and fill it."""
        selectors = [
            f'input[name="{field_name}"]',
            f'input[id="{field_name}"]',
            f'textarea[name="{field_name}"]',
            f'input[placeholder*="{field_name}"]',
            f'input[aria-label*="{field_name}"]',
        ]

        for selector in selectors:
            try:
                el = await page.query_selector(selector)
                if el:
                    await el.fill(value)
                    return True
            except Exception:
                continue

        # Fallback: try filling any visible text input
        try:
            inputs = await page.query_selector_all('input[type="text"], textarea')
            for inp in inputs[:5]:
                try:
                    is_visible = await inp.is_visible()
                    if is_visible:
                        await inp.fill(value)
                        return True
                except Exception:
                    continue
        except Exception:
            pass

        return False

    async def _submit_form(self, page):
        """Try to submit the form containing the filled field."""
        submit_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            '.slds-button--brand',
            'button.slds-button',
        ]
        for selector in submit_selectors:
            try:
                btn = await page.query_selector(selector)
                if btn and await btn.is_visible():
                    await btn.click()
                    await page.wait_for_timeout(1000)
                    return
            except Exception:
                continue

    async def _check_reflection(self, page, probe_payload: str) -> bool:
        """Check if the probe payload is reflected in the page DOM."""
        try:
            body_html = await page.evaluate("() => document.body ? document.body.outerHTML : ''")
            return probe_payload in (body_html or "")
        except Exception:
            return False

    def _make_result(
        self,
        probe: PlannedTest,
        reflected: bool,
        reasoning: str,
        screenshot_path: str | None = None,
        dom_html: str | None = None,
    ) -> FindingResult:
        """Create a FindingResult from a probe execution."""
        verdict = FindingVerdict.POTENTIAL_FINDING if reflected else FindingVerdict.NOT_FINDING

        severity_map = {
            "xss": Severity.HIGH,
            "sqli": Severity.CRITICAL,
            "ssrf": Severity.HIGH,
            "bola": Severity.CRITICAL,
            "admin_bypass": Severity.HIGH,
        }

        return FindingResult(
            test_case_id=probe.test_id,
            test_name=probe.description,
            endpoint_id=probe.target_page_id,
            endpoint_url=probe.target_url,
            endpoint_method=probe.http_method,
            portal_name="",
            owasp_category=probe.risk_type.upper(),
            owasp_name=probe.payload_category,
            severity=severity_map.get(probe.risk_type, Severity.MEDIUM),
            verdict=verdict,
            confidence=ConfidenceLevel.HIGH if reflected else ConfidenceLevel.HIGH,
            reasoning=reasoning,
            element_outer_html=dom_html,
        )

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
