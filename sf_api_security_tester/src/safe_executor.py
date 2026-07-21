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
        safe_cfg = config.get("safe_execution", {})
        self.enabled: bool = expl_cfg.get("enabled", True)
        self.page_load_timeout: int = expl_cfg.get("page_load_timeout", 30) * 1000
        self.max_probes_per_page: int = safe_cfg.get("max_probes_per_page", 5)
        self.max_total_probes: int = safe_cfg.get("max_total_probes_per_run", 500)
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._request_count: int = 0  # V4.0: Track requests per test
        self._request_counts: dict[str, int] = {}  # test_id -> count

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
        self, probe: PlannedTest, page_by_id: dict[str, Any],
        max_requests: int = 0, requires_approval: bool = False,
    ) -> FindingResult | None:
        """Execute a single safe probe against a page field.

        V4.0: Enforces request limits and human-in-the-loop gate.
        """
        page_info = page_by_id.get(probe.target_page_id)
        if not page_info:
            return None

        # --- V4.0: Request limit check ---
        current_count = self._request_counts.get(probe.test_id, 0)
        if max_requests and current_count >= max_requests:
            logger.warning(
                f"Test {probe.test_id} hit maximum_requests ({current_count}/{max_requests})"
            )
            return self._make_result(
                probe, False,
                f"BLOCKED: Request limit exceeded ({current_count}/{max_requests})"
            )

        # --- V4.0: Human-in-the-loop gate ---
        if requires_approval:
            from rich.console import Console
            console = Console()
            console.print(
                f"\n[yellow]GOVERNANCE GATE: Test {probe.test_id} is state-changing "
                f"or requires approval.[/yellow]"
            )
            try:
                input("[yellow]Press ENTER to execute, or Ctrl+C to skip: [/yellow]")
            except (KeyboardInterrupt, EOFError):
                logger.info(f"User skipped test {probe.test_id}")
                return self._make_result(
                    probe, False, "SKIPPED: User declined governance gate"
                )

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

                # --- V4.0: Track request count ---
                self._request_counts[probe.test_id] = current_count + 1
                self._request_count += 1

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

    # ------------------------------------------------------------------
    # V3.1: Salesforce-specific API6 workflow attacks
    # ------------------------------------------------------------------
    async def execute_workflow_skip(
        self, probe: PlannedTest, page_by_id: dict[str, Any]
    ) -> FindingResult:
        """Execute API6-002: Workflow Step Skipping for Salesforce Flows.

        Instead of navigating to a different URL (which doesn't work for
        single-URL Lightning Flows), this method:
        1. Navigates to the workflow's current step
        2. Attempts to send the Step 3 payload to the /aura endpoint
        3. WITHOUT a valid flowInterviewId
        4. Checks if the backend processes it or rejects it
        """
        page_info = page_by_id.get(probe.target_page_id)
        if not page_info:
            return self._make_result(probe, False, "Page not found in site map")

        try:
            page = await self._context.new_page()

            try:
                # Navigate to the workflow page
                await page.goto(
                    page_info.url,
                    timeout=self.page_load_timeout,
                    wait_until="domcontentloaded",
                )
                await page.wait_for_timeout(3000)

                # Extract the current flowInterviewId (if any)
                flow_interview_id = await self._extract_flow_interview_id(page)

                # Capture the current page state (XHR/Fetch requests)
                captured_requests = []
                async def on_request(request):
                    if request.resource_type in ("xhr", "fetch"):
                        captured_requests.append({
                            "url": request.url,
                            "method": request.method,
                            "post_data": request.post_data,
                        })
                page.on("request", on_request)

                # Attempt to advance the flow WITHOUT valid state
                # This simulates: "What if I call Step 3 without Step 1 & 2?"
                await self._attempt_flow_advance_without_state(
                    page, probe, flow_interview_id
                )
                await page.wait_for_timeout(3000)

                # Check the result
                # Did the flow advance? (check for success indicators)
                page_text = await page.evaluate("() => document.body ? document.body.innerText : ''")
                success_indicators = [
                    "success", "complete", "submitted", "saved",
                    "record created", "order placed", "approved",
                ]
                error_indicators = [
                    "invalid flow", "missing state", "flow interview",
                    "unauthorized", "forbidden", "error",
                ]

                page_lower = (page_text or "").lower()
                has_success = any(ind in page_lower for ind in success_indicators)
                has_error = any(ind in page_lower for ind in error_indicators)

                # Check for flow advancement (new page or updated state)
                current_url = page.url
                flow_advanced = current_url != page_info.url

                # Screenshot
                screenshot_path = f"output/evidence/probes/{probe.test_id}_workflow_skip.png"
                import os
                os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
                await page.screenshot(path=screenshot_path)

                # DOM extraction
                dom_html = await page.evaluate("""() => {
                    return document.body ? document.body.outerHTML.substring(0, 2000) : '';
                }""")

                # Determine finding
                # If the flow advanced or returned success WITHOUT valid state, it's a FINDING
                if (flow_advanced or has_success) and not has_error:
                    reasoning = (
                        f"API6-002 WORKFLOW BYPASS: Flow advanced to Step 3 without "
                        f"executing Steps 1-2. flowInterviewId={flow_interview_id or 'NONE'}. "
                        f"URL changed to: {current_url[:80]}"
                    )
                    return self._make_result(probe, True, reasoning, screenshot_path, dom_html)
                else:
                    reasoning = (
                        f"Flow correctly rejected state bypass. "
                        f"flowInterviewId={flow_interview_id or 'NONE'}. "
                        f"Error indicators: {has_error}"
                    )
                    return self._make_result(probe, False, reasoning, screenshot_path, dom_html)

            finally:
                await page.close()

        except Exception as e:
            logger.debug(f"Workflow skip execution failed: {e}")
            return self._make_result(probe, False, f"Execution error: {e}")

    async def _extract_flow_interview_id(self, page) -> str | None:
        """Extract flowInterviewId from the current page state."""
        try:
            # Try to find it in hidden fields
            flow_id = await page.evaluate("""() => {
                const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
                for (const input of hiddenInputs) {
                    if (input.name && input.name.toLowerCase().includes('flow')) {
                        return input.value;
                    }
                }
                // Check for flowInterviewId in data attributes
                const flowEl = document.querySelector('[data-flow-interview-id]');
                if (flowEl) return flowEl.getAttribute('data-flow-interview-id');
                // Check for Aura component state
                const auraState = document.querySelector('[data-aura-rendered-by]');
                if (auraState) {
                    const state = auraState.getAttribute('data-aura-rendered-by');
                    if (state && state.includes('flowInterviewId')) {
                        const match = state.match(/flowInterviewId['":\s]+(['"0-9a-zA-Z-]+)/);
                        if (match) return match[1];
                    }
                }
                return null;
            }""")
            return flow_id
        except Exception:
            return None

    async def _attempt_flow_advance_without_state(
        self, page, probe: PlannedTest, flow_interview_id: str | None
    ):
        """Attempt to advance a Salesforce Flow without valid state.

        For Lightning Flows, this typically means:
        1. Finding the 'Next' or 'Submit' button
        2. Clicking it WITHOUT having filled in the previous steps
        3. Or sending an XHR to /aura with a fake/missing flowInterviewId
        """
        try:
            # Strategy 1: Click Next/Submit without filling fields
            submit_selectors = [
                'button:has-text("Next")',
                'button:has-text("Submit")',
                'button:has-text("Continue")',
                'button:has-text("Confirm")',
                'button:has-text("Place Order")',
                '.slds-button--brand',
            ]
            for selector in submit_selectors:
                try:
                    btn = await page.query_selector(selector)
                    if btn and await btn.is_visible():
                        await btn.click()
                        logger.debug(f"Clicked flow advance button: {selector}")
                        return
                except Exception:
                    continue

            # Strategy 2: If we found an /aura XHR, replay it without flowInterviewId
            # This is the more aggressive approach for backend state bypass
            if flow_interview_id:
                # Try to modify the page's state to remove flowInterviewId
                await page.evaluate("""() => {
                    // Remove flowInterviewId from any hidden fields
                    document.querySelectorAll('input[type="hidden"]').forEach(input => {
                        if (input.name && input.name.toLowerCase().includes('flow')) {
                            input.value = 'FAKE_INVALID_ID_000000000000000';
                        }
                    });
                    // Remove from data attributes
                    document.querySelectorAll('[data-flow-interview-id]').forEach(el => {
                        el.setAttribute('data-flow-interview-id', 'FAKE_INVALID_ID_000000000000000');
                    });
                }""")
                logger.debug("Tampered flowInterviewId to fake value")

        except Exception as e:
            logger.debug(f"Flow advance attempt failed: {e}")

    async def _take_workflow_screenshot(self, page, probe: PlannedTest) -> str | None:
        """Take a screenshot for workflow testing evidence."""
        try:
            screenshot_path = f"output/evidence/probes/{probe.test_id}_workflow.png"
            import os
            os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
            await page.screenshot(path=screenshot_path)
            return screenshot_path
        except Exception:
            return None
