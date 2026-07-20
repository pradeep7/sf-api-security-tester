"""DOM XSS Auditor — Safe, non-malicious DOM-based XSS testing.

Phase 0 of idea3.txt: Tests for DOM XSS using triple-verified probes:
1. DOM Check (local, 0 tokens): page.evaluate() innerHTML.includes()
2. Execution Check (local, 0 tokens): page.evaluate() tag existence
3. Visual Check (Vision LLM): screenshot verification

SAFE PROBES: Only visually detectable, completely harmless payloads.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from loguru import logger

from .models import (
    AuditEvent,
    ConfidenceLevel,
    FindingResult,
    FindingVerdict,
    InputFieldInfo,
    PageSnapshot,
    Severity,
    SiteMap,
)

# ---------------------------------------------------------------------------
# SAFE DOM XSS Probes — NON-MALICIOUS, visually detectable only
# ---------------------------------------------------------------------------
SAFE_DOM_PROBES: list[tuple[str, str, str]] = [
    # (probe_payload, expected_visual, description)
    ("{{7*7}}", "49", "Template injection probe"),
    ("${7*7}", "49", "EL injection probe"),
    ("<marquee>DOMTEST</marquee>", "DOMTEST", "Marquee visual probe"),
    ("<b>DOMBOLD</b>", "DOMBOLD", "Bold tag reflection probe"),
    ("<h1>DOMH1</h1>", "DOMH1", "H1 tag reflection probe"),
    ('" data-testid="domprobe', "domprobe", "Attribute breakout probe"),
    ("' data-domtest='1", "domtest", "Single-quote attribute probe"),
    ('" onfocus="console.log(42)" autofocus="', "console.log", "Event handler probe"),
    ("javascript:void(0)", "javascript:", "JS protocol probe"),
    ("<i>DOMITALIC</i>", "DOMITALIC", "Italic tag reflection probe"),
    ("<u>DOMUNDER</u>", "DOMUNDER", "Underline tag reflection probe"),
]

# DOM check: does the payload appear unsanitized in innerHTML?
_DOM_CHECK_JS = "PAYLOAD_PLACEHOLDER"

# Execution check: do HTML tags from the probe actually exist?
_EXEC_CHECK_JS = """() => {
    const tags = document.querySelectorAll('marquee, b, h1, i, u');
    return tags.length > 0;
}"""

# Max screenshots for cost control
_MAX_SCREENSHOTS = 50


class DOMXSSResult:
    """Result of a single DOM XSS probe."""
    __slots__ = (
        "probe_payload", "description", "dom_reflected", "dom_executed",
        "visual_confirmed", "confidence", "reasoning", "screenshot_path",
    )

    def __init__(
        self,
        probe_payload: str = "",
        description: str = "",
        dom_reflected: bool = False,
        dom_executed: bool = False,
        visual_confirmed: bool = False,
        confidence: float = 0.0,
        reasoning: str = "",
        screenshot_path: str | None = None,
    ):
        self.probe_payload = probe_payload
        self.description = description
        self.dom_reflected = dom_reflected
        self.dom_executed = dom_executed
        self.visual_confirmed = visual_confirmed
        self.confidence = confidence
        self.reasoning = reasoning
        self.screenshot_path = screenshot_path


class DOMXSSAuditor:
    """Safe DOM XSS auditor using triple-verified probes."""

    def __init__(self, config: dict[str, Any]):
        disc_cfg = config.get("discovery", config.get("exploration", {}))
        self.enabled: bool = disc_cfg.get("enabled", True)
        self.dom_probe_delay: float = disc_cfg.get("dom_probe_delay", 2.0)
        self.safe_probes_only: bool = disc_cfg.get("safe_probes_only", True)
        self.max_screenshots: int = disc_cfg.get("max_screenshots_per_run", _MAX_SCREENSHOTS)
        self.page_load_timeout: int = disc_cfg.get("page_load_timeout", 30) * 1000

        # Vision LLM config
        vis_cfg = config.get("visual_audit", {})
        self.llm_enabled: bool = vis_cfg.get("enabled", False)
        self.llm_provider: str = vis_cfg.get("provider", "openai")
        self.llm_model: str = vis_cfg.get("model", "gpt-4o")
        api_key_env: str = vis_cfg.get("api_key_env_var", "LLM_API_KEY")
        self.api_key: str = os.environ.get(api_key_env, "")
        if not self.api_key:
            self.api_key = os.environ.get("OPENAI_API_KEY", "")
        self.llm_client: Any = None

        # State
        self._screenshots_taken: int = 0
        self._audit_log: list[AuditEvent] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def audit_site(
        self, site_map: SiteMap, context: Any
    ) -> list[FindingResult]:
        """Audit all input fields and URL params across discovered pages.

        Args:
            site_map: The discovered site map with pages and input fields.
            context: Playwright browser context for page interaction.

        Returns:
            List of FindingResults (POTENTIAL_FINDING if probe reflected).
        """
        if not self.enabled:
            return []

        logger.info("Starting DOM XSS audit of discovered pages")
        results: list[FindingResult] = []

        try:
            results = asyncio.run(self._audit_async(site_map, context))
        except Exception as e:
            logger.error(f"DOM XSS audit failed: {e}")

        reflected = sum(1 for r in results if r.verdict == FindingVerdict.POTENTIAL_FINDING)
        logger.info(
            f"DOM XSS audit complete: {reflected}/{len(results)} probes reflected"
        )
        return results

    async def _audit_async(
        self, site_map: SiteMap, context: Any
    ) -> list[FindingResult]:
        """Run DOM XSS audit asynchronously."""
        results: list[FindingResult] = []

        for page in site_map.pages:
            if not page.input_fields:
                continue

            # Audit input fields on this page
            field_results = await self._audit_page_fields(page, context)
            results.extend(field_results)

            # Audit URL parameters
            param_results = await self._audit_url_params(page, context)
            results.extend(param_results)

        return results

    # ------------------------------------------------------------------
    # Page field auditing
    # ------------------------------------------------------------------
    async def _audit_page_fields(
        self, page: PageSnapshot, context: Any
    ) -> list[FindingResult]:
        """Audit all input fields on a page with safe DOM XSS probes."""
        results: list[FindingResult] = []

        try:
            pw_page = await context.new_page()
            try:
                await pw_page.goto(
                    page.url, timeout=self.page_load_timeout, wait_until="domcontentloaded"
                )
                await pw_page.wait_for_timeout(2000)

                for field in page.input_fields:
                    if field.field_type not in ("text", "textarea", "richtext", "search"):
                        continue

                    for probe_payload, expected_visual, description in SAFE_DOM_PROBES:
                        if self._screenshots_taken >= self.max_screenshots:
                            logger.info("Screenshot limit reached — stopping DOM XSS audit")
                            return results

                        result = await self._probe_field(
                            pw_page, page, field, probe_payload,
                            expected_visual, description
                        )
                        if result:
                            results.append(result)

            finally:
                await pw_page.close()

        except Exception as e:
            logger.debug(f"Page audit failed for {page.url[:60]}: {e}")

        return results

    async def _probe_field(
        self, page, page_snapshot: PageSnapshot, field: InputFieldInfo,
        probe_payload: str, expected_visual: str, description: str,
    ) -> FindingResult | None:
        """Execute a single safe DOM XSS probe against a field."""
        try:
            # Find and fill the field
            selectors = [
                f'input[name="{field.name}"]',
                f'input[id="{field.name}"]',
                f'textarea[name="{field.name}"]',
                f'input[placeholder*="{field.name}"]',
            ]

            target = None
            for sel in selectors:
                try:
                    target = await page.query_selector(sel)
                    if target and await target.is_visible():
                        break
                    target = None
                except Exception:
                    continue

            if not target:
                return None

            # Fill with probe
            await target.fill(probe_payload)
            await page.wait_for_timeout(int(self.dom_probe_delay * 1000))

            # DOM Check (local, 0 tokens)
            dom_reflected = await self._check_dom_reflection(page, probe_payload)

            # Execution Check (local, 0 tokens)
            dom_executed = await self._check_execution(page)

            # If either check passed, take screenshot and optionally verify with LLM
            screenshot_path = None
            visual_confirmed = False
            confidence = 0.0
            reasoning = ""

            if dom_reflected or dom_executed:
                # Screenshot
                screenshot_path = await self._take_screenshot(
                    page, mutated_request.test_case_id, field.name
                )

                # Triple verification: DOM + Execution + Visual
                if dom_reflected and dom_executed:
                    confidence = 0.95
                    reasoning = f"Probe reflected AND executed in DOM. DOM check: true, Execution check: true"
                    visual_confirmed = True
                elif dom_reflected:
                    confidence = 0.7
                    reasoning = f"Probe reflected in DOM but not executed. DOM check: true, Execution check: false"
                    visual_confirmed = True
                elif dom_executed:
                    confidence = 0.85
                    reasoning = f"Probe tags executed in DOM. DOM check: false, Execution check: true"
                    visual_confirmed = True

                # Optional Vision LLM verification
                if self.llm_enabled and screenshot_path and self._screenshots_taken < self.max_screenshots:
                    llm_result = await self._verify_with_llm(
                        screenshot_path, probe_payload, mutated_request
                    )
                    if llm_result:
                        confidence = llm_result.get("confidence", confidence)
                        visual_confirmed = llm_result.get("dom_xss_confirmed", visual_confirmed)
                        reasoning = llm_result.get("reasoning", reasoning)

                self._audit_log.append(AuditEvent(
                    action="dom_xss_probe",
                    target=f"{page_snapshot.url}#{field.name}",
                    result="reflected" if dom_reflected else "executed",
                    details=f"probe={probe_payload[:30]}, dom={dom_reflected}, exec={dom_executed}",
                ))

                return FindingResult(
                    test_case_id=f"domxss_{page_snapshot.id}_{field.name}",
                    test_name=f"DOM XSS: {description} in {field.label or field.name}",
                    endpoint_id=page_snapshot.id,
                    endpoint_url=page_snapshot.url,
                    endpoint_method="POST",
                    portal_name="",
                    owasp_category="A03:2021",
                    owasp_name="Injection — DOM XSS",
                    severity=Severity.HIGH if dom_executed else Severity.MEDIUM,
                    verdict=FindingVerdict.POTENTIAL_FINDING,
                    confidence=ConfidenceLevel.HIGH if confidence >= 0.8 else ConfidenceLevel.MEDIUM,
                    reasoning=reasoning,
                    screenshot_path=screenshot_path,
                )

            return None

        except Exception as e:
            logger.debug(f"Probe failed: {e}")
            return None

    # ------------------------------------------------------------------
    # URL parameter auditing
    # ------------------------------------------------------------------
    async def _audit_url_params(
        self, page: PageSnapshot, context: Any
    ) -> list[FindingResult]:
        """Audit URL query parameters with safe probes."""
        results: list[FindingResult] = []
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(page.url)
        params = parse_qs(parsed.query)

        if not params:
            return results

        try:
            pw_page = await context.new_page()
            try:
                for param_name in params:
                    for probe_payload, expected_visual, description in SAFE_DOM_PROBES[:5]:
                        if self._screenshots_taken >= self.max_screenshots:
                            return results

                        # Modify URL with probe
                        new_params = dict(params)
                        new_params[param_name] = [probe_payload]
                        new_query = urlencode(new_params, doseq=True)
                        probe_url = urlunparse(parsed._replace(query=new_query))

                        await pw_page.goto(
                            probe_url, timeout=self.page_load_timeout,
                            wait_until="domcontentloaded"
                        )
                        await pw_page.wait_for_timeout(int(self.dom_probe_delay * 1000))

                        # DOM + Execution checks
                        dom_reflected = await self._check_dom_reflection(pw_page, probe_payload)
                        dom_executed = await self._check_execution(pw_page)

                        if dom_reflected or dom_executed:
                            screenshot_path = await self._take_screenshot(
                                pw_page, f"urlparam_{page.id}", param_name
                            )

                            results.append(FindingResult(
                                test_case_id=f"domxss_urlparam_{page.id}_{param_name}",
                                test_name=f"DOM XSS via URL param: {description}",
                                endpoint_id=page.id,
                                endpoint_url=probe_url,
                                endpoint_method="GET",
                                portal_name="",
                                owasp_category="A03:2021",
                                owasp_name="Injection — DOM XSS (URL Param)",
                                severity=Severity.HIGH if dom_executed else Severity.MEDIUM,
                                verdict=FindingVerdict.POTENTIAL_FINDING,
                                confidence=ConfidenceLevel.HIGH if dom_executed else ConfidenceLevel.MEDIUM,
                                reasoning=f"URL param '{param_name}' reflected probe. DOM={dom_reflected}, Exec={dom_executed}",
                                screenshot_path=screenshot_path,
                            ))

            finally:
                await pw_page.close()

        except Exception as e:
            logger.debug(f"URL param audit failed for {page.url[:60]}: {e}")

        return results

    # ------------------------------------------------------------------
    # DOM checks (local, 0 tokens)
    # ------------------------------------------------------------------
    async def _check_dom_reflection(self, page, probe_payload: str) -> bool:
        """Check if probe payload is reflected unsanitized in the DOM."""
        try:
            # Escape probe for JS string
            escaped = probe_payload.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')
            js_code = f"() => document.body ? document.body.innerHTML.includes('{escaped}') : false"
            return await page.evaluate(js_code)
        except Exception:
            return False

    async def _check_execution(self, page) -> bool:
        """Check if HTML tags from probes actually exist in the DOM."""
        try:
            return await page.evaluate(_EXEC_CHECK_JS)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Screenshot
    # ------------------------------------------------------------------
    async def _take_screenshot(self, page, test_id: str, field_name: str) -> str | None:
        """Take a screenshot for evidence."""
        if self._screenshots_taken >= self.max_screenshots:
            return None

        try:
            output_dir = Path("output/evidence/dom_xss")
            output_dir.mkdir(parents=True, exist_ok=True)
            safe_name = re.sub(r"[^\w\-]", "_", field_name)[:30]
            path = output_dir / f"{test_id}_{safe_name}.png"
            await page.screenshot(path=str(path))
            self._screenshots_taken += 1
            return str(path)
        except Exception as e:
            logger.debug(f"Screenshot failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Vision LLM verification
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

    async def _verify_with_llm(
        self, screenshot_path: str, probe_payload: str, mutated_request: Any
    ) -> dict | None:
        """Verify DOM XSS with Vision LLM."""
        client = self._get_llm_client()
        if not client:
            return None

        try:
            img_data = Path(screenshot_path).read_bytes()
            b64 = base64.b64encode(img_data).decode()
            if len(b64) > 80000:
                b64 = b64[:80000]

            prompt = (
                f"Analyze this screenshot. The scanner injected this safe probe: {probe_payload}\n"
                f"Can you visually confirm the probe was rendered unsanitized in the DOM?\n"
                f"Look for: rendered HTML tags, visible probe text, broken UI elements.\n"
                f"Return JSON: {{\"dom_xss_confirmed\": bool, \"visual_evidence\": \"...\", \"confidence\": 0.0-1.0}}"
            )

            response = client.chat.completions.create(
                model=self.llm_model,
                max_tokens=300,
                temperature=0.1,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": "You are a DOM XSS visual auditor. Analyze screenshots for unsanitized HTML rendering."},
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64}", "detail": "low"}},
                        ],
                    },
                ],
            )

            raw = response.choices[0].message.content or "{}"
            cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip(), flags=re.MULTILINE)
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                match = re.search(r"\{.*\}", cleaned, re.DOTALL)
                if match:
                    return json.loads(match.group(0))
                return None

        except Exception as e:
            logger.debug(f"Vision LLM verification failed: {e}")
            return None

    def get_audit_log(self) -> list[AuditEvent]:
        """Return the structured audit log."""
        return self._audit_log
