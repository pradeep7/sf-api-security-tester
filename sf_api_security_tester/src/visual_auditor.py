"""Visual DAST — Vision LLM analysis of Playwright screenshots.

V2.3: Analyses screenshots for visual DOM-based XSS, UI data exposure,
and broken rendering using Vision-capable LLMs (gpt-4o, claude-3-sonnet).
Only reviews findings where the local script already detected payload
reflection in the HTTP response (cost control gate).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from loguru import logger

from .models import (
    ConfidenceLevel,
    Evidence,
    FindingResult,
    FindingVerdict,
    Severity,
)

# ---------------------------------------------------------------------------
# System prompt — Vision Security Auditor
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = """\
You are an expert Visual Security Auditor analysing a screenshot and DOM \
snippet of a Salesforce portal.  The automated scanner injected a specific \
payload and captured the resulting page.

Analyse the screenshot and DOM for:
1. VISUAL_REFLECTION: Is the raw payload text visibly rendered on screen?
2. VISUAL_EXECUTION: Did the payload execute? (alert box, broken image, \
unexpected UI behaviour, injected iframe, etc.)
3. DATA_EXPOSURE: Is any PII, internal IDs, or sensitive data visibly \
exposed in the UI that should not be?

You MUST return ONLY a valid JSON object matching this schema — no markdown, \
no commentary outside the JSON:

{
  "visual_verdict": "CONFIRMED_XSS" | "REFLECTED_NOT_EXECUTED" | "DATA_EXPOSURE" | "INCONCLUSIVE" | "CLEAN",
  "confidence": <float 0.0-1.0>,
  "reasoning": "<1-3 sentence explanation>",
  "visible_evidence": "<Describe exactly what you see in the screenshot — UI text, broken elements, data fields, etc.>"
}

Rules:
- CONFIRMED_XSS          = payload is visibly rendered AND executed (alert, image load, DOM mutation).
- REFLECTED_NOT_EXECUTED = payload text appears in the page but did not execute.
- DATA_EXPOSURE          = PII/sensitive data visibly exposed (not XSS-related).
- INCONCLUSIVE           = screenshot is unclear or ambiguous.
- CLEAN                  = no visual evidence of any issue.
- Keep reasoning under 100 words.
- visible_evidence must describe EXACTLY what you see (e.g. "The text '<script>alert(1)</script>' appears in a red error banner").
"""

_MAX_DOM_CHARS = 2000
_MAX_IMG_B64_LEN = 100_000  # ~75KB base64 — keeps token cost manageable


class VisualAuditResult:
    """Structured result from Vision LLM analysis."""

    __slots__ = ("visual_verdict", "confidence", "reasoning", "visible_evidence")

    def __init__(
        self,
        visual_verdict: str = "INCONCLUSIVE",
        confidence: float = 0.5,
        reasoning: str = "",
        visible_evidence: str = "",
    ):
        self.visual_verdict = visual_verdict
        self.confidence = confidence
        self.reasoning = reasoning
        self.visible_evidence = visible_evidence


class VisualAuditor:
    """Vision LLM auditor — reviews screenshots for visual security issues.

    Cost control: only reviews findings where the payload was reflected
    in the HTTP response body (local detection first, then VLM confirms).
    """

    def __init__(self, config: dict[str, Any]):
        vis_cfg = config.get("visual_audit", {})
        self.enabled: bool = vis_cfg.get("enabled", False)
        self.provider: str = vis_cfg.get("provider", "openai")
        self.model: str = vis_cfg.get("model", "gpt-4o")

        # API key — reuse LLM_API_KEY or provider-specific env var
        api_key_env: str = vis_cfg.get("api_key_env_var", "LLM_API_KEY")
        self.api_key: str = os.environ.get(api_key_env, "")
        if not self.api_key and self.enabled:
            if self.provider == "openai":
                self.api_key = os.environ.get("OPENAI_API_KEY", "")
            elif self.provider == "anthropic":
                self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")

        self.max_tokens: int = vis_cfg.get("max_tokens", 800)
        self.temperature: float = vis_cfg.get("temperature", 0.1)
        self.timeout_seconds: int = vis_cfg.get("timeout_seconds", 45)
        self.max_dom_chars: int = vis_cfg.get("max_dom_chars", _MAX_DOM_CHARS)
        self._client: Any = None
        self._cache: dict[str, VisualAuditResult] = {}

        if self.enabled and not self.api_key:
            logger.warning(
                f"Visual audit enabled but no API key found "
                f"(env: {api_key_env}). Visual audit will be skipped."
            )
            self.enabled = False

        if self.enabled:
            logger.info(
                f"VisualAuditor initialised (provider={self.provider}, "
                f"model={self.model})"
            )

    # ------------------------------------------------------------------
    # Client management
    # ------------------------------------------------------------------
    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client

        if self.provider == "openai":
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key, timeout=self.timeout_seconds)
            except ImportError:
                logger.error("openai package not installed. Run: pip install openai")
                self.enabled = False
                return None
        elif self.provider == "anthropic":
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key, timeout=self.timeout_seconds)
            except ImportError:
                logger.error("anthropic package not installed. Run: pip install anthropic")
                self.enabled = False
                return None
        else:
            logger.error(f"Unsupported vision provider: {self.provider}")
            self.enabled = False
            return None

        return self._client

    # ------------------------------------------------------------------
    # Image encoding
    # ------------------------------------------------------------------
    @staticmethod
    def _encode_image(image_path: str) -> str | None:
        """Read an image file and return base64-encoded string."""
        try:
            path = Path(image_path)
            if not path.exists():
                logger.warning(f"Screenshot not found: {image_path}")
                return None
            data = path.read_bytes()
            b64 = base64.b64encode(data).decode("utf-8")
            # Truncate if too large (saves tokens)
            if len(b64) > _MAX_IMG_B64_LEN:
                logger.debug(
                    f"Image base64 truncated from {len(b64)} to "
                    f"{_MAX_IMG_B64_LEN} chars"
                )
                b64 = b64[:_MAX_IMG_B64_LEN]
            return b64
        except Exception as e:
            logger.error(f"Failed to encode image {image_path}: {e}")
            return None

    # ------------------------------------------------------------------
    # Cost control gate
    # ------------------------------------------------------------------
    @staticmethod
    def _payload_reflected_in_response(finding: FindingResult) -> bool:
        """Check if the injected payload is actually present in the response.

        This is the cost-control gate: if the payload wasn't even reflected,
        there's nothing visual to analyse.
        """
        if not finding.evidence or not finding.evidence.response.body:
            return False

        resp_body = finding.evidence.response.body.lower()

        # Check for common payload signatures in the response
        payload_signatures = [
            "<script",
            "<img",
            "<svg",
            "onerror",
            "onload",
            "alert(",
            "document.cookie",
            "javascript:",
            "eval(",
            "<iframe",
            "expression(",
            "prompt(",
            "confirm(",
        ]

        # Also check the mutation description for payload hints
        mutation_text = ""
        if finding.evidence.raw_request_text:
            mutation_text = finding.evidence.raw_request_text.lower()

        for sig in payload_signatures:
            if sig in resp_body or sig in mutation_text:
                return True

        return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def audit_finding(self, finding: FindingResult) -> FindingResult:
        """Audit a single finding via Vision LLM.

        Only processes findings that have a screenshot AND whose payload
        was reflected in the HTTP response.
        """
        if not self.enabled:
            return finding

        # Cost control gate 1: must have a screenshot
        if not finding.evidence or not finding.evidence.screenshot_path:
            return finding

        # Cost control gate 2: payload must be reflected in response
        if not self._payload_reflected_in_response(finding):
            logger.debug(
                f"Visual Audit: Payload not reflected in HTTP response "
                f"for {finding.test_case_id} — skipping screenshot analysis"
            )
            return finding

        try:
            # Encode image
            image_b64 = self._encode_image(finding.evidence.screenshot_path)
            if not image_b64:
                return finding

            # Build prompt
            prompt = self._build_visual_prompt(finding, image_b64)

            # Cache check
            # Use a prompt hash WITHOUT the image (same payload = same result)
            prompt_key = self._build_cache_key(finding)
            if prompt_key in self._cache:
                logger.info(
                    f"  Visual AI: Cache hit for {finding.test_case_id} — "
                    f"skipping Vision LLM call"
                )
                result = self._cache[prompt_key]
            else:
                result = self._call_vision_llm(image_b64, prompt)
                self._cache[prompt_key] = result

            return self._apply_result(finding, result)

        except Exception as e:
            logger.error(
                f"Visual audit failed for {finding.test_case_id}: {e}"
            )
            finding.visual_reasoning = f"Visual audit error: {e}"
            return finding

    def audit_batch(self, findings: list[FindingResult]) -> list[FindingResult]:
        """Audit a batch of findings. Only processes those with screenshots
        and reflected payloads."""
        if not self.enabled:
            logger.info("Visual audit disabled — skipping.")
            return findings

        # Filter to candidates (has screenshot + payload reflection)
        candidates = [
            f for f in findings
            if f.evidence
            and f.evidence.screenshot_path
            and self._payload_reflected_in_response(f)
        ]
        skipped = len(findings) - len(candidates)

        logger.info(
            f"Visual audit: {len(candidates)} candidates with reflected "
            f"payloads, {skipped} skipped"
        )

        audited = []
        for i, finding in enumerate(findings):
            if (
                finding.evidence
                and finding.evidence.screenshot_path
                and self._payload_reflected_in_response(finding)
            ):
                logger.info(
                    f"  [{i+1}/{len(findings)}] Visual audit: "
                    f"{finding.test_case_id} ({finding.test_name[:30]})..."
                )
                result = self.audit_finding(finding)
                audited.append(result)

                if result.visual_verdict:
                    logger.info(
                        f"    -> Visual verdict: {result.visual_verdict} "
                        f"(confidence: {result.visual_confidence})"
                    )
            else:
                audited.append(finding)

        # Summary
        confirmed = sum(1 for f in audited if f.visual_verdict == "CONFIRMED_XSS")
        reflected = sum(1 for f in audited if f.visual_verdict == "REFLECTED_NOT_EXECUTED")
        data_exp = sum(1 for f in audited if f.visual_verdict == "DATA_EXPOSURE")
        clean = sum(1 for f in audited if f.visual_verdict == "CLEAN")
        logger.info(
            f"Visual audit complete: {confirmed} confirmed XSS, "
            f"{reflected} reflected, {data_exp} data exposure, {clean} clean"
        )

        return audited

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------
    def _build_visual_prompt(self, finding: FindingResult, image_b64: str) -> str:
        """Build the text portion of the vision prompt."""
        parts = [
            "## Visual Security Audit",
            f"Test: {finding.test_name}",
            f"OWASP: {finding.owasp_category} — {finding.owasp_name}",
            f"Severity: {finding.severity.value}",
            "",
            "### Injected Payload",
        ]

        # Extract payload from mutation description or evidence
        payload = ""
        if finding.evidence and finding.evidence.raw_request_text:
            # Try to find the payload in the request text
            payload = finding.evidence.raw_request_text[:500]
        if not payload:
            payload = finding.reasoning[:500]

        parts.append(payload[:500])
        parts.append("")

        # DOM snippet
        if finding.element_outer_html:
            parts.append("### DOM Snippet (outerHTML)")
            parts.append(finding.element_outer_html[:self.max_dom_chars])
            parts.append("")

        # HTTP response status
        if finding.evidence:
            parts.append("### HTTP Response")
            parts.append(
                f"Status: {finding.evidence.response.status_code} "
                f"{finding.evidence.response.status_text}"
            )

        return "\n".join(parts)

    def _build_cache_key(self, finding: FindingResult) -> str:
        """Build a cache key from the finding's identifying info."""
        key_str = (
            f"{finding.test_case_id}|"
            f"{finding.endpoint_url}|"
            f"{finding.endpoint_method}|"
            f"{finding.severity.value}"
        )
        return hashlib.md5(key_str.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Vision LLM call
    # ------------------------------------------------------------------
    def _call_vision_llm(
        self, image_b64: str, text_prompt: str
    ) -> VisualAuditResult:
        """Call the Vision LLM with image + text."""
        client = self._get_client()
        if client is None:
            return VisualAuditResult(
                visual_verdict="INCONCLUSIVE",
                reasoning="Vision LLM client unavailable",
            )

        if self.provider == "openai":
            return self._call_openai_vision(client, image_b64, text_prompt)
        elif self.provider == "anthropic":
            return self._call_anthropic_vision(client, image_b64, text_prompt)
        else:
            return VisualAuditResult(
                visual_verdict="INCONCLUSIVE",
                reasoning=f"Unsupported provider: {self.provider}",
            )

    def _call_openai_vision(
        self, client: Any, image_b64: str, text_prompt: str
    ) -> VisualAuditResult:
        """Call OpenAI Vision API."""
        response = client.chat.completions.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": text_prompt},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/png;base64,{image_b64}",
                                "detail": "low",  # Saves tokens
                            },
                        },
                    ],
                },
            ],
        )

        raw = response.choices[0].message.content or "{}"
        return self._parse_response(raw)

    def _call_anthropic_vision(
        self, client: Any, image_b64: str, text_prompt: str
    ) -> VisualAuditResult:
        """Call Anthropic Vision API."""
        response = client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": image_b64,
                            },
                        },
                        {"type": "text", "text": text_prompt},
                    ],
                },
            ],
        )

        raw = response.content[0].text if response.content else "{}"
        return self._parse_response(raw)

    # ------------------------------------------------------------------
    # Response parsing (robust, same as llm_verifier.py)
    # ------------------------------------------------------------------
    def _parse_response(self, raw: str) -> VisualAuditResult:
        """Parse the Vision LLM's JSON response.

        3-tier fallback: strip markdown → extract {…} → INCONCLUSIVE.
        """
        cleaned = raw.strip()
        cleaned = re.sub(
            r"^```(?:json)?\s*|\s*```$",
            "",
            cleaned,
            flags=re.MULTILINE,
        )

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group(0))
                except json.JSONDecodeError:
                    return VisualAuditResult(
                        visual_verdict="INCONCLUSIVE",
                        reasoning="Vision LLM returned invalid JSON after extraction",
                    )
            else:
                return VisualAuditResult(
                    visual_verdict="INCONCLUSIVE",
                    reasoning="Vision LLM response contained no JSON object",
                )

        verdict = data.get("visual_verdict", "INCONCLUSIVE")
        valid_verdicts = (
            "CONFIRMED_XSS", "REFLECTED_NOT_EXECUTED",
            "DATA_EXPOSURE", "INCONCLUSIVE", "CLEAN",
        )
        if verdict not in valid_verdicts:
            verdict = "INCONCLUSIVE"

        confidence = data.get("confidence", 0.5)
        try:
            confidence = float(confidence)
            confidence = max(0.0, min(1.0, confidence))
        except (TypeError, ValueError):
            confidence = 0.5

        return VisualAuditResult(
            visual_verdict=verdict,
            confidence=confidence,
            reasoning=data.get("reasoning", ""),
            visible_evidence=data.get("visible_evidence", ""),
        )

    # ------------------------------------------------------------------
    # Apply result back to FindingResult
    # ------------------------------------------------------------------
    def _apply_result(
        self, finding: FindingResult, result: VisualAuditResult
    ) -> FindingResult:
        """Update FindingResult with visual audit data."""
        finding.visual_verdict = result.visual_verdict
        finding.visual_confidence = result.confidence
        finding.visual_reasoning = result.reasoning
        finding.visible_evidence = result.visible_evidence

        if result.visual_verdict == "CONFIRMED_XSS":
            # Promote to confirmed FINDING if still POTENTIAL
            if finding.verdict == FindingVerdict.POTENTIAL_FINDING:
                finding.verdict = FindingVerdict.FINDING
            finding.confidence = ConfidenceLevel.HIGH
            finding.reasoning = (
                f"{finding.reasoning}\n\n"
                f"[Visual XSS Confirmed] {result.reasoning}\n"
                f"[Visible Evidence] {result.visible_evidence}"
            )

        elif result.visual_verdict == "REFLECTED_NOT_EXECUTED":
            # Payload reflected but didn't execute — still a finding but lower severity
            if finding.verdict == FindingVerdict.POTENTIAL_FINDING:
                finding.verdict = FindingVerdict.FINDING
            finding.confidence = ConfidenceLevel.MEDIUM
            finding.reasoning = (
                f"{finding.reasoning}\n\n"
                f"[Visual: Reflected, Not Executed] {result.reasoning}\n"
                f"[Visible Evidence] {result.visible_evidence}"
            )

        elif result.visual_verdict == "DATA_EXPOSURE":
            # Data exposure — still a finding
            if finding.verdict == FindingVerdict.POTENTIAL_FINDING:
                finding.verdict = FindingVerdict.FINDING
            finding.confidence = ConfidenceLevel.HIGH
            finding.reasoning = (
                f"{finding.reasoning}\n\n"
                f"[Visual: Data Exposure] {result.reasoning}\n"
                f"[Visible Evidence] {result.visible_evidence}"
            )

        elif result.visual_verdict == "CLEAN":
            # No visual evidence — demote
            if finding.verdict in (
                FindingVerdict.POTENTIAL_FINDING, FindingVerdict.FINDING
            ):
                finding.verdict = FindingVerdict.NOT_FINDING
            finding.reasoning = (
                f"[Visual Audit: Clean] {result.reasoning}"
            )

        elif result.visual_verdict == "INCONCLUSIVE":
            # Keep current verdict, add note
            finding.reasoning = (
                f"{finding.reasoning}\n\n"
                f"[Visual Audit: Inconclusive] {result.reasoning}"
            )

        return finding
