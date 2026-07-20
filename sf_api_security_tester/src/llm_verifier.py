"""Hybrid AI Layer — LLM verification of potential security findings.

V2.2: The local evaluator outputs POTENTIAL_FINDING for anomalies.
This module reviews those via LLM to confirm TRUE_POSITIVE, eliminate
FALSE_POSITIVE, or flag NEEDS_MANUAL_REVIEW.  API keys are read from
environment variables — never hardcoded.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
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
# System prompt — tightly constrained to minimise token spend
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = """\
You are an expert Salesforce Security Engineer reviewing a potential security \
finding produced by an automated API security scanner.  Analyse the evidence \
and determine if this is a TRUE POSITIVE, FALSE POSITIVE, or requires \
NEEDS_MANUAL_REVIEW.

You MUST return ONLY a valid JSON object matching this schema — no markdown, \
no commentary outside the JSON:

{
  "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "NEEDS_MANUAL_REVIEW",
  "confidence_score": <float 0.0-1.0>,
  "reasoning": "<1-3 sentence explanation>",
  "salesforce_remediation": "<Specific Apex/Config/PermissionSet fix, or empty string if FALSE_POSITIVE>"
}

Rules:
- TRUE_POSITIVE  = the evidence conclusively demonstrates the vulnerability.
- FALSE_POSITIVE = the scanner was misled (e.g. generic 403, WAF block, \
normal error handling, or the payload did not actually execute).
- NEEDS_MANUAL_REVIEW = inconclusive; a human should verify.
- Keep reasoning under 150 words.
- Salesforce remediation must reference concrete SF concepts: Apex, SOQL, \
FLS, OWD, Sharing Rules, Profiles, PermissionSets, ConnectedApp, etc.

CRITICAL SALESFORCE CONTEXT: In Salesforce, if User A cannot access User B's \
record via the API, this is often NOT an IDOR/BOLA vulnerability.  It is \
likely the expected behavior of Salesforce Organization-Wide Defaults (OWD) \
set to Private, or controlled by Role Hierarchy/Sharing Rules.  Only mark \
BOLA/IDOR as a TRUE_POSITIVE if the user accesses a record they explicitly \
shouldn't have access to based on standard sharing, OR if the API bypasses \
sharing entirely (e.g., running in 'without sharing' mode).
"""

# Max chars sent to LLM (saves tokens)
_MAX_BODY_CHARS = 2000
_MAX_REQUEST_CHARS = 1000


class LLMVerificationResult:
    """Structured result from LLM verification."""

    __slots__ = (
        "verdict", "confidence_score", "reasoning", "salesforce_remediation"
    )

    def __init__(
        self,
        verdict: str = "NEEDS_MANUAL_REVIEW",
        confidence_score: float = 0.5,
        reasoning: str = "",
        salesforce_remediation: str = "",
    ):
        self.verdict = verdict
        self.confidence_score = confidence_score
        self.reasoning = reasoning
        self.salesforce_remediation = salesforce_remediation


class LLMVerifier:
    """AI Senior Security Engineer — reviews POTENTIAL_FINDING results via LLM.

    Cost control: only called for results with verdict == POTENTIAL_FINDING.
    """

    def __init__(self, config: dict[str, Any]):
        llm_cfg = config.get("llm_config", config.get("llm_verification", {}))
        self.enabled: bool = llm_cfg.get("enabled", False)
        self.provider: str = llm_cfg.get("provider", "openai")
        self.model: str = llm_cfg.get("model", "gpt-4o-mini")

        # Read API key from env var (never hardcoded)
        api_key_env: str = llm_cfg.get("api_key_env_var", "LLM_API_KEY")
        self.api_key: str = os.environ.get(api_key_env, llm_cfg.get("api_key", ""))
        if not self.api_key and self.enabled:
            # Fallback: try provider-specific env vars
            if self.provider == "openai":
                self.api_key = os.environ.get("OPENAI_API_KEY", "")
            elif self.provider == "anthropic":
                self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")

        self.max_tokens: int = llm_cfg.get("max_tokens_per_request", llm_cfg.get("max_tokens", 500))
        self.temperature: float = llm_cfg.get("temperature", 0.1)
        self.timeout_seconds: int = llm_cfg.get("timeout_seconds", 30)
        self.max_body_chars: int = llm_cfg.get("max_body_chars", _MAX_BODY_CHARS)
        self.max_request_chars: int = llm_cfg.get("max_request_chars", _MAX_REQUEST_CHARS)
        self._client: Any = None
        self._cache: dict[str, LLMVerificationResult] = {}

        if self.enabled and not self.api_key:
            logger.warning(
                f"LLM verification enabled but no API key found "
                f"(env: {api_key_env}). LLM verification will be skipped."
            )
            self.enabled = False

        if self.enabled:
            logger.info(
                f"LLM Verifier initialised (provider={self.provider}, "
                f"model={self.model})"
            )

    # ------------------------------------------------------------------
    # Client management
    # ------------------------------------------------------------------
    def _get_client(self) -> Any:
        """Lazy-init the LLM client."""
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
            logger.error(f"Unsupported LLM provider: {self.provider}")
            self.enabled = False
            return None

        return self._client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def verify_finding(self, finding: FindingResult) -> FindingResult:
        """Verify a single POTENTIAL_FINDING via the LLM.

        Only called when ``finding.verdict == FindingVerdict.POTENTIAL_FINDING``.
        Returns the updated FindingResult with LLM fields populated.
        Uses in-memory cache to avoid redundant LLM calls for identical payloads.
        """
        if not self.enabled:
            return finding

        if finding.verdict != FindingVerdict.POTENTIAL_FINDING:
            return finding

        try:
            prompt = self._build_prompt(finding)

            # --- Cache check ---
            cache_key = hashlib.md5(prompt.encode("utf-8")).hexdigest()
            if cache_key in self._cache:
                logger.info(
                    f"  AI Brain: Cache hit for {finding.test_case_id} — "
                    f"skipping LLM call"
                )
                llm_result = self._cache[cache_key]
            else:
                llm_result = self._call_llm(prompt)
                self._cache[cache_key] = llm_result

            return self._apply_result(finding, llm_result)
        except Exception as e:
            logger.error(
                f"LLM verification failed for {finding.test_case_id}: {e}"
            )
            # On error, leave as POTENTIAL_FINDING (human should review)
            finding.llm_verified = False
            finding.llm_reasoning = f"LLM verification error: {e}"
            return finding

    def verify_batch(self, findings: list[FindingResult]) -> list[FindingResult]:
        """Verify a batch of findings. Only sends POTENTIAL_FINDING to LLM."""
        if not self.enabled:
            logger.info("LLM verification disabled — skipping.")
            return findings

        to_verify = [f for f in findings if f.verdict == FindingVerdict.POTENTIAL_FINDING]
        skipped = len(findings) - len(to_verify)

        logger.info(
            f"LLM verification: {len(to_verify)} potential findings to verify, "
            f"{skipped} skipped (not POTENTIAL_FINDING)"
        )

        verified = []
        for i, finding in enumerate(findings):
            if finding.verdict == FindingVerdict.POTENTIAL_FINDING:
                logger.info(
                    f"  [{i+1}/{len(findings)}] Verifying {finding.test_case_id} "
                    f"({finding.test_name[:40]})..."
                )
                result = self.verify_finding(finding)
                verified.append(result)

                if result.llm_verified:
                    logger.info(
                        f"    -> LLM verdict: {result.llm_verdict} "
                        f"(confidence: {result.llm_confidence})"
                    )
            else:
                verified.append(finding)

        # Summary
        tp = sum(1 for f in verified if f.llm_verdict == "TRUE_POSITIVE")
        fp = sum(1 for f in verified if f.llm_verdict == "FALSE_POSITIVE")
        mr = sum(1 for f in verified if f.llm_verdict == "NEEDS_MANUAL_REVIEW")
        logger.info(
            f"LLM verification complete: {tp} true positive, "
            f"{fp} false positive, {mr} needs manual review"
        )

        return verified

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------
    def _build_prompt(self, finding: FindingResult) -> str:
        """Build a concise user prompt from the FindingResult evidence."""
        parts = [
            f"## Finding: {finding.test_name}",
            f"OWASP Category: {finding.owasp_category} — {finding.owasp_name}",
            f"Severity: {finding.severity.value}",
            "",
            f"### Endpoint",
            f"Method: {finding.endpoint_method}",
            f"URL: {finding.endpoint_url}",
            "",
            f"### Scanner Hypothesis",
            finding.reasoning,
        ]

        if finding.evidence:
            evidence: Evidence = finding.evidence

            parts.append("")
            parts.append("### HTTP Request (truncated)")
            req_text = evidence.raw_request_text or ""
            parts.append(req_text[:self.max_request_chars])

            parts.append("")
            parts.append("### HTTP Response")
            parts.append(f"Status: {evidence.response.status_code} {evidence.response.status_text}")
            resp_text = evidence.response.body or ""
            parts.append(f"Body (truncated to {self.max_body_chars} chars):")
            parts.append(resp_text[:self.max_body_chars])

            parts.append("")
            parts.append(f"Execution time: {evidence.execution_time_ms}ms")

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # LLM call
    # ------------------------------------------------------------------
    def _call_llm(self, user_prompt: str) -> LLMVerificationResult:
        """Call the configured LLM provider and parse the JSON response."""
        client = self._get_client()
        if client is None:
            return LLMVerificationResult(
                verdict="NEEDS_MANUAL_REVIEW",
                reasoning="LLM client unavailable",
            )

        if self.provider == "openai":
            return self._call_openai(client, user_prompt)
        elif self.provider == "anthropic":
            return self._call_anthropic(client, user_prompt)
        else:
            return LLMVerificationResult(
                verdict="NEEDS_MANUAL_REVIEW",
                reasoning=f"Unsupported provider: {self.provider}",
            )

    def _call_openai(self, client: Any, user_prompt: str) -> LLMVerificationResult:
        """Call OpenAI API."""
        response = client.chat.completions.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )

        raw = response.choices[0].message.content or "{}"
        return self._parse_response(raw)

    def _call_anthropic(self, client: Any, user_prompt: str) -> LLMVerificationResult:
        """Call Anthropic API."""
        response = client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=_SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": user_prompt},
            ],
        )

        raw = response.content[0].text if response.content else "{}"
        return self._parse_response(raw)

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------
    def _parse_response(self, raw: str) -> LLMVerificationResult:
        """Parse the LLM's JSON response into a structured result.

        Handles markdown code blocks, extra text around JSON, and other
        common LLM output quirks.  On total failure, defaults to
        NEEDS_MANUAL_REVIEW (never hallucinate).
        """
        cleaned = raw.strip()

        # Strip markdown code blocks (```json ... ```)
        cleaned = re.sub(
            r"^```(?:json)?\s*|\s*```$",
            "",
            cleaned,
            flags=re.MULTILINE,
        )

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            # Fallback: extract the first { ... } block from the response
            match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group(0))
                except json.JSONDecodeError:
                    logger.warning(
                        f"LLM returned unparseable JSON even after "
                        f"extraction. Raw: {raw[:300]}"
                    )
                    return LLMVerificationResult(
                        verdict="NEEDS_MANUAL_REVIEW",
                        reasoning="LLM returned invalid JSON after extraction attempt",
                    )
            else:
                logger.warning(f"LLM returned no JSON object at all: {raw[:300]}")
                return LLMVerificationResult(
                    verdict="NEEDS_MANUAL_REVIEW",
                    reasoning="LLM response contained no JSON object",
                )

        verdict = data.get("verdict", "NEEDS_MANUAL_REVIEW")
        if verdict not in ("TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_MANUAL_REVIEW"):
            verdict = "NEEDS_MANUAL_REVIEW"

        confidence = data.get("confidence_score", 0.5)
        try:
            confidence = float(confidence)
            confidence = max(0.0, min(1.0, confidence))
        except (TypeError, ValueError):
            confidence = 0.5

        return LLMVerificationResult(
            verdict=verdict,
            confidence_score=confidence,
            reasoning=data.get("reasoning", ""),
            salesforce_remediation=data.get("salesforce_remediation", ""),
        )

    # ------------------------------------------------------------------
    # Apply result back to FindingResult
    # ------------------------------------------------------------------
    def _apply_result(
        self, finding: FindingResult, llm_result: LLMVerificationResult
    ) -> FindingResult:
        """Update the FindingResult with LLM verification data.

        - TRUE_POSITIVE  -> promote to FINDING, add remediation
        - FALSE_POSITIVE -> demote to NOT_FINDING
        - NEEDS_MANUAL_REVIEW -> keep POTENTIAL_FINDING, add reasoning
        """
        finding.llm_verified = True
        finding.llm_verdict = llm_result.verdict
        finding.llm_confidence = llm_result.confidence_score
        finding.llm_reasoning = llm_result.reasoning
        finding.llm_remediation = llm_result.salesforce_remediation

        if llm_result.verdict == "TRUE_POSITIVE":
            # Promote to confirmed FINDING
            finding.verdict = FindingVerdict.FINDING
            finding.reasoning = (
                f"{finding.reasoning}\n\n"
                f"[LLM Confirmed - True Positive] {llm_result.reasoning}"
            )
            if llm_result.salesforce_remediation:
                finding.reasoning += (
                    f"\n\n[LLM Remediation] {llm_result.salesforce_remediation}"
                )
            # Adjust confidence
            if llm_result.confidence_score >= 0.8:
                finding.confidence = ConfidenceLevel.HIGH
            elif llm_result.confidence_score >= 0.5:
                finding.confidence = ConfidenceLevel.MEDIUM
            else:
                finding.confidence = ConfidenceLevel.LOW

        elif llm_result.verdict == "FALSE_POSITIVE":
            # Demote to NOT_FINDING
            logger.info(
                f"  LLM marked {finding.test_case_id} as FALSE POSITIVE — "
                f"removing from findings"
            )
            finding.verdict = FindingVerdict.NOT_FINDING
            finding.confidence = ConfidenceLevel.HIGH
            finding.reasoning = (
                f"[LLM False Positive] {llm_result.reasoning}"
            )

        elif llm_result.verdict == "NEEDS_MANUAL_REVIEW":
            # Keep as POTENTIAL_FINDING, enrich with reasoning
            finding.reasoning = (
                f"{finding.reasoning}\n\n"
                f"[LLM: Needs Manual Review] {llm_result.reasoning}"
            )

        return finding

    def promote_unverified(self, findings: list[FindingResult]) -> list[FindingResult]:
        """Promote remaining POTENTIAL_FINDINGs to FINDING (fallback mode).

        Called when LLM verification is disabled — reverts to V2.1 behaviour
        where all anomalies are treated as confirmed findings.
        """
        promoted = 0
        for f in findings:
            if f.verdict == FindingVerdict.POTENTIAL_FINDING:
                f.verdict = FindingVerdict.FINDING
                promoted += 1

        if promoted > 0:
            logger.info(
                f"LLM disabled: promoted {promoted} POTENTIAL_FINDINGs to FINDINGs"
            )

        return findings
