"""Evaluates evidence against test case criteria to determine findings.

V2.2: The local evaluator outputs POTENTIAL_FINDING (instead of FINDING)
when it detects anomalies.  This creates the queue for the LLM layer to
review and confirm/reject before findings are finalised.
"""

from __future__ import annotations

import json
import re
from typing import Any

from loguru import logger

from .models import (
    ConfidenceLevel,
    Evidence,
    FindingResult,
    FindingVerdict,
    HTTPMethod,
    HttpResponse,
    MutatedRequest,
    Severity,
)


class FindingEvaluator:
    """Evaluates test execution results against finding criteria."""

    def evaluate(
        self,
        test_case_id: str,
        test_name: str,
        test_owasp_category: str,
        test_owasp_name: str,
        test_severity: str,
        endpoint_id: str,
        endpoint_url: str,
        endpoint_method: str,
        portal_name: str,
        finding_criteria: dict[str, Any],
        evidence: Evidence,
        mutation_description: str = "",
        is_na: bool = False,
        na_reason: str = "",
    ) -> FindingResult:
        """Evaluate a single test execution result."""

        # Handle NA cases
        if is_na:
            return FindingResult(
                test_case_id=test_case_id,
                test_name=test_name,
                endpoint_id=endpoint_id,
                endpoint_url=endpoint_url,
                endpoint_method=endpoint_method,
                portal_name=portal_name,
                owasp_category=test_owasp_category,
                owasp_name=test_owasp_name,
                severity=Severity(test_severity),
                verdict=FindingVerdict.NA,
                confidence=ConfidenceLevel.HIGH,
                reasoning=na_reason,
                evidence=evidence,
            )

        # Check if this is an error (request failed)
        if evidence.response.status_code == 0:
            return FindingResult(
                test_case_id=test_case_id,
                test_name=test_name,
                endpoint_id=endpoint_id,
                endpoint_url=endpoint_url,
                endpoint_method=endpoint_method,
                portal_name=portal_name,
                owasp_category=test_owasp_category,
                owasp_name=test_owasp_name,
                severity=Severity(test_severity),
                verdict=FindingVerdict.ERROR,
                confidence=ConfidenceLevel.HIGH,
                reasoning=f"Request failed: {evidence.response.body}",
                evidence=evidence,
                error_message=evidence.response.body,
            )

        # Evaluate based on criteria
        verdict, confidence, reasoning = self._evaluate_criteria(
            finding_criteria, evidence
        )

        severity_enum = Severity(test_severity)

        return FindingResult(
            test_case_id=test_case_id,
            test_name=test_name,
            endpoint_id=endpoint_id,
            endpoint_url=endpoint_url,
            endpoint_method=endpoint_method,
            portal_name=portal_name,
            owasp_category=test_owasp_category,
            owasp_name=test_owasp_name,
            severity=severity_enum,
            verdict=verdict,
            confidence=confidence,
            reasoning=reasoning,
            evidence=evidence,
        )

    def _evaluate_criteria(
        self,
        criteria: dict[str, Any],
        evidence: Evidence,
    ) -> tuple[FindingVerdict, ConfidenceLevel, str]:
        """Evaluate evidence against finding criteria."""
        response = evidence.response
        status_code = response.status_code
        response_body = response.body or ""
        response_headers = response.headers

        # Collect all reasoning points
        reasoning_parts: list[str] = []
        finding_indicators = 0
        non_finding_indicators = 0
        total_checks = 0

        # ------------------------------------------------------------------
        # 1. Status code check
        # ------------------------------------------------------------------
        finding_status_codes = criteria.get("status_codes", [])
        if finding_status_codes:
            total_checks += 1
            if status_code in finding_status_codes:
                finding_indicators += 1
                reasoning_parts.append(
                    f"Response status {status_code} matches finding criteria "
                    f"(expected: {finding_status_codes})"
                )
            else:
                non_finding_indicators += 1
                reasoning_parts.append(
                    f"Response status {status_code} does not match finding criteria "
                    f"(expected: {finding_status_codes})"
                )

        # ------------------------------------------------------------------
        # 2. Response body must NOT contain (should be absent for secure behavior)
        # ------------------------------------------------------------------
        must_not_contain = criteria.get("response_must_not_contain", [])
        for pattern in must_not_contain:
            total_checks += 1
            if pattern.lower() in response_body.lower():
                finding_indicators += 1
                reasoning_parts.append(
                    f"Response body contains prohibited pattern: '{pattern}'"
                )
            else:
                non_finding_indicators += 1
                reasoning_parts.append(
                    f"Response body does not contain prohibited pattern: '{pattern}'"
                )

        # ------------------------------------------------------------------
        # 3. Response body must contain (should be present for a finding)
        # ------------------------------------------------------------------
        must_contain = criteria.get("response_must_contain", [])
        for pattern in must_contain:
            total_checks += 1
            if pattern.lower() in response_body.lower():
                finding_indicators += 1
                reasoning_parts.append(
                    f"Response body contains expected finding indicator: '{pattern}'"
                )
            else:
                non_finding_indicators += 1
                reasoning_parts.append(
                    f"Response body missing expected finding indicator: '{pattern}'"
                )

        # ------------------------------------------------------------------
        # 4. Header checks (CORS, security headers)
        # ------------------------------------------------------------------
        header_name = criteria.get("header_name")
        if header_name:
            header_must_not_contain = criteria.get("header_must_not_contain", [])
            header_value = response_headers.get(header_name, "").lower()

            total_checks += 1
            if any(pattern.lower() in header_value for pattern in header_must_not_contain):
                finding_indicators += 1
                reasoning_parts.append(
                    f"Header '{header_name}' contains prohibited value: {header_value}"
                )
            elif header_value:
                non_finding_indicators += 1
                reasoning_parts.append(
                    f"Header '{header_name}' value is safe: {header_value}"
                )
            else:
                non_finding_indicators += 1
                reasoning_parts.append(
                    f"Header '{header_name}' not present (secure behavior)"
                )

        # ------------------------------------------------------------------
        # 5. Missing security headers check
        # ------------------------------------------------------------------
        required_headers = criteria.get("required_headers", [])
        for req_header in required_headers:
            total_checks += 1
            header_name_check = req_header.get("name", "")
            if header_name_check.lower() not in {k.lower() for k in response_headers}:
                finding_indicators += 1
                reasoning_parts.append(
                    f"Missing required security header: {header_name_check}"
                )
            else:
                non_finding_indicators += 1
                reasoning_parts.append(
                    f"Security header present: {header_name_check}"
                )

        # ------------------------------------------------------------------
        # 6. Response time check (blind injection)
        # ------------------------------------------------------------------
        time_threshold = criteria.get("response_time_threshold_ms")
        if time_threshold:
            total_checks += 1
            if evidence.execution_time_ms > time_threshold:
                finding_indicators += 1
                reasoning_parts.append(
                    f"Response time {evidence.execution_time_ms}ms exceeds "
                    f"threshold {time_threshold}ms (possible blind injection)"
                )
            else:
                non_finding_indicators += 1
                reasoning_parts.append(
                    f"Response time {evidence.execution_time_ms}ms within "
                    f"normal range (<{time_threshold}ms)"
                )

        # ------------------------------------------------------------------
        # 7. 500 Internal Server Error check
        # ------------------------------------------------------------------
        if status_code == 500:
            # 500 is a finding unless it's the expected behavior for the test
            expected_500 = criteria.get("status_codes", [])
            if 500 not in expected_500:
                finding_indicators += 1
                reasoning_parts.append(
                    "Internal Server Error (500) - possible unhandled exception"
                )

        # ------------------------------------------------------------------
        # Determine verdict
        # V2.2: Output POTENTIAL_FINDING instead of FINDING.
        # The LLM layer will confirm/reject these before they become final.
        # ------------------------------------------------------------------
        description = criteria.get("description", "")

        if total_checks == 0:
            # No specific criteria defined, use status code heuristic
            if status_code >= 200 and status_code < 300:
                verdict = FindingVerdict.POTENTIAL_FINDING
                confidence = ConfidenceLevel.MEDIUM
                reasoning_parts.append(
                    "No specific criteria defined; positive response indicates potential finding"
                )
            elif status_code in (401, 403):
                verdict = FindingVerdict.NOT_FINDING
                confidence = ConfidenceLevel.HIGH
                reasoning_parts.append(
                    f"Secure behavior: {status_code} response"
                )
            else:
                verdict = FindingVerdict.NOT_FINDING
                confidence = ConfidenceLevel.MEDIUM
                reasoning_parts.append(
                    f"Non-success status code: {status_code}"
                )
        else:
            # Weighted evaluation
            finding_ratio = finding_indicators / total_checks if total_checks > 0 else 0

            if finding_ratio >= 0.5:
                # More indicators point to finding — flag as POTENTIAL for LLM review
                verdict = FindingVerdict.POTENTIAL_FINDING
                if finding_ratio >= 0.8:
                    confidence = ConfidenceLevel.HIGH
                elif finding_ratio >= 0.6:
                    confidence = ConfidenceLevel.MEDIUM
                else:
                    confidence = ConfidenceLevel.LOW
            elif non_finding_indicators > finding_indicators:
                verdict = FindingVerdict.NOT_FINDING
                confidence = ConfidenceLevel.HIGH if finding_ratio < 0.2 else ConfidenceLevel.MEDIUM
            else:
                # Equal indicators - inconclusive
                verdict = FindingVerdict.NOT_FINDING
                confidence = ConfidenceLevel.LOW

        # Build final reasoning
        reasoning = " | ".join(reasoning_parts)
        if description:
            reasoning = f"[{description}] {reasoning}"

        return verdict, confidence, reasoning

    def evaluate_batch(
        self, evaluations: list[dict[str, Any]]
    ) -> list[FindingResult]:
        """Evaluate a batch of test results."""
        results = []
        for eval_data in evaluations:
            result = self.evaluate(**eval_data)
            results.append(result)
        return results
