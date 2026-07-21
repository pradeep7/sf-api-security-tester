"""Bundles HTTP requests, responses, and screenshots into evidence objects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from loguru import logger

from .models import (
    Evidence,
    HttpRequest,
    HttpResponse,
    MutatedRequest,
)

# Maximum sizes before truncation (characters)
_MAX_RESPONSE_BODY = 51200   # 50 KB
_MAX_REQUEST_BODY = 10240    # 10 KB


class EvidenceCollector:
    """Collects and stores evidence from test executions."""

    def __init__(
        self,
        output_dir: str | Path,
        save_raw_http: bool = True,
        max_response_body: int = _MAX_RESPONSE_BODY,
        max_request_body: int = _MAX_REQUEST_BODY,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.save_raw_http = save_raw_http
        self.max_response_body = max_response_body
        self.max_request_body = max_request_body

    def collect(
        self,
        test_case_id: str,
        endpoint_id: str,
        mutated_request: MutatedRequest,
        http_request: HttpRequest,
        http_response: HttpResponse,
        execution_time_ms: int,
        screenshot_path: str | None = None,
    ) -> Evidence:
        """Create and persist an Evidence object.

        Response bodies are truncated to ``max_response_body`` characters and
        request bodies to ``max_request_body`` to prevent disk bloat on large
        test suites.
        """
        # --- Truncate bodies to prevent evidence bloat ---
        original_resp_len = len(http_response.body) if http_response.body else 0
        if original_resp_len > self.max_response_body:
            truncated = http_response.body[:self.max_response_body]
            http_response.body = (
                truncated
                + f"\n\n[TRUNCATED BY FRAMEWORK - ORIGINAL SIZE: {original_resp_len} bytes]"
            )

        original_req_len = len(http_request.body) if http_request.body else 0
        if original_req_len > self.max_request_body:
            truncated = http_request.body[:self.max_request_body]
            http_request.body = (
                truncated
                + f"\n\n[TRUNCATED BY FRAMEWORK - ORIGINAL SIZE: {original_req_len} bytes]"
            )

        evidence = Evidence(
            test_case_id=test_case_id,
            endpoint_id=endpoint_id,
            mutation_id=mutated_request.mutation_id,
            mutated_request_id=mutated_request.id,
            request=http_request,
            response=http_response,
            screenshot_path=screenshot_path,
            execution_time_ms=execution_time_ms,
        )

        # Save raw HTTP dumps
        if self.save_raw_http:
            evidence_dir = self.output_dir / test_case_id / endpoint_id
            evidence_dir.mkdir(parents=True, exist_ok=True)

            # Save request
            req_file = evidence_dir / f"request_{mutated_request.mutation_id[:8]}.txt"
            req_text = self._format_request(http_request, mutated_request)
            req_file.write_text(req_text, encoding="utf-8")
            evidence.raw_request_text = req_text

            # Save response
            resp_file = evidence_dir / f"response_{mutated_request.mutation_id[:8]}.txt"
            resp_text = self._format_response(http_response)
            resp_file.write_text(resp_text, encoding="utf-8")
            evidence.raw_response_text = resp_text

            # Save mutation details
            mut_file = evidence_dir / f"mutation_{mutated_request.mutation_id[:8]}.json"
            mut_data = {
                "mutation_id": mutated_request.mutation_id,
                "mutation_description": mutated_request.mutation_description,
                "original_url": "",
                "mutated_url": mutated_request.url,
                "method": mutated_request.method.value,
                "headers": mutated_request.headers,
                "body": mutated_request.body,
                "cookies": mutated_request.cookies,
            }
            mut_file.write_text(json.dumps(mut_data, indent=2), encoding="utf-8")

        return evidence

    def _format_request(
        self, request: HttpRequest, mutated_request: MutatedRequest
    ) -> str:
        """Format HTTP request as raw text (body already truncated)."""
        lines = [
            f"=== MUTATED REQUEST ===",
            f"Test Case: {mutated_request.test_case_id}",
            f"Mutation: {mutated_request.mutation_id}",
            f"Description: {mutated_request.mutation_description}",
            f"",
            f"--- HTTP Request ---",
            f"{request.method} {request.url} {request.http_version}",
        ]

        for name, value in sorted(request.headers.items()):
            lines.append(f"{name}: {value}")

        if request.cookies:
            lines.append("")
            lines.append("--- Cookies ---")
            for name, value in request.cookies.items():
                lines.append(f"{name}={value}")

        if request.body:
            lines.append("")
            lines.append("--- Body ---")
            lines.append(request.body)

        return "\n".join(lines)

    def _format_response(self, response: HttpResponse) -> str:
        """Format HTTP response as raw text (body already truncated)."""
        lines = [
            f"--- HTTP Response ---",
            f"{response.http_version} {response.status_code} {response.status_text}",
        ]

        for name, value in sorted(response.headers.items()):
            lines.append(f"{name}: {value}")

        if response.body:
            lines.append("")
            lines.append("--- Body ---")
            lines.append(response.body)

        return "\n".join(lines)

    def collect_batch(
        self,
        results: list[dict[str, Any]],
    ) -> list[Evidence]:
        """Collect evidence from a batch of results."""
        evidences = []
        for result in results:
            evidence = self.collect(
                test_case_id=result["test_case_id"],
                endpoint_id=result["endpoint_id"],
                mutated_request=result["mutated_request"],
                http_request=result["http_request"],
                http_response=result["http_response"],
                execution_time_ms=result.get("execution_time_ms", 0),
                screenshot_path=result.get("screenshot_path"),
            )
            evidences.append(evidence)
        return evidences

    def validate_evidence(
        self,
        test_id: str,
        evidence_required: list[str],
        captured_evidence: dict[str, str],
    ) -> tuple[bool, list[str]]:
        """V4.0: Validate that all required evidence was captured.

        Returns:
            (all_captured, list_of_missing_types)

        If a required evidence type cannot be captured (e.g., no baseline
        was established), the test status must be set to Blocked.
        """
        missing = []
        for evidence_type in evidence_required:
            if evidence_type not in captured_evidence or not captured_evidence[evidence_type]:
                missing.append(evidence_type)
                logger.warning(
                    f"Test {test_id}: Missing required evidence: {evidence_type}"
                )

        all_captured = len(missing) == 0
        if not all_captured:
            logger.warning(
                f"Test {test_id}: {len(missing)}/{len(evidence_required)} "
                f"evidence items missing: {missing}"
            )

        return all_captured, missing
