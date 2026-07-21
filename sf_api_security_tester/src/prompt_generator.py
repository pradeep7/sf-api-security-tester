"""Prompt Generator — Produces ready-to-use AI prompts from test results.

V4.0: Generates Markdown prompt artifacts at the end of Phase 6 so
developers can instantly feed high-value, context-rich prompts to their
AI IDE (Cursor/Copilot/Claude) for remediation and triage.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from loguru import logger

from .models import FindingResult, FindingVerdict, Severity, TestReport

# Residual Risk Disclaimer (from V4.0 workbook)
_RESIDUAL_RISK_DISCLAIMER = (
    "This assessment is evidence-backed only for the executed route, role, "
    "method, data context, and environment. It does not prove alternate roles, "
    "routes, versions, batch paths, or trust boundaries. Untested variants, "
    "exclusions, and residual risk must be reviewed manually."
)


class PromptGenerator:
    """Generates ready-to-use AI prompts from test results.

    Cost: $0.00 — all text is built locally, no LLM API calls.
    """

    def __init__(self, output_dir: str | Path = "output/prompts"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "remediation").mkdir(exist_ok=True)
        (self.output_dir / "triage").mkdir(exist_ok=True)

    def generate_all(self, report: TestReport, catalog: list[dict] | None = None) -> dict[str, list[str]]:
        """Generate all prompt artifacts. Returns dict of type -> file paths."""
        results: dict[str, list[str]] = {
            "remediation": [],
            "triage": [],
            "executive": [],
        }

        # Load catalog for reference
        catalog_map = {}
        if catalog:
            catalog_map = {c.get("test_id", ""): c for c in catalog}

        # Generate remediation prompts
        remediation_files = self.generate_remediation_prompts(report, catalog_map)
        results["remediation"] = remediation_files

        # Generate triage prompts
        triage_files = self.generate_triage_prompts(report, catalog_map)
        results["triage"] = triage_files

        # Generate executive summary prompt
        exec_file = self.generate_executive_summary_prompt(report)
        if exec_file:
            results["executive"] = [exec_file]

        total = sum(len(v) for v in results.values())
        logger.info(f"Generated {total} prompt artifacts in {self.output_dir}")
        return results

    # ------------------------------------------------------------------
    # Remediation Prompts
    # ------------------------------------------------------------------
    def generate_remediation_prompts(
        self, report: TestReport, catalog_map: dict[str, dict]
    ) -> list[str]:
        """Generate remediation prompts for Failed/Probable findings."""
        files: list[str] = []

        for finding in report.all_results:
            if finding.verdict not in (FindingVerdict.FINDING, FindingVerdict.POTENTIAL_FINDING):
                continue

            prompt = self._build_remediation_prompt(finding, catalog_map)
            if prompt:
                safe_id = finding.test_case_id.replace(":", "-").replace(" ", "_")
                filename = f"{safe_id}_remediation.md"
                filepath = self.output_dir / "remediation" / filename
                filepath.write_text(prompt, encoding="utf-8")
                files.append(str(filepath))

        logger.info(f"Generated {len(files)} remediation prompts")
        return files

    def _build_remediation_prompt(
        self, finding: FindingResult, catalog_map: dict[str, dict]
    ) -> str:
        """Build a remediation prompt for a single finding."""
        catalog_entry = catalog_map.get(finding.test_case_id, {})

        # Extract evidence (redacted)
        request_text = ""
        response_text = ""
        if finding.evidence:
            request_text = self._redact_evidence(
                finding.evidence.raw_request_text or "", max_len=2000
            )
            response_text = self._redact_evidence(
                finding.evidence.raw_response_text or "", max_len=2000
            )

        prompt = f"""# Security Remediation Prompt

## Context
You are a Senior Salesforce Security Engineer. You have received a confirmed security finding from an automated, governance-enforced security assessment. Your task is to generate the **exact code fix** for this vulnerability.

## Governance Boundary
{_RESIDUAL_RISK_DISCLAIMER}

## Finding Details
- **Test ID:** {finding.test_case_id}
- **OWASP Category:** {finding.owasp_category} — {finding.owasp_name}
- **Severity:** {finding.severity.value}
- **Verdict:** {finding.verdict.value}
- **Endpoint:** {finding.endpoint_method} {finding.endpoint_url}
- **Portal:** {finding.portal_name}

## Bible Control Requirement
"""
        if catalog_entry:
            prompt += f"- **Control Scenario:** {catalog_entry.get('test_scenario', 'N/A')}\n"
            prompt += f"- **Test Objective:** {catalog_entry.get('test_objective', 'N/A')}\n"
            prompt += f"- **Pass Criteria:** {catalog_entry.get('pass', 'N/A')}\n"
            prompt += f"- **Fail Criteria:** {catalog_entry.get('fail', 'N/A')}\n"
        else:
            prompt += f"- **Scanner Reasoning:** {finding.reasoning}\n"

        prompt += f"""
## Injected Payload
The scanner injected a payload that triggered this finding. The exact payload details are in the HTTP request below.

## HTTP Evidence (Redacted)
### Request
```
{request_text}
```

### Response
```
{response_text}
```

## Your Task
1. Analyze the HTTP evidence above.
2. Determine the **root cause** of the vulnerability in Salesforce terms (e.g., missing FLS, no OWD enforcement, unvalidated input).
3. Generate the **exact code fix** (Apex class, JSON schema, permission set, or configuration change).
4. Explain **why** this fix addresses the vulnerability.

## Output Format
Provide your response as:
1. **Root Cause Analysis** (2-3 sentences)
2. **Recommended Fix** (code block with the exact implementation)
3. **Salesforce-Specific Guidance** (FLS, OWD, Sharing Rules, Profiles, PermissionSets)
4. **Residual Risk** (what remains after the fix)
"""
        return prompt

    # ------------------------------------------------------------------
    # Triage Prompts
    # ------------------------------------------------------------------
    def generate_triage_prompts(
        self, report: TestReport, catalog_map: dict[str, dict]
    ) -> list[str]:
        """Generate triage prompts for Possible/Unable to Determine findings."""
        files: list[str] = []

        for finding in report.all_results:
            if finding.verdict not in (
                FindingVerdict.POTENTIAL_FINDING,
                FindingVerdict.NOT_FINDING,
            ):
                continue

            prompt = self._build_triage_prompt(finding, catalog_map)
            if prompt:
                safe_id = finding.test_case_id.replace(":", "-").replace(" ", "_")
                filename = f"{safe_id}_triage.md"
                filepath = self.output_dir / "triage" / filename
                filepath.write_text(prompt, encoding="utf-8")
                files.append(str(filepath))

        logger.info(f"Generated {len(files)} triage prompts")
        return files

    def _build_triage_prompt(
        self, finding: FindingResult, catalog_map: dict[str, dict]
    ) -> str:
        """Build a triage prompt for a single finding."""
        catalog_entry = catalog_map.get(finding.test_case_id, {})

        request_text = ""
        response_text = ""
        if finding.evidence:
            request_text = self._redact_evidence(
                finding.evidence.raw_request_text or "", max_len=2000
            )
            response_text = self._redact_evidence(
                finding.evidence.raw_response_text or "", max_len=2000
            )

        prompt = f"""# Security Triage Prompt

## Context
You are a Senior Triage Engineer reviewing a potential security finding from an automated scanner. Your task is to determine if this is a **True Positive** or **False Positive**.

## Governance Boundary
{_RESIDUAL_RISK_DISCLAIMER}

## Finding Details
- **Test ID:** {finding.test_case_id}
- **OWASP Category:** {finding.owasp_category} — {finding.owasp_name}
- **Severity:** {finding.severity.value}
- **Verdict:** {finding.verdict.value}
- **Endpoint:** {finding.endpoint_method} {finding.endpoint_url}
- **Portal:** {finding.portal_name}

## Scanner Reasoning
{finding.reasoning}

## HTTP Evidence (Redacted)
### Baseline Request
```
{request_text}
```

### Baseline Response
```
{response_text}
```

## Your Task
1. Compare the **baseline request** (legitimate) with the **negative request** (attack).
2. Analyze if the server response indicates a **True Positive** (vulnerability exists) or **False Positive** (expected platform behavior, e.g., Salesforce OWD).
3. Consider Salesforce-specific context:
   - OWD (Organization-Wide Defaults) set to Private means 403/404 on records is EXPECTED
   - Sharing Rules and Role Hierarchy control visibility
   - Field-Level Security (FLS) masks fields based on profile
4. Provide your triage decision with confidence score.

## Output Format
Provide your response as:
1. **Triage Decision:** TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_MANUAL_REVIEW
2. **Confidence:** 0.0 - 1.0
3. **Reasoning** (2-3 sentences)
4. **Evidence Summary** (what the HTTP response actually shows)
"""
        return prompt

    # ------------------------------------------------------------------
    # Executive Summary Prompt
    # ------------------------------------------------------------------
    def generate_executive_summary_prompt(self, report: TestReport) -> str | None:
        """Generate a CISO briefing prompt."""
        summary = report.executive_summary

        prompt = f"""# Executive Security Assessment Briefing Prompt

## Context
You are a Security Assessment Lead writing a CISO briefing for the {report.project_name} engagement. The assessment was conducted using an automated, governance-enforced security testing framework with {summary.total_tests} executed tests across {summary.total_endpoints} endpoints.

## Governance Boundary
{_RESIDUAL_RISK_DISCLAIMER}

## Assessment Statistics
- **Total Tests Executed:** {summary.total_tests}
- **Total Endpoints:** {summary.total_endpoints}
- **Confirmed Findings:** {summary.findings_count}
- **Potential Findings:** {summary.potential_findings_count}
- **Not Findings (Passed):** {summary.not_findings_count}
- **Not Applicable:** {summary.na_count}
- **Errors:** {summary.errors_count}

## Severity Breakdown
- **Critical:** {summary.critical_count}
- **High:** {summary.high_count}
- **Medium:** {summary.medium_count}
- **Low:** {summary.low_count}

## AI Verification Summary
- **True Positives (LLM Confirmed):** {summary.llm_true_positives}
- **False Positives (LLM Eliminated):** {summary.llm_false_positives}
- **Needs Manual Review:** {summary.llm_manual_review}
- **Visual XSS/Data Exposure:** {summary.visual_findings_count}

## Portals Tested
{', '.join(summary.portals_tested) if summary.portals_tested else 'N/A'}

## Your Task
Write a **1-paragraph CISO briefing** that:
1. States the evidence-backed governance methodology used
2. Reports the exact number of confirmed risks and residual risk
3. Emphasizes that this assessment covers only the executed route, role, method, data context, and environment
4. Recommends next steps (e.g., sandbox testing, manual review of exclusions)

## Output Format
Write exactly one professional paragraph suitable for a CISO executive summary.
"""
        return prompt

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _redact_evidence(text: str, max_len: int = 2000) -> str:
        """Redact sensitive data from evidence before including in prompts."""
        if not text:
            return ""

        # Truncate
        redacted = text[:max_len]

        # Redact common sensitive patterns
        patterns = [
            (r"Bearer\s+[A-Za-z0-9\-._]+", "Bearer [REDACTED]"),
            (r"sid=[A-Za-z0-9\-._]+", "sid=[REDACTED]"),
            (r"Cookie:\s*[^\n]+", "Cookie: [REDACTED]"),
            (r"password[=:]\s*[^\s&]+", "password=[REDACTED]"),
            (r"00D[A-Za-z0-9]{12,}", "[SF_TOKEN_REDACTED]"),
        ]

        for pattern, replacement in patterns:
            redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)

        return redacted
