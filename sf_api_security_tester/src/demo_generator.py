"""
Demo Generator — Produces structurally valid sample output files for Pipeline 1
integration validation, stakeholder demos, and regression testing.

ZERO network requests. All data is synthetic but structurally identical to real output.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger


# ── Constants ──────────────────────────────────────────────────────────────────

RESIDUAL_RISK_DISCLAIMER = (
    "This assessment is evidence-backed only for the executed route, role, method, "
    "data context, and environment. It does not prove alternate roles, routes, versions, "
    "batch paths, or trust boundaries. Untested variants, exclusions, and residual risk "
    "must be reviewed manually."
)

TELEMETRY_HEADERS = {
    "X-SecTest-Phase": "3",
    "X-SecTest-OWASP": "API1:2023",
    "X-SecTest-Category": "BOLA",
    "X-SecTest-Case-ID": "API-BOLA-004",
    "X-SecTest-Payload-Hash": "e3b0c44298fc1c149afbf4c8996fb924",
    "X-SecTest-Target-Field": "recordId",
    "X-SecTest-Inject-Location": "url_path",
}

DOMAIN_COUNTS = {
    "Identity, Authentication & Session": 79,
    "Record & Tenant Access (BOLA / IDOR)": 22,
    "Privilege & Function Boundaries (BFLA)": 35,
    "Field, Property & Payload Authorisation": 34,
    "Input, Parser & Query Safety": 115,
    "Data Exposure, Privacy & Cryptography": 21,
    "Guest, File & Public Surface Security": 24,
    "Integration & Trust Boundary Security": 47,
    "Abuse Resistance, Logging & Monitoring": 15,
    "Business Logic & Transaction Integrity": 20,
    "Configuration, Inventory & Engineering Assurance": 64,
    "Client, Platform & General API Assurance": 7,
}

NOW = datetime.now(timezone.utc).isoformat()


# ── DemoGenerator ──────────────────────────────────────────────────────────────

class DemoGenerator:
    """Generates all sample output files for demo/integration testing."""

    def __init__(self, output_dir: str | Path = "output") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "reports").mkdir(exist_ok=True)
        (self.output_dir / "prompts" / "remediation").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "prompts" / "triage").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "evidence").mkdir(exist_ok=True)

    def generate_all(self) -> list[str]:
        """Generate all demo files. Returns list of created file paths."""
        files: list[str] = []
        files.extend(self.generate_sample_report())
        files.extend(self.generate_sample_prompts())
        files.extend(self.generate_sample_evidence())
        files.extend(self.generate_sample_html_report())
        return files

    # ── 2a: JSON Report ────────────────────────────────────────────────────

    def generate_sample_report(self) -> list[str]:
        report = {
            "demo_mode": True,
            "report_metadata": {
                "framework_version": "V4.0",
                "scan_mode": "demo",
                "generated_at": NOW,
                "residual_risk_disclaimer": RESIDUAL_RISK_DISCLAIMER,
            },
            "summary": {
                "total_bible_tests": 483,
                "applicable": 47,
                "not_applicable": 312,
                "not_observed": 89,
                "blocked": 12,
                "passed": 38,
                "failed": 3,
                "potential": 4,
                "critical_findings": 1,
                "high_findings": 1,
                "medium_findings": 1,
                "low_findings": 0,
                "portals_tested": ["assist_portal", "tenant_portal"],
            },
            "owasp_compliance": [
                {
                    "framework": "OWASP API Top 10 (2023)",
                    "categories_tested": 10,
                    "total_categories": 10,
                    "status": "100% COVERAGE",
                    "details": [
                        {"id": "API1:2023", "name": "Broken Object Level Authorization", "status": "TESTED", "tests_passed": 18, "tests_failed": 2},
                        {"id": "API2:2023", "name": "Broken Authentication", "status": "TESTED", "tests_passed": 22, "tests_failed": 0},
                        {"id": "API3:2023", "name": "Broken Object Property Level Authorization", "status": "TESTED", "tests_passed": 15, "tests_failed": 1},
                        {"id": "API4:2023", "name": "Unrestricted Resource Consumption", "status": "TESTED", "tests_passed": 8, "tests_failed": 0},
                        {"id": "API5:2023", "name": "Broken Function Level Authorization", "status": "TESTED", "tests_passed": 12, "tests_failed": 0},
                        {"id": "API6:2023", "name": "Unrestricted Access to Sensitive Business Flows", "status": "TESTED", "tests_passed": 5, "tests_failed": 0},
                        {"id": "API7:2023", "name": "Server Side Request Forgery", "status": "TESTED", "tests_passed": 4, "tests_failed": 0},
                        {"id": "API8:2023", "name": "Security Misconfiguration", "status": "TESTED", "tests_passed": 10, "tests_failed": 0},
                        {"id": "API9:2023", "name": "Improper Inventory Management", "status": "TESTED", "tests_passed": 6, "tests_failed": 0},
                        {"id": "API10:2023", "name": "Unsafe Consumption of APIs", "status": "NOT_OBSERVED", "tests_passed": 0, "tests_failed": 0},
                    ],
                },
                {
                    "framework": "OWASP Web Top 10 (2021)",
                    "categories_tested": 10,
                    "total_categories": 10,
                    "status": "100% COVERAGE",
                    "details": [
                        {"id": "A01:2021", "name": "Broken Access Control", "status": "TESTED", "tests_passed": 14, "tests_failed": 1},
                        {"id": "A02:2021", "name": "Cryptographic Failures", "status": "TESTED", "tests_passed": 6, "tests_failed": 0},
                        {"id": "A03:2021", "name": "Injection", "status": "TESTED", "tests_passed": 8, "tests_failed": 1},
                        {"id": "A04:2021", "name": "Insecure Design", "status": "NOT_OBSERVED", "tests_passed": 0, "tests_failed": 0},
                        {"id": "A05:2021", "name": "Security Misconfiguration", "status": "TESTED", "tests_passed": 10, "tests_failed": 0},
                        {"id": "A06:2021", "name": "Vulnerable and Outdated Components", "status": "NOT_OBSERVED", "tests_passed": 0, "tests_failed": 0},
                        {"id": "A07:2021", "name": "Identification and Authentication Failures", "status": "TESTED", "tests_passed": 8, "tests_failed": 0},
                        {"id": "A08:2021", "name": "Software and Data Integrity Failures", "status": "TESTED", "tests_passed": 4, "tests_failed": 0},
                        {"id": "A09:2021", "name": "Security Logging and Monitoring Failures", "status": "TESTED", "tests_passed": 5, "tests_failed": 0},
                        {"id": "A10:2021", "name": "Server-Side Request Forgery", "status": "TESTED", "tests_passed": 3, "tests_failed": 0},
                    ],
                },
                {
                    "framework": "OWASP Secure Coding Practices (v2)",
                    "categories_tested": 13,
                    "total_categories": 13,
                    "status": "100% COVERAGE",
                    "details": [
                        {"id": "SCP-01", "name": "Input Validation", "status": "TESTED", "tests_passed": 10, "tests_failed": 0},
                        {"id": "SCP-02", "name": "Authentication", "status": "TESTED", "tests_passed": 8, "tests_failed": 0},
                        {"id": "SCP-03", "name": "Session Management", "status": "TESTED", "tests_passed": 6, "tests_failed": 0},
                        {"id": "SCP-04", "name": "Access Control", "status": "TESTED", "tests_passed": 5, "tests_failed": 0},
                        {"id": "SCP-05", "name": "Cryptography", "status": "TESTED", "tests_passed": 4, "tests_failed": 0},
                        {"id": "SCP-06", "name": "Error Handling and Logging", "status": "TESTED", "tests_passed": 3, "tests_failed": 0},
                        {"id": "SCP-07", "name": "Data Protection", "status": "TESTED", "tests_passed": 5, "tests_failed": 0},
                        {"id": "SCP-08", "name": "Communication Security", "status": "TESTED", "tests_passed": 4, "tests_failed": 0},
                        {"id": "SCP-09", "name": "System Configuration", "status": "TESTED", "tests_passed": 3, "tests_failed": 0},
                        {"id": "SCP-10", "name": "Database Security", "status": "TESTED", "tests_passed": 2, "tests_failed": 0},
                        {"id": "SCP-11", "name": "File Management", "status": "TESTED", "tests_passed": 3, "tests_failed": 0},
                        {"id": "SCP-12", "name": "Memory Management", "status": "NOT_OBSERVED", "tests_passed": 0, "tests_failed": 0},
                        {"id": "SCP-13", "name": "API Security", "status": "TESTED", "tests_passed": 4, "tests_failed": 0},
                    ],
                },
            ],
            "domain_coverage": [
                {"domain": name, "total_tests": count, "applicable": max(1, count // 10), "passed": max(1, count // 15), "failed": 1 if count > 20 else 0, "not_applicable": count - max(1, count // 10)}
                for name, count in DOMAIN_COUNTS.items()
            ],
            "findings": [
                {
                    "finding_id": "FIND-2026-001",
                    "test_id": "API-BOLA-004",
                    "domain": "Record & Tenant Access (BOLA / IDOR)",
                    "subcategory": "Object Identifier Authorisation",
                    "title": "Cross-tenant record access via SOQL query parameter manipulation",
                    "severity": "Critical",
                    "confidence": "CONFIRMED",
                    "status": "FAILED",
                    "owasp_mapping": {
                        "api_top10": "API1:2023 - Broken Object Level Authorization",
                        "web_top10": "A01:2021 - Broken Access Control",
                        "secure_coding": "SCP-04 - Access Control",
                        "bible_domain": "Domain 2: Record & Tenant Access (BOLA / IDOR)",
                    },
                    "endpoint": {
                        "method": "GET",
                        "url": "https://your-assist-portal.salesforce.com/services/data/v58.0/query/",
                        "injection_point": {
                            "location": "query",
                            "field": "q",
                            "original_value": "SELECT Id, Subject FROM Case WHERE Id = '5003t000001AbCdEFG'",
                            "injected_value": "SELECT Id, Subject, Description FROM Case WHERE Id = '5003t000009XyZaBCD'",
                        },
                    },
                    "evidence": {
                        "baseline_request": {"method": "GET", "url": "https://your-assist-portal.salesforce.com/services/data/v58.0/query/?q=SELECT+Id,Subject+FROM+Case+WHERE+Id='5003t000001AbCdEFG'", "headers": {"Authorization": "Bearer [REDACTED]", "Content-Type": "application/json"}, "telemetry": TELEMETRY_HEADERS},
                        "baseline_response": {"status": 200, "body_preview": {"totalSize": 1, "records": [{"Id": "5003t000001AbCdEFG", "Subject": "Tenant A - Service Request"}]}},
                        "negative_request": {"method": "GET", "url": "https://your-assist-portal.salesforce.com/services/data/v58.0/query/?q=SELECT+Id,Subject,Description+FROM+Case+WHERE+Id='5003t000009XyZaBCD'", "headers": {"Authorization": "Bearer [REDACTED]", "Content-Type": "application/json"}, "telemetry": TELEMETRY_HEADERS},
                        "negative_response": {"status": 200, "body_preview": {"totalSize": 1, "records": [{"Id": "5003t000009XyZaBCD", "Subject": "Tenant B - Confidential Claim", "Description": "[REDACTED_PII]"}]}},
                        "tested_role": "Standard User (Tenant A)",
                        "correlation_id": "demo-bola-004-2026",
                    },
                    "observed_behavior": "HTTP 200 with Tenant B Case record data returned to Tenant A user. SOQL injection in query parameter allows cross-tenant record access.",
                    "expected_behavior": "HTTP 403 or empty result set when querying records outside the user's tenant scope.",
                    "control_observed": "SOQL query accepts arbitrary WHERE clause without tenant isolation enforcement.",
                    "business_impact": "Critical: Cross-tenant data exposure allows any authenticated user to access confidential records from other tenants via SOQL manipulation.",
                    "remediation": "Implement row-level security (WITH SECURITY_ENFORCED) on all SOQL queries. Validate record ownership before returning data. Use parameterized queries with bound variables.",
                    "residual_risk_disclaimer": RESIDUAL_RISK_DISCLAIMER,
                },
                {
                    "finding_id": "FIND-2026-002",
                    "test_id": "API-INPUT-014",
                    "domain": "Input, Parser & Query Safety",
                    "subcategory": "Injection Resistance",
                    "title": "Unicode normalisation bypass in SOQL query parameter",
                    "severity": "High",
                    "confidence": "CONFIRMED",
                    "status": "FAILED",
                    "owasp_mapping": {
                        "api_top10": "API3:2023 - Broken Object Property Level Authorization",
                        "web_top10": "A03:2021 - Injection",
                        "secure_coding": "SCP-01 - Input Validation",
                        "bible_domain": "Domain 5: Input, Parser & Query Safety",
                    },
                    "endpoint": {
                        "method": "GET",
                        "url": "https://your-assist-portal.salesforce.com/services/data/v58.0/query/",
                        "injection_point": {
                            "location": "query",
                            "field": "q",
                            "original_value": "SELECT Id FROM Contact WHERE Name = 'John'",
                            "injected_value": "SELECT Id FROM Contact WHERE Name = 'J\u006fhn' OR 1=1--",
                        },
                    },
                    "evidence": {
                        "baseline_request": {"method": "GET", "url": "https://your-assist-portal.salesforce.com/services/data/v58.0/query/?q=SELECT+Id+FROM+Contact+WHERE+Name='John'", "headers": {"Authorization": "Bearer [REDACTED]"}, "telemetry": TELEMETRY_HEADERS},
                        "baseline_response": {"status": 200, "body_preview": {"totalSize": 3, "records": [{"Id": "0033t000001AbCd"}]}},
                        "negative_request": {"method": "GET", "url": "https://your-assist-portal.salesforce.com/services/data/v58.0/query/?q=SELECT+Id+FROM+Contact+WHERE+Name='J\u006fhn'+OR+1=1--", "headers": {"Authorization": "Bearer [REDACTED]"}, "telemetry": TELEMETRY_HEADERS},
                        "negative_response": {"status": 200, "body_preview": {"totalSize": 487, "records": []}},
                        "tested_role": "Standard User",
                        "correlation_id": "demo-input-014-2026",
                    },
                    "observed_behavior": "Unicode normalisation (U+006F → 'o') combined with OR tautology returns all Contact records. Server does not normalise Unicode before SOQL processing.",
                    "expected_behavior": "Server should normalise Unicode input before query processing or reject homoglyph characters.",
                    "control_observed": "SOQL query parameter passes through without Unicode normalisation.",
                    "business_impact": "High: Attackers can bypass string-based access controls using Unicode homoglyphs to extract all records from restricted objects.",
                    "remediation": "Implement Unicode normalisation (NFC/NFKC) on all input parameters before query processing. Reject input containing homoglyph characters.",
                    "residual_risk_disclaimer": RESIDUAL_RISK_DISCLAIMER,
                },
                {
                    "finding_id": "FIND-2026-003",
                    "test_id": "API-PROP-015",
                    "domain": "Field, Property & Payload Authorisation",
                    "subcategory": "Mass Assignment",
                    "title": "LastModifiedById manipulable via JSON payload on Case update",
                    "severity": "High",
                    "confidence": "CONFIRMED",
                    "status": "FAILED",
                    "owasp_mapping": {
                        "api_top10": "API3:2023 - Broken Object Property Level Authorization",
                        "web_top10": "A01:2021 - Broken Access Control",
                        "secure_coding": "SCP-01 - Input Validation",
                        "bible_domain": "Domain 4: Field, Property & Payload Authorisation",
                    },
                    "endpoint": {
                        "method": "PATCH",
                        "url": "https://your-assist-portal.salesforce.com/services/data/v58.0/sobjects/Case/5003t000001AbCdEFG",
                        "injection_point": {
                            "location": "json_body",
                            "field": "LastModifiedById",
                            "original_value": None,
                            "injected_value": "0053t000001AdminXYZ",
                        },
                    },
                    "evidence": {
                        "baseline_request": {"method": "PATCH", "url": "https://your-assist-portal.salesforce.com/services/data/v58.0/sobjects/Case/5003t000001AbCdEFG", "body": {"Subject": "Updated Subject"}, "headers": {"Authorization": "Bearer [REDACTED]", "Content-Type": "application/json"}, "telemetry": TELEMETRY_HEADERS},
                        "baseline_response": {"status": 204, "body": None},
                        "negative_request": {"method": "PATCH", "url": "https://your-assist-portal.salesforce.com/services/data/v58.0/sobjects/Case/5003t000001AbCdEFG", "body": {"Subject": "Updated", "LastModifiedById": "0053t000001AdminXYZ"}, "headers": {"Authorization": "Bearer [REDACTED]", "Content-Type": "application/json"}, "telemetry": TELEMETRY_HEADERS},
                        "negative_response": {"status": 204, "body": None},
                        "tested_role": "Standard User",
                        "corjection_id": "demo-prop-015-2026",
                    },
                    "observed_behavior": "HTTP 204 accepted with LastModifiedById field silently applied. System field overwritten without validation.",
                    "expected_behavior": "Server should ignore or reject attempts to set read-only system fields (LastModifiedById, CreatedById, etc.).",
                    "control_observed": "JSON body accepts arbitrary fields including system-computed identifiers.",
                    "business_impact": "High: Mass assignment of system fields allows audit trail manipulation, attribution spoofing, and potential compliance violations.",
                    "remediation": "Implement strict allowlisting of writable fields per object type. Reject requests containing non-writable fields with HTTP 400.",
                    "residual_risk_disclaimer": RESIDUAL_RISK_DISCLAIMER,
                },
                {
                    "finding_id": "FIND-2026-004",
                    "test_id": "API-DATA-008",
                    "domain": "Data Exposure, Privacy & Cryptography",
                    "subcategory": "Sensitive Data Minimisation",
                    "title": "Verbose error messages expose internal stack traces in production",
                    "severity": "Medium",
                    "confidence": "POTENTIAL",
                    "status": "FAILED",
                    "owasp_mapping": {
                        "api_top10": "API8:2023 - Security Misconfiguration",
                        "web_top10": "A05:2021 - Security Misconfiguration",
                        "secure_coding": "SCP-06 - Error Handling and Logging",
                        "bible_domain": "Domain 6: Data Exposure, Privacy & Cryptography",
                    },
                    "endpoint": {
                        "method": "POST",
                        "url": "https://your-assist-portal.salesforce.com/services/data/v58.0/sobjects/Case/",
                        "injection_point": {
                            "location": "json_body",
                            "field": "Subject",
                            "original_value": "Valid Subject",
                            "injected_value": None,
                        },
                    },
                    "evidence": {
                        "baseline_request": {"method": "POST", "url": "https://your-assist-portal.salesforce.com/services/data/v58.0/sobjects/Case/", "body": {"Subject": "Valid Subject", "Origin": "Web"}, "headers": {"Authorization": "Bearer [REDACTED]", "Content-Type": "application/json"}, "telemetry": TELEMETRY_HEADERS},
                        "baseline_response": {"status": 201, "body_preview": {"id": "5003t000002XyZ"}},
                        "negative_request": {"method": "POST", "url": "https://your-assist-portal.salesforce.com/services/data/v58.0/sobjects/Case/", "body": {"Subject": None, "InvalidField": "test"}, "headers": {"Authorization": "Bearer [REDACTED]", "Content-Type": "application/json"}, "telemetry": TELEMETRY_HEADERS},
                        "negative_response": {"status": 400, "body_preview": {"message": "Invalid data provided", "errorCode": "INVALID_FIELD", "fields": ["Subject"], "debugInfo": "System.QueryException: Field not found: InvalidField at line 42 of CaseTrigger.trigger"}},
                        "tested_role": "Standard User",
                        "correlation_id": "demo-data-008-2026",
                    },
                    "observed_behavior": "Error response includes debugInfo with trigger line numbers and internal class names. Stack trace visible to end user.",
                    "expected_behavior": "Error responses should contain generic messages without internal implementation details.",
                    "control_observed": "Error handler includes debug information in API responses without filtering.",
                    "business_impact": "Medium: Verbose errors expose internal code structure, line numbers, and class names to attackers for targeted exploitation.",
                    "remediation": "Remove debug information from API error responses. Use generic error messages. Log detailed errors server-side only.",
                    "residual_risk_disclaimer": RESIDUAL_RISK_DISCLAIMER,
                },
            ],
            "blocked_tests": [
                {
                    "test_id": "API-BFLA-003",
                    "reason": "Apex executeAnonymous not accessible — admin endpoint not discoverable",
                    "blocking_dependency": "API-IAM-001",
                },
                {
                    "test_id": "API-TRUST-016",
                    "reason": "URL fetch to loopback destination — parser baseline (INPUT-001) not tested in demo mode",
                    "blocking_dependency": "API-INPUT-001",
                },
            ],
            "workflows_discovered": [
                {
                    "workflow_id": "WF-001",
                    "name": "Case Creation Wizard",
                    "steps": [
                        {"step_number": 1, "url": "/flow/CaseCreation", "action_description": "Enter Case Details"},
                        {"step_number": 2, "url": "/flow/CaseCreation?step=2", "action_description": "Select Related Account"},
                        {"step_number": 3, "url": "/flow/CaseCreation?step=3", "action_description": "Submit Case"},
                    ],
                    "entry_point": "/flow/CaseCreation",
                    "exit_point": "/flow/CaseCreation?step=3",
                    "api6_test_results": {
                        "API6-002_step_skip": {"status": "FAILED", "detail": "Step 3 accessible without completing Steps 1-2"},
                        "API6-003_state_replay": {"status": "PASSED", "detail": "State tokens validated on each step"},
                    },
                },
            ],
            "feature_inventory": {
                "pages_discovered": 42,
                "input_fields_total": 187,
                "risk_surfaces": [
                    {"surface": "REST API (/services/data/)", "risk_score": 85, "endpoints": 28},
                    {"surface": "SOQL Query Endpoint", "risk_score": 92, "endpoints": 4},
                    {"surface": "Apex REST (/services/apexrest/)", "risk_score": 78, "endpoints": 6},
                    {"surface": "Lightning Aura (/aura)", "risk_score": 65, "endpoints": 12},
                ],
            },
            "audit_trail_summary": {
                "total_events": 1847,
                "navigations": 412,
                "clicks": 893,
                "form_submissions": 124,
                "llm_calls": 48,
                "screenshots": 42,
                "probes_sent": 268,
                "errors": 60,
            },
        }

        path = self.output_dir / "reports" / "security_report.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        logger.info(f"Generated sample report: {path}")
        return [str(path)]

    # ── 2b: Sample Prompts ─────────────────────────────────────────────────

    def generate_sample_prompts(self) -> list[str]:
        files: list[str] = []

        # Remediation prompt
        remediation = f"""> ⚠️ DEMO MODE — SAMPLE DATA. Not from a live scan.

# Remediation Prompt: API-BOLA-004 — Cross-Tenant SOQL Injection

## System Prompt
You are a Principal Salesforce Security Engineer with 15+ years of platform experience. You specialise in Apex security, sharing rules, and OWASP API security controls. Your code must follow Salesforce secure coding best practices.

## Bible Requirement
- **Test ID:** API-BOLA-004
- **Domain:** Domain 2 — Record & Tenant Access (BOLA / IDOR)
- **Severity:** Critical
- **OWASP API 10 (2023):** API1 — Broken Object Level Authorization
- **OWASP Web 10 (2021):** A01 — Broken Access Control
- **OWASP Secure Coding v2:** SCP-04 — Access Control
- **Control:** Object Identifier Authorisation
- **Evidence Set:** EVD-PUBLIC-GUEST-ANONYMOUS-BASE

## Vulnerability Summary
The SOQL query endpoint at `GET /services/data/v58.0/query/` accepts user-controlled input in the `q` parameter without tenant isolation enforcement. An authenticated user from Tenant A can manipulate the WHERE clause to retrieve records belonging to Tenant B.

## Redacted HTTP Evidence

### Baseline Request (Authorized)
```
GET /services/data/v58.0/query/?q=SELECT+Id,Subject+FROM+Case+WHERE+Id='5003t000001AbCdEFG'
Host: your-assist-portal.salesforce.com
Authorization: Bearer [REDACTED]
Content-Type: application/json
X-SecTest-Phase: 3
X-SecTest-OWASP: API1:2023
X-SecTest-Category: BOLA
X-SecTest-Case-ID: API-BOLA-004
X-SecTest-Payload-Hash: e3b0c44298fc1c149afbf4c8996fb924
X-SecTest-Target-Field: q
X-SecTest-Inject-Location: query
```

### Baseline Response (200 OK — Own Record)
```json
{{"totalSize": 1, "records": [{{"Id": "5003t000001AbCdEFG", "Subject": "Tenant A - Service Request"}}]}}
```

### Negative Request (Injection)
```
GET /services/data/v58.0/query/?q=SELECT+Id,Subject,Description+FROM+Case+WHERE+Id='5003t000009XyZaBCD'
```

### Negative Response (200 OK — Cross-Tenant Data Leaked)
```json
{{"totalSize": 1, "records": [{{"Id": "5003t000009XyZaBCD", "Subject": "Tenant B - Confidential Claim"}}]}}
```

## Task
Generate the exact Apex code fix that:
1. Enforces tenant isolation on SOQL queries using `WITH SECURITY_ENFORCED`
2. Adds record ownership validation before returning data
3. Uses bound variables instead of string concatenation

Provide the fix as a complete, production-ready Apex class with:
- Before-trigger validation
- Sharing rules enforcement
- Unit test class with positive and negative test cases

> **Residual Risk Disclaimer:** This assessment is evidence-backed only for the executed route, role, method, data context, and environment. It does not prove alternate roles, routes, versions, batch paths, or trust boundaries. Untested variants, exclusions, and residual risk must be reviewed manually.
"""
        path = self.output_dir / "prompts" / "remediation" / "API-BOLA-004_remediation.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write(remediation)
        files.append(str(path))

        # Triage prompt
        triage = f"""> ⚠️ DEMO MODE — SAMPLE DATA. Not from a live scan.

# Triage Prompt: API-DATA-008 — Verbose Error Exposure

## System Prompt
You are a Senior Security Triage Engineer specialising in Salesforce platform security. Your role is to determine whether a detected anomaly is a TRUE POSITIVE (confirmed vulnerability) or FALSE POSITIVE (expected platform behaviour). You must consider Salesforce-specific context including debug modes, sandbox behaviour, and org-wide defaults.

## Bible Requirement
- **Test ID:** API-DATA-008
- **Domain:** Domain 6 — Data Exposure, Privacy & Cryptography
- **Severity:** Medium
- **Control:** Sensitive Data Minimisation
- **OWASP Mapping:** API8:2023 (Security Misconfiguration), A05:2021 (Security Misconfiguration)

## Baseline vs Negative Comparison

### Baseline (Normal Request)
```
POST /services/data/v58.0/sobjects/Case/
Body: {{"Subject": "Valid Subject", "Origin": "Web"}}
Response: 201 Created — {{"id": "5003t000002XyZ"}}
```

### Negative (Trigger Error)
```
POST /services/data/v58.0/sobjects/Case/
Body: {{"Subject": null, "InvalidField": "test"}}
Response: 400 Bad Request —
{{
  "message": "Invalid data provided",
  "errorCode": "INVALID_FIELD",
  "fields": ["Subject"],
  "debugInfo": "System.QueryException: Field not found: InvalidField at line 42 of CaseTrigger.trigger"
}}
```

## Salesforce-Specific Context
- **Debug Mode:** In production orgs, debug info should never be returned in API responses. In sandbox/test environments, debug info may be present for development purposes.
- **OWD (Organisation-Wide Defaults):** This test is independent of OWD settings as it relates to error message content, not data access.
- **API Version:** Testing against v58.0. Earlier versions may have different error handling behaviour.

## Task
Determine if this is a TRUE POSITIVE or FALSE POSITIVE based on the evidence. Consider:
1. Is this a production org or sandbox?
2. Is the `debugInfo` field always present or only under specific conditions?
3. Does Salesforce inherently return stack traces via the REST API?

Provide your determination with reasoning and recommended next steps.
"""
        path = self.output_dir / "prompts" / "triage" / "API-DATA-008_triage.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write(triage)
        files.append(str(path))

        # CISO summary
        ciso = f"""> ⚠️ DEMO MODE — SAMPLE DATA. Not from a live scan.

# CISO Executive Briefing — SF API Security Assessment

## Assessment Statistics
| Metric | Count |
|--------|-------|
| Total Bible v7.1 Tests | 483 |
| Applicable to Scope | 47 |
| Confirmed Findings (Failed) | 3 |
| Potential Findings | 1 |
| Passed | 38 |
| Not Observed (Manual Review Required) | 89 |
| Blocked by Prerequisites | 12 |

## Confirmed Findings Summary

### 1. [CRITICAL] Cross-Tenant SOQL Injection (API-BOLA-004)
An authenticated user can manipulate SOQL query parameters to access Case records belonging to other tenants. This represents a fundamental tenant isolation failure in the data query layer.

### 2. [HIGH] Unicode Normalisation Bypass (API-INPUT-014)
SOQL queries are vulnerable to Unicode homoglyph attacks, allowing bypass of string-based access controls. Attackers can use visually identical characters to bypass WHERE clause restrictions.

### 3. [HIGH] Mass Assignment of System Fields (API-PROP-015)
The Case update endpoint accepts modifications to read-only system fields (LastModifiedById), enabling audit trail manipulation and attribution spoofing.

### 4. [MEDIUM] Verbose Error Exposure (API-DATA-008 — Potential)
Error responses include internal stack traces and trigger line numbers, providing attackers with detailed information about internal code structure.

## Residual Risk Statement
> This assessment is evidence-backed only for the executed route, role, method, data context, and environment. It does not prove alternate roles, routes, versions, batch paths, or trust boundaries. Untested variants, exclusions, and residual risk must be reviewed manually.

## Manual Review Required
89 tests were classified as "Not Observed" — these tests could not be evaluated against the scanned endpoints and require manual verification by the security team.

## Task
Write a 4-sentence CISO briefing summarising the security posture, the most critical finding, the governance approach, and the recommended immediate actions. Tone: executive, factual, action-oriented.
"""
        path = self.output_dir / "prompts" / "ciso_summary.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write(ciso)
        files.append(str(path))

        logger.info("Generated sample prompts")
        return files

    # ── 2c: Sample Evidence ────────────────────────────────────────────────

    def generate_sample_evidence(self) -> list[str]:
        files: list[str] = []

        evidence_files = {
            "EVD-REQ-BOLA-004-NEG.json": {
                "demo_mode": True,
                "evidence_type": "negative_request",
                "test_id": "API-BOLA-004",
                "finding_id": "FIND-2026-001",
                "captured_at": NOW,
                "request": {
                    "method": "GET",
                    "url": "https://your-assist-portal.salesforce.com/services/data/v58.0/query/",
                    "query_params": {
                        "q": "SELECT Id, Subject, Description FROM Case WHERE Id = '5003t000009XyZaBCD'",
                    },
                    "headers": {
                        "Authorization": "Bearer [REDACTED]",
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        **TELEMETRY_HEADERS,
                    },
                },
                "injection_point": {
                    "location": "query",
                    "field": "q",
                    "original_value": "SELECT Id, Subject FROM Case WHERE Id = '5003t000001AbCdEFG'",
                    "injected_value": "SELECT Id, Subject, Description FROM Case WHERE Id = '5003t000009XyZaBCD'",
                },
                "redaction_status": "REDACTED",
                "correlation_id": "demo-bola-004-2026",
            },
            "EVD-RSP-BOLA-004-NEG.json": {
                "demo_mode": True,
                "evidence_type": "negative_response",
                "test_id": "API-BOLA-004",
                "finding_id": "FIND-2026-001",
                "captured_at": NOW,
                "response": {
                    "status_code": 200,
                    "status_text": "OK",
                    "headers": {
                        "Content-Type": "application/json",
                        "Cache-Control": "no-cache",
                        "X-SF-Request-Id": "demo-response-001",
                    },
                    "body": {
                        "totalSize": 1,
                        "done": True,
                        "records": [
                            {
                                "attributes": {"type": "Case", "url": "/services/data/v58.0/sobjects/Case/5003t000009XyZaBCD"},
                                "Id": "5003t000009XyZaBCD",
                                "Subject": "Tenant B - Confidential Claim",
                                "Description": "[REDACTED_PII]",
                            }
                        ],
                    },
                    "body_size_bytes": 312,
                    "response_time_ms": 245,
                },
                "correlation_id": "demo-bola-004-2026",
            },
            "EVD-REQ-BOLA-004-BASE.json": {
                "demo_mode": True,
                "evidence_type": "baseline_request",
                "test_id": "API-BOLA-004",
                "finding_id": "FIND-2026-001",
                "captured_at": NOW,
                "request": {
                    "method": "GET",
                    "url": "https://your-assist-portal.salesforce.com/services/data/v58.0/query/",
                    "query_params": {
                        "q": "SELECT Id, Subject FROM Case WHERE Id = '5003t000001AbCdEFG'",
                    },
                    "headers": {
                        "Authorization": "Bearer [REDACTED]",
                        "Content-Type": "application/json",
                        **TELEMETRY_HEADERS,
                    },
                },
                "injection_point": {
                    "location": "query",
                    "field": "q",
                    "original_value": None,
                    "injected_value": None,
                },
                "redaction_status": "REDACTED",
                "correlation_id": "demo-bola-004-2026",
            },
            "EVD-RSP-BOLA-004-BASE.json": {
                "demo_mode": True,
                "evidence_type": "baseline_response",
                "test_id": "API-BOLA-004",
                "finding_id": "FIND-2026-001",
                "captured_at": NOW,
                "response": {
                    "status_code": 200,
                    "status_text": "OK",
                    "headers": {
                        "Content-Type": "application/json",
                        "Cache-Control": "no-cache",
                    },
                    "body": {
                        "totalSize": 1,
                        "done": True,
                        "records": [
                            {
                                "attributes": {"type": "Case", "url": "/services/data/v58.0/sobjects/Case/5003t000001AbCdEFG"},
                                "Id": "5003t000001AbCdEFG",
                                "Subject": "Tenant A - Service Request",
                            }
                        ],
                    },
                    "body_size_bytes": 198,
                    "response_time_ms": 189,
                },
                "correlation_id": "demo-bola-004-2026",
            },
        }

        for filename, data in evidence_files.items():
            path = self.output_dir / "evidence" / filename
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            files.append(str(path))

        logger.info("Generated sample evidence files")
        return files

    # ── 2d: HTML Report ────────────────────────────────────────────────────

    def generate_sample_html_report(self) -> list[str]:
        html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SF API Security Test Report — DEMO</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
  .watermark { background: #da3633; color: #fff; text-align: center; padding: 8px; font-weight: 700; font-size: 14px; position: sticky; top: 0; z-index: 100; }
  .container { max-width: 1100px; margin: 0 auto; padding: 24px; }
  h1 { color: #58a6ff; margin-bottom: 8px; }
  h2 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 6px; margin: 24px 0 12px; }
  h3 { color: #c9d1d9; margin: 12px 0 6px; }
  .disclaimer { background: #1c1410; border-left: 4px solid #d29922; padding: 12px 16px; margin: 16px 0; border-radius: 4px; font-size: 13px; }
  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }
  .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; text-align: center; }
  .stat-card .number { font-size: 28px; font-weight: 700; color: #58a6ff; }
  .stat-card .label { font-size: 12px; color: #8b949e; margin-top: 4px; }
  .finding { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin: 12px 0; }
  .finding-header { display: flex; justify-content: space-between; align-items: center; }
  .severity-critical { color: #f85149; } .severity-high { color: #d29922; } .severity-medium { color: #e3b341; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge-failed { background: #f8514922; color: #f85149; }
  .badge-confirmed { background: #f8514922; color: #f85149; }
  .badge-potential { background: #d2992222; color: #d29922; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0; }
  th, td { padding: 8px 12px; border: 1px solid #30363d; text-align: left; font-size: 13px; }
  th { background: #161b22; color: #58a6ff; }
  .owasp-matrix th { font-size: 11px; }
  .evidence-toggle { cursor: pointer; color: #58a6ff; font-size: 12px; margin-top: 8px; }
  .evidence-content { display: none; background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 12px; margin-top: 8px; font-family: 'Cascadia Code', monospace; font-size: 12px; white-space: pre-wrap; }
  footer { text-align: center; padding: 24px; color: #484f58; font-size: 12px; border-top: 1px solid #30363d; margin-top: 24px; }
</style>
</head>
<body>
<div class="watermark">DEMO MODE — SAMPLE DATA — NOT FROM A LIVE SCAN</div>
<div class="container">
  <h1>SF API Security Test Report</h1>
  <p style="color:#8b949e">Framework V4.0 &bull; Generated: """ + NOW[:10] + """ &bull; Mode: DEMO</p>

  <div class="disclaimer"><strong>Residual Risk Statement:</strong> This assessment is evidence-backed only for the executed route, role, method, data context, and environment. It does not prove alternate roles, routes, versions, batch paths, or trust boundaries. Untested variants, exclusions, and residual risk must be reviewed manually.</div>

  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="stat-card"><div class="number">483</div><div class="label">Total Bible Tests</div></div>
    <div class="stat-card"><div class="number">47</div><div class="label">Applicable</div></div>
    <div class="stat-card"><div class="number" style="color:#f85149">3</div><div class="label">Confirmed Findings</div></div>
    <div class="stat-card"><div class="number" style="color:#d29922">1</div><div class="label">Potential Finding</div></div>
  </div>

  <h2>OWASP Compliance Matrix</h2>
  <table class="owasp-matrix">
    <tr><th>Framework</th><th>Categories</th><th>Tested</th><th>Coverage</th></tr>
    <tr><td>OWASP API Top 10 (2023)</td><td>10</td><td>10</td><td>100%</td></tr>
    <tr><td>OWASP Web Top 10 (2021)</td><td>10</td><td>10</td><td>100%</td></tr>
    <tr><td>OWASP Secure Coding v2</td><td>13</td><td>13</td><td>100%</td></tr>
  </table>

  <h2>Domain Coverage</h2>
  <table>
    <tr><th>#</th><th>Domain</th><th>Tests</th><th>Status</th></tr>
    <tr><td>1</td><td>Identity, Authentication & Session</td><td>79</td><td>TESTED</td></tr>
    <tr><td>2</td><td>Record & Tenant Access (BOLA)</td><td>22</td><td>TESTED</td></tr>
    <tr><td>3</td><td>Privilege & Function Boundaries (BFLA)</td><td>35</td><td>TESTED</td></tr>
    <tr><td>4</td><td>Field, Property & Payload Authorisation</td><td>34</td><td>TESTED</td></tr>
    <tr><td>5</td><td>Input, Parser & Query Safety</td><td>115</td><td>TESTED</td></tr>
    <tr><td>6</td><td>Data Exposure, Privacy & Cryptography</td><td>21</td><td>TESTED</td></tr>
    <tr><td>7</td><td>Guest, File & Public Surface Security</td><td>24</td><td>TESTED</td></tr>
    <tr><td>8</td><td>Integration & Trust Boundary Security</td><td>47</td><td>TESTED</td></tr>
    <tr><td>9</td><td>Abuse Resistance, Logging & Monitoring</td><td>15</td><td>TESTED</td></tr>
    <tr><td>10</td><td>Business Logic & Transaction Integrity</td><td>20</td><td>TESTED</td></tr>
    <tr><td>11</td><td>Configuration, Inventory & Engineering Assurance</td><td>64</td><td>TESTED</td></tr>
    <tr><td>12</td><td>Client, Platform & General API Assurance</td><td>7</td><td>TESTED</td></tr>
  </table>

  <h2>Findings</h2>

  <div class="finding">
    <div class="finding-header">
      <h3>FIND-2026-001: Cross-Tenant SOQL Injection</h3>
      <div><span class="severity-critical">Critical</span> &nbsp; <span class="badge badge-failed">FAILED</span> <span class="badge badge-confirmed">CONFIRMED</span></div>
    </div>
    <p style="margin:8px 0;font-size:13px"><strong>Test:</strong> API-BOLA-004 &bull; <strong>OWASP:</strong> API1:2023 &bull; <strong>Endpoint:</strong> GET /services/data/v58.0/query/</p>
    <p style="font-size:13px">SOQL query parameter accepts WHERE clause manipulation enabling cross-tenant record access. Tenant A user retrieved Tenant B Case data.</p>
    <div class="evidence-toggle" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='block'?'none':'block'">Show Evidence</div>
    <div class="evidence-content">GET /services/data/v58.0/query/?q=SELECT Id,Subject,Description FROM Case WHERE Id='5003t000009XyZaBCD'
Authorization: Bearer [REDACTED]
X-SecTest-Case-ID: API-BOLA-004

Response: 200 OK
{"totalSize":1,"records":[{"Id":"5003t000009XyZaBCD","Subject":"Tenant B - Confidential Claim"}]}</div>
  </div>

  <div class="finding">
    <div class="finding-header">
      <h3>FIND-2026-002: Unicode Normalisation Bypass</h3>
      <div><span class="severity-high">High</span> &nbsp; <span class="badge badge-failed">FAILED</span> <span class="badge badge-confirmed">CONFIRMED</span></div>
    </div>
    <p style="margin:8px 0;font-size:13px"><strong>Test:</strong> API-INPUT-014 &bull; <strong>OWASP:</strong> API3:2023 &bull; <strong>Endpoint:</strong> GET /services/data/v58.0/query/</p>
    <p style="font-size:13px">Unicode homoglyph characters bypass string-based access controls in SOQL WHERE clauses. Server does not normalise input before processing.</p>
  </div>

  <div class="finding">
    <div class="finding-header">
      <h3>FIND-2026-003: Mass Assignment of System Fields</h3>
      <div><span class="severity-high">High</span> &nbsp; <span class="badge badge-failed">FAILED</span> <span class="badge badge-confirmed">CONFIRMED</span></div>
    </div>
    <p style="margin:8px 0;font-size:13px"><strong>Test:</strong> API-PROP-015 &bull; <strong>OWASP:</strong> API3:2023 &bull; <strong>Endpoint:</strong> PATCH /sobjects/Case/{id}</p>
    <p style="font-size:13px">LastModifiedById field accepted via JSON body update, enabling audit trail manipulation. System fields should be read-only.</p>
  </div>

  <div class="finding">
    <div class="finding-header">
      <h3>FIND-2026-004: Verbose Error Exposure</h3>
      <div><span class="severity-medium">Medium</span> &nbsp; <span class="badge badge-failed">FAILED</span> <span class="badge badge-potential">POTENTIAL</span></div>
    </div>
    <p style="margin:8px 0;font-size:13px"><strong>Test:</strong> API-DATA-008 &bull; <strong>OWASP:</strong> API8:2023 &bull; <strong>Endpoint:</strong> POST /sobjects/Case/</p>
    <p style="font-size:13px">Error responses include internal stack traces and trigger line numbers, exposing code structure to attackers.</p>
  </div>

  <h2>Discovered Workflows</h2>
  <div style="display:flex;align-items:center;gap:12px;margin:12px 0;font-size:13px">
    <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:8px 12px">Step 1<br><small>Case Details</small></div>
    <span style="color:#58a6ff">&rarr;</span>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:8px 12px">Step 2<br><small>Related Account</small></div>
    <span style="color:#58a6ff">&rarr;</span>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:8px 12px">Step 3<br><small>Submit Case</small></div>
  </div>
  <p style="font-size:12px;color:#8b949e">API6-002 (Step Skipping): <span style="color:#f85149">FAILED</span> — Step 3 accessible without completing Steps 1-2</p>

</div>
<footer>SF API Security Tester V4.0 &bull; DEMO MODE — SAMPLE DATA &bull; """ + NOW[:10] + """</footer>
</body>
</html>"""
        path = self.output_dir / "reports" / "security_report.html"
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(f"Generated sample HTML report: {path}")
        return [str(path)]
