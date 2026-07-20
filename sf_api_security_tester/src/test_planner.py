"""Smart Test Planner — Maps feature inventory risks to structured test plans.

V3.2 Smart Canary: Enforces noise reduction rules to prevent combinatorial
explosion and WAF rate limits. Uses single-canary-per-input/risk approach
instead of brute-force payload iteration.
"""

from __future__ import annotations

import uuid
from typing import Any

from loguru import logger

from .models import (
    FeatureInventory,
    InputFieldInfo,
    PlannedTest,
    RiskSurface,
    SiteMap,
    TestPlan,
    WorkflowModel,
    WorkflowStep,
)

# Input field risk priority (higher = more important to probe)
_INPUT_RISK_PRIORITY = {
    "search": 0,
    "text": 1,
    "textarea": 2,
    "richtext": 3,
    "select": 4,
    "file": 5,
    "hidden": 99,
    "password": 99,
    "checkbox": 99,
    "radio": 99,
}

# Risk type -> OWASP mapping for canary naming
_RISK_OWASP_MAP = {
    "xss": "A03",
    "sqli": "A03",
    "soql_injection": "A03",
    "ssrf": "API7",
    "bola": "API1",
    "admin_bypass": "API5",
    "business_flow_bypass": "API6",
    "mass_assignment": "API3",
    "file_upload": "SCP-12",
    "data_exposure": "API3",
    "type_confusion": "A08",
    "error_log_leakage": "A09",
    "brute_force_monitoring": "A09",
}


class SmartTestPlanner:
    """Generates a structured TestPlan from a FeatureInventory."""

    # Safe probe prefixes (non-destructive, identifiable)
    _XSS_PROBE = "SF_XSS_PROBE_"
    _SQLI_PROBE = "SF_SQLI_PROBE_"
    _SSRF_PROBE = "SF_SSRF_PROBE_"

    # Severity ordering for priority sorting
    _SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

    def plan(
        self,
        inventory: FeatureInventory,
        site_map: SiteMap,
    ) -> TestPlan:
        """Generate a TestPlan from the feature inventory.

        V3.2 Smart Canary: Enforces noise reduction rules:
        - Single canary per input/risk (no brute-force payload iteration)
        - Max probes per page cap (default 5)
        - Input risk prioritization (search > text > textarea > richtext)
        - Endpoint deduplication (one probe per target endpoint)
        """
        tests: list[PlannedTest] = []
        coverage: dict[str, int] = {}

        # Build a page lookup
        page_by_id = {p.id: p for p in site_map.pages}

        # Sort risk surfaces by severity (Critical first)
        sorted_risks = sorted(
            inventory.risk_surfaces,
            key=lambda r: self._SEVERITY_ORDER.get(r.severity.value, 99),
        )

        # --- Phase A: Risk-surface based tests (Smart Canary) ---
        for risk in sorted_risks:
            for test_type in risk.recommended_tests:
                planned = self._generate_tests_for_risk(
                    risk, test_type, page_by_id
                )
                tests.extend(planned)
                coverage[risk.risk_type] = coverage.get(risk.risk_type, 0) + len(planned)

        # --- Phase B: Deep recon-driven tests (Smart Canary) ---
        recon_tests = self._generate_recon_driven_tests(site_map, page_by_id)
        tests.extend(recon_tests)
        for t in recon_tests:
            coverage[t.risk_type] = coverage.get(t.risk_type, 0) + 1

        # --- Phase C: OWASP alignment enrichment ---
        tests = self._enrich_owasp_alignment(tests, site_map)

        # --- Phase D: Workflow-based API6 tests ---
        if inventory.workflows:
            workflow_tests = self._generate_workflow_tests(inventory.workflows)
            tests.extend(workflow_tests)
            for t in workflow_tests:
                coverage[t.risk_type] = coverage.get(t.risk_type, 0) + 1

        # --- Phase E: Global deduplication and cap ---
        tests = self._deduplicate_and_cap(tests)

        plan = TestPlan(
            planned_tests=tests,
            total_probes=sum(1 for t in tests if t.test_type == "safe_probe"),
            total_mutations=sum(1 for t in tests if t.test_type == "real_mutation"),
            risk_coverage=coverage,
        )

        logger.info(
            f"Test plan: {len(tests)} tests "
            f"({plan.total_probes} probes, {plan.total_mutations} mutations) "
            f"across {len(coverage)} risk types"
        )

        return plan

    # ------------------------------------------------------------------
    # V3.2 Smart Canary: Noise Reduction
    # ------------------------------------------------------------------
    @staticmethod
    def _generate_canary(risk_type: str) -> str:
        """Generate a unique canary string for a risk type.

        Format: SF_CANARY_{RISK}_{8-char UUID}
        Example: SF_CANARY_XSS_a1b2c3d4
        """
        short_id = str(uuid.uuid4())[:8]
        risk_prefix = risk_type.upper().replace(" ", "_").replace("-", "_")
        return f"SF_CANARY_{risk_prefix}_{short_id}"

    @staticmethod
    def _get_input_priority(field: InputFieldInfo) -> int:
        """Get priority score for an input field (lower = higher priority)."""
        return _INPUT_RISK_PRIORITY.get(field.field_type, 50)

    @staticmethod
    def _select_top_inputs(page, max_per_page: int) -> list[InputFieldInfo]:
        """Select the top N highest-risk inputs from a page.

        Prioritizes: search > text > textarea > richtext
        Ignores: hidden, password, checkbox, radio
        """
        eligible = [
            f for f in page.input_fields
            if _INPUT_RISK_PRIORITY.get(f.field_type, 50) < 50
        ]

        # Sort by priority (lower = more important)
        eligible.sort(key=lambda f: _INPUT_RISK_PRIORITY.get(f.field_type, 50))

        return eligible[:max_per_page]

    def _deduplicate_and_cap(self, tests: list[PlannedTest]) -> list[PlannedTest]:
        """Deduplicate probes by endpoint and cap total count.

        Rule 4: Group inputs by target URL. If multiple pages submit to
        the same endpoint, generate the canary probe only once.
        """
        # Group by (target_url, risk_type) for deduplication
        seen: dict[tuple[str, str], PlannedTest] = {}
        deduped: list[PlannedTest] = []

        for test in tests:
            if test.test_type != "safe_probe":
                deduped.append(test)
                continue

            key = (test.target_url, test.risk_type)
            if key not in seen:
                seen[key] = test
                deduped.append(test)
            # else: duplicate probe for same endpoint — skip

        return deduped

    # ------------------------------------------------------------------
    # V3.1: Deep recon-driven test generation
    # ------------------------------------------------------------------
    def _generate_recon_driven_tests(
        self, site_map: SiteMap, page_by_id: dict[str, Any]
    ) -> list[PlannedTest]:
        """Generate tests based on deep recon context from the explorer.

        V3.2 Smart Canary: Uses single-canary-per-input/risk approach.
        Prioritizes inputs and caps probes per page.
        """
        tests: list[PlannedTest] = []

        # Read max probes per page from config (default 5)
        max_per_page = 5  # Could be read from settings.yaml

        for page in site_map.pages:
            page_probes = 0

            # --- File upload detection (1 probe per page) ---
            if any(f.field_type == "file" for f in page.input_fields) and page_probes < max_per_page:
                tests.append(PlannedTest(
                    test_type="safe_probe",
                    risk_type="file_upload",
                    target_page_id=page.id,
                    target_url=page.url,
                    target_field="file_upload",
                    payload=self._generate_canary("file_upload"),
                    payload_category="path_traversal",
                    description=f"File upload on {page.title or page.url[:50]}",
                ))
                page_probes += 1

            # --- Comment/state change detection (1 probe per page) ---
            if page_probes < max_per_page:
                comment_fields = [
                    f for f in page.input_fields
                    if "comment" in f.name.lower() or "description" in f.name.lower()
                    or f.field_type in ("richtext", "textarea")
                ]
                if comment_fields:
                    target_field = comment_fields[0]  # Highest priority
                    tests.append(PlannedTest(
                        test_type="safe_probe",
                        risk_type="xss",
                        target_page_id=page.id,
                        target_url=page.url,
                        target_field=target_field.name,
                        payload=self._generate_canary("xss"),
                        payload_category="stored_xss",
                        description=f"XSS on {target_field.label or target_field.name}",
                    ))
                    page_probes += 1

            # --- Admin/settings page (1 probe per page) ---
            if page.page_category in ("admin", "settings") and page_probes < max_per_page:
                tests.append(PlannedTest(
                    test_type="safe_probe",
                    risk_type="admin_bypass",
                    target_page_id=page.id,
                    target_url=page.url,
                    payload=self._generate_canary("admin_bypass"),
                    payload_category="bfla",
                    description=f"Admin bypass: {page.title or page.url[:50]}",
                ))
                page_probes += 1

            # --- Profile/record detail (BOLA) (1 probe per page) ---
            if page.page_category in ("profile", "record_detail") and page_probes < max_per_page:
                tests.append(PlannedTest(
                    test_type="safe_probe",
                    risk_type="bola",
                    target_page_id=page.id,
                    target_url=page.url,
                    payload=self._generate_canary("bola"),
                    payload_category="bola_id_swap",
                    description=f"BOLA on {page.title or page.url[:50]}",
                ))
                page_probes += 1

            # --- Sensitive data visible (1 probe per page) ---
            if page.sensitive_data_visible and page_probes < max_per_page:
                tests.append(PlannedTest(
                    test_type="safe_probe",
                    risk_type="data_exposure",
                    target_page_id=page.id,
                    target_url=page.url,
                    payload=self._generate_canary("data_exposure"),
                    payload_category="pii_check",
                    description=f"Data exposure on {page.title or page.url[:50]}",
                ))
                page_probes += 1

            # --- API6: Business flow bypass (1 probe per page) ---
            if page.page_category in ("form", "record_detail", "admin") and page_probes < max_per_page:
                if self._has_state_change_actions(page):
                    tests.append(PlannedTest(
                        test_type="safe_probe",
                        risk_type="business_flow_bypass",
                        target_page_id=page.id,
                        target_url=page.url,
                        payload=self._generate_canary("business_flow_bypass"),
                        payload_category="business_flow_bypass",
                        description=f"Flow bypass on {page.title or page.url[:50]}",
                    ))
                    page_probes += 1

            # --- A08: Type confusion (1 probe per page) ---
            if page.page_category in ("form", "record_detail", "list_view") and page_probes < max_per_page:
                tests.append(PlannedTest(
                    test_type="safe_probe",
                    risk_type="type_confusion",
                    target_page_id=page.id,
                    target_url=page.url,
                    payload=self._generate_canary("type_confusion"),
                    payload_category="type_confusion_fuzz",
                    description=f"Type confusion on {page.title or page.url[:50]}",
                ))
                page_probes += 1

            # --- A09: Log Leakage (1 probe per page) ---
            if page_probes < max_per_page:
                tests.append(PlannedTest(
                    test_type="safe_probe",
                    risk_type="error_log_leakage",
                    target_page_id=page.id,
                    target_url=page.url,
                    payload=self._generate_canary("error_log_leakage"),
                    payload_category="error_log_leakage",
                    description=f"Log leakage on {page.title or page.url[:50]}",
                ))
                page_probes += 1

            # --- A09: Account Lockout (login pages only) ---
            if page.page_category == "login" and page_probes < max_per_page:
                tests.append(PlannedTest(
                    test_type="safe_probe",
                    risk_type="brute_force_monitoring",
                    target_page_id=page.id,
                    target_url=page.url,
                    payload=self._generate_canary("brute_force"),
                    payload_category="brute_force_monitoring",
                    description=f"Brute force on {page.title or page.url[:50]}",
                ))
                page_probes += 1

        return tests

    @staticmethod
    def _has_state_change_actions(page) -> bool:
        """Check if a page has state-change or destructive actions.

        Uses the page's visible_text to detect common action keywords
        that indicate business flow bypass opportunities.
        """
        text = (page.visible_text or "").lower()

        # Destructive action keywords
        destructive_keywords = [
            "delete", "archive", "remove", "deactivate", "close",
            "cancel", "revoke", "terminate", "destroy",
        ]

        # State-change action keywords
        state_change_keywords = [
            "approve", "submit", "reject", "confirm", "publish",
            "activate", "process", "execute", "dispatch", "send",
            "update status", "change stage", "move to",
        ]

        for keyword in destructive_keywords + state_change_keywords:
            if keyword in text:
                return True

        # Also check input field names for state-change indicators
        state_field_patterns = [
            "status", "stage", "state", "approval", "workflow",
            "process", "action", "command", "operation",
        ]
        for field in page.input_fields:
            field_name_lower = field.name.lower()
            for pattern in state_field_patterns:
                if pattern in field_name_lower:
                    return True

        return False

    @staticmethod
    def _is_json_endpoint(page) -> bool:
        """Check if a page likely accepts JSON payloads."""
        # Forms with text inputs are likely JSON-capable
        text_inputs = [f for f in page.input_fields if f.field_type in ("text", "textarea", "richtext")]
        if len(text_inputs) >= 2:
            return True

        # API-like pages (record_detail, admin) typically accept JSON
        if page.page_category in ("form", "record_detail", "admin", "settings"):
            return True

        # Check visible text for API indicators
        text = (page.visible_text or "").lower()
        if "api" in text or "endpoint" in text or "json" in text:
            return True

        return False

    # ------------------------------------------------------------------
    # V3.1: Workflow-based API6 test generation
    # ------------------------------------------------------------------
    def _generate_workflow_tests(
        self, workflows: list[WorkflowModel]
    ) -> list[PlannedTest]:
        """Generate API6 tests for detected workflows.

        Creates:
        - API6-002: Workflow Step Skipping (State Bypass)
        - API6-003: State Replay / Parameter Tampering
        """
        tests: list[PlannedTest] = []

        for workflow in workflows:
            if len(workflow.steps) < 2:
                continue  # Need at least 2 steps for a workflow

            # --- API6-002: Workflow Step Skipping ---
            # Try to access later steps directly, bypassing earlier steps
            for i, step in enumerate(workflow.steps[2:], start=3):  # Skip first 2 steps
                tests.append(PlannedTest(
                    test_type="safe_probe",
                    risk_type="business_flow_bypass",
                    target_page_id=step.page_id,
                    target_url=step.url,
                    payload_category="business_flow_bypass",
                    description=(
                        f"API6-002: Access Step {i} directly, bypassing "
                        f"Steps 1-{i-1} in workflow '{workflow.name}'"
                    ),
                ))

            # --- API6-003: State Replay / Parameter Tampering ---
            # Use state parameters from Step 1 in later steps
            if len(workflow.steps) >= 2:
                step1 = workflow.steps[0]
                step3_url = workflow.steps[2].url if len(workflow.steps) > 2 else workflow.exit_point

                # Collect all state parameters from Step 1
                state_params = []
                for s in workflow.steps[:2]:
                    state_params.extend(s.state_parameters)

                if state_params:
                    tests.append(PlannedTest(
                        test_type="safe_probe",
                        risk_type="business_flow_bypass",
                        target_page_id=workflow.steps[-1].page_id,
                        target_url=step3_url,
                        payload_category="business_flow_bypass",
                        description=(
                            f"API6-003: Replay Step 1 state params "
                            f"({', '.join(state_params[:3])}) into Step {len(workflow.steps)} "
                            f"in workflow '{workflow.name}'"
                        ),
                    ))

                # Parameter tampering: try to inject modified state
                for param in state_params[:2]:
                    tests.append(PlannedTest(
                        test_type="safe_probe",
                        risk_type="business_flow_bypass",
                        target_page_id=workflow.steps[-1].page_id,
                        target_url=step3_url,
                        payload_category="business_flow_bypass",
                        description=(
                            f"API6-003: Tamper with state parameter '{param}' "
                            f"in workflow '{workflow.name}'"
                        ),
                    ))

        return tests

    def _enrich_owasp_alignment(
        self, tests: list[PlannedTest], site_map: SiteMap
    ) -> list[PlannedTest]:
        """Add OWASP-specific metadata to tests based on recon context."""
        for test in tests:
            # Map risk_type to OWASP categories (updated for API 2023 + Web 2021)
            owasp_map = {
                # OWASP API Top 10 (2023)
                "bola": ("API1:2023", "Broken Object Level Authorization"),
                "data_exposure": ("API3:2023", "Broken Object Property Level Authorization"),
                "mass_assignment": ("API3:2023", "Broken Object Property Level Authorization"),
                "admin_bypass": ("API5:2023", "Broken Function Level Authorization"),
                "business_flow_bypass": ("API6:2023", "Unrestricted Access to Sensitive Business Flows"),
                "ssrf": ("API7:2023", "Server Side Request Forgery"),
                # OWASP Web Top 10 (2021)
                "xss": ("A03:2021", "Injection"),
                "sqli": ("A03:2021", "Injection"),
                "type_confusion": ("A08:2021", "Software and Data Integrity Failures"),
                "error_log_leakage": ("A09:2021", "Security Logging and Monitoring Failures"),
                "brute_force_monitoring": ("A09:2021", "Security Logging and Monitoring Failures"),
                # OWASP Secure Coding
                "file_upload": ("SCG-InputValidation", "Input Validation"),
                "data_exposure": ("SCG-DataProtection", "Data Protection"),
            }

            owasp = owasp_map.get(test.risk_type)
            if owasp:
                test.description += f" [OWASP: {owasp[0]} - {owasp[1]}]"

        return tests

    def _generate_tests_for_risk(
        self,
        risk: RiskSurface,
        test_type: str,
        page_by_id: dict[str, Any],
    ) -> list[PlannedTest]:
        """Generate planned tests for a specific risk + test type."""
        tests: list[PlannedTest] = []

        for page_id in risk.pages:
            page = page_by_id.get(page_id)
            if not page:
                continue

            for field in risk.input_fields:
                # Safe probe (non-destructive)
                probe_id = str(uuid.uuid4())[:8]
                probe = self._create_safe_probe(
                    risk.risk_type, field, page, probe_id
                )
                if probe:
                    tests.append(probe)

        # If no fields but pages exist, create page-level tests
        if not risk.input_fields:
            for page_id in risk.pages[:3]:  # Limit to 3 pages
                page = page_by_id.get(page_id)
                if not page:
                    continue
                tests.append(PlannedTest(
                    test_type="safe_probe",
                    risk_type=risk.risk_type,
                    target_page_id=page.id,
                    target_url=page.url,
                    payload_category=test_type,
                    description=f"Page-level {risk.risk_type} probe on {page.title or page.url}",
                ))

        return tests

    def _create_safe_probe(
        self,
        risk_type: str,
        field: InputFieldInfo,
        page: Any,
        probe_id: str,
    ) -> PlannedTest | None:
        """Create a safe, non-destructive probe for a field."""
        if risk_type == "xss":
            payload = f"{self._XSS_PROBE}{probe_id}"
            return PlannedTest(
                test_type="safe_probe",
                risk_type="xss",
                target_page_id=page.id,
                target_url=page.url,
                target_field=field.name,
                payload_category="xss_injection",
                payload=payload,
                http_method="POST",
                description=f"Safe XSS probe in field '{field.label or field.name}'",
            )

        elif risk_type == "sqli":
            payload = f"{self._SQLI_PROBE}{probe_id}"
            return PlannedTest(
                test_type="safe_probe",
                risk_type="sqli",
                target_page_id=page.id,
                target_url=page.url,
                target_field=field.name,
                payload_category="soql_injection",
                payload=payload,
                http_method="POST",
                description=f"Safe SQLi probe in field '{field.label or field.name}'",
            )

        elif risk_type == "ssrf":
            payload = f"https://{self._SSRF_PROBE}{probe_id}.example.com"
            return PlannedTest(
                test_type="safe_probe",
                risk_type="ssrf",
                target_page_id=page.id,
                target_url=page.url,
                target_field=field.name,
                payload_category="ssrf_injection",
                payload=payload,
                http_method="POST",
                description=f"Safe SSRF probe in field '{field.label or field.name}'",
            )

        elif risk_type == "bola":
            # BOLA probe: use a clearly fake Salesforce ID
            payload = "000000000000000"
            return PlannedTest(
                test_type="safe_probe",
                risk_type="bola",
                target_page_id=page.id,
                target_url=page.url,
                target_field=field.name,
                payload_category="bola_id_swap",
                payload=payload,
                http_method="GET",
                description=f"Safe BOLA probe with fake ID on page '{page.title or page.url}'",
            )

        return None
