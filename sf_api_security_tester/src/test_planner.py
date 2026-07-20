"""Smart Test Planner — Maps feature inventory risks to structured test plans.

Phase 0.5 of V3.0: Takes the FeatureInventory and generates a TestPlan
with safe probes and real mutation strategies for each risk surface.
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
)


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
        """Generate a TestPlan from the feature inventory, sorted by risk severity."""
        tests: list[PlannedTest] = []
        coverage: dict[str, int] = {}

        # Build a page lookup
        page_by_id = {p.id: p for p in site_map.pages}

        # Sort risk surfaces by severity (Critical first)
        sorted_risks = sorted(
            inventory.risk_surfaces,
            key=lambda r: self._SEVERITY_ORDER.get(r.severity.value, 99),
        )

        for risk in sorted_risks:
            for test_type in risk.recommended_tests:
                planned = self._generate_tests_for_risk(
                    risk, test_type, page_by_id
                )
                tests.extend(planned)
                coverage[risk.risk_type] = coverage.get(risk.risk_type, 0) + len(planned)

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
