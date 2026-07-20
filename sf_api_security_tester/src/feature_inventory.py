"""Feature Inventory — Aggregates exploration results into a risk surface.

Phase 0.5 of V3.0: Takes the SiteMap from AutonomousExplorer and builds
a structured inventory of pages, input fields, and risk surfaces.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from loguru import logger

from .models import (
    FeatureInventory,
    InputFieldInfo,
    PageSnapshot,
    RiskSurface,
    Severity,
    SiteMap,
)


class FeatureInventoryBuilder:
    """Builds a FeatureInventory from a SiteMap."""

    def build(self, site_map: SiteMap) -> FeatureInventory:
        """Aggregate SiteMap pages into a risk-oriented FeatureInventory."""
        pages_by_category: dict[str, list[str]] = defaultdict(list)
        all_input_fields: list[InputFieldInfo] = []
        risk_surfaces: list[RiskSurface] = []

        # Group pages by category
        for page in site_map.pages:
            cat = page.page_category or "other"
            pages_by_category[cat].append(page.id)
            all_input_fields.extend(page.input_fields)

        # Identify risk surfaces
        risk_surfaces = self._identify_risks(site_map, all_input_fields)

        high = sum(1 for r in risk_surfaces if r.severity == Severity.HIGH)
        med = sum(1 for r in risk_surfaces if r.severity == Severity.MEDIUM)
        low = sum(1 for r in risk_surfaces if r.severity == Severity.LOW)

        inventory = FeatureInventory(
            pages_by_category=dict(pages_by_category),
            all_input_fields=all_input_fields,
            risk_surfaces=risk_surfaces,
            total_risks=len(risk_surfaces),
            high_risk_count=high,
            medium_risk_count=med,
            low_risk_count=low,
        )

        logger.info(
            f"Feature inventory: {len(site_map.pages)} pages, "
            f"{len(all_input_fields)} input fields, "
            f"{len(risk_surfaces)} risk surfaces "
            f"({high} high, {med} medium, {low} low)"
        )

        return inventory

    def _identify_risks(
        self, site_map: SiteMap, all_fields: list[InputFieldInfo]
    ) -> list[RiskSurface]:
        """Identify risk surfaces from pages and input fields."""
        risks: list[RiskSurface] = []

        # Risk type -> page IDs + fields
        risk_map: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"pages": set(), "fields": [], "tests": []}
        )

        for page in site_map.pages:
            for field in page.input_fields:
                rt = field.risk_type
                if rt == "none":
                    continue

                risk_map[rt]["pages"].add(page.id)
                risk_map[rt]["fields"].append(field)

                # Map risk type to recommended tests
                if rt == "xss" and field.field_type in ("text", "textarea", "richtext"):
                    if "stored_xss" not in risk_map[rt]["tests"]:
                        risk_map[rt]["tests"].append("stored_xss")
                    if "xss_injection" not in risk_map[rt]["tests"]:
                        risk_map[rt]["tests"].append("xss_injection")
                elif rt == "sqli":
                    if "soql_injection" not in risk_map[rt]["tests"]:
                        risk_map[rt]["tests"].append("soql_injection")
                    if "sosl_injection" not in risk_map[rt]["tests"]:
                        risk_map[rt]["tests"].append("sosl_injection")
                elif rt == "ssrf":
                    if "ssrf_injection" not in risk_map[rt]["tests"]:
                        risk_map[rt]["tests"].append("ssrf_injection")
                    if field.field_type == "file":
                        if "path_traversal" not in risk_map[rt]["tests"]:
                            risk_map[rt]["tests"].append("path_traversal")

        # Admin/settings pages get privilege escalation risks
        admin_pages = [
            p for p in site_map.pages
            if p.page_category in ("admin", "settings")
        ]
        if admin_pages:
            risk_map["admin_bypass"]["pages"].update(p.id for p in admin_pages)
            risk_map["admin_bypass"]["tests"].extend([
                "bfla", "method_override", "mass_assignment"
            ])

        # Sensitive data pages get BOLA/IDOR risks
        sensitive_pages = [p for p in site_map.pages if p.sensitive_data_visible]
        if sensitive_pages:
            risk_map["bola"]["pages"].update(p.id for p in sensitive_pages)
            risk_map["bola"]["tests"].extend([
                "bola_id_swap", "bola_query_swap"
            ])

        # Build RiskSurface objects
        severity_map = {
            "xss": Severity.HIGH,
            "sqli": Severity.CRITICAL,
            "ssrf": Severity.HIGH,
            "bola": Severity.CRITICAL,
            "admin_bypass": Severity.HIGH,
            "mass_assignment": Severity.MEDIUM,
            "file_upload": Severity.MEDIUM,
        }

        for risk_type, data in risk_map.items():
            if not data["pages"]:
                continue
            risks.append(RiskSurface(
                risk_type=risk_type,
                pages=list(data["pages"]),
                input_fields=data["fields"],
                recommended_tests=list(set(data["tests"])),
                severity=severity_map.get(risk_type, Severity.MEDIUM),
            ))

        return risks
