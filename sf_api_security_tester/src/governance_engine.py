"""Governance Engine — Strict enforcement of workbook schema.

V4.0: Evaluates every test before execution against the workbook's
applicability rules, dependency gates, exclusion evidence, and
mandatory evidence capture requirements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from loguru import logger

from .models import FindingVerdict, PlannedTest


@dataclass
class GovernanceResult:
    """Result of governance evaluation for a single test."""
    test_id: str
    status: str  # "APPLICABLE" | "NOT_APPLICABLE" | "BLOCKED" | "NEEDS_APPROVAL"
    reason: str = ""
    missing_signals: list[str] = field(default_factory=list)
    exclusion_found: str = ""
    blocked_by: list[str] = field(default_factory=list)
    evidence_checklist: dict[str, str] = field(default_factory=dict)  # evidence_type -> "captured" | "missing"


class GovernanceEngine:
    """Strict enforcement engine for workbook schema compliance.

    Evaluates every test before execution against:
    - required_signals (applicability)
    - exclusion_evidence (skip conditions)
    - blocking dependencies (circuit breaker)
    - evidence_required (mandatory capture)
    - state_changing / requires_human_approval (safety gates)
    """

    def __init__(self, config: dict[str, Any]):
        gov_cfg = config.get("governance", {})
        self.enabled: bool = gov_cfg.get("enabled", True)
        self.strict_mode: bool = gov_cfg.get("strict_mode", True)

    def evaluate_test(
        self,
        test_id: str,
        test_config: dict[str, Any],
        feature_signals: set[str],
        exclusion_evidence: set[str],
        dependency_statuses: dict[str, str],
    ) -> GovernanceResult:
        """Evaluate a single test against governance rules.

        Args:
            test_id: The test identifier.
            test_config: The workbook row for this test.
            feature_signals: Set of signals detected in the FeatureInventory.
            exclusion_evidence: Set of exclusion evidence found in HAR/exploration.
            dependency_statuses: Dict of test_id -> status for blocking dependencies.

        Returns:
            GovernanceResult with status and reason.
        """
        # --- Step 1: Signal Matching ---
        required_signals = test_config.get("required_signals", [])
        if required_signals:
            missing = [s for s in required_signals if s not in feature_signals]
            if missing:
                return GovernanceResult(
                    test_id=test_id,
                    status="NOT_APPLICABLE",
                    reason=f"Missing required signal: {', '.join(missing)}",
                    missing_signals=missing,
                )

        # --- Step 2: Exclusion Checking ---
        exclusions = test_config.get("exclusion_evidence", [])
        if exclusions:
            found_exclusions = [e for e in exclusions if e in exclusion_evidence]
            if found_exclusions:
                return GovernanceResult(
                    test_id=test_id,
                    status="NOT_APPLICABLE",
                    reason=f"Exclusion evidence found: {', '.join(found_exclusions)}",
                    exclusion_found=", ".join(found_exclusions),
                )

        # --- Step 3: Circuit Breaker (Dependencies) ---
        blocking_deps = test_config.get("blocking", [])
        if blocking_deps:
            failed_blocks = []
            for dep_id in blocking_deps:
                dep_status = dependency_statuses.get(dep_id, "UNKNOWN")
                if dep_status in ("FAILED", "BLOCKED", "ERROR"):
                    failed_blocks.append(dep_id)

            if failed_blocks:
                return GovernanceResult(
                    test_id=test_id,
                    status="BLOCKED",
                    reason=f"Invalidated by failed prerequisite: {', '.join(failed_blocks)}",
                    blocked_by=failed_blocks,
                )

        # --- Step 4: Check if test was previously blocked ---
        prev_status = dependency_statuses.get(test_id, "")
        if prev_status == "BLOCKED":
            return GovernanceResult(
                test_id=test_id,
                status="BLOCKED",
                reason=f"Previously blocked: {test_config.get('blocked_reason', 'dependency failure')}",
            )

        # --- Step 5: Human approval gate ---
        if test_config.get("requires_human_approval", False):
            return GovernanceResult(
                test_id=test_id,
                status="NEEDS_APPROVAL",
                reason="Test requires human approval before execution",
            )

        # --- All checks passed ---
        return GovernanceResult(
            test_id=test_id,
            status="APPLICABLE",
            reason="All governance checks passed",
        )

    def evaluate_evidence(
        self,
        test_id: str,
        evidence_required: list[str],
        captured_evidence: dict[str, str],
    ) -> tuple[bool, list[str]]:
        """Evaluate whether all required evidence was captured.

        Returns:
            (all_captured, list_of_missing_types)
        """
        missing = []
        for evidence_type in evidence_required:
            if evidence_type not in captured_evidence or not captured_evidence[evidence_type]:
                missing.append(evidence_type)

        return len(missing) == 0, missing

    def check_request_limit(
        self,
        test_id: str,
        request_count: int,
        maximum_requests: int,
    ) -> bool:
        """Check if a test has exceeded its request limit.

        Returns True if within limits, False if exceeded.
        """
        if maximum_requests and request_count >= maximum_requests:
            logger.warning(
                f"Test {test_id} hit maximum_requests limit "
                f"({request_count}/{maximum_requests})"
            )
            return False
        return True

    def build_governance_summary(
        self,
        results: list[GovernanceResult],
    ) -> dict[str, Any]:
        """Build a summary of governance decisions."""
        summary = {
            "total_evaluated": len(results),
            "applicable": sum(1 for r in results if r.status == "APPLICABLE"),
            "not_applicable": sum(1 for r in results if r.status == "NOT_APPLICABLE"),
            "blocked": sum(1 for r in results if r.status == "BLOCKED"),
            "needs_approval": sum(1 for r in results if r.status == "NEEDS_APPROVAL"),
        }

        # Group by reason
        reasons = {}
        for r in results:
            if r.status != "APPLICABLE":
                key = r.status
                if key not in reasons:
                    reasons[key] = []
                reasons[key].append({"test_id": r.test_id, "reason": r.reason})

        summary["details"] = reasons
        return summary
