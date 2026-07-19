"""Loads YAML test case definitions and determines applicability per endpoint."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from loguru import logger

from .endpoint_classifier import EndpointClassifier
from .models import (
    APIEndpoint,
    EndpointCategory,
    FindingVerdict,
    Severity,
    TestCase,
)


class TestCase:
    """Parsed test case from YAML definition."""

    def __init__(self, raw: dict[str, Any]):
        self.id: str = raw.get("id", "")
        self.name: str = raw.get("name", "")
        self.owasp_mapping: dict[str, str] = raw.get("owasp_mapping", {})
        self.applicable_categories: list[str] = raw.get("applicable_categories", [])
        self.severity: str = raw.get("severity", "Medium")
        self.mutation_type: str = raw.get("mutation_type", "")
        self.payloads: dict[str, Any] = raw.get("payloads", {})
        self.expected_secure_behavior: str = raw.get("expected_secure_behavior", "")
        self.finding_criteria: dict[str, Any] = raw.get("finding_criteria", {})
        self._raw = raw

    @property
    def owasp_category(self) -> str:
        return self.owasp_mapping.get("category", "Unknown")

    @property
    def owasp_name(self) -> str:
        return self.owasp_mapping.get("name", "Unknown")

    def is_applicable_to(self, endpoint: APIEndpoint) -> bool:
        """Check if this test case applies to the given endpoint."""
        if not self.applicable_categories:
            return True

        endpoint_cat_values = {c.value for c in endpoint.categories}
        return bool(set(self.applicable_categories).intersection(endpoint_cat_values))

    def __repr__(self) -> str:
        return f"TestCase({self.id}: {self.name})"


class TestCaseEngine:
    """Loads test cases and filters them for each endpoint."""

    def __init__(self, test_case_dir: str | Path):
        self.test_case_dir = Path(test_case_dir)
        self.all_test_cases: list[TestCase] = []
        self.classifier = EndpointClassifier()

    def load_all(self) -> list[TestCase]:
        """Load all test cases from YAML files in the test case directory."""
        if not self.test_case_dir.exists():
            logger.error(f"Test case directory not found: {self.test_case_dir}")
            return []

        yaml_files = list(self.test_case_dir.glob("*.yaml"))
        logger.info(f"Found {len(yaml_files)} test case files")

        for yaml_file in yaml_files:
            cases = self._load_file(yaml_file)
            self.all_test_cases.extend(cases)

        logger.info(f"Loaded {len(self.all_test_cases)} total test cases")
        return self.all_test_cases

    def _load_file(self, file_path: Path) -> list[TestCase]:
        """Load test cases from a single YAML file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.error(f"YAML parse error in {file_path.name}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error loading {file_path.name}: {e}")
            return []

        test_cases_raw = data.get("test_cases", [])
        cases = []
        for tc_raw in test_cases_raw:
            try:
                case = TestCase(tc_raw)
                cases.append(case)
            except Exception as e:
                logger.warning(f"Failed to parse test case: {e}")

        logger.info(f"Loaded {len(cases)} test cases from {file_path.name}")
        return cases

    def build_execution_plan(
        self, endpoints: list[APIEndpoint]
    ) -> list[tuple[APIEndpoint, TestCase]]:
        """Build a list of (endpoint, test_case) pairs to execute."""
        plan: list[tuple[APIEndpoint, TestCase]] = []

        for endpoint in endpoints:
            for test_case in self.all_test_cases:
                if test_case.is_applicable_to(endpoint):
                    plan.append((endpoint, test_case))

        logger.info(
            f"Execution plan: {len(plan)} test-executions across "
            f"{len(endpoints)} endpoints and {len(self.all_test_cases)} test cases"
        )

        # Count N/A tests
        total_possible = len(endpoints) * len(self.all_test_cases)
        na_count = total_possible - len(plan)
        if na_count > 0:
            logger.info(f"Filtered out {na_count} N/A (non-applicable) combinations")

        return plan

    def get_test_case_by_id(self, test_id: str) -> TestCase | None:
        """Look up a test case by its ID."""
        for tc in self.all_test_cases:
            if tc.id == test_id:
                return tc
        return None
