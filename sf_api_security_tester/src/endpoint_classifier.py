"""Classifies API endpoints by risk category to determine applicable test cases."""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

from .models import APIEndpoint, EndpointCategory

# Path patterns that indicate specific categories
CATEGORY_PATTERNS: dict[EndpointCategory, list[re.Pattern]] = {
    EndpointCategory.AUTHENTICATION: [
        re.compile(r"/login", re.IGNORECASE),
        re.compile(r"/logout", re.IGNORECASE),
        re.compile(r"/token", re.IGNORECASE),
        re.compile(r"/oauth", re.IGNORECASE),
        re.compile(r"/auth", re.IGNORECASE),
        re.compile(r"/session", re.IGNORECASE),
        re.compile(r"/identity", re.IGNORECASE),
        re.compile(r"/s/login", re.IGNORECASE),
    ],
    EndpointCategory.ADMIN_OPERATIONS: [
        re.compile(r"/setup/", re.IGNORECASE),
        re.compile(r"/tooling/", re.IGNORECASE),
        re.compile(r"/metadata/", re.IGNORECASE),
        re.compile(r"/admin", re.IGNORECASE),
        re.compile(r"/deploy", re.IGNORECASE),
        re.compile(r"/apex/", re.IGNORECASE),
        re.compile(r"/aura.*setup", re.IGNORECASE),
        re.compile(r"/_ui/", re.IGNORECASE),
        re.compile(r"/async/", re.IGNORECASE),
    ],
    EndpointCategory.DATA_QUERY: [
        re.compile(r"/query", re.IGNORECASE),
        re.compile(r"/search", re.IGNORECASE),
        re.compile(r"/q=", re.IGNORECASE),
        re.compile(r"SELECT.*FROM", re.IGNORECASE),
    ],
    EndpointCategory.FILE_UPLOAD: [
        re.compile(r"/blob", re.IGNORECASE),
        re.compile(r"/document", re.IGNORECASE),
        re.compile(r"/attachment", re.IGNORECASE),
        re.compile(r"/content", re.IGNORECASE),
        re.compile(r"/upload", re.IGNORECASE),
        re.compile(r"/file", re.IGNORECASE),
        re.compile(r"/version", re.IGNORECASE),
    ],
    EndpointCategory.TENANT_ISOLATION: [
        re.compile(r"/tenant", re.IGNORECASE),
        re.compile(r"/community", re.IGNORECASE),
        re.compile(r"/partner", re.IGNORECASE),
        re.compile(r"/customer", re.IGNORECASE),
        re.compile(r"/s/", re.IGNORECASE),
    ],
}

# HTTP methods that indicate CRUD operations
CRUD_METHODS = {
    "POST": "create",
    "GET": "read",
    "PUT": "update",
    "PATCH": "patch",
    "DELETE": "delete",
}

# Admin-only HTTP methods (in certain contexts)
DANGEROUS_METHODS = {"DELETE", "PUT", "PATCH"}


class EndpointClassifier:
    """Classifies API endpoints into risk categories."""

    def __init__(self, cross_tenant_ids: dict[str, Any] | None = None):
        self.cross_tenant_ids = cross_tenant_ids or {}

    def classify(self, endpoint: APIEndpoint) -> list[EndpointCategory]:
        """Classify an endpoint into one or more risk categories."""
        categories: set[EndpointCategory] = set()

        # Check path patterns
        for category, patterns in CATEGORY_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(endpoint.path):
                    categories.add(category)
                    break

        # Check method-based classification
        categories.update(self._classify_by_method(endpoint))

        # Check query-based classification
        categories.update(self._classify_by_query(endpoint))

        # Check response body for sensitive data
        categories.update(self._classify_by_response(endpoint))

        # Default: if no specific category found, mark as user_data_crud
        if not categories:
            if endpoint.method.value in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                categories.add(EndpointCategory.USER_DATA_CRUD)

        return sorted(categories, key=lambda c: c.value)

    def classify_all(self, endpoints: list[APIEndpoint]) -> list[APIEndpoint]:
        """Classify all endpoints and assign categories."""
        for endpoint in endpoints:
            endpoint.categories = self.classify(endpoint)
            logger.debug(
                f"Endpoint {endpoint.method.value} {endpoint.path[:60]}... "
                f"-> {', '.join(c.value for c in endpoint.categories)}"
            )

        # Summary
        category_counts = {}
        for ep in endpoints:
            for cat in ep.categories:
                category_counts[cat.value] = category_counts.get(cat.value, 0) + 1

        logger.info(f"Classification summary: {category_counts}")
        return endpoints

    def _classify_by_method(self, endpoint: APIEndpoint) -> set[EndpointCategory]:
        """Classify based on HTTP method."""
        categories = set()
        method = endpoint.method.value

        # DELETE on sensitive objects is admin-like
        if method == "DELETE":
            categories.add(EndpointCategory.ADMIN_OPERATIONS)

        # POST/PUT/PATCH on User/Profile/Permission objects is admin-like
        if method in ("POST", "PUT", "PATCH"):
            path_lower = endpoint.path.lower()
            if any(obj in path_lower for obj in ["/user/", "/profile/", "/permission", "/setup/"]):
                categories.add(EndpointCategory.ADMIN_OPERATIONS)

        return categories

    def _classify_by_query(self, endpoint: APIEndpoint) -> set[EndpointCategory]:
        """Classify based on query parameters (SOQL/SOSL)."""
        categories = set()

        # Check query parameter for SOQL patterns
        q_value = endpoint.query_string.get("q", "")
        if q_value:
            q_upper = q_value.upper()
            # SOQL queries are data queries
            if "SELECT" in q_upper and "FROM" in q_upper:
                categories.add(EndpointCategory.DATA_QUERY)

                # Querying sensitive objects
                sensitive_objects = ["USER", "PROFILE", "PERMISSION", "SETUP", "AUDIT"]
                for obj in sensitive_objects:
                    if obj in q_upper:
                        categories.add(EndpointCategory.ADMIN_OPERATIONS)
                        break

            # SOSL searches
            if "FIND" in q_upper:
                categories.add(EndpointCategory.DATA_QUERY)

        return categories

    def _classify_by_response(self, endpoint: APIEndpoint) -> set[EndpointCategory]:
        """Classify based on response content."""
        categories = set()

        if not endpoint.response_body:
            return categories

        # Check for PII-like data in response
        pii_patterns = [
            r'"Email"',
            r'"Phone"',
            r'"MobilePhone"',
            r'"HomePhone"',
            r'"MailingAddress"',
        ]
        for pattern in pii_patterns:
            if re.search(pattern, endpoint.response_body):
                categories.add(EndpointCategory.USER_DATA_CRUD)
                break

        # Check for admin-level data
        admin_patterns = [
            r'"ProfileId"',
            r'"PermissionSetAssignment"',
            r'"IsAdmin"',
            r'"SetupEntityAccess"',
        ]
        for pattern in admin_patterns:
            if re.search(pattern, endpoint.response_body):
                categories.add(EndpointCategory.ADMIN_OPERATIONS)
                break

        return categories

    def get_applicable_categories_for_test(
        self, test_categories: list[str]
    ) -> list[EndpointCategory]:
        """Convert test case category strings to EndpointCategory enums."""
        result = []
        for cat_str in test_categories:
            try:
                result.append(EndpointCategory(cat_str))
            except ValueError:
                logger.warning(f"Unknown endpoint category: {cat_str}")
        return result

    def is_endpoint_applicable(
        self, endpoint: APIEndpoint, test_categories: list[str]
    ) -> bool:
        """Check if an endpoint is applicable for a test based on categories."""
        if not test_categories:
            return True

        applicable_cats = self.get_applicable_categories_for_test(test_categories)
        endpoint_cats = set(endpoint.categories)

        # Endpoint must match at least one test category
        return bool(endpoint_cats.intersection(applicable_cats))
