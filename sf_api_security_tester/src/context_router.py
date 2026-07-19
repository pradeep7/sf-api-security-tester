"""Context-aware endpoint analysis that determines applicable test categories and injection points."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from loguru import logger

from .models import APIEndpoint, EndpointCategory, HTTPMethod


# ---------------------------------------------------------------------------
# Heuristic patterns for injection-point detection
# ---------------------------------------------------------------------------
_SOQL_PATH_PATTERNS = [
    re.compile(r"/query", re.IGNORECASE),
    re.compile(r"/search", re.IGNORECASE),
    re.compile(r"/apexrest/", re.IGNORECASE),
    re.compile(r"/tooling/", re.IGNORECASE),
    re.compile(r"/composite/", re.IGNORECASE),
]

_SOQL_PARAM_NAMES = {"q", "query", "soql", "filter", "search", "where"}

_SOSL_PARAM_NAMES = {"q", "search", "sosl"}

_XSS_PARAM_NAMES = {
    "name", "subject", "title", "description", "body", "content",
    "comment", "message", "text", "note", "label", "value",
}

_SSRF_PARAM_NAMES = {
    "url", "callback", "redirect", "redirect_uri", "return_to",
    "next", "continue", "target", "dest", "website", "image_url",
    "document_url", "file", "path", "uri", "link", "href",
}

_PATH_TRAVERSAL_PARAM_NAMES = {
    "file", "filename", "path", "document", "page", "template",
    "include", "load", "dir", "directory", "folder",
}

_BOLA_PATH_PATTERN = re.compile(r"/(0[0-9A-Za-z]{12,17}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
_SF_ID_PATTERN = re.compile(r"\b[0-9A-Za-z]{15}\b|\b[0-9A-Za-z]{18}\b")

_AUTH_PATH_PATTERNS = [
    re.compile(r"/login", re.IGNORECASE),
    re.compile(r"/logout", re.IGNORECASE),
    re.compile(r"/token", re.IGNORECASE),
    re.compile(r"/oauth", re.IGNORECASE),
    re.compile(r"/auth", re.IGNORECASE),
    re.compile(r"/session", re.IGNORECASE),
]

_ADMIN_PATH_PATTERNS = [
    re.compile(r"/setup/", re.IGNORECASE),
    re.compile(r"/tooling/", re.IGNORECASE),
    re.compile(r"/metadata/", re.IGNORECASE),
    re.compile(r"/deploy/", re.IGNORECASE),
    re.compile(r"/admin", re.IGNORECASE),
]

_WRITABLE_METHODS = {HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.PATCH, HTTPMethod.DELETE}


@dataclass
class InjectionPoint:
    """Describes a single injection point on an endpoint."""
    category: str
    injection_field: str
    injection_type: str  # "url_path", "url_param", "body_param", "header", "query_string"
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class EndpointContext:
    """Full context analysis result for an endpoint."""
    endpoint: APIEndpoint
    injection_points: list[InjectionPoint]
    applicable_test_categories: list[str]
    risk_score: int  # 0-100
    notes: list[str] = field(default_factory=list)


class ContextRouter:
    """Analyses an APIEndpoint and determines which test categories are applicable
    and where injection points exist."""

    def analyse(self, endpoint: APIEndpoint) -> EndpointContext:
        """Perform full context analysis of an endpoint."""
        injection_points: list[InjectionPoint] = []
        applicable_categories: set[str] = set()
        notes: list[str] = []
        risk_score = 0

        # --- 1. SOQL / SQLi analysis ---
        if self._is_soql_endpoint(endpoint):
            points = self._find_soql_injection_points(endpoint)
            injection_points.extend(points)
            applicable_categories.add("soql_injection")
            applicable_categories.add("sql_injection")
            risk_score += 25
            notes.append(f"SOQL endpoint detected ({len(points)} injection points)")

        # --- 2. SOSL analysis ---
        if self._is_sosl_endpoint(endpoint):
            points = self._find_sosl_injection_points(endpoint)
            injection_points.extend(points)
            applicable_categories.add("soql_injection")
            risk_score += 15
            notes.append(f"SOSL endpoint detected ({len(points)} injection points)")

        # --- 3. XSS analysis ---
        if self._is_writable_endpoint(endpoint):
            points = self._find_xss_injection_points(endpoint)
            injection_points.extend(points)
            if points:
                applicable_categories.add("xss")
                risk_score += 20
                notes.append(f"XSS injection points found: {[p.injection_field for p in points]}")

        # --- 4. SSRF analysis ---
        points = self._find_ssrf_injection_points(endpoint)
        injection_points.extend(points)
        if points:
            applicable_categories.add("ssrf")
            risk_score += 25
            notes.append(f"SSRF injection points found: {[p.injection_field for p in points]}")

        # --- 5. Path traversal analysis ---
        points = self._find_path_traversal_points(endpoint)
        injection_points.extend(points)
        if points:
            applicable_categories.add("path_traversal")
            applicable_categories.add("lfi")
            risk_score += 15
            notes.append(f"Path traversal points found: {[p.injection_field for p in points]}")

        # --- 6. BOLA / IDOR analysis ---
        if self._has_bola_indicators(endpoint):
            applicable_categories.add("bola_idor")
            risk_score += 30
            sf_ids = _SF_ID_PATTERN.findall(endpoint.path)
            injection_points.append(
                InjectionPoint(
                    category="bola_idor",
                    injection_field="url_path_record_id",
                    injection_type="url_path",
                    config={"sf_ids_in_path": sf_ids},
                )
            )
            notes.append(f"BOLA indicators: {len(sf_ids)} SF IDs in URL path")

        # --- 7. Authentication analysis ---
        if self._is_auth_endpoint(endpoint):
            applicable_categories.add("authentication_bypass")
            risk_score += 20
            notes.append("Authentication endpoint detected")

        # --- 8. Admin operations analysis ---
        if self._is_admin_endpoint(endpoint):
            applicable_categories.add("bfla")
            applicable_categories.add("mass_assignment")
            risk_score += 20
            notes.append("Admin operation detected")

        # --- 9. CORS analysis (always applicable for API endpoints) ---
        applicable_categories.add("cors_misconfiguration")
        risk_score += 5

        # --- 10. Header analysis (always applicable) ---
        applicable_categories.add("security_headers")

        # --- 11. Mass assignment for writable endpoints ---
        if self._is_writable_endpoint(endpoint):
            applicable_categories.add("mass_assignment")
            if endpoint.request_body:
                risk_score += 10

        # --- 12. Object type-based analysis ---
        obj = (endpoint.sf_object_type or "").upper()
        sensitive_objects = {"USER", "PROFILE", "PERMISSIONSET", "SETUPENTITYACCESS", "AUDITTRAIL"}
        if obj in sensitive_objects:
            applicable_categories.add("authorization")
            risk_score += 15
            notes.append(f"Sensitive SF object: {obj}")

        # Cap risk score
        risk_score = min(risk_score, 100)

        # Always include generic SQLi and XSS for API endpoints
        applicable_categories.add("sql_injection")
        applicable_categories.add("xss")

        ctx = EndpointContext(
            endpoint=endpoint,
            injection_points=injection_points,
            applicable_test_categories=sorted(applicable_categories),
            risk_score=risk_score,
            notes=notes,
        )

        logger.debug(
            f"Context analysis: {endpoint.method.value} {endpoint.path[:50]}... "
            f"-> {len(injection_points)} injection points, risk={risk_score}, "
            f"categories={ctx.applicable_test_categories}"
        )
        return ctx

    # ------------------------------------------------------------------
    # SOQL / SQLi detection
    # ------------------------------------------------------------------
    def _is_soql_endpoint(self, ep: APIEndpoint) -> bool:
        """Check if endpoint is a SOQL query endpoint."""
        # Path match
        for pattern in _SOQL_PATH_PATTERNS:
            if pattern.search(ep.path):
                return True

        # Query parameter name match
        for param_name in ep.query_string:
            if param_name.lower() in _SOQL_PARAM_NAMES:
                return True

        # SOQL keywords in query value
        for param_name, param_value in ep.query_string.items():
            upper_val = param_value.upper()
            if "SELECT" in upper_val and "FROM" in upper_val:
                return True

        # SOQL in request body
        if ep.request_body:
            body_upper = ep.request_body.upper()
            if "SELECT" in body_upper and "FROM" in body_upper:
                return True

        return False

    def _find_soql_injection_points(self, ep: APIEndpoint) -> list[InjectionPoint]:
        """Find all SOQL injection points."""
        points: list[InjectionPoint] = []

        # Query string parameters
        for param_name, param_value in ep.query_string.items():
            if param_name.lower() in _SOQL_PARAM_NAMES or (
                "SELECT" in param_value.upper() and "FROM" in param_value.upper()
            ):
                points.append(
                    InjectionPoint(
                        category="soql_injection",
                        injection_field=param_name,
                        injection_type="query_string",
                        config={"original_value": param_value, "injection_position": "full_replace"},
                    )
                )
                # Also add a positional injection point (append to existing query)
                points.append(
                    InjectionPoint(
                        category="soql_injection",
                        injection_field=param_name,
                        injection_type="query_string_append",
                        config={"original_value": param_value, "injection_position": "append"},
                    )
                )

        # Request body with SOQL
        if ep.request_body and "SELECT" in (ep.request_body or "").upper():
            points.append(
                InjectionPoint(
                    category="soql_injection",
                    injection_field="request_body",
                    injection_type="body_param",
                    config={"injection_position": "body_soql"},
                )
            )

        # URL path segments that might be SOQL-adjacent
        if any(p.search(ep.path) for p in _SOQL_PATH_PATTERNS):
            points.append(
                InjectionPoint(
                    category="soql_injection",
                    injection_field="url_path",
                    injection_type="url_path",
                    config={"injection_position": "url_path"},
                )
            )

        return points

    # ------------------------------------------------------------------
    # SOSL detection
    # ------------------------------------------------------------------
    def _is_sosl_endpoint(self, ep: APIEndpoint) -> bool:
        """Check if endpoint accepts SOSL searches."""
        # Look for FIND keyword in query params
        for param_name, param_value in ep.query_string.items():
            upper_val = param_value.upper()
            if "FIND" in upper_val:
                return True
            if param_name.lower() in _SOSL_PARAM_NAMES:
                # Heuristic: SOSL endpoints often use /search path
                if "/search" in ep.path.lower():
                    return True
        return False

    def _find_sosl_injection_points(self, ep: APIEndpoint) -> list[InjectionPoint]:
        points: list[InjectionPoint] = []
        for param_name in ep.query_string:
            if param_name.lower() in _SOSL_PARAM_NAMES or param_name.lower() == "q":
                points.append(
                    InjectionPoint(
                        category="soql_injection",
                        injection_field=param_name,
                        injection_type="sosl_search_term",
                        config={"original_value": ep.query_string.get(param_name, "")},
                    )
                )
        return points

    # ------------------------------------------------------------------
    # XSS detection
    # ------------------------------------------------------------------
    def _is_writable_endpoint(self, ep: APIEndpoint) -> bool:
        """Check if endpoint accepts write operations."""
        return ep.method in _WRITABLE_METHODS

    def _find_xss_injection_points(self, ep: APIEndpoint) -> list[InjectionPoint]:
        """Find injection points for XSS testing."""
        points: list[InjectionPoint] = []

        if not ep.request_body:
            return points

        # Try to parse body as JSON and find string fields
        import json
        try:
            body_dict = json.loads(ep.request_body)
        except (json.JSONDecodeError, TypeError):
            body_dict = {}

        if isinstance(body_dict, dict):
            for field_name, field_value in body_dict.items():
                if isinstance(field_value, str) and field_name.lower() in _XSS_PARAM_NAMES:
                    points.append(
                        InjectionPoint(
                            category="xss",
                            injection_field=field_name,
                            injection_type="body_param",
                            config={"original_value": field_value, "field_type": "string"},
                        )
                    )
                elif isinstance(field_value, str):
                    # Any string field is a potential XSS vector
                    points.append(
                        InjectionPoint(
                            category="xss",
                            injection_field=field_name,
                            injection_type="body_param",
                            config={"original_value": field_value, "field_type": "string"},
                        )
                    )

        # Also check query params
        for param_name, param_value in ep.query_string.items():
            if param_name.lower() in _XSS_PARAM_NAMES:
                points.append(
                    InjectionPoint(
                        category="xss",
                        injection_field=param_name,
                        injection_type="query_string",
                        config={"original_value": param_value},
                    )
                )

        return points

    # ------------------------------------------------------------------
    # SSRF detection
    # ------------------------------------------------------------------
    def _find_ssrf_injection_points(self, ep: APIEndpoint) -> list[InjectionPoint]:
        """Find SSRF injection points."""
        points: list[InjectionPoint] = []

        # Check query parameters
        for param_name in ep.query_string:
            if param_name.lower() in _SSRF_PARAM_NAMES:
                points.append(
                    InjectionPoint(
                        category="ssrf",
                        injection_field=param_name,
                        injection_type="query_string",
                        config={"original_value": ep.query_string[param_name]},
                    )
                )

        # Check body parameters
        if ep.request_body:
            import json
            try:
                body_dict = json.loads(ep.request_body)
                if isinstance(body_dict, dict):
                    for field_name in body_dict:
                        if field_name.lower() in _SSRF_PARAM_NAMES:
                            points.append(
                                InjectionPoint(
                                    category="ssrf",
                                    injection_field=field_name,
                                    injection_type="body_param",
                                    config={"original_value": str(body_dict[field_name])},
                                )
                            )
            except (json.JSONDecodeError, TypeError):
                pass

        return points

    # ------------------------------------------------------------------
    # Path traversal detection
    # ------------------------------------------------------------------
    def _find_path_traversal_points(self, ep: APIEndpoint) -> list[InjectionPoint]:
        """Find path traversal injection points."""
        points: list[InjectionPoint] = []

        # URL path
        if "/" in ep.path:
            points.append(
                InjectionPoint(
                    category="path_traversal",
                    injection_field="url_path",
                    injection_type="url_path",
                    config={"original_path": ep.path},
                )
            )

        # Query parameters with file-like names
        for param_name in ep.query_string:
            if param_name.lower() in _PATH_TRAVERSAL_PARAM_NAMES:
                points.append(
                    InjectionPoint(
                        category="path_traversal",
                        injection_field=param_name,
                        injection_type="query_string",
                        config={"original_value": ep.query_string[param_name]},
                    )
                )

        return points

    # ------------------------------------------------------------------
    # BOLA / IDOR detection
    # ------------------------------------------------------------------
    def _has_bola_indicators(self, ep: APIEndpoint) -> bool:
        """Check if endpoint has BOLA/IDOR indicators."""
        # Has SF IDs in URL path
        if _SF_ID_PATTERN.search(ep.path):
            return True

        # Has SF IDs in query string
        for param_value in ep.query_string.values():
            if _SF_ID_PATTERN.search(param_value):
                return True

        # Has SF IDs in request body
        if ep.request_body:
            if _SF_ID_PATTERN.search(ep.request_body):
                return True

        return False

    # ------------------------------------------------------------------
    # Auth / Admin detection
    # ------------------------------------------------------------------
    def _is_auth_endpoint(self, ep: APIEndpoint) -> bool:
        """Check if endpoint is authentication-related."""
        return any(p.search(ep.path) for p in _AUTH_PATH_PATTERNS)

    def _is_admin_endpoint(self, ep: APIEndpoint) -> bool:
        """Check if endpoint is admin-related."""
        return any(p.search(ep.path) for p in _ADMIN_PATH_PATTERNS)

    # ------------------------------------------------------------------
    # Batch analysis
    # ------------------------------------------------------------------
    def analyse_batch(self, endpoints: list[APIEndpoint]) -> list[EndpointContext]:
        """Analyse multiple endpoints."""
        contexts = []
        for ep in endpoints:
            ctx = self.analyse(ep)
            contexts.append(ctx)
        return contexts

    def get_summary(self, contexts: list[EndpointContext]) -> dict[str, Any]:
        """Generate a summary of the batch analysis."""
        total_injection_points = sum(len(c.injection_points) for c in contexts)
        category_counts: dict[str, int] = {}
        for ctx in contexts:
            for cat in ctx.applicable_test_categories:
                category_counts[cat] = category_counts.get(cat, 0) + 1

        avg_risk = (
            sum(c.risk_score for c in contexts) / len(contexts)
            if contexts
            else 0
        )

        return {
            "total_endpoints": len(contexts),
            "total_injection_points": total_injection_points,
            "avg_risk_score": round(avg_risk, 1),
            "category_distribution": category_counts,
            "high_risk_endpoints": [
                {
                    "url": ctx.endpoint.url[:80],
                    "method": ctx.endpoint.method.value,
                    "risk_score": ctx.risk_score,
                    "injection_points": len(ctx.injection_points),
                }
                for ctx in sorted(contexts, key=lambda c: c.risk_score, reverse=True)[:10]
            ],
        }
