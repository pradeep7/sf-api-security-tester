"""Generates mutated HTTP requests based on test case definitions (V2 Smart Engine)."""

from __future__ import annotations

import copy
import json
import re
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs, quote

from loguru import logger

from .models import (
    APIEndpoint,
    HTTPMethod,
    MutatedRequest,
    Mutation,
    MutationType,
)
from .payload_manager import PayloadManager
from .context_router import ContextRouter, EndpointContext, InjectionPoint


class MutationEngine:
    """Generates mutated requests using dynamic payloads and context-aware routing."""

    def __init__(
        self,
        cross_tenant_ids: dict[str, Any] | None = None,
        payload_manager: PayloadManager | None = None,
        context_router: ContextRouter | None = None,
        payload_config: dict[str, Any] | None = None,
    ):
        self.cross_tenant_ids = cross_tenant_ids or {}
        self.payload_manager = payload_manager or PayloadManager(
            cache_dir=payload_config.get("cache_dir", "payloads_cache") if payload_config else "payloads_cache",
            max_payloads_per_category=payload_config.get("max_payloads_per_category", 200) if payload_config else 200,
            cache_ttl_days=payload_config.get("cache_ttl_days", 7) if payload_config else 7,
            request_timeout=payload_config.get("request_timeout", 15) if payload_config else 15,
        )
        self.context_router = context_router or ContextRouter()

    # ------------------------------------------------------------------
    # Encoding helpers (V2.1 — prevent broken requests)
    # ------------------------------------------------------------------
    @staticmethod
    def _encode_payload_for_url(payload: str) -> str:
        """URL-encode a payload for safe injection into query parameters.

        Salesforce SOQL query strings require strict encoding — raw ``'``,
        ``;``, ``--`` etc. will break the URL or get stripped by CDNs.
        """
        return quote(payload, safe="")

    @staticmethod
    def _safe_json_body(body_dict: dict[str, Any]) -> str:
        """Serialize a dict to a JSON string, handling nested escaping properly.

        Ensures the final body is valid JSON even when payload values contain
        quotes, newlines, or backslashes.
        """
        return json.dumps(body_dict, ensure_ascii=False, separators=(",", ":"))

    def generate_mutations(
        self,
        endpoint: APIEndpoint,
        test_case_id: str,
        mutation_type: str,
        payloads: dict[str, Any],
    ) -> list[MutatedRequest]:
        """Generate all mutations for a given endpoint and test case.

        V2: Uses ContextRouter to analyse the endpoint and PayloadManager
        to fetch dynamic payloads from cached external sources.
        """
        mutations: list[MutatedRequest] = []

        try:
            mt = MutationType(mutation_type)
        except ValueError:
            logger.warning(f"Unknown mutation type: {mutation_type}")
            return []

        # Analyse endpoint context for smart routing
        context = self.context_router.analyse(endpoint)

        dispatch = {
            MutationType.BOLA_ID_SWAP: self._bola_id_swap,
            MutationType.BOLA_QUERY_SWAP: self._bola_query_swap,
            MutationType.HEADER_REMOVAL: self._header_removal,
            MutationType.HEADER_VALUE_INJECTION: self._header_value_injection,
            MutationType.METHOD_CHANGE: self._method_change,
            MutationType.METHOD_OVERRIDE: self._method_override,
            MutationType.SOQL_INJECTION: self._soql_injection,
            MutationType.SOSL_INJECTION: self._sosl_injection,
            MutationType.CORS_TEST: self._cors_test,
            MutationType.HEADER_CHECK: self._header_check,
            MutationType.PATH_TRAVERSAL: self._path_traversal,
            MutationType.ERROR_ENUMERATION: self._error_enumeration,
            MutationType.VERSION_ENUMERATION: self._version_enumeration,
            MutationType.SSRF_INJECTION: self._ssrf_injection,
            MutationType.MASS_ASSIGNMENT: self._mass_assignment,
            MutationType.STORED_XSS: self._stored_xss,
            MutationType.XSS_INJECTION: self._xss_injection,
            MutationType.RESOURCE_EXHAUSTION: self._resource_exhaustion,
            MutationType.TRANSPORT_CHECK: self._transport_check,
            MutationType.SESSION_FIXATION: self._session_fixation,
            MutationType.AUTH_ENUMERATION: self._auth_enumeration,
            MutationType.BUSINESS_LOGIC_BYPASS: self._business_logic_bypass,
            MutationType.FORCED_BROWSING: self._forced_browsing,
            MutationType.PII_CHECK: self._pii_check,
            MutationType.RACE_CONDITION: self._race_condition,
        }

        handler = dispatch.get(mt)
        if handler:
            mutations = handler(endpoint, test_case_id, payloads, context)
        else:
            logger.warning(f"No handler for mutation type: {mt}")

        return mutations

    def get_context(self, endpoint: APIEndpoint) -> EndpointContext:
        """Public accessor: analyse endpoint and return context (for external use)."""
        return self.context_router.analyse(endpoint)

    def _build_mutated_request(
        self,
        endpoint: APIEndpoint,
        test_case_id: str,
        mutation: Mutation,
        *,
        url: str | None = None,
        method: HTTPMethod | None = None,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        content_type: str | None = None,
    ) -> MutatedRequest:
        """Build a MutatedRequest from an endpoint and mutation details."""
        return MutatedRequest(
            endpoint_id=endpoint.id,
            test_case_id=test_case_id,
            mutation_id=mutation.id,
            url=url or endpoint.url,
            method=method or endpoint.method,
            headers=headers if headers is not None else copy.deepcopy(endpoint.headers),
            body=body if body is not None else endpoint.request_body,
            content_type=content_type or endpoint.request_content_type,
            cookies=copy.deepcopy(endpoint.cookies),
            mutation_description=mutation.description,
        )

    # -------------------------------------------------------------------------
    # BOLA / IDOR Mutations
    # -------------------------------------------------------------------------
    def _bola_id_swap(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Replace Salesforce IDs in URL with cross-tenant/other user IDs."""
        mutations = []

        portal_ids = self.cross_tenant_ids.get(endpoint.portal_name, {})
        other_user_id = portal_ids.get("other_user_id", "")
        other_tenant_id = portal_ids.get("other_tenant_user_id", "")

        # Get record IDs from config
        record_ids = portal_ids.get("record_ids", [])
        other_record_id = ""
        other_tenant_record = ""
        for rec in record_ids:
            if "other user" in rec.get("description", "").lower():
                other_record_id = rec.get("id", "")
            if "other tenant" in rec.get("description", "").lower():
                other_tenant_record = rec.get("id", "")

        # Replace IDs in URL path
        for sf_id in endpoint.sf_ids:
            if other_record_id:
                m = Mutation(
                    mutation_type=MutationType.BOLA_ID_SWAP,
                    description=f"Replace {sf_id} with other user's record {other_record_id}",
                    original_value=sf_id,
                    mutated_value=other_record_id,
                    target_field="url_path_record_id",
                )
                new_url = endpoint.url.replace(sf_id, other_record_id)
                mutations.append(
                    self._build_mutated_request(
                        endpoint, test_case_id, m, url=new_url
                    )
                )

            if other_tenant_record:
                m = Mutation(
                    mutation_type=MutationType.BOLA_ID_SWAP,
                    description=f"Replace {sf_id} with cross-tenant record {other_tenant_record}",
                    original_value=sf_id,
                    mutated_value=other_tenant_record,
                    target_field="url_path_record_id",
                )
                new_url = endpoint.url.replace(sf_id, other_tenant_record)
                mutations.append(
                    self._build_mutated_request(
                        endpoint, test_case_id, m, url=new_url
                    )
                )

        # Also try replacing IDs in request body
        if endpoint.request_body and other_record_id:
            body = endpoint.request_body
            for sf_id in endpoint.sf_ids:
                if sf_id in body:
                    m = Mutation(
                        mutation_type=MutationType.BOLA_ID_SWAP,
                        description=f"Replace body ID {sf_id} with other user record {other_record_id}",
                        original_value=sf_id,
                        mutated_value=other_record_id,
                        target_field="body_record_id",
                    )
                    new_body = body.replace(sf_id, other_record_id)
                    mutations.append(
                        self._build_mutated_request(
                            endpoint, test_case_id, m, body=new_body
                        )
                    )

        if not mutations:
            m = Mutation(
                mutation_type=MutationType.BOLA_ID_SWAP,
                description="BOLA test - no replaceable IDs found in endpoint",
            )
            mutations.append(
                self._build_mutated_request(endpoint, test_case_id, m)
            )

        return mutations

    def _bola_query_swap(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Modify SOQL query to target other user's data."""
        mutations = []
        portal_ids = self.cross_tenant_ids.get(endpoint.portal_name, {})
        other_user_id = portal_ids.get("other_user_id", "")

        soql_templates = payloads.get("soql_templates", [])
        for template in soql_templates:
            soql = template.replace("{other_user_id}", other_user_id)
            m = Mutation(
                mutation_type=MutationType.BOLA_QUERY_SWAP,
                description=f"SOQL query targeting other user: {soql[:80]}",
                soql_payload=soql,
                target_field="query_param",
            )

            # Build new URL with modified query
            parsed = urlparse(endpoint.url)
            params = parse_qs(parsed.query)
            params["q"] = [soql]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))

            mutations.append(
                self._build_mutated_request(endpoint, test_case_id, m, url=new_url)
            )

        return mutations

    # -------------------------------------------------------------------------
    # Authentication Mutations
    # -------------------------------------------------------------------------
    def _header_removal(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Remove authentication headers."""
        mutations = []
        headers_to_remove = payloads.get("headers_to_remove", ["Authorization", "Cookie"])

        for header_name in headers_to_remove:
            new_headers = copy.deepcopy(endpoint.headers)
            new_headers.pop(header_name, None)
            new_cookies = copy.deepcopy(endpoint.cookies)

            # Also remove from cookies if "sid"
            if header_name.lower() == "cookie":
                new_cookies.pop("sid", None)

            m = Mutation(
                mutation_type=MutationType.HEADER_REMOVAL,
                description=f"Remove {header_name} header",
                target_header=header_name,
            )
            req = self._build_mutated_request(
                endpoint, test_case_id, m, headers=new_headers
            )
            req.cookies = new_cookies
            mutations.append(req)

        # Remove ALL auth headers at once
        new_headers = copy.deepcopy(endpoint.headers)
        new_headers.pop("Authorization", None)
        new_headers.pop("Cookie", None)
        m = Mutation(
            mutation_type=MutationType.HEADER_REMOVAL,
            description="Remove all authentication headers",
        )
        req = self._build_mutated_request(
            endpoint, test_case_id, m, headers=new_headers
        )
        req.cookies = {}
        mutations.append(req)

        return mutations

    def _header_value_injection(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Replace header values with injected payloads."""
        mutations = []
        header_name = payloads.get("header", "Authorization")
        values = payloads.get("values", [])

        for value in values:
            new_headers = copy.deepcopy(endpoint.headers)
            new_headers[header_name] = value

            m = Mutation(
                mutation_type=MutationType.HEADER_VALUE_INJECTION,
                description=f"Inject {header_name}: {value[:50]}",
                original_value=endpoint.headers.get(header_name, ""),
                mutated_value=value,
                target_header=header_name,
            )
            mutations.append(
                self._build_mutated_request(
                    endpoint, test_case_id, m, headers=new_headers
                )
            )

        return mutations

    # -------------------------------------------------------------------------
    # Method Mutations
    # -------------------------------------------------------------------------
    def _method_change(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Change HTTP method to test method-based authorization."""
        mutations = []
        methods_to_test = payloads.get("methods_to_test", ["GET", "POST", "PUT", "DELETE"])

        for method_str in methods_to_test:
            if method_str == endpoint.method.value:
                continue
            try:
                method = HTTPMethod(method_str)
            except ValueError:
                continue

            m = Mutation(
                mutation_type=MutationType.METHOD_CHANGE,
                description=f"Change method from {endpoint.method.value} to {method_str}",
                http_method_override=method_str,
            )
            mutations.append(
                self._build_mutated_request(
                    endpoint, test_case_id, m, method=method
                )
            )

        return mutations

    def _method_override(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Add method override headers to bypass restrictions."""
        mutations = []
        override_headers = payloads.get(
            "method_override_headers", ["X-HTTP-Method-Override", "X-HTTP-Method"]
        )
        target_methods = payloads.get("target_methods", ["DELETE", "PUT", "PATCH"])

        for override_header in override_headers:
            for method_str in target_methods:
                new_headers = copy.deepcopy(endpoint.headers)
                new_headers[override_header] = method_str

                m = Mutation(
                    mutation_type=MutationType.METHOD_OVERRIDE,
                    description=f"Add {override_header}: {method_str} to bypass method restriction",
                    target_header=override_header,
                    http_method_override=method_str,
                )
                mutations.append(
                    self._build_mutated_request(
                        endpoint, test_case_id, m, headers=new_headers
                    )
                )

        return mutations

    # -------------------------------------------------------------------------
    # Injection Mutations (V2: Dynamic Payloads)
    # -------------------------------------------------------------------------
    def _soql_injection(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Inject SOQL payloads into query parameters.

        V2: Uses PayloadManager to fetch dynamic SOQL payloads and
        ContextRouter injection points to target the right parameters.
        """
        mutations = []

        # Merge: test-case payloads + dynamic payloads from PayloadManager
        tc_payloads = payloads.get("soql_payloads", [])
        dynamic_payloads = self.payload_manager.get_payloads("soql_injection", limit=50)
        # Also fetch general sql_injection payloads that work as SOQL
        dynamic_payloads += self.payload_manager.get_payloads("sql_injection", limit=30)
        all_soql = list(tc_payloads) + dynamic_payloads

        # Use context injection points if available
        injection_points = []
        if context:
            injection_points = [
                ip for ip in context.injection_points
                if ip.category == "soql_injection"
            ]

        # If no context injection points, discover from endpoint
        if not injection_points:
            parsed = urlparse(endpoint.url)
            params = parse_qs(parsed.query)
            for param_name in params:
                injection_points.append(
                    InjectionPoint(
                        category="soql_injection",
                        injection_field=param_name,
                        injection_type="query_string",
                        config={"original_value": params[param_name][0] if params[param_name] else ""},
                    )
                )

        for ip in injection_points:
            for payload in all_soql[:20]:  # Cap at 20 per injection point
                m = Mutation(
                    mutation_type=MutationType.SOQL_INJECTION,
                    description=f"SOQL injection via {ip.injection_field}: {payload[:60]}",
                    soql_payload=payload,
                    target_field=ip.injection_field,
                )

                parsed = urlparse(endpoint.url)
                params = parse_qs(parsed.query)

                # V2.1: Pre-encode payload for safe URL injection
                encoded_payload = self._encode_payload_for_url(payload)

                if ip.injection_type == "query_string" and ip.injection_field in params:
                    original_q = params[ip.injection_field][0] if params[ip.injection_field] else ""
                    injected_queries = self._build_soql_injections(original_q, payload)
                    for inj_q in injected_queries:
                        new_params = dict(params)
                        new_params[ip.injection_field] = [inj_q]
                        new_query = urlencode(new_params, doseq=True)
                        new_url = urlunparse(parsed._replace(query=new_query))
                        mutations.append(
                            self._build_mutated_request(
                                endpoint, test_case_id, m, url=new_url
                            )
                        )
                elif ip.injection_type == "query_string_append":
                    original_q = params.get(ip.injection_field, [""])[0]
                    new_q = f"{original_q}' OR '1'='1"
                    new_params = dict(params)
                    new_params[ip.injection_field] = [new_q]
                    new_query = urlencode(new_params, doseq=True)
                    new_url = urlunparse(parsed._replace(query=new_query))
                    mutations.append(
                        self._build_mutated_request(
                            endpoint, test_case_id, m, url=new_url
                        )
                    )
                else:
                    # Add as new query param (pre-encoded)
                    new_params = dict(params)
                    new_params[ip.injection_field] = [f"SELECT Id FROM Account WHERE Name='{encoded_payload}'"]
                    new_query = urlencode(new_params, doseq=True)
                    new_url = urlunparse(parsed._replace(query=new_query))
                    mutations.append(
                        self._build_mutated_request(
                            endpoint, test_case_id, m, url=new_url
                        )
                    )

        # Special character injection
        special_chars = payloads.get("special_characters", [])
        special_chars += list("';\"\\/\n\r\t")
        for char in special_chars[:10]:
            m = Mutation(
                mutation_type=MutationType.SOQL_INJECTION,
                description=f"Special character injection: {repr(char)}",
                soql_payload=char,
                target_field="query_param",
            )
            parsed = urlparse(endpoint.url)
            params = parse_qs(parsed.query)
            for param_name in params:
                original_val = params[param_name][0]
                new_params = dict(params)
                new_params[param_name] = [original_val + char]
                new_query = urlencode(new_params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))
                mutations.append(
                    self._build_mutated_request(
                        endpoint, test_case_id, m, url=new_url
                    )
                )

        return mutations

    def _build_soql_injections(self, original_query: str, payload: str) -> list[str]:
        """Build multiple SOQL injection variants from an original query."""
        injections = []

        # Tautology in WHERE clause
        if "WHERE" in original_query.upper():
            injections.append(f"{original_query} OR '1'='1")
            injections.append(f"{original_query}' OR '1'='1")
            injections.append(original_query.replace("WHERE", f"WHERE '1'='1' OR "))

        # Union-based
        injections.append(
            f"{original_query} UNION SELECT Id,Name,Email,Phone FROM User"
        )

        # Direct payload
        injections.append(payload)

        return injections

    def _sosl_injection(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Inject SOSL payloads.

        V2: Uses dynamic payloads from PayloadManager.
        """
        mutations = []
        tc_payloads = payloads.get("sosl_payloads", [])
        dynamic_payloads = self.payload_manager.get_payloads("soql_injection", limit=20)
        all_sosl = list(tc_payloads) + dynamic_payloads

        for payload in all_sosl:
            m = Mutation(
                mutation_type=MutationType.SOSL_INJECTION,
                description=f"SOSL injection: {payload[:60]}",
                soql_payload=payload,
                target_field="query_param",
            )

            parsed = urlparse(endpoint.url)
            params = parse_qs(parsed.query)
            # Find the search parameter (q, search, etc.)
            search_param = None
            for pname in params:
                if pname.lower() in ("q", "search", "sosl"):
                    search_param = pname
                    break
            if search_param is None:
                search_param = "q"

            params[search_param] = [payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))

            mutations.append(
                self._build_mutated_request(
                    endpoint, test_case_id, m, url=new_url
                )
            )

        return mutations

    # -------------------------------------------------------------------------
    # CORS Mutations (V2: Dynamic)
    # -------------------------------------------------------------------------
    def _cors_test(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Test CORS with various malicious origins."""
        mutations = []
        # Merge test-case origins with dynamic ones
        tc_origins = payloads.get("origins_to_test", [])
        dynamic_origins = self.payload_manager.get_payloads("cors_misconfiguration", limit=10)
        # Default malicious origins if nothing from PayloadManager
        default_origins = [
            "https://evil.com", "https://attacker.com", "null",
            f"https://{endpoint.portal_name}.salesforce.com.evil.com",
        ]
        all_origins = list(tc_origins) + dynamic_origins + default_origins
        # Deduplicate
        seen = set()
        unique_origins = []
        for o in all_origins:
            if o and o not in seen:
                seen.add(o)
                unique_origins.append(o)

        for origin in unique_origins[:15]:  # Cap at 15
            new_headers = copy.deepcopy(endpoint.headers)
            new_headers["Origin"] = origin

            m = Mutation(
                mutation_type=MutationType.CORS_TEST,
                description=f"CORS test with malicious origin: {origin}",
                original_value=endpoint.headers.get("Origin", ""),
                mutated_value=origin,
                target_header="Origin",
            )
            mutations.append(
                self._build_mutated_request(
                    endpoint, test_case_id, m, headers=new_headers
                )
            )

        return mutations

    # -------------------------------------------------------------------------
    # Header / Security Check Mutations
    # -------------------------------------------------------------------------
    def _header_check(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Check for required security headers (mutation is passthrough - evaluation handles it)."""
        m = Mutation(
            mutation_type=MutationType.HEADER_CHECK,
            description="Security header presence check",
        )
        return [self._build_mutated_request(endpoint, test_case_id, m)]

    # -------------------------------------------------------------------------
    # Path Traversal Mutations (V2: Dynamic)
    # -------------------------------------------------------------------------
    def _path_traversal(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Inject path traversal payloads into URL.

        V2: Uses dynamic payloads from PayloadManager.
        """
        mutations = []
        # Merge test-case payloads with dynamic ones
        tc_payloads = payloads.get("traversal_payloads", [])
        dynamic_payloads = self.payload_manager.get_payloads("path_traversal", limit=30)
        dynamic_payloads += self.payload_manager.get_payloads("lfi", limit=20)
        all_traversal = list(tc_payloads) + dynamic_payloads
        if not all_traversal:
            all_traversal = [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            ]

        # Use context injection points
        injection_points = []
        if context:
            injection_points = [
                ip for ip in context.injection_points
                if ip.category == "path_traversal"
            ]

        for payload in all_traversal[:25]:
            # URL path injection
            parsed = urlparse(endpoint.url)
            new_path = f"{parsed.path}/{payload}"
            new_url = urlunparse(parsed._replace(path=new_path))
            m = Mutation(
                mutation_type=MutationType.PATH_TRAVERSAL,
                description=f"Path traversal in URL: {payload[:40]}",
                original_value=endpoint.path,
                mutated_value=new_path,
                target_field="url_path",
            )
            mutations.append(
                self._build_mutated_request(endpoint, test_case_id, m, url=new_url)
            )

            # Also inject into context-identified file params
            for ip in injection_points:
                if ip.injection_type == "query_string":
                    parsed = urlparse(endpoint.url)
                    params = parse_qs(parsed.query)
                    params[ip.injection_field] = [payload]
                    new_query = urlencode(params, doseq=True)
                    new_url2 = urlunparse(parsed._replace(query=new_query))
                    m2 = Mutation(
                        mutation_type=MutationType.PATH_TRAVERSAL,
                        description=f"Path traversal in {ip.injection_field}: {payload[:40]}",
                        mutated_value=payload,
                        target_field=ip.injection_field,
                    )
                    mutations.append(
                        self._build_mutated_request(endpoint, test_case_id, m2, url=new_url2)
                    )

        # Directory listing paths
        paths_to_test = payloads.get("paths_to_test", [
            "/services/data/", "/services/", "/s/", "/aura/", "/_ui/",
        ])
        for test_path in paths_to_test:
            parsed = urlparse(endpoint.url)
            new_url = urlunparse(parsed._replace(path=test_path))
            m = Mutation(
                mutation_type=MutationType.PATH_TRAVERSAL,
                description=f"Directory listing check: {test_path}",
                mutated_value=test_path,
                target_field="url_path",
            )
            mutations.append(
                self._build_mutated_request(endpoint, test_case_id, m, url=new_url)
            )

        return mutations

    # -------------------------------------------------------------------------
    # Error Enumeration Mutations
    # -------------------------------------------------------------------------
    def _error_enumeration(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Send malformed requests to elicit verbose error messages."""
        mutations = []

        malformed_requests = payloads.get("malformed_requests", [
            {"type": "invalid_json", "body": "not json at all"},
            {"type": "empty_body", "body": ""},
            {"type": "missing_fields", "body": "{}"},
        ])
        invalid_payloads = payloads.get("invalid_payloads", [])

        for req in malformed_requests:
            body = req.get("body", "{}")
            m = Mutation(
                mutation_type=MutationType.ERROR_ENUMERATION,
                description=f"Malformed request: {req.get('type', 'unknown')}",
                target_field="request_body",
            )
            mutations.append(
                self._build_mutated_request(endpoint, test_case_id, m, body=body)
            )

        for payload in invalid_payloads:
            m = Mutation(
                mutation_type=MutationType.ERROR_ENUMERATION,
                description=f"Invalid payload: {payload[:40]}",
                mutated_value=payload,
                target_field="request_body",
            )
            mutations.append(
                self._build_mutated_request(endpoint, test_case_id, m, body=payload)
            )

        return mutations

    # -------------------------------------------------------------------------
    # Version Enumeration Mutations
    # -------------------------------------------------------------------------
    def _version_enumeration(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Test different API versions."""
        mutations = []
        versions = payloads.get("version_swaps", payloads.get("versions_to_test", []))

        if not versions:
            return mutations

        for version in versions:
            if endpoint.sf_api_version and version == endpoint.sf_api_version:
                continue
            new_url = re.sub(r"/v\d+\.\d+/", f"/{version}/", endpoint.url)
            m = Mutation(
                mutation_type=MutationType.VERSION_ENUMERATION,
                description=f"API version enumeration: {version}",
                original_value=endpoint.sf_api_version or "",
                mutated_value=version,
                target_field="url_version",
            )
            mutations.append(
                self._build_mutated_request(endpoint, test_case_id, m, url=new_url)
            )

        return mutations

    # -------------------------------------------------------------------------
    # SSRF Mutations (V2: Dynamic + Context)
    # -------------------------------------------------------------------------
    def _ssrf_injection(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Inject SSRF payloads into URL-like fields.

        V2: Uses dynamic payloads from PayloadManager and context injection points.
        """
        mutations = []
        # Merge test-case targets with dynamic ones
        tc_targets = payloads.get("ssrf_targets", payloads.get("internal_targets", []))
        dynamic_targets = self.payload_manager.get_payloads("ssrf", limit=30)
        all_targets = list(tc_targets) + dynamic_targets
        if not all_targets:
            all_targets = [
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost:8080", "http://127.0.0.1",
            ]

        # Use context injection points for SSRF fields
        injection_fields = set(payloads.get("injection_fields", ["url", "website"]))
        if context:
            for ip in context.injection_points:
                if ip.category == "ssrf":
                    injection_fields.add(ip.injection_field)

        for target in all_targets[:15]:
            for field in injection_fields:
                # Body injection (V2.1: use _safe_json_body)
                if endpoint.request_body:
                    try:
                        body_dict = json.loads(endpoint.request_body)
                        if field in body_dict:
                            body_dict[field] = target
                            new_body = self._safe_json_body(body_dict)
                            m = Mutation(
                                mutation_type=MutationType.SSRF_INJECTION,
                                description=f"SSRF via {field}: {target[:40]}",
                                original_value=str(body_dict.get(field, "")),
                                mutated_value=target,
                                target_body_param=field,
                            )
                            mutations.append(
                                self._build_mutated_request(endpoint, test_case_id, m, body=new_body)
                            )
                    except (json.JSONDecodeError, TypeError):
                        pass

                # Query param injection
                parsed = urlparse(endpoint.url)
                params = parse_qs(parsed.query)
                if field in params or field in endpoint.query_string:
                    params[field] = [target]
                    new_query = urlencode(params, doseq=True)
                    new_url = urlunparse(parsed._replace(query=new_query))
                    m = Mutation(
                        mutation_type=MutationType.SSRF_INJECTION,
                        description=f"SSRF via query param {field}: {target[:40]}",
                        mutated_value=target,
                        target_url_param=field,
                    )
                    mutations.append(
                        self._build_mutated_request(endpoint, test_case_id, m, url=new_url)
                    )

        return mutations

    # -------------------------------------------------------------------------
    # Mass Assignment Mutations (V2: Dynamic)
    # -------------------------------------------------------------------------
    def _mass_assignment(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Inject privileged fields into request body."""
        mutations = []
        tc_injections = payloads.get("field_injections", [])

        # Dynamic privileged fields
        dynamic_fields = self.payload_manager.get_payloads("mass_assignment", limit=20)

        if not endpoint.request_body:
            return mutations

        try:
            body_dict = json.loads(endpoint.request_body)
        except (json.JSONDecodeError, TypeError):
            return mutations

        # Merge field injections
        all_injections = list(tc_injections)
        # If no dynamic payload lines parsed as field injections, add common ones
        if not all_injections:
            all_injections = [
                {"field": "IsAdmin", "value": True},
                {"field": "IsPortalUser", "value": True},
                {"field": "UserType", "value": "Standard"},
                {"field": "IsActive", "value": True},
                {"field": "ProfileId", "value": "00e000000000001"},
                {"field": "OwnerId", "value": "005000000000001"},
            ]

        for inj in all_injections:
            field = inj.get("field", "")
            value = inj.get("value", True)
            modified_body = copy.deepcopy(body_dict)
            modified_body[field] = value
            new_body = self._safe_json_body(modified_body)
            m = Mutation(
                mutation_type=MutationType.MASS_ASSIGNMENT,
                description=f"Mass assignment: inject {field}={value}",
                mutated_value=self._safe_json_body({field: value}),
                target_body_param=field,
            )
            mutations.append(
                self._build_mutated_request(endpoint, test_case_id, m, body=new_body)
            )

        return mutations

    # -------------------------------------------------------------------------
    # XSS / Stored XSS Mutations (V2: Dynamic)
    # -------------------------------------------------------------------------
    def _stored_xss(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Inject XSS payloads for stored XSS testing.

        V2: Uses dynamic XSS payloads from PayloadManager and context injection points.
        """
        mutations = []
        if endpoint.method.value not in ("POST", "PUT", "PATCH"):
            return mutations

        target_objects = payloads.get("target_objects", [])
        if target_objects and endpoint.sf_object_type:
            if endpoint.sf_object_type not in target_objects:
                return mutations

        if not endpoint.request_body:
            return mutations

        try:
            body_dict = json.loads(endpoint.request_body)
        except (json.JSONDecodeError, TypeError):
            return mutations

        # Merge XSS payloads
        tc_xss = payloads.get("xss_payloads", [])
        dynamic_xss = self.payload_manager.get_payloads("xss", limit=40)
        all_xss = list(tc_xss) + dynamic_xss
        if not all_xss:
            all_xss = ['<script>alert("XSS")</script>', '<img src=x onerror=alert(1)>']

        # Use context injection points for target fields
        target_fields = set()
        if context:
            for ip in context.injection_points:
                if ip.category == "xss":
                    target_fields.add(ip.injection_field)

        # Fallback to known text fields
        text_fields = [
            "Subject", "Description", "Name", "Title", "CommentBody",
            "Body", "Content", "MessageBody", "Body__c",
        ]
        all_fields = list(target_fields) + [f for f in text_fields if f not in target_fields]

        for field in all_fields:
            if field in body_dict or any(f.lower() == field.lower() for f in body_dict.keys()):
                for xss in all_xss[:15]:
                    modified_body = copy.deepcopy(body_dict)
                    modified_body[field] = xss
                    # V2.1: Use _safe_json_body for proper escaping of XSS payloads
                    new_body = self._safe_json_body(modified_body)
                    m = Mutation(
                        mutation_type=MutationType.STORED_XSS,
                        description=f"Stored XSS in {field}: {xss[:40]}",
                        mutated_value=xss,
                        target_body_param=field,
                    )
                    mutations.append(
                        self._build_mutated_request(endpoint, test_case_id, m, body=new_body)
                    )

        return mutations

    def _xss_injection(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Inject XSS payloads (non-stored, for response-based XSS).

        V2: Uses dynamic payloads from PayloadManager.
        """
        mutations = []
        # Merge payloads
        tc_xss = payloads.get("xss_payloads", [])
        dynamic_xss = self.payload_manager.get_payloads("xss", limit=30)
        all_xss = list(tc_xss) + dynamic_xss
        if not all_xss:
            all_xss = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']

        # Determine injection fields from context or payloads
        injection_fields = set(payloads.get("injection_fields", []))
        if context:
            for ip in context.injection_points:
                if ip.category == "xss":
                    injection_fields.add(ip.injection_field)

        if endpoint.request_body:
            try:
                body_dict = json.loads(endpoint.request_body)
            except (json.JSONDecodeError, TypeError):
                body_dict = {}

            for field in injection_fields:
                if field in body_dict:
                    for xss in all_xss[:10]:
                        modified_body = copy.deepcopy(body_dict)
                        modified_body[field] = xss
                        # V2.1: Use _safe_json_body for proper escaping
                        new_body = self._safe_json_body(modified_body)
                        m = Mutation(
                            mutation_type=MutationType.XSS_INJECTION,
                            description=f"XSS injection in {field}: {xss[:40]}",
                            mutated_value=xss,
                            target_body_param=field,
                        )
                        mutations.append(
                            self._build_mutated_request(endpoint, test_case_id, m, body=new_body)
                        )

        # Query param XSS (V2.1: pre-encode payload for URL safety)
        for xss in all_xss[:10]:
            parsed = urlparse(endpoint.url)
            params = parse_qs(parsed.query)
            if "q" in params:
                params["q"] = [xss]
                new_query = urlencode(params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))
                m = Mutation(
                    mutation_type=MutationType.XSS_INJECTION,
                    description=f"XSS in query param: {xss[:40]}",
                    mutated_value=xss,
                    target_url_param="q",
                )
                mutations.append(
                    self._build_mutated_request(endpoint, test_case_id, m, url=new_url)
                )

        return mutations

    # -------------------------------------------------------------------------
    # Resource Exhaustion Mutations
    # -------------------------------------------------------------------------
    def _resource_exhaustion(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Generate resource exhaustion test requests."""
        mutations = []

        # Large SOQL queries
        soql_mods = payloads.get("soql_modifications", [])
        for soql in soql_mods:
            parsed = urlparse(endpoint.url)
            params = parse_qs(parsed.query)
            if "q" in params:
                params["q"] = [soql]
                new_query = urlencode(params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))
                m = Mutation(
                    mutation_type=MutationType.RESOURCE_EXHAUSTION,
                    description=f"Resource exhaustion: {soql[:60]}",
                    soql_payload=soql,
                    target_field="query_param",
                )
                mutations.append(
                    self._build_mutated_request(endpoint, test_case_id, m, url=new_url)
                )

        # Large payloads (V2.1: use _safe_json_body)
        large_payloads = payloads.get("large_payloads", [])
        for lp in large_payloads:
            field_len = lp.get("field_length", 100000)
            large_value = "A" * field_len
            if endpoint.request_body:
                try:
                    body_dict = json.loads(endpoint.request_body)
                    for key, val in body_dict.items():
                        if isinstance(val, str):
                            body_dict[key] = large_value
                            break
                    new_body = self._safe_json_body(body_dict)
                    m = Mutation(
                        mutation_type=MutationType.RESOURCE_EXHAUSTION,
                        description=f"Oversized payload: {field_len} chars",
                        mutated_value=large_value[:50],
                        target_field="body",
                    )
                    mutations.append(
                        self._build_mutated_request(endpoint, test_case_id, m, body=new_body)
                    )
                    break
                except (json.JSONDecodeError, TypeError):
                    pass

        return mutations

    # -------------------------------------------------------------------------
    # Transport Check Mutations
    # -------------------------------------------------------------------------
    def _transport_check(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Check transport security (TLS, HTTPS redirect)."""
        m = Mutation(
            mutation_type=MutationType.TRANSPORT_CHECK,
            description="Transport security check",
        )
        mutations = []
        http_urls = payloads.get("http_base_urls", [])
        for http_url in http_urls:
            new_url = endpoint.url.replace("https://", "http://")
            mutations.append(
                self._build_mutated_request(endpoint, test_case_id, m, url=new_url)
            )
        if not mutations:
            mutations.append(self._build_mutated_request(endpoint, test_case_id, m))
        return mutations

    # -------------------------------------------------------------------------
    # Session Fixation Mutations
    # -------------------------------------------------------------------------
    def _session_fixation(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Test session fixation via URL parameters."""
        mutations = []
        url_params = payloads.get(
            "url_token_params",
            payloads.get("url_params", ["sid", "token", "access_token"]),
        )
        for param in url_params:
            parsed = urlparse(endpoint.url)
            params = parse_qs(parsed.query)
            params[param] = ["fake_session_token_12345"]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            m = Mutation(
                mutation_type=MutationType.SESSION_FIXATION,
                description=f"Session fixation via URL param: {param}",
                mutated_value="fake_session_token_12345",
                target_url_param=param,
            )
            mutations.append(
                self._build_mutated_request(endpoint, test_case_id, m, url=new_url)
            )
        return mutations

    # -------------------------------------------------------------------------
    # Auth Enumeration Mutations
    # -------------------------------------------------------------------------
    def _auth_enumeration(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Test with weak/default credentials."""
        mutations = []
        weak_passwords = payloads.get("weak_passwords", [])
        # Add dynamic auth bypass payloads
        dynamic_auth = self.payload_manager.get_payloads("authentication_bypass", limit=10)

        all_passwords = list(weak_passwords) + dynamic_auth
        for pwd in all_passwords:
            m = Mutation(
                mutation_type=MutationType.AUTH_ENUMERATION,
                description=f"Test weak/bypass: {pwd[:40]}",
                mutated_value=pwd,
                target_field="password",
            )
            if endpoint.request_body:
                try:
                    body_dict = json.loads(endpoint.request_body)
                    if "password" in body_dict:
                        body_dict["password"] = pwd
                        new_body = self._safe_json_body(body_dict)
                        mutations.append(
                            self._build_mutated_request(endpoint, test_case_id, m, body=new_body)
                        )
                except (json.JSONDecodeError, TypeError):
                    pass
        return mutations

    # -------------------------------------------------------------------------
    # Business Logic Mutations
    # -------------------------------------------------------------------------
    def _business_logic_bypass(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Test business logic bypass with negative values."""
        mutations = []
        negative_values = payloads.get("negative_values", [])
        if not endpoint.request_body:
            return mutations
        try:
            body_dict = json.loads(endpoint.request_body)
        except (json.JSONDecodeError, TypeError):
            return mutations

        for nv in negative_values:
            field = nv.get("field", "")
            value = nv.get("value", -1)
            if field in body_dict:
                modified_body = copy.deepcopy(body_dict)
                modified_body[field] = value
                new_body = self._safe_json_body(modified_body)
                m = Mutation(
                    mutation_type=MutationType.BUSINESS_LOGIC_BYPASS,
                    description=f"Business logic bypass: {field}={value}",
                    original_value=str(body_dict.get(field)),
                    mutated_value=str(value),
                    target_body_param=field,
                )
                mutations.append(
                    self._build_mutated_request(endpoint, test_case_id, m, body=new_body)
                )

        bypass_sequences = payloads.get("bypass_sequences", [])
        for bypass in bypass_sequences:
            if isinstance(bypass, dict):
                for key, val in bypass.items():
                    modified_body = copy.deepcopy(body_dict)
                    modified_body[key] = val
                    new_body = self._safe_json_body(modified_body)
                    m = Mutation(
                        mutation_type=MutationType.BUSINESS_LOGIC_BYPASS,
                        description=f"Business logic bypass: {key}={val}",
                        mutated_value=str(val),
                        target_body_param=key,
                    )
                    mutations.append(
                        self._build_mutated_request(endpoint, test_case_id, m, body=new_body)
                    )
        return mutations

    # -------------------------------------------------------------------------
    # Forced Browsing Mutations
    # -------------------------------------------------------------------------
    def _forced_browsing(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Test forced browsing to admin paths."""
        mutations = []
        paths = payloads.get("paths_to_test", [])
        for path in paths:
            parsed = urlparse(endpoint.url)
            new_url = urlunparse(parsed._replace(path=path))
            m = Mutation(
                mutation_type=MutationType.FORCED_BROWSING,
                description=f"Forced browsing to: {path}",
                mutated_value=path,
                target_field="url_path",
            )
            mutations.append(
                self._build_mutated_request(
                    endpoint, test_case_id, m, url=new_url, method=HTTPMethod.GET
                )
            )
        return mutations

    # -------------------------------------------------------------------------
    # PII Check Mutations
    # -------------------------------------------------------------------------
    def _pii_check(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Check for PII exposure in responses (passthrough - evaluation handles it)."""
        m = Mutation(
            mutation_type=MutationType.PII_CHECK,
            description="PII exposure check",
        )
        return [self._build_mutated_request(endpoint, test_case_id, m)]

    # -------------------------------------------------------------------------
    # Race Condition Mutations
    # -------------------------------------------------------------------------
    def _race_condition(
        self, endpoint: APIEndpoint, test_case_id: str, payloads: dict,
        context: EndpointContext | None = None,
    ) -> list[MutatedRequest]:
        """Generate concurrent requests for race condition testing."""
        count = payloads.get("concurrent_requests", 5)
        mutations = []
        for i in range(count):
            m = Mutation(
                mutation_type=MutationType.RACE_CONDITION,
                description=f"Race condition request #{i + 1} of {count}",
            )
            mutations.append(
                self._build_mutated_request(endpoint, test_case_id, m)
            )
        return mutations
