"""Pydantic models for the SF API Security Testing Framework."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class EndpointCategory(str, Enum):
    AUTHENTICATION = "authentication"
    USER_DATA_CRUD = "user_data_crud"
    ADMIN_OPERATIONS = "admin_operations"
    DATA_QUERY = "data_query"
    FILE_UPLOAD = "file_upload"
    BUSINESS_LOGIC = "business_logic"
    TENANT_ISOLATION = "tenant_isolation"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class FindingVerdict(str, Enum):
    FINDING = "Finding"
    NOT_FINDING = "Not Finding"
    NA = "NA"
    ERROR = "Error"


class ConfidenceLevel(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class MutationType(str, Enum):
    BOLA_ID_SWAP = "bola_id_swap"
    BOLA_QUERY_SWAP = "bola_query_swap"
    HEADER_REMOVAL = "header_removal"
    HEADER_VALUE_INJECTION = "header_value_injection"
    METHOD_CHANGE = "method_change"
    METHOD_OVERRIDE = "method_override"
    SOQL_INJECTION = "soql_injection"
    SOSL_INJECTION = "sosl_injection"
    CORS_TEST = "cors_test"
    HEADER_CHECK = "header_check"
    PATH_TRAVERSAL = "path_traversal"
    ERROR_ENUMERATION = "error_enumeration"
    VERSION_ENUMERATION = "version_enumeration"
    SSRF_INJECTION = "ssrf_injection"
    MASS_ASSIGNMENT = "mass_assignment"
    STORED_XSS = "stored_xss"
    XSS_INJECTION = "xss_injection"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    TRANSPORT_CHECK = "transport_check"
    SESSION_FIXATION = "session_fixation"
    AUTH_ENUMERATION = "auth_enumeration"
    BUSINESS_LOGIC_BYPASS = "business_logic_bypass"
    FORCED_BROWSING = "forced_browsing"
    PII_CHECK = "pii_check"
    RACE_CONDITION = "race_condition"


# ---------------------------------------------------------------------------
# Core Data Models
# ---------------------------------------------------------------------------
class APIEndpoint(BaseModel):
    """Represents a discovered API endpoint from HAR analysis."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    url: str
    method: HTTPMethod
    path: str
    query_string: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    request_content_type: Optional[str] = None
    response_status: int = 0
    response_body: Optional[str] = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    sf_ids: list[str] = Field(default_factory=list)
    sf_api_version: Optional[str] = None
    sf_object_type: Optional[str] = None
    portal_name: str = ""
    categories: list[EndpointCategory] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_har_entry: Optional[dict[str, Any]] = None


class Mutation(BaseModel):
    """Describes a single mutation to apply to a request."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    mutation_type: MutationType
    description: str = ""
    original_value: Optional[str] = None
    mutated_value: Optional[str] = None
    target_field: str = ""
    target_header: Optional[str] = None
    target_body_param: Optional[str] = None
    target_url_param: Optional[str] = None
    soql_payload: Optional[str] = None
    http_method_override: Optional[str] = None


class MutatedRequest(BaseModel):
    """A fully-formed mutated HTTP request ready for execution."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    endpoint_id: str
    test_case_id: str
    mutation_id: str
    url: str
    method: HTTPMethod
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    content_type: Optional[str] = None
    cookies: dict[str, str] = Field(default_factory=dict)
    mutation_description: str = ""


class HttpRequest(BaseModel):
    """Captured raw HTTP request."""
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    cookies: dict[str, str] = Field(default_factory=dict)
    http_version: str = "HTTP/1.1"


class HttpResponse(BaseModel):
    """Captured raw HTTP response."""
    status_code: int
    status_text: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    http_version: str = "HTTP/1.1"
    content_length: int = 0


class Evidence(BaseModel):
    """Bundled evidence from a single test execution."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    test_case_id: str
    endpoint_id: str
    mutation_id: str
    mutated_request_id: str
    request: HttpRequest
    response: HttpResponse
    screenshot_path: Optional[str] = None
    execution_time_ms: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_request_text: Optional[str] = None
    raw_response_text: Optional[str] = None


class FindingResult(BaseModel):
    """The evaluated result of a single test case against an endpoint."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    test_case_id: str
    test_name: str
    endpoint_id: str
    endpoint_url: str
    endpoint_method: str
    portal_name: str
    owasp_category: str
    owasp_name: str
    severity: Severity
    verdict: FindingVerdict
    confidence: ConfidenceLevel
    reasoning: str
    evidence: Optional[Evidence] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error_message: Optional[str] = None


# ---------------------------------------------------------------------------
# Report Models
# ---------------------------------------------------------------------------
class ExecutiveSummary(BaseModel):
    """Summary statistics for the report."""
    total_tests: int = 0
    total_endpoints: int = 0
    findings_count: int = 0
    not_findings_count: int = 0
    na_count: int = 0
    errors_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None
    portals_tested: list[str] = Field(default_factory=list)


class TestReport(BaseModel):
    """Complete test report."""
    project_name: str = ""
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    executive_summary: ExecutiveSummary = Field(default_factory=ExecutiveSummary)
    findings: list[FindingResult] = Field(default_factory=list)
    all_results: list[FindingResult] = Field(default_factory=list)
