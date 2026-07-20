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
    POTENTIAL_FINDING = "Potential Finding"
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
    # Injection point metadata (V3.2: for telemetry headers)
    injection_field: str = ""       # e.g., "q", "IsDeleted", "recordId"
    injection_location: str = ""    # query | json_body | form_body | url_path | header | cookie | multipart


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
    # LLM verification fields (populated by LLMVerifier)
    llm_verified: bool = False
    llm_verdict: Optional[str] = None          # TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_MANUAL_REVIEW
    llm_confidence: Optional[float] = None     # 0.0 - 1.0
    llm_reasoning: Optional[str] = None
    llm_remediation: Optional[str] = None      # Salesforce-specific remediation advice
    # Visual DAST fields (populated by VisualAuditor)
    visual_verdict: Optional[str] = None       # CONFIRMED_XSS / REFLECTED_NOT_EXECUTED / DATA_EXPOSURE / INCONCLUSIVE / CLEAN
    visual_confidence: Optional[float] = None  # 0.0 - 1.0
    visual_reasoning: Optional[str] = None
    visible_evidence: Optional[str] = None     # What the VLM sees in the screenshot
    element_outer_html: Optional[str] = None   # DOM snippet around injection point


# ---------------------------------------------------------------------------
# Report Models
# ---------------------------------------------------------------------------
class ExecutiveSummary(BaseModel):
    """Summary statistics for the report."""
    total_tests: int = 0
    total_endpoints: int = 0
    findings_count: int = 0
    not_findings_count: int = 0
    potential_findings_count: int = 0
    na_count: int = 0
    errors_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    llm_true_positives: int = 0
    llm_false_positives: int = 0
    llm_manual_review: int = 0
    visual_findings_count: int = 0
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
    site_map: Optional["SiteMap"] = None
    feature_inventory: Optional["FeatureInventory"] = None


# ---------------------------------------------------------------------------
# V3.0: Autonomous Exploration Models
# ---------------------------------------------------------------------------
class AuditEvent(BaseModel):
    """A single audit trail event during exploration or testing."""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    action: str               # navigate | click | fill | submit | llm_call | probe | screenshot | error
    target: str = ""          # URL, field name, or description
    result: str = ""          # success | fail | timeout | skip
    details: str = ""         # additional context
    role: str = ""            # which role performed the action (for role comparison)


class InputFieldInfo(BaseModel):
    """An input field discovered on a page."""
    name: str
    field_type: str          # text | select | file | richtext | search | textarea | checkbox | radio
    label: str = ""
    risk_type: str = "none"  # xss | sqli | ssrf | none
    placeholder: str = ""
    max_length: Optional[int] = None


class PageSnapshot(BaseModel):
    """A single page discovered during autonomous exploration."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    url: str
    title: str = ""
    page_purpose: str = ""
    page_category: str = "other"  # dashboard | list_view | record_detail | form | settings | admin | login | other
    features: list[str] = Field(default_factory=list)
    input_fields: list[InputFieldInfo] = Field(default_factory=list)
    navigation_targets: list[str] = Field(default_factory=list)
    sensitive_data_visible: bool = False
    sensitive_data_description: str = ""
    role_indicators: str = ""
    api_endpoints_inferred: list[str] = Field(default_factory=list)
    analysis_confidence: float = 0.0
    screenshot_path: Optional[str] = None
    dom_summary: str = ""
    visible_text: str = ""
    depth: int = 0
    parent_url: Optional[str] = None
    navigation_method: str = ""  # link | button | tab | url
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SiteMap(BaseModel):
    """Complete site map from autonomous exploration."""
    pages: list[PageSnapshot] = Field(default_factory=list)
    total_pages: int = 0
    total_input_fields: int = 0
    categories: dict[str, int] = Field(default_factory=dict)
    sensitive_pages: list[str] = Field(default_factory=list)
    exploration_duration_seconds: float = 0.0
    audit_log: list[AuditEvent] = Field(default_factory=list)


class RiskSurface(BaseModel):
    """A risk area identified from the feature inventory."""
    risk_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    risk_type: str              # xss | sqli | ssrf | bola | mass_assignment | file_upload | admin_bypass
    pages: list[str] = Field(default_factory=list)  # page IDs
    input_fields: list[InputFieldInfo] = Field(default_factory=list)
    recommended_tests: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM


class WorkflowStep(BaseModel):
    """A single step in a multi-step business workflow."""
    step_number: int
    url: str
    action_description: str = ""  # e.g., "Enter Shipping Info"
    state_parameters: list[str] = Field(default_factory=list)  # Hidden fields, tokens, flow IDs
    page_id: str = ""  # Reference to PageSnapshot.id


class WorkflowModel(BaseModel):
    """A complete multi-step business workflow (state machine)."""
    workflow_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    steps: list[WorkflowStep] = Field(default_factory=list)
    entry_point: str = ""  # URL of first step
    exit_point: str = ""   # URL of final step
    detected_via: str = ""  # heuristic | vision_llm | navigation_pattern
    confidence: float = 0.0
    api6_test_results: dict[str, str] = Field(default_factory=dict)  # test_id -> PASS|FAIL|NA


class FeatureInventory(BaseModel):
    """Aggregated risk surface from exploration."""
    pages_by_category: dict[str, list[str]] = Field(default_factory=dict)
    all_input_fields: list[InputFieldInfo] = Field(default_factory=list)
    risk_surfaces: list[RiskSurface] = Field(default_factory=list)
    role_differences: dict[str, Any] = Field(default_factory=dict)
    workflows: list[WorkflowModel] = Field(default_factory=list)
    total_risks: int = 0
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0

    def to_markdown(self) -> str:
        """Generate a human-readable Markdown feature document."""
        lines = [
            "# Application Feature Inventory\n",
            f"**Total Pages:** {sum(len(v) for v in self.pages_by_category.values())}",
            f"**Total Input Fields:** {len(self.all_input_fields)}",
            f"**Risk Surfaces:** {self.total_risks} "
            f"({self.high_risk_count} high, {self.medium_risk_count} medium, {self.low_risk_count} low)\n",
        ]

        # Pages by category
        lines.append("## Pages by Category\n")
        for cat, page_ids in self.pages_by_category.items():
            lines.append(f"### {cat} ({len(page_ids)} pages)\n")
            for pid in page_ids:
                lines.append(f"- Page `{pid}`")
            lines.append("")

        # Input fields summary
        lines.append("## Input Fields Summary\n")
        risk_counts: dict[str, int] = {}
        for f in self.all_input_fields:
            risk_counts[f.risk_type] = risk_counts.get(f.risk_type, 0) + 1
        for risk, count in sorted(risk_counts.items(), key=lambda x: -x[1]):
            lines.append(f"- **{risk}**: {count} field(s)")
        lines.append("")

        # Risk surfaces
        if self.risk_surfaces:
            lines.append("## Risk Surfaces\n")
            for risk in self.risk_surfaces:
                lines.append(
                    f"### {risk.risk_type.upper()} — Severity: {risk.severity.value}"
                )
                lines.append(f"- Affected pages: {len(risk.pages)}")
                lines.append(f"- Input fields at risk: {len(risk.input_fields)}")
                lines.append(f"- Recommended tests: {', '.join(risk.recommended_tests)}")
                lines.append("")

        # Role differences
        if self.role_differences:
            lines.append("## Role Differences\n")
            for role, diff in self.role_differences.items():
                lines.append(f"### {role}")
                if isinstance(diff, dict):
                    for key, val in diff.items():
                        lines.append(f"- {key}: {val}")
                else:
                    lines.append(f"- {diff}")
                lines.append("")

        return "\n".join(lines)

    def to_json(self) -> str:
        """Generate a machine-readable JSON representation."""
        return self.model_dump_json(indent=2)


class PlannedTest(BaseModel):
    """A single test planned from the feature inventory."""
    test_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    test_type: str              # safe_probe | real_mutation | visual_dast
    risk_type: str              # xss | sqli | ssrf | bola | etc.
    target_page_id: str
    target_url: str
    target_field: str = ""
    payload_category: str = ""
    payload: str = ""           # For safe probes: the probe string; for mutations: the real payload
    http_method: str = "POST"
    description: str = ""


class TestPlan(BaseModel):
    """Complete test plan generated from the feature inventory."""
    planned_tests: list[PlannedTest] = Field(default_factory=list)
    total_probes: int = 0
    total_mutations: int = 0
    risk_coverage: dict[str, int] = Field(default_factory=dict)
