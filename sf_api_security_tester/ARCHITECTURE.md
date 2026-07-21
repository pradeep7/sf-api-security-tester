# Salesforce API Security Tester — Architecture & Developer Guide (V4.0)

Welcome to the **Salesforce API Security Tester V4.0: The Governed Agentic Control Plane**. This guide is designed for security engineers, developers, and maintainers to deeply understand the framework's architecture, core components, and data flow.

---

## 1. High-Level Architecture Overview

This framework is an **autonomous, context-aware AI security agent** specifically tailored for Salesforce portals (Assist/Tenant portals, Communities, etc.). Unlike traditional scanners that passively replay recorded traffic, V3.1 **actively explores the live application** like a human would — clicking every link, understanding every page, mapping every role — and *then* tests intelligently.

It operates as a **9-phase governed pipeline**: it autonomously discovers the application surface, enforces the Bible v7.1 workbook schema via a Governance Engine, builds a feature inventory, executes safe probes to identify reflection points, fires real attack mutations, uses a **Hybrid AI Engine** (Text LLMs and Vision LLMs) to verify findings and eliminate false positives, and generates comprehensive reports with auto-generated AI prompts for developer remediation.

### **The Pipeline (Orchestrator)**

The entire flow is managed by `src/orchestrator.py`. The execution lifecycle follows these phases:

| Phase | Name | Module(s) | Purpose |
|-------|------|-----------|---------|
| **-1** | HAR Generation | `har_generator.py` | Records live browser traffic as HAR via Playwright native recording (with proxy support) |
| **0** | Autonomous Explore | `autonomous_explorer.py` | Playwright BFS discovers every page; Vision LLM understands context; Smart SSO/MFA fallback |
| **0.5** | Feature Inventory & Safe Probing | `feature_inventory.py`, `test_planner.py`, `safe_executor.py`, `dom_xss_auditor.py` | Maps risk surfaces; executes harmless canary probes to verify reflection |
| **1** | HAR Parse + Smart Analysis | `har_parser.py`, `har_analyzer.py` | Parses browser traffic; LLM-powered deep API intelligence analysis |
| **1.5** | Governance Engine | `governance_engine.py` | Enforces Bible v7.1 schema: signal matching, dependency circuit breakers, exclusion checking, evidence validation |
| **2** | Classify & Plan | `endpoint_classifier.py`, `test_case_engine.py` | Categorizes endpoints; maps OWASP rules to attack surfaces |
| **3** | Execute Mutations | `mutation_engine.py`, `executor.py` | Sends real attack payloads with WAF evasion, telemetry headers, and request limits |
| **4** | LLM Triage | `llm_verifier.py` | Text LLM confirms/rejects `POTENTIAL_FINDING` verdicts |
| **5** | Visual DAST | `visual_auditor.py` | Vision LLM analyzes screenshots for DOM XSS and data exposure |
| **6** | Report & AI Prompt Bridge | `report_generator.py`, `prompt_generator.py` | HTML/JSON reports + auto-generated redacted AI prompts for developer remediation |

---

## 1.5 The Data-Driven Workflow (How it Works)

Unlike older security frameworks that rely on hardcoded Python scripts for every vulnerability (e.g., a specific Python class just to test BOLA on a single endpoint), this V3.0 architecture uses a **Data-Driven Mutation Engine** combined with **Autonomous AI Reconnaissance**.

Here is how the framework handles vulnerabilities without requiring custom Python code for each test:

1. **The Eyes (Phase 0 — Autonomous Explorer)**: The framework logs into the Salesforce portal, then uses Playwright's BFS to click every `<a>`, `<button>`, and Lightning tab. At each page, it captures a screenshot and DOM summary, then sends both to a Vision LLM that categorizes the page (dashboard, list_view, form, admin, etc.) and identifies input fields with their risk types. This builds a complete **SiteMap** — the attack surface model.

2. **The Brain (Phase 0.5 — Feature Inventory & Safe Probing)**: The `FeatureInventoryBuilder` aggregates the SiteMap into risk surfaces (e.g., "3 search fields across 5 pages → SOQL Injection risk"). The `SmartTestPlanner` generates a prioritized test plan. The `SafePayloadExecutor` then executes **harmless probes** (e.g., `SF_XSS_PROBE_7f3a`) to verify which fields actually reflect input — without sending real attacks yet.

3. **The Blueprint (YAML Rules)**: All attack rules are stored in `testcases/owasp_api_top10.yaml`. A rule simply describes the attack conceptually (e.g., "Find an endpoint with a Salesforce Record ID and swap it with another tenant's ID").

4. **The Factory (Phase 3 — MutationEngine)**: The engine reads the HAR file and the YAML blueprint. It automatically mutates the legitimate requests into hundreds of context-aware attack requests on the fly (manipulating URLs, headers, or JSON bodies).

5. **The Local Detective (Phase 3 — FindingEvaluator)**: The framework fires the mutated requests and examines the responses. If a response matches the vulnerable criteria (e.g., returning 200 OK with leaked data), it flags a `POTENTIAL_FINDING`.

6. **The AI Senior Engineer (Phase 4 — LLMVerifier)**: To eliminate false positives, the AI brain reviews the `POTENTIAL_FINDING`. It acts as a senior engineer, analyzing the raw HTTP evidence to confirm if the vulnerability is a true exploit or a normal server error. Salesforce-specific context (OWD, Sharing Rules) prevents hallucinated BOLA findings.

7. **The Visual Auditor (Phase 5 — VisualAuditor)**: Uses Vision LLMs to analyze Playwright screenshots, confirming whether XSS payloads actually rendered in the DOM or if PII is visually exposed in the UI.


## 1.6 Attack Surface Synthesis & Traceability

The framework's true power lies in how it synthesizes multiple discovery methods into a single, unified attack surface, and how every finding is 100% traceable back to its origin.

### Three Paths to Endpoint Discovery
The framework supports three distinct ways to discover the target's attack surface, all of which merge into the same execution pipeline:

| Path | Method | Output | Best Use Case |
|------|--------|--------|---------------|
| **Path 1: Autonomous Explorer** (Phase 0) | Playwright BFS crawl + Vision LLM analysis | `SiteMap` (pages, forms, inputs, risk types, LLM context) | Greenfield testing, discovering hidden UI features and complex SSO flows. |
| **Path 2: Manual HAR** (Phase 1) | User browses manually → Exports `.har` from browser | `APIEndpoint` list (URLs, methods, bodies, headers, SF IDs) | Targeted testing of specific, known workflows or complex multi-step transactions. |
| **Path 3: Live HAR Recording** (Phase -1) | `python main.py --generate-har --target <url> --manual-auth` | Same as Path 2, but auto-captured and proxy-routed | Quick, repeatable traffic capture without manual browser dev-tools export. |

**The Key Insight:** Path 1 discovers *WHAT* the app does (pages, forms, features). Paths 2 & 3 discover *HOW* it communicates (API calls, tokens, request bodies). Together, they provide a complete, 360-degree view of the attack surface.

### Weaponizing Recon for OWASP-Aligned Testing
The `test_planner.py` does not guess; it generates smarter, OWASP-aligned tests based *exactly* on what the recon phase discovered:

| Recon Discovery | Test Generated | OWASP Category |
|-----------------|----------------|----------------|
| File upload input | `path_traversal` probe on upload field | A04: Insecure Design |
| Comment / Rich-text field | `stored_xss` probe on textarea | A03: Injection |
| Admin / Settings page | `bfla` probe (privilege escalation) | API3: Broken Function Level Auth |
| Profile / User page | `bola` probe (swap user IDs) | API1: Broken Object Level Auth |
| Record detail page | `bola` probe (swap record IDs) | API1: Broken Object Level Auth |
| Sensitive data visible | `pii_check` (verify data exposure) | A02: Cryptographic Failures |
| Search / Filter input | `soql_injection` probe | A03: Injection |
| URL-accepting field | `ssrf` probe | API7: SSRF |
| Delete / Archive button | `admin_bypass` probe | API3: BFLA |

### The Traceability Flow
Every single test is mathematically traceable from discovery to the final report:

```text
1. Recon: Finds "Search" input on "Contact List" page
   ↓
2. Context Router: Identifies "This is a SOQL query field"  
   ↓
3. Test Planner: Generates "SOQL injection probe" strategy
   ↓
4. Mutation Engine: Fetches dynamic SQLi payloads from PayloadManager
   ↓
5. Executor: Sends `SF_SQLI_PROBE_xxx` with `X-SecTest-OWASP: A03` header
   ↓
6. Evaluator: Checks if probe reflected in DOM (Local Detective)
   ↓
7. Visual Auditor: Verifies with Vision LLM screenshot analysis
   ↓
8. Report: Generates finding mapped to "API1 BOLA + A03 SQLi on Contact List search"

---

## 1.7 The V4.0 Governance Layer & Bible v7.1

V4.0 introduces a **strict enforcement engine** that transforms the framework from a "smart scanner" into a **governed security testing platform**. Every test must comply with the `API_Security_Testing_Bible_v7_1` workbook before execution.

### The Bible v7.1: 12 Domains, 483 Tests

| # | Security Domain | Tests | Focus Area |
|---|-----------------|-------|------------|
| 1 | Identity, Authentication & Session | 79 | API Keys, MFA, Password Recovery, Session Management |
| 2 | Record & Tenant Access (BOLA / IDOR) | 22 | Object Identifier Authorisation, Cross-Tenant Isolation |
| 3 | Privilege & Function Boundaries (BFLA) | 35 | Admin Bypass, Method Tampering, Workflow State Enforcement |
| 4 | Field, Property & Payload Authorisation | 34 | Mass Assignment, Field-level Read Controls, Over-posting |
| 5 | Input, Parser & Query Safety | 115 | Injection, Content Types, Boundaries, Deserialisation |
| 6 | Data Exposure, Privacy & Cryptography | 21 | Response Minimisation, Secrets, Encryption, Pagination |
| 7 | Guest, File & Public Surface Security | 24 | Guest APIs, File Uploads, Public Links, Archives |
| 8 | Integration & Trust Boundary Security | 47 | SSRF, Callbacks, Delegated Credentials, Downstream Auth |
| 9 | Abuse Resistance, Logging & Monitoring | 15 | Rate Limits, Quotas, Security Logging, Correlation |
| 10 | Business Logic & Transaction Integrity | 20 | Concurrency, Replay, Idempotency, Multi-step Atomicity |
| 11 | Configuration, Inventory & Engineering Assurance | 64 | API Inventory, Deprecation, Secrets Management, Drift Detection |
| 12 | Client, Platform & General API Assurance | 7 | CORS, Browser Headers, Client Storage, Protocol Contracts |
| **TOTAL** | **12 Domains** | **483 Tests** | **267 Critical/High Priority \| 32 Foundation Tests** |

### Governance Engine Features

- **Signal-Based Applicability:** Tests only run if `required_signals` (e.g., `authenticated_operation`, `record_identifier`) are found in the HAR/Explorer data. Otherwise, they are marked `Not Applicable` or `Not Observed`.
- **The Circuit Breaker:** If a blocking prerequisite (e.g., `API-AUTH-001`) fails, all dependent tests are immediately marked `Blocked` to prevent wasted execution.
- **Strict Evidence Validation:** A test cannot pass/fail unless all `evidence_required` items are captured. Missing evidence = Blocked status.
- **Request Limits:** The executor tracks requests per `test_id` and stops at `maximum_requests`.
- **Human-in-the-Loop Gate:** Tests with `requires_human_approval: true` pause the CLI for explicit confirmation.

---

## 2. Core Modules Deep Dive

The codebase is highly modular and strictly typed using **Pydantic** (`src/models.py`), which acts as the glue for data passing between layers.

### 2.1 The Data Models (`src/models.py`)

This is the heart of the framework's type safety. Key models include:

- `APIEndpoint`: Represents a discovered API route from HAR parsing.
- `Mutation` / `MutatedRequest`: Represents a single attack payload and the fully-formed HTTP request ready to be sent.
- `Evidence`: Bundles the raw HTTP request, response, timing, and screenshot paths.
- `FindingResult`: The final evaluated result containing verdicts (`FINDING`, `POTENTIAL_FINDING`, `NOT_FINDING`, `ERROR`) and LLM reasoning.
- `PageSnapshot`: A single page discovered during autonomous exploration, with LLM analysis results.
- `SiteMap`: Complete site map from exploration, containing all `PageSnapshot` objects and the structured audit log.
- `FeatureInventory`: Aggregated risk surface mapping pages to risk types (XSS, SQLi, SSRF, BOLA).
- `TestPlan` / `PlannedTest`: Structured test plan with safe probes and real mutation strategies.
- `AuditEvent`: Timestamped record of every navigation, click, probe, and LLM call for compliance.

### 2.2 HAR Generator (`src/har_generator.py`)

Phase -1: Captures live browser traffic as HAR files using Playwright's native recording.

- Uses `context.record_har_path` and `context.record_har_mode` for native HAR capture
- Routes traffic through upstream proxy (ZAP/Caido/Burp) via `proxy={"server": url}`
- **Manual mode:** Opens headed browser, waits for user to browse, saves HAR on ENTER
- **Auto mode:** Simple BFS clicking `<a>` links (max 5 pages) to generate baseline traffic
- Finalizes HAR on `context.close()` — Playwright handles the actual file writing

### 2.3 The Autonomous Explorer (`src/autonomous_explorer.py`)

The "Eyes" of the system. This module uses Playwright to drive a real browser through the Salesforce Lightning portal.

**Smart Recon Flow (V3.1):**
1. Try automated login with provided credentials
2. If SSO/MFA detected → open separate headed browser for manual login
3. After manual login → extract cookies, inject into main context, verify
4. If manual login fails → explore as guest
5. BFS-crawl every page/tab, respecting domain scope

**Login Flow:**
- Reads credentials from `config/credentials.yaml`
- `_smart_login()`: tries automated login with SF-specific selectors (`#username`, `#password`, `#Login`)
- Handles "Remember this browser" prompt automatically
- Detects MFA/2FA → opens separate headed browser, pauses for user, extracts cookies
- `_manual_login()`: opens visible browser for SSO/JIT/MFA, waits for ENTER, extracts cookies via `context.cookies()`, injects into main session
- Verifies login success by checking URL doesn't contain `/login`

**BFS Navigation:**
- Maintains a queue of `(url, depth, parent_url)` tuples
- At each page: extracts DOM summary, visible text, all `<input>`/`<select>`/`<textarea>` fields
- Handles Salesforce Lightning SPA navigation using `page.wait_for_selector('.oneAppLauncher, .slds-page-header')`
- Limits to `max_pages` (default 100) and `max_depth` (default 5)
- Scope check: prevents following external links out of domain

**V3.1 Enhanced Data Capture (per page):**
- **Response headers**: Status codes from performance API
- **Network interception**: Captures XHR/Fetch requests via `page.on('request')`
- **localStorage/sessionStorage**: Extracts cached tokens and settings
- **iframe content**: Detects embedded Salesforce components
- **SF metadata**: Object types, record IDs, Aura components, field names from DOM
- **Page characteristics**: File uploads, comment boxes, rich text editors, delete/save buttons, admin/profile indicators, PII detection

**Vision LLM Page Understanding:**
- Sends each page screenshot + enhanced DOM summary to a Vision LLM
- LLM returns strict JSON with 16 fields: `page_purpose`, `page_category`, `features`, `input_fields`, `navigation_targets`, `sensitive_data_visible`, `sensitive_data_description`, `role_indicators`, `api_endpoints_inferred`, `file_upload_detected`, `comment_or_state_change_detected`, `admin_or_settings_page`, `profile_page`, `destructive_actions`, `state_change_actions`, `confidence`
- Robust 3-tier JSON parsing: strip markdown → extract `{...}` → fallback to `INCONCLUSIVE`

**Output:** A complete `SiteMap` object with all `PageSnapshot`s, enhanced DOM summaries, and a structured `audit_log`.

### 2.4 Smart HAR Analyzer (`src/har_analyzer.py`)

LLM-powered deep inspection of HAR traffic that goes beyond regex parsing.

**How it works:**
1. `har_parser.py` extracts raw endpoints (URLs, methods, bodies, SF IDs) — fast, zero-cost
2. `har_analyzer.py` sends a concise endpoint summary to the LLM and asks it to determine:
   - **Purpose** of each endpoint (what business function it serves)
   - **Auth mechanism** (Bearer, Session, Cookie, SAML)
   - **Sensitive data** exposure (PII, credentials, internal IDs)
   - **Risk level** (low/medium/high/critical)
   - **Attack surface** (which OWASP categories apply)
   - **Business logic** (observable rules like "requires AccountId", "filters by OwnerId")
3. LLM returns a structured JSON intelligence report with:
   - Per-endpoint analysis
   - Overall assessment: `app_type`, `auth_pattern`, `data_classification`, `attack_priority`

**Token economy:** Endpoints are chunked (50 per LLM call). Results are cached via MD5 hash. If LLM is disabled, returns a heuristic analysis (no tokens spent).

### 2.5 Feature Inventory & Test Planning (`src/feature_inventory.py`, `src/test_planner.py`)

**FeatureInventoryBuilder** aggregates the SiteMap into:
- `pages_by_category`: Pages grouped by LLM-assigned category
- `all_input_fields`: Flat list of every input field across all pages
- `risk_surfaces`: Risk type → pages/fields mapping (XSS, SQLi, SSRF, BOLA, admin_bypass)
- `role_differences`: If multiple roles were explored, the mathematical diff

**SmartTestPlanner** maps risk surfaces to test strategies:
- Search inputs → SOQL/SOSL injection tests
- Rich text/text inputs → XSS tests
- File inputs → Path traversal / upload tests
- Record IDs in URLs → BOLA/IDOR tests
- Admin pages → Privilege escalation tests
- Tests are sorted by severity (Critical → High → Medium → Low)

**Export Methods:**
- `to_markdown()`: Generates a human-readable Markdown feature document
- `to_json()`: Machine-readable JSON via Pydantic's `model_dump_json()`

### 2.6 Triple-Verified DOM XSS Auditor (`src/dom_xss_auditor.py`)

The most innovative module — tests for DOM-based XSS using **zero-token local checks** before involving the LLM.

**Safe Probes (NON-MALICIOUS — never execute harmful code):**
```python
SAFE_DOM_PROBES = [
    ("{{7*7}}", "49", "Template injection probe"),
    ("${7*7}", "49", "EL injection probe"),
    ("<marquee>DOMTEST</marquee>", "DOMTEST", "Marquee visual probe"),
    ("<b>DOMBOLD</b>", "DOMBOLD", "Bold tag reflection probe"),
    ("<h1>DOMH1</h1>", "DOMH1", "H1 tag reflection probe"),
    ('" data-testid="domprobe', "domprobe", "Attribute breakout probe"),
    ("javascript:void(0)", "javascript:", "JS protocol probe"),
]
```

**Triple Verification Flow:**
1. **DOM Check (0 tokens):** `page.evaluate("document.body.innerHTML.includes('probe')")` — Checks if the raw payload text appears unsanitized in the DOM.
2. **Execution Check (0 tokens):** `page.evaluate("document.querySelectorAll('marquee, b, h1').length > 0")` — Checks if HTML tags from the probe actually rendered as DOM elements.
3. **Visual Check (Vision LLM):** If either local check passes, takes a screenshot and sends it to the Vision LLM for final confirmation. This is the only step that costs tokens.

**Cost Control:** Limits total screenshots per scan (`max_screenshots_per_run: 50`). Prioritizes pages with input fields over static pages.

### 2.7 Safe Executor (`src/safe_executor.py`)

Executes the safe probes from the TestPlan using Playwright.

- Navigates to target pages, finds input fields by name/id/selector
- Fills fields with safe probe strings (`SF_XSS_PROBE_{uuid}`, `SF_SQLI_PROBE_{uuid}`)
- Submits forms, waits for response, captures screenshots
- Checks DOM for probe reflection: `document.body.outerHTML.includes(probe_payload)`
- If reflected → flags as `POTENTIAL_FINDING` for Phase 3 real mutation escalation

**Safety Rules:**
- NEVER sends real destructive payloads during exploration
- NEVER deletes records, modifies production data, or triggers real actions
- Always uses test/sandbox credentials
- Every action is logged to the `AuditEvent` audit trail

### 2.8 Payload Generation & Mutation

- **`src/mutation_engine.py`**: The core factory that dynamically manipulates HTTP requests. Knows how to inject payloads into headers, query strings, JSON bodies, or perform HTTP method overrides. Uses `PayloadManager` for dynamic payload fetching and `ContextRouter` for Salesforce-aware injection.
- **`src/payload_manager.py`**: Manages the retrieval and caching of dynamic payloads from external sources (SecLists, PayloadsAllTheThings). Checks file modification time; only re-fetches if older than 7 days.
- **`src/context_router.py`**: Analyses endpoints using regex/heuristics to determine the injection type (SOQL, XSS, SSRF, BOLA) and the exact injection points (URL params, body fields, headers).

### 2.9 Network Execution & WAF Evasion

- **`src/executor.py`**: The network layer handling outbound HTTP requests via `EvasionClient`.
- **`src/waf_evasion.py`**: Integrates with the executor. Detects WAF blocks (HTTP 403/429, signature matching for Cloudflare/Akamai/AWS WAF), applies exponential backoff, rotates User-Agents, and detects Salesforce API limits (`REQUEST_LIMIT_EXCEEDED`) to halt execution before org lockout.

### 2.10 Evidence & Proof

- **`src/evidence_collector.py`**: Saves raw request and response dumps to disk. Truncates response bodies to 50KB and request bodies to 10KB to prevent evidence bloat. Appends `[TRUNCATED BY FRAMEWORK]` markers.
- **`src/screenshot_capture.py`**: Uses Playwright to capture screenshots and extract DOM `outerHTML` around injection points for Visual DAST analysis.

### 2.11 Hybrid AI Verification Layer

**Text LLM Triage (`src/llm_verifier.py`):**
- Takes the `POTENTIAL_FINDING` queue (only anomalies, never passed tests)
- Truncates HTTP bodies to 2000 chars (Cost Control)
- Prompts with strict JSON schema: `{verdict, confidence_score, reasoning, salesforce_remediation}`
- Includes Salesforce-specific context to prevent OWD/Sharing Rule hallucinations
- Caches identical prompts via MD5 hash to avoid redundant LLM calls

**Vision LLM DAST (`src/visual_auditor.py`):**
- Cost Control Gate: Only processes findings where `status == POTENTIAL_FINDING` AND `screenshot_path` is not None AND the payload is actually present in the response body
- Dual-Context Prompt: Base64 screenshot + exact payload + DOM `outerHTML` (truncated to 2000 chars)
- Verdicts: `CONFIRMED_XSS`, `REFLECTED_NOT_EXECUTED`, `DATA_EXPOSURE`, `INCONCLUSIVE`, `CLEAN`
- Robust 3-tier JSON parsing and MD5 prompt caching

### 2.12 Multi-Role Comparison (`src/role_manager.py`)

Enables privilege escalation detection by comparing what different user roles can see.

- **`RoleManager`**: Creates isolated `RoleSession` objects, each with its own Playwright browser context (complete cookie/session isolation)
- **`RoleSession`**: Holds `page`, `context`, `browser`, `verified` flag, and `audit_log`
- **`login_session()`**: Uses `browser.new_context()` per role — no cookie bleeding between Admin and Standard User
- **`_verify_role()`**: Checks the Salesforce user profile page for role indicators (System Administrator, Standard User, etc.)
- **Role diff**: Mathematical set comparison of discovered pages — identifies pages only visible to Admin but not Standard User

### 2.13 The Audit Trail

Every action is timestamped and logged via the `AuditEvent` dataclass:
- `timestamp`: When the event occurred
- `action`: What was done (`navigate`, `click`, `fill`, `submit`, `llm_call`, `probe`, `screenshot`, `error`)
- `target`: The URL, field name, or description
- `result`: `success`, `fail`, `timeout`, `skip`
- `details`: Additional context (e.g., "depth=3, category=form")
- `role`: Which role performed the action (for role comparison)

The `SiteMap.audit_log` field stores all events for the scan. This provides complete compliance evidence of what was tested and when.

### 2.14 Governance Engine (`src/governance_engine.py`)

The Governance Engine enforces the Bible v7.1 workbook schema before any test is executed.

**Signal-Based Applicability:** Each test has `required_signals` (e.g., `["authenticated_operation", "record_identifier"]`). The engine compares these against the FeatureInventory and ContextRouter output. If a signal is missing, the test is marked `Not Applicable` with the reason: *"Missing required signal: [signal_name]"*.

**Exclusion Checking:** If `exclusion_evidence` is found in the HAR/Exploration data, the test is marked `Not Applicable`.

**Circuit Breaker (Dependencies):** Before scheduling a test, the engine checks its `blocking` dependencies. If any blocking test has a status of `Failed` or `Blocked`, the current test is immediately marked `Blocked` with: *"Invalidated by failed prerequisite: [blocking_test_id]"*.

**Evidence Validation:** A test cannot be marked Passed or Failed unless all `evidence_required` items (e.g., `baseline_request`, `negative_response`, `tested_role`) are successfully captured.

### 2.15 AI Prompt Bridge (`src/prompt_generator.py`)

The AI Prompt Bridge auto-generates ready-to-use Markdown prompts at the end of Phase 6, so developers can instantly feed context-rich prompts to their AI IDE (Cursor/Copilot/Claude).

**Remediation Prompts** (`output/prompts/remediation/`): For each Failed/Probable finding, generates a prompt with Test ID, Bible Control Requirement, Endpoint, Injected Payload, and redacted HTTP Evidence. Includes the Residual Risk Disclaimer and tasks the AI to generate the exact code fix.

**Triage Prompts** (`output/prompts/triage/`): For each Possible/Unable to Determine finding, generates a prompt instructing the AI to act as a "Senior Triage Engineer", compare baseline vs. negative request, and determine True Positive vs. False Positive.

**Executive Summary Prompt** (`output/prompts/ciso_summary.md`): Aggregates all test statistics and generates a prompt for the AI to write a 1-paragraph CISO briefing.

All prompts pass evidence through redaction logic (no raw tokens/passwords) and include the Residual Risk Disclaimer.

### 2.16 Forensic Telemetry Headers

The executor injects 7 forensic headers into every HTTP request for proxy/SIEM correlation:

| Header | Purpose |
|--------|---------|
| `X-SecTest-Phase` | Pipeline phase (`Phase-3-Mutation`, `Phase-0.5-SafeProbe`) |
| `X-SecTest-OWASP` | OWASP categories (`A03`, `API1`, etc.) |
| `X-SecTest-Category` | Test type (`SOQL-Injection`, `BOLA`, `XSS`, etc.) |
| `X-SecTest-Case-ID` | Test case identifier |
| `X-SecTest-Payload-Hash` | MD5 hash of payload (never raw payload in headers) |
| `X-SecTest-Target-Field` | Parameter/field name being injected (`q`, `IsDeleted`, etc.) |
| `X-SecTest-Inject-Location` | Injection structure (`query`, `json_body`, `url_path`, `header`) |

---

## 3. Configuration & Rules

### `config/settings.yaml`

The central configuration file with these sections:

```yaml
general:
  project_name: "Salesforce Portal Security Assessment"
  dry_run: false

exploration:
  enabled: true
  max_pages: 100
  max_depth: 5
  page_load_timeout: 30

discovery:
  enabled: true
  dom_probe_delay: 2
  safe_probes_only: true
  vision_model: "gpt-4o"
  max_screenshots_per_run: 50

safe_execution:
  enabled: true
  probe_prefix: "SF_PROBE_"
  max_tests_per_page: 10
  screenshot_after_each_test: true

visual_audit:
  enabled: true
  provider: "openai"
  model: "gpt-4o"
  max_dom_chars: 2000
  timeout_seconds: 45

llm_config:
  enabled: false
  provider: "openai"
  model: "gpt-4o-mini"
  api_key_env_var: "LLM_API_KEY"
  max_tokens_per_request: 1000

waf_evasion:
  enabled: true
  delay_between_requests: 1.0
  backoff_multiplier: 2.0
  max_retries: 5
  rotate_user_agent: true

role_comparison:
  enabled: false
  roles:
    - name: "admin"
      credentials_key: "admin_creds"
    - name: "standard_user"
      credentials_key: "user_creds"
```

### `config/credentials.yaml` (Excluded from version control)

```yaml
portals:
  assist_portal:
    access_token: "YOUR_TOKEN_HERE"
    username: "user@org.com"
    password: ""

role_comparison:
  admin_creds:
    login_url: "https://test.salesforce.com"
    username: "admin@org.sandbox.com"
    password: ""
    password_env_var: "SF_ADMIN_PASSWORD"
    expected_role: "System Administrator"
  user_creds:
    login_url: "https://test.salesforce.com"
    username: "user@org.sandbox.com"
    password: ""
    password_env_var: "SF_USER_PASSWORD"
    expected_role: "Standard User"
```

### `testcases/*.yaml`

YAML-based security rules mapping to OWASP Top 10. Each test case defines:
- `mutation_type`: The injection strategy (e.g., `bola_id_swap`, `soql_injection`, `cors_test`)
- `payloads`: Static payloads and configuration
- `finding_criteria`: What HTTP status codes or body patterns signify a vulnerability
- `severity`: Critical, High, Medium, or Low

---

## 4. CLI Usage & Quick Start

### Prerequisites

- Python 3.10+
- **Playwright** (mandatory for Phase 0): `pip install playwright && playwright install chromium`
- A valid `LLM_API_KEY` environment variable (if using AI verification)
- Exported `.har` files from your browser session (for HAR-based testing)
- Salesforce portal credentials (for autonomous exploration)

### CLI Flags

| Flag | Description |
|------|-------------|
| `--mode <mode>` | Execution mode: `observe` (zero requests, map coverage), `validate` (safe canaries only), or `confirm` (full mutation, pauses for human approval on state-changing tests) |
| `--generate-har` | Phase -1: Record live browser traffic as a HAR file (use with `--target`) |
| `--target <url>` | Target URL for HAR generation or exploration (required with `--generate-har`) |
| `--manual-auth` | Opens browser for manual SSO/JIT login, harvests cookies, and uses them for automated testing |
| `--explore-only` | Run Phase 0 & 0.5 only — map the application without attack testing |
| `--skip-explore` | Skip Phase 0, rely purely on HAR files (V2.x legacy behavior) |
| `--role-compare` | Run exploration with multiple credential sets to find privilege escalation |
| `--dry-run` | Preview mutations without sending HTTP requests |
| `--har <files>` | Specify HAR files (overrides auto-discovery in `input/`) |
| `--verbose` / `-v` | Enable debug logging |
| `--no-screenshots` | Disable Playwright screenshot capture |

### Use Case 0: HAR Generation (Phase -1)

Record live browser traffic through a proxy (ZAP/Caido/Burp) for subsequent analysis.

```bash
# Manual browsing mode (user logs in, clicks around)
python main.py --generate-har --target https://your-portal.salesforce.com --manual-auth

# Auto-browsing mode (clicks links automatically)
python main.py --generate-har --target https://your-portal.salesforce.com

# Then use the generated HAR for the full attack pipeline
python main.py --har output/live_crawl.har -v
```

### Use Case 1: Observe Mode (Zero Requests)

Map Bible coverage, identify risk surfaces — zero active requests sent.

```bash
python main.py --mode observe --har output/live_crawl.har

# Output:
# Phase 0: AI Explorer mapping application... (45 pages)
# Phase 0.5: Feature inventory: 12 risk surfaces
# Phase 1.5: Governance Engine: 483 tests evaluated, 180 applicable
# Reports generated with full coverage matrix
```

### Use Case 2: Validate Mode (Safe Canaries Only)

Run safe canary probes and read-only mutations — no destructive actions.

```bash
python main.py --mode validate --har output/live_crawl.har

# Output:
# Phase 0.5: Safe canaries executed (47 probes)
# Phase 3: Read-only mutations only
# Phase 4: LLM verification
# Reports with evidence-backed findings
```

### Use Case 3: Confirm Mode (Full Attack Pipeline)

Complete 9-phase governed pipeline — pauses for human approval on state-changing tests.

```bash
python main.py --mode confirm --har output/live_crawl.har

# Output:
# Phase 3: GOVERNANCE GATE: Test API-BOLA-001 is state-changing. Press ENTER.
# Phase 4: AI Brain: Verifying 14 potential findings...
# Phase 5: Visual AI: Analyzing 6 screenshots for DOM XSS...
# Phase 6: Reports + AI Prompts generated
```

### Use Case 3: Multi-Role Privilege Check

Compares Admin vs Standard User views to find privilege escalation vulnerabilities.

```bash
python main.py --role-compare -v

# Output:
# AI Explorer: Mapping site as admin...
# AI Explorer: Mapping site as standard_user...
# Role comparison: 12 pages only for admin, 3 only for standard_user, 30 shared
```

### Use Case 4: HAR-Only Legacy Mode

Skip autonomous exploration — test only endpoints from recorded HAR files (V2.x behavior).

```bash
python main.py --skip-explore --har input/assist_portal.har -v
```

---

## 5. Architectural Boundaries & Coupling

- **High Fan-In (Core Libs)**: `models.py`, `finding_evaluator.py`, and `waf_evasion.py` are imported everywhere. Do not add heavy dependencies to these files.
- **Orchestrator as State Machine**: The `Orchestrator` manages a complex 9-phase state machine. It imports everything but nothing imports the `Orchestrator`. It wires components and manages phase transitions.
- **Governance is Immutable**: The `GovernanceEngine` strictly enforces the Bible v7.1 schema. Tests marked `Blocked` or `Not Applicable` are never executed. The governance layer cannot be bypassed.
- **Evidence is Mandatory**: No test can be marked Passed or Failed unless all `evidence_required` items are successfully captured. Missing evidence = Blocked status.
- **Residual Risk Disclaimer**: The HTML report and all AI prompts explicitly state: *"This assessment is evidence-backed only for the executed route, role, method, data context, and environment. It does not prove alternate roles, routes, versions, batch paths, or trust boundaries. Untested variants, exclusions and residual risk must be reviewed manually."*
- **AI Brain is Decoupled**: The `LLMVerifier` and `VisualAuditor` are strictly gated. If API keys are missing or disabled in `settings.yaml`, the orchestrator seamlessly falls back to legacy logic (promoting all anomalies to findings) without crashing.
- **RoleManager Enforces Isolation**: The `RoleManager` ensures strict browser context isolation between roles. Each role gets its own `browser.new_context()` — no shared cookies, no session contamination.
- **Audit Trail is Append-Only**: `AuditEvent` objects are appended to `SiteMap.audit_log` and never modified after creation. This ensures compliance evidence integrity.
- **Safe Probes are Non-Negotiable**: `safe_executor.py` and `dom_xss_auditor.py` never send real attack payloads. The `safe_probes_only: true` config flag is the hard constraint. Real payloads only flow through `mutation_engine.py` in Phase 3.
- **Forensic Telemetry**: Every HTTP request carries 7 `X-SecTest-*` headers for proxy/SIEM correlation. Payload hashes are MD5'd — raw payloads are never placed in headers.

---

## 6. Module Dependency Graph

```
main.py
  └── orchestrator.py
        ├── autonomous_explorer.py  (Phase 0)
        │     └── models.py (PageSnapshot, SiteMap, AuditEvent)
        ├── feature_inventory.py     (Phase 0.5)
        │     └── models.py (FeatureInventory, RiskSurface)
        ├── test_planner.py          (Phase 0.5)
        │     └── models.py (TestPlan, PlannedTest)
        ├── safe_executor.py         (Phase 0.5)
        │     └── models.py (FindingResult)
        ├── dom_xss_auditor.py       (Phase 0.5)
        │     └── models.py (FindingResult, AuditEvent)
        ├── role_manager.py          (Phase 0, role comparison)
        │     └── models.py (AuditEvent)
        ├── har_parser.py            (Phase 1)
        ├── endpoint_classifier.py   (Phase 2)
        ├── test_case_engine.py      (Phase 2)
        ├── mutation_engine.py        (Phase 3)
        │     ├── payload_manager.py
        │     └── context_router.py
        ├── executor.py              (Phase 3)
        │     └── waf_evasion.py
        ├── finding_evaluator.py     (Phase 3)
        ├── llm_verifier.py          (Phase 4)
        ├── governance_engine.py     (Phase 1.5)
        │     └── models.py (GovernanceResult)
        ├── visual_auditor.py        (Phase 5)
        ├── evidence_collector.py    (Phases 3-5)
        ├── screenshot_capture.py    (Phases 0, 3, 5)
        ├── report_generator.py      (Phase 6)
        │     └── models.py (TestReport, ExecutiveSummary)
        └── prompt_generator.py      (Phase 6)
              └── models.py (PromptGenerator)
```

---

## 7. Setup Instructions

### Prerequisites

- Python 3.10+
- **Playwright** with Chromium (mandatory for Phase 0 autonomous exploration)
- A valid `LLM_API_KEY` environment variable (if using AI verification)
- Exported `.har` files from your browser session (for HAR-based testing)
- Salesforce portal credentials (for autonomous exploration)

### 1. Install Dependencies

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browser (MANDATORY for Phase 0)
playwright install chromium
```

### 2. Configure the Framework

1. Copy your `.har` files into the `input/` directory (e.g., `input/assist_portal.har`).
2. Update `config/settings.yaml`:
   - Set `llm_config.enabled: true` and specify your preferred provider.
   - Set `exploration.enabled: true` for autonomous discovery.
   - Update `cross_tenant_ids` with valid 15/18-character Salesforce IDs for BOLA testing.
3. Configure credentials in `config/credentials.yaml`:
   - Add portal credentials under `portals.assist_portal`
   - Add role comparison credentials under `role_comparison.admin_creds` / `user_creds`
4. Export your API key:
```bash
export LLM_API_KEY="sk-your-key-here"
export SF_ADMIN_PASSWORD="your-admin-password"
export SF_USER_PASSWORD="your-user-password"
```

### 3. Run the Scanner

```bash
# Full autonomous scan
python main.py -v

# Safe recon only (no attacks)
python main.py --explore-only -v

# Multi-role privilege check
python main.py --role-compare -v

# HAR-only legacy mode
python main.py --skip-explore --har input/portal.har -v
```

The framework will print a rich console output showing the execution progress, WAF evasion events, and the AI Brain's verification steps. Once finished, check:
- `output/reports/security_report.html` — Full HTML report with Feature Inventory, Visual Evidence, OWASP Compliance Matrix
- `output/reports/security_report.json` — Machine-readable JSON report
- `output/evidence/` — Raw HTTP dumps, screenshots, and probe results
- `output/evidence/exploration/` — Page snapshots from autonomous exploration
- `output/evidence/dom_xss/` — DOM XSS probe screenshots
