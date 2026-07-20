# Salesforce API Security Tester — Architecture & Developer Guide (V3.0)

Welcome to the **Salesforce API Security Tester V3.0: The Autonomous AI Security Agent**. This guide is designed for security engineers, developers, and maintainers to deeply understand the framework's architecture, core components, and data flow.

---

## 1. High-Level Architecture Overview

This framework is an **autonomous, context-aware AI security agent** specifically tailored for Salesforce portals (Assist/Tenant portals, Communities, etc.). Unlike traditional scanners that passively replay recorded traffic, V3.0 **actively explores the live application** like a human would — clicking every link, understanding every page, mapping every role — and *then* tests intelligently.

It operates as a **7-phase pipeline**: it autonomously discovers the application surface, builds a feature inventory, executes safe probes to identify reflection points, fires real attack mutations, uses a **Hybrid AI Engine** (Text LLMs and Vision LLMs) to verify findings and eliminate false positives, and generates comprehensive reports with visual evidence.

### **The Pipeline (Orchestrator)**

The entire flow is managed by `src/orchestrator.py`. The execution lifecycle follows these phases:

| Phase | Name | Module(s) | Purpose |
|-------|------|-----------|---------|
| **-1** | HAR Generation | `har_generator.py` | Records live browser traffic as HAR via Playwright native recording (with proxy support) |
| **0** | Autonomous Explore | `autonomous_explorer.py` | Playwright BFS discovers every page; Vision LLM understands context |
| **0.5** | Feature Inventory & Safe Probing | `feature_inventory.py`, `test_planner.py`, `safe_executor.py`, `dom_xss_auditor.py` | Maps risk surfaces; executes harmless probes to verify reflection |
| **1** | HAR Parse (Enriched) | `har_parser.py` | Parses browser traffic; enriched with Phase 0 discoveries |
| **2** | Classify & Plan | `endpoint_classifier.py`, `test_case_engine.py` | Categorizes endpoints; maps OWASP rules to attack surfaces |
| **3** | Execute Mutations | `mutation_engine.py`, `executor.py` | Sends real attack payloads with WAF evasion |
| **4** | LLM Triage | `llm_verifier.py` | Text LLM confirms/rejects `POTENTIAL_FINDING` verdicts |
| **5** | Visual DAST | `visual_auditor.py` | Vision LLM analyzes screenshots for DOM XSS and data exposure |
| **6** | Report Generation | `report_generator.py` | HTML/JSON report with Feature Inventory, Visual Evidence, OWASP matrix |

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

**Login Flow:**
- Reads credentials from `config/credentials.yaml`
- Handles Salesforce-specific login: waits for `#username`/`#password` fields, clicks `#Login`, handles "Remember this browser" prompt
- Detects MFA/2FA, pauses with a console message asking the user to complete manually, waits for post-login selectors
- Verifies login success by checking URL doesn't contain `/login`

**BFS Navigation:**
- Maintains a queue of `(url, depth, parent_url)` tuples
- At each page: extracts DOM summary, visible text, all `<input>`/`<select>`/`<textarea>` fields
- Handles Salesforce Lightning SPA navigation using `page.wait_for_selector('.oneAppLauncher, .slds-page-header')`
- Limits to `max_pages` (default 100) and `max_depth` (default 5)

**Vision LLM Page Understanding:**
- Sends each page screenshot + DOM summary to a Vision LLM
- LLM returns strict JSON: `page_purpose`, `page_category`, `features`, `input_fields` (with `risk_type`), `navigation_targets`, `sensitive_data_visible`, `role_indicators`, `api_endpoints_inferred`, `confidence`
- Robust 3-tier JSON parsing: strip markdown → extract `{...}` → fallback to `INCONCLUSIVE`

**Output:** A complete `SiteMap` object with all `PageSnapshot`s and a structured `audit_log`.

### 2.3 Feature Inventory & Test Planning (`src/feature_inventory.py`, `src/test_planner.py`)

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

### 2.4 Triple-Verified DOM XSS Auditor (`src/dom_xss_auditor.py`)

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

### 2.5 Safe Executor (`src/safe_executor.py`)

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

### 2.6 Payload Generation & Mutation

- **`src/mutation_engine.py`**: The core factory that dynamically manipulates HTTP requests. Knows how to inject payloads into headers, query strings, JSON bodies, or perform HTTP method overrides. Uses `PayloadManager` for dynamic payload fetching and `ContextRouter` for Salesforce-aware injection.
- **`src/payload_manager.py`**: Manages the retrieval and caching of dynamic payloads from external sources (SecLists, PayloadsAllTheThings). Checks file modification time; only re-fetches if older than 7 days.
- **`src/context_router.py`**: Analyses endpoints using regex/heuristics to determine the injection type (SOQL, XSS, SSRF, BOLA) and the exact injection points (URL params, body fields, headers).

### 2.7 Network Execution & WAF Evasion

- **`src/executor.py`**: The network layer handling outbound HTTP requests via `EvasionClient`.
- **`src/waf_evasion.py`**: Integrates with the executor. Detects WAF blocks (HTTP 403/429, signature matching for Cloudflare/Akamai/AWS WAF), applies exponential backoff, rotates User-Agents, and detects Salesforce API limits (`REQUEST_LIMIT_EXCEEDED`) to halt execution before org lockout.

### 2.8 Evidence & Proof

- **`src/evidence_collector.py`**: Saves raw request and response dumps to disk. Truncates response bodies to 50KB and request bodies to 10KB to prevent evidence bloat. Appends `[TRUNCATED BY FRAMEWORK]` markers.
- **`src/screenshot_capture.py`**: Uses Playwright to capture screenshots and extract DOM `outerHTML` around injection points for Visual DAST analysis.

### 2.9 Hybrid AI Verification Layer

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

### 2.10 Multi-Role Comparison (`src/role_manager.py`)

Enables privilege escalation detection by comparing what different user roles can see.

- **`RoleManager`**: Creates isolated `RoleSession` objects, each with its own Playwright browser context (complete cookie/session isolation)
- **`RoleSession`**: Holds `page`, `context`, `browser`, `verified` flag, and `audit_log`
- **`login_session()`**: Uses `browser.new_context()` per role — no cookie bleeding between Admin and Standard User
- **`_verify_role()`**: Checks the Salesforce user profile page for role indicators (System Administrator, Standard User, etc.)
- **Role diff**: Mathematical set comparison of discovered pages — identifies pages only visible to Admin but not Standard User

### 2.11 The Audit Trail

Every action is timestamped and logged via the `AuditEvent` dataclass:
- `timestamp`: When the event occurred
- `action`: What was done (`navigate`, `click`, `fill`, `submit`, `llm_call`, `probe`, `screenshot`, `error`)
- `target`: The URL, field name, or description
- `result`: `success`, `fail`, `timeout`, `skip`
- `details`: Additional context (e.g., "depth=3, category=form")
- `role`: Which role performed the action (for role comparison)

The `SiteMap.audit_log` field stores all events for the scan. This provides complete compliance evidence of what was tested and when.

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

### Use Case 1: Safe Recon (Zero Attacks)

Maps the application, runs safe probes, identifies risk surfaces — no real payloads sent.

```bash
# Set credentials
$env:SF_ADMIN_PASSWORD = "your-admin-password"
$env:LLM_API_KEY = "sk-your-openai-key"

# Run exploration only
python main.py --explore-only -v

# Output:
# AI Explorer: Mapping application...
#   Discovered 45 pages, 120 input fields
# Feature inventory: 12 risk surfaces identified
# Safe probes: 8 potential findings from 95 probes
```

### Use Case 2: Full Autonomous Attack

Complete 7-phase pipeline — exploration, probing, real mutations, LLM verification, visual DAST.

```bash
python main.py -v

# Output:
# AI Explorer: Mapping application... (45 pages)
# Planning tests from 45 discovered pages...
# Phase 1: Parsing HAR files...
# Phase 3: Executing mutations...
# AI Brain: Verifying 14 potential findings...
# Visual AI: Analyzing 6 screenshots for DOM XSS...
# Reports generated: output/reports/security_report.html
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
- **Orchestrator as State Machine**: The `Orchestrator` manages a complex 7-phase state machine. It imports everything but nothing imports the `Orchestrator`. It wires components and manages phase transitions.
- **AI Brain is Decoupled**: The `LLMVerifier` and `VisualAuditor` are strictly gated. If API keys are missing or disabled in `settings.yaml`, the orchestrator seamlessly falls back to legacy logic (promoting all anomalies to findings) without crashing.
- **RoleManager Enforces Isolation**: The `RoleManager` ensures strict browser context isolation between roles. Each role gets its own `browser.new_context()` — no shared cookies, no session contamination.
- **Audit Trail is Append-Only**: `AuditEvent` objects are appended to `SiteMap.audit_log` and never modified after creation. This ensures compliance evidence integrity.
- **Safe Probes are Non-Negotiable**: `safe_executor.py` and `dom_xss_auditor.py` never send real attack payloads. The `safe_probes_only: true` config flag is the hard constraint. Real payloads only flow through `mutation_engine.py` in Phase 3.

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
        ├── visual_auditor.py        (Phase 5)
        ├── evidence_collector.py    (Phases 3-5)
        ├── screenshot_capture.py    (Phases 0, 3, 5)
        └── report_generator.py      (Phase 6)
              └── models.py (TestReport, ExecutiveSummary)
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
