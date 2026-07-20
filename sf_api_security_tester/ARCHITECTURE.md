# Salesforce API Security Tester — Architecture & Developer Guide

Welcome to the **Salesforce API Security Tester**! This guide is designed for new developers, security engineers, and maintainers to deeply understand the framework's architecture, core components, and data flow.

## 1. High-Level Architecture Overview

This framework is an automated, context-aware API security scanner specifically tailored for Salesforce portals (Assist/Tenant portals, Communities, etc.). 
It operates as a pipeline: it ingests browser traffic (HAR files), classifies the API endpoints, generates intelligent attack payloads using local heuristics and context, executes them while bypassing WAFs, and finally uses a **Hybrid AI Engine** (LLMs and Vision models) to verify findings and eliminate false positives.

### **The Pipeline (Orchestrator)**
The entire flow is managed by `src/orchestrator.py`. The execution lifecycle follows these steps:
1. **HAR Parsing** (`har_parser.py`): Parses `.har` files exported from a browser to discover API endpoints, methods, parameters, and headers.
2. **Endpoint Classification** (`endpoint_classifier.py`): Categorizes endpoints based on Salesforce patterns (e.g., `/services/data/` for data queries, `/aura` for business logic, authentication endpoints).
3. **Test Planning** (`test_case_engine.py`): Loads YAML-based security rules (found in `testcases/`) and maps them to the classified endpoints.
4. **Execution & Mutation** (`mutation_engine.py`, `executor.py`): Generates mutated HTTP requests injected with payloads and fires them at the target.
5. **Evidence Collection** (`evidence_collector.py`, `screenshot_capture.py`): Captures the raw HTTP request/response and takes a headless browser screenshot of the exploit.
6. **Local Evaluation** (`finding_evaluator.py`): Analyzes the response (status codes, headers, body reflections) to determine if there is a `POTENTIAL_FINDING`.
7. **Hybrid AI Verification** (`llm_verifier.py`, `visual_auditor.py`): Sends potential findings to an LLM (e.g., GPT-4o) to confirm it is a true positive, minimizing human triaging.
8. **Reporting** (`report_generator.py`): Generates a rich HTML/JSON executive summary and technical report.

---

## 1.5 The Data-Driven Workflow (How it Works)

Unlike older security frameworks that rely on hardcoded Python scripts for every vulnerability (e.g., a specific Python class just to test BOLA on a single endpoint), this V2 architecture uses a **Data-Driven Mutation Engine**.

Here is how the framework handles vulnerabilities without requiring custom Python code for each test:

1. **The Blueprint (YAML Rules)**: All attack rules are stored in `testcases/owasp_api_top10.yaml`. A rule simply describes the attack conceptually (e.g., "Find an endpoint with a Salesforce Record ID and swap it with another tenant's ID").
2. **The Factory (`MutationEngine`)**: The engine reads the HAR file and the YAML blueprint. It automatically mutates the legitimate requests into hundreds of context-aware attack requests on the fly (manipulating URLs, headers, or JSON bodies).
3. **The Local Detective (`FindingEvaluator`)**: The framework fires the mutated requests and examines the responses. If a response matches the vulnerable criteria (e.g., returning 200 OK with leaked data), it flags a `POTENTIAL_FINDING`.
4. **The AI Senior Engineer (`LLMVerifier`)**: To eliminate false positives, the AI brain (e.g., GPT-4o) reviews the `POTENTIAL_FINDING`. It acts as a senior engineer, analyzing the raw HTTP evidence to confirm if the vulnerability is a true exploit or a normal server error, heavily reducing human triage time.

---
## 2. Core Modules Deep Dive

The codebase is highly modular and strictly typed using **Pydantic** (`src/models.py`), which acts as the glue for data passing between layers.

### 2.1 The Data Models (`src/models.py`)
This is the heart of the framework's type safety. Key models include:
- `APIEndpoint`: Represents a discovered API route.
- `Mutation` / `MutatedRequest`: Represents a single attack payload and the fully-formed HTTP request ready to be sent.
- `Evidence`: Bundles the raw HTTP request, response, timing, and screenshot paths.
- `FindingResult`: The final evaluated result containing verdicts (`FINDING`, `POTENTIAL_FINDING`, `NOT_FINDING`, `ERROR`) and LLM reasoning.

### 2.2 Payload Generation & Mutation
- **`src/mutation_engine.py`**: The core factory that dynamically manipulates HTTP requests. It knows how to inject payloads into headers, query strings, JSON bodies, or perform HTTP method overrides.
- **`src/payload_manager.py`**: Manages the retrieval and caching of dynamic payloads (e.g., fetching lists from SecLists or PayloadsAllTheThings).
- **`src/context_router.py`**: Ensures payloads are contextually relevant to Salesforce (e.g., formatting a BOLA payload as a valid 15/18 character Salesforce ID).

### 2.3 Network Execution & WAF Evasion
- **`src/executor.py`**: The network layer handling the actual outbound HTTP requests.
- **`src/waf_evasion.py`**: Integrates closely with the executor. If a request is blocked by a Web Application Firewall (WAF) or hits a Salesforce API rate limit, this module handles exponential backoffs, User-Agent rotation, and cooldowns to ensure the scan completes successfully without getting blacklisted.

### 2.4 Evidence & Proof
- **`src/evidence_collector.py`**: Saves raw request and response dumps to the local disk for audit trails.
- **`src/screenshot_capture.py`**: Uses **Playwright** to open a headless browser, navigate to the target, inject the mutated request/cookies, and capture a screenshot of the result (e.g., an XSS popup or an error trace).

### 2.5 Hybrid AI Verification Layer (V2.2+)
To drastically reduce false positives (a common issue in dynamic scanners), the framework uses AI to act as a "Senior Security Engineer".
- **`src/finding_evaluator.py`**: The local, regex/rule-based engine. Instead of marking things immediately as vulnerabilities, it acts defensively and flags them as `POTENTIAL_FINDING`.
- **`src/llm_verifier.py`**: Takes the `POTENTIAL_FINDING` queue, truncates the HTTP bodies to conserve tokens (Cost Control), and prompts an LLM with strict JSON schemas to confidently label it as `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `NEEDS_MANUAL_REVIEW`. It also generates Salesforce-specific remediation advice (e.g., OWD, FLS, Apex sharing).
- **`src/visual_auditor.py`**: Uses Vision LLMs to review the Playwright screenshots to verify visual bugs (like reflected XSS or data exposure in the UI).

---

## 3. Configuration & Rules

- **`config/settings.yaml`**: The central configuration file. It dictates target environments, LLM settings, Playwright browser configs, WAF delays, and cross-tenant Salesforce IDs for BOLA testing.
- **`config/credentials.yaml`**: (Excluded from version control). Stores sensitive Auth Tokens and session cookies.
- **`testcases/*.yaml`**: The security rules mapping to the OWASP Top 10. Each test case defines `mutation_type`, `payloads`, and `finding_criteria` (what HTTP status codes or body patterns signify a vulnerability).

---

## 4. Entry Points & Adding New Features

### Starting the Framework
The framework is instantiated and run from `main.py`:
```python
python main.py
```

### Extending the Framework
- **Adding a new vulnerability test**: Create a new entry in `testcases/owasp_api_top10.yaml`. Define the `mutation_type` and `finding_criteria`.
- **Adding a new mutation strategy**: Add a new `MutationType` enum in `src/models.py`, then implement the logic inside `src/mutation_engine.py`.
- **Improving WAF Evasion**: Modify `src/waf_evasion.py` to add new heuristics for detecting blocks (e.g., Akamai, Cloudflare specific response headers).

## 5. Architectural Boundaries & Coupling
- **High Fan-In (Core Libs)**: `models.py`, `finding_evaluator.py`, and `waf_evasion.py` are imported everywhere. Do not add heavy dependencies to these files.
- **Orchestrator acts as a Leaf**: The `Orchestrator` imports everything but nothing imports the `Orchestrator`. It simply wires up the components and manages the `for` loops.
- **AI Brain is Decoupled**: The `LLMVerifier` is strictly gated. If API keys are missing or disabled in `settings.yaml`, the orchestrator seamlessly falls back to legacy V2.1 logic (promoting all anomalies to findings) without crashing.

---

## 6. Setup Instructions

To get the Salesforce API Security Tester running on your local machine, follow these steps:

### Prerequisites
- Python 3.10+
- A valid `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` (if using the AI Verifier)
- Exported `.har` files from your browser session interacting with your Salesforce portals

### 1. Install Dependencies
```bash
# It is recommended to use a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

### 2. Configure the Framework
1. Copy your `.har` files into the `input/` directory (e.g., `input/assist_portal.har`).
2. Update `config/settings.yaml`:
   - Set `llm_config.enabled: true` and specify your preferred provider.
   - Update `cross_tenant_ids` with valid 15/18-character Salesforce IDs from your org to test BOLA (Broken Object Level Authorization).
3. Ensure your API key is exported:
```bash
export LLM_API_KEY="sk-your-key-here"
```

### 3. Run the Scanner
```bash
python main.py
```

The framework will print a rich console output showing the execution progress, WAF evasion events, and the AI Brain's verification steps. Once finished, check the `output/reports/` directory for the final HTML/JSON reports and `output/evidence/` for screenshots of the exploits!
