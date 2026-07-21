# SF API Security Tester — Knowledge Transfer Document (V4.0)

## Project Overview

This is a **production-grade, autonomous AI security testing framework** for Salesforce portals. It combines Playwright browser automation, OWASP-aligned test cases, LLM-powered analysis, and a governed enforcement engine to perform comprehensive API security assessments.

**Key Numbers:**
- 24 Python modules (~500KB total code)
- 66 OWASP test cases across 3 standards (100% coverage)
- 483 Bible v7.1 tests catalogued
- 9-phase governed pipeline
- 7 forensic telemetry headers per request

---

## Architecture Summary

```
Phase -1: HAR Generation (Playwright native recording)
Phase 0:  Autonomous Explorer (BFS + Vision LLM)
Phase 0.5: Feature Inventory & Safe Probing (Canary approach)
Phase 1:  HAR Parse + Smart Analysis
Phase 1.5: Governance Engine (Bible v7.1 enforcement)
Phase 2:  Classify & Plan
Phase 3:  Execute Mutations (WAF evasion + telemetry)
Phase 4:  LLM Triage (Text LLM)
Phase 5:  Visual DAST (Vision LLM)
Phase 6:  Report & AI Prompt Bridge
```

---

## Key Files (by size/importance)

### Core Engine
| File | Size | Purpose |
|------|------|---------|
| `src/mutation_engine.py` | 59KB | 25 mutation types, dynamic payload injection, SOQL/XSS/SSRF/BOLA |
| `src/orchestrator.py` | 50KB | 9-phase pipeline manager, CLI, component wiring |
| `src/report_generator.py` | 61KB | HTML/JSON reports, OWASP Compliance Matrix, Workflow visualization |
| `src/autonomous_explorer.py` | 54KB | Playwright BFS, Vision LLM, SSO/MFA handling |
| `src/safe_executor.py` | 20KB | Canary probe execution, workflow step skipping |
| `src/visual_auditor.py` | 22KB | Vision LLM screenshot analysis |

### Smart Modules
| File | Size | Purpose |
|------|------|---------|
| `src/context_router.py` | 21KB | Regex/heuristic endpoint analysis, risk scoring |
| `src/payload_manager.py` | 15KB | Dynamic payload fetching from GitHub, caching |
| `src/test_planner.py` | 24KB | Smart canary approach, noise reduction, workflow tests |
| `src/test_case_engine.py` | 4.6KB | YAML test case loading, applicability matching |
| `src/governance_engine.py` | 6.9KB | Bible v7.1 enforcement, signal matching, circuit breakers |

### AI/LLM Modules
| File | Size | Purpose |
|------|------|---------|
| `src/llm_verifier.py` | 18KB | Text LLM triage, Salesforce OWD awareness, MD5 caching |
| `src/visual_auditor.py` | 22KB | Vision LLM screenshot analysis, triple-verified DOM XSS |
| `src/har_analyzer.py` | 12KB | LLM-powered deep HAR analysis |
| `src/prompt_generator.py` | 12KB | Auto-generates redacted AI prompts for VS Code |

### Infrastructure
| File | Size | Purpose |
|------|------|---------|
| `src/models.py` | 16KB | 25+ Pydantic models, all type-safe |
| `src/executor.py` | 14KB | HTTP execution, WAF evasion, telemetry headers |
| `src/waf_evasion.py` | 19KB | Rate limiting, UA rotation, SF API limit detection |
| `src/evidence_collector.py` | 7.5KB | Evidence capture, redaction, size limits |
| `src/har_parser.py` | 10KB | HAR file parsing, SF-specific extraction |
| `src/endpoint_classifier.py` | 8KB | Endpoint categorization by risk |

---

## OWASP Coverage (100%)

| Standard | Categories | Tests |
|----------|-----------|-------|
| OWASP API Top 10 (2023) | 10/10 | 23 |
| OWASP Web Top 10 (2021) | 10/10 | 19 |
| OWASP Secure Coding v2 | 13/13 | 22 |
| **Bible v7.1** | **12 domains** | **483 tests** |

---

## Configuration Files

| File | Purpose |
|------|---------|
| `config/settings.yaml` | Global config: portals, exploration, payloads, WAF, LLM, visual audit, governance |
| `config/credentials.yaml` | Auth tokens (gitignored) |
| `testcases/catalog.yaml` | Bible v7.1 strict schema |
| `testcases/owasp_api_top10.yaml` | OWASP API Top 10 test definitions |
| `testcases/owasp_web_top10.yaml` | OWASP Web Top 10 test definitions |
| `testcases/owasp_secure_coding.yaml` | OWASP Secure Coding test definitions |

---

## CLI Usage

```bash
# Full autonomous scan
python main.py -v

# Explore-only (no attacks)
python main.py --explore-only --target https://portal.salesforce.com/

# HAR-only legacy mode
python main.py --skip-explore --har input/portal.har -v

# Multi-role privilege check
python main.py --role-compare -v

# Manual SSO login
python main.py --manual-auth --target https://portal.salesforce.com/

# Generate HAR from live site
python main.py --generate-har --target https://portal.salesforce.com/ --manual-auth

# Dry run (no requests sent)
python main.py --dry-run --har input/portal.har -v

# Execution modes
python main.py --mode observe --har output/live_crawl.har    # Zero requests
python main.py --mode validate --har output/live_crawl.har   # Safe canaries only
python main.py --mode confirm --har output/live_crawl.har    # Full attack (pauses for approval)
```

---

## Critical Constraints

1. **Safety:** `safe_executor.py` NEVER sends real destructive payloads. Canary probes only.
2. **Token Economy:** LLMs only receive truncated data (2000 chars max). MD5 caching prevents redundant calls.
3. **Proxy Support:** When `upstream_proxy.enabled`, `verify=False` is forced for MITM certs. Runtime `httpx.ProxyError` fallback.
4. **SF API Limits:** Detects `REQUEST_LIMIT_EXCEEDED` and halts immediately (no backoff).
5. **Governance:** Tests marked `Blocked` or `Not Applicable` are never executed.
6. **Evidence:** No test can Pass/Fail unless all `evidence_required` items are captured.
7. **Telemetry:** 7 `X-SecTest-*` headers per request for proxy/SIEM correlation.
