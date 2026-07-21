# Orchestrator Agent Dispatch Protocol

## Overview

The Orchestrator Agent is the brain of the multi-agent security pipeline. It:
1. Receives scope definition (target, credentials, authorization)
2. Dispatches to specialized domain agents
3. Collects and normalizes findings
4. Applies cross-domain correlation rules
5. Generates unified report for downstream consumers

---

## Dispatch Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    ORCHESTRATOR AGENT                            │
│                                                                 │
│  1. RECEIVE SCOPE                                               │
│     ├── target_url                                              │
│     ├── credentials (encrypted)                                 │
│     ├── authorization_level                                     │
│     └── scope_boundaries                                        │
│                                                                 │
│  2. SELECT DOMAIN AGENTS                                        │
│     ├── Based on target type (Salesforce, Cloud, etc.)          │
│     ├── Based on discovered attack surface                      │
│     └── Based on scope boundaries                               │
│                                                                 │
│  3. DISPATCH AGENTS (Parallel or Sequential)                    │
│     ├── Salesforce API Agent (V4.0)                             │
│     ├── Cloud IAM Agent                                         │
│     ├── Network Scanner Agent                                   │
│     ├── Web App DAST Agent                                      │
│     └── [Additional domain agents as needed]                    │
│                                                                 │
│  4. COLLECT RESULTS                                             │
│     ├── Each agent outputs security_report.json                 │
│     ├── Normalize to shared finding schema                      │
│     └── Aggregate into unified findings list                    │
│                                                                 │
│  5. APPLY CORRELATION RULES                                     │
│     ├── Load correlation_rules.yaml                             │
│     ├── Compare findings across domains                         │
│     ├── Escalate severity if rules trigger                      │
│     └── Mark correlated findings                                │
│                                                                 │
│  6. GENERATE UNIFIED REPORT                                     │
│     ├── Merge all findings                                      │
│     ├── Apply residual risk disclaimers                         │
│     ├── Generate executive summary                              │
│     └── Output to downstream consumers                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Agent Invocation Protocol

### Salesforce API Agent (V4.0)
```bash
# Mode 1: Observe (Zero requests)
python main.py --mode observe --har output/live_crawl.har

# Mode 2: Validate (Safe canaries)
python main.py --mode validate --har output/live_crawl.har

# Mode 3: Confirm (Full attack, human approval)
python main.py --mode confirm --har output/live_crawl.har
```

### Cloud IAM Agent
```bash
# AWS
python cloud_agent.py --provider aws --region us-east-1 --profile production

# Azure
python cloud_agent.py --provider azure --subscription-id xxx --tenant-id yyy

# GCP
python cloud_agent.py --provider gcp --project-id xxx
```

### Network Scanner Agent
```bash
# Nmap scan
python network_agent.py --target 10.0.0.0/24 --scan-type full

# Nessus scan
python network_agent.py --nessus-server https://nessus.local --scan-id xxx
```

### Web App DAST Agent
```bash
# ZAP scan
python web_agent.py --target https://portal.example.com --scan-type active

# Custom DAST
python web_agent.py --har output/live_crawl.har --mutation-level aggressive
```

---

## Finding Normalization

All agents output findings in the shared JSON schema. The Orchestrator normalizes:

```python
def normalize_finding(agent_finding: dict) -> dict:
    """Normalize agent-specific finding to shared schema."""
    return {
        "finding_id": agent_finding.get("id", str(uuid.uuid4())),
        "domain": map_agent_domain(agent_finding["agent_id"]),
        "test_id": agent_finding.get("test_id", "UNKNOWN"),
        "severity": normalize_severity(agent_finding["severity"]),
        "status": normalize_status(agent_finding["verdict"]),
        "evidence": extract_evidence(agent_finding),
        "owasp_mapping": map_owasp(agent_finding),
        "residual_risk_disclaimer": MANDATORY_DISCLAIMER,
        "metadata": {
            "agent_id": agent_finding["agent_id"],
            "execution_mode": agent_finding.get("mode", "validate"),
            "execution_timestamp": agent_finding["timestamp"],
        }
    }
```

---

## Correlation Engine

```python
def apply_correlation_rules(findings: list, rules: list) -> list:
    """Apply cross-domain correlation rules to findings."""
    for rule in rules:
        matching_findings = []
        
        for condition in rule["trigger_conditions"]:
            for finding in findings:
                if (finding["domain"] == condition["finding_domain"] and
                    re.match(condition["finding_test_id_pattern"], finding["test_id"]) and
                    finding["status"] in condition["status"]):
                    matching_findings.append(finding)
        
        if len(matching_findings) >= rule.get("correlation_threshold", 2):
            # Apply severity escalation
            for finding in matching_findings:
                finding["severity"] = rule["severity_escalation"]
                finding["correlated"] = True
                finding["correlation_rule"] = rule["rule_id"]
    
    return findings
```

---

## Output Format

The unified output from the Orchestrator follows the same JSON schema as individual agents, with additional fields:

```json
{
  "report_id": "uuid",
  "target": "https://portal.example.com",
  "execution_timestamp": "2026-01-15T10:30:00Z",
  "agents_invoked": [
    {"agent_id": "salesforce-api-v4", "findings_count": 12, "execution_time": "45s"},
    {"agent_id": "cloud-iam", "findings_count": 5, "execution_time": "30s"},
    {"agent_id": "network-scanner", "findings_count": 3, "execution_time": "120s"}
  ],
  "findings": [...],
  "correlations_applied": [
    {"rule_id": "CORR-001", "findings_correlated": 2, "escalation": "Critical"}
  ],
  "summary": {
    "total_findings": 20,
    "critical": 5,
    "high": 8,
    "medium": 5,
    "low": 2,
    "correlations_triggered": 2
  },
  "residual_risk_disclaimer": "This assessment is evidence-backed only for the executed routes, roles, methods, data contexts and environments. Record untested variants, exclusions and residual risk."
}
```

---

## Integration Points

| Consumer | Input | Protocol |
|----------|-------|----------|
| Jira Agent | `findings[]` with severity + OWASP mapping | REST API |
| SIEM Agent | `findings[]` with correlation IDs | Syslog/CEF |
| Remediation Agent | `findings[]` with evidence + residual risk | VS Code Extension |
| CISO Agent | `summary` + executive overview | PDF/HTML Report |
| Compliance Agent | `owasp_mapping[]` + domain coverage | SOC2/ISO27001 Template |
