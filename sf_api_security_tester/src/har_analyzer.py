"""Smart HAR Analyzer — LLM-powered deep inspection of HAR traffic.

Goes beyond regex parsing: sends endpoint summaries to the LLM to understand
the application's API architecture, authentication patterns, data flows,
and business logic.  Generates a structured "API Intelligence Report".
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from typing import Any

from loguru import logger

from .models import APIEndpoint, HTTPMethod


# ---------------------------------------------------------------------------
# System prompt for HAR deep analysis
# ---------------------------------------------------------------------------
_HAR_ANALYSIS_PROMPT = """\
You are an expert Salesforce Security Architect performing API reconnaissance.
You have been given a list of API endpoints captured from a Salesforce portal's \
HAR file.  Analyse them and return a structured JSON intelligence report.

For each endpoint, determine:
1. PURPOSE: What business function does this endpoint serve?
2. AUTH_MECHANISM: How is it authenticated? (Bearer token, Session ID, Cookie, etc.)
3. SENSITIVE_DATA: Does it expose PII, credentials, internal IDs, or business data?
4. RISK_LEVEL: low | medium | high | critical
5. ATTACK_SURFACE: Which OWASP categories apply? (e.g., ["API1:BOLA", "A03:Injection"])
6. BUSINESS_LOGIC: Any observable business rules (e.g., "requires AccountId", "filters by OwnerId")

Also provide an OVERALL summary:
- app_type: What kind of Salesforce org is this? (Community, Internal, Partner, etc.)
- auth_pattern: How does authentication flow? (OAuth2, Session, SAML, etc.)
- data_classification: What types of data are accessed? (PII, Financial, Cases, etc.)
- attack_priority: Ordered list of endpoints to test first (by risk)

Return ONLY a valid JSON object matching this schema:
{
  "endpoints": [
    {
      "url": "string",
      "method": "string",
      "purpose": "string",
      "auth_mechanism": "string",
      "sensitive_data": "string",
      "risk_level": "low|medium|high|critical",
      "attack_surface": ["string"],
      "business_logic": "string"
    }
  ],
  "overall": {
    "app_type": "string",
    "auth_pattern": "string",
    "data_classification": "string",
    "attack_priority": ["url strings"],
    "notes": "string"
  }
}
"""


class HarAnalyzer:
    """LLM-powered deep analysis of HAR traffic for API intelligence."""

    def __init__(self, config: dict[str, Any]):
        llm_cfg = config.get("llm_config", config.get("llm_verification", {}))
        self.enabled: bool = llm_cfg.get("enabled", False)
        self.provider: str = llm_cfg.get("provider", "openai")
        self.model: str = llm_cfg.get("model", "gpt-4o-mini")

        # API key
        api_key_env: str = llm_cfg.get("api_key_env_var", "LLM_API_KEY")
        self.api_key: str = os.environ.get(api_key_env, "")
        if not self.api_key:
            self.api_key = os.environ.get("OPENAI_API_KEY", "")

        self.max_tokens: int = llm_cfg.get("max_tokens_per_request", 2000)
        self.temperature: float = llm_cfg.get("temperature", 0.1)
        self.max_endpoints_per_call: int = 50  # Token economy
        self._client: Any = None
        self._cache: dict[str, dict] = {}

    def analyse_endpoints(
        self, endpoints: list[APIEndpoint]
    ) -> dict[str, Any]:
        """Perform deep LLM analysis of parsed HAR endpoints.

        Returns:
            Structured intelligence report with per-endpoint analysis
            and overall application assessment.
        """
        if not self.enabled:
            logger.info("HAR LLM analysis disabled — returning heuristic summary")
            return self._heuristic_summary(endpoints)

        logger.info(f"HAR LLM analysis: {len(endpoints)} endpoints")

        # Chunk endpoints to stay within token limits
        chunks = self._chunk_endpoints(endpoints, self.max_endpoints_per_call)
        all_analyses: list[dict] = []

        for i, chunk in enumerate(chunks):
            logger.info(f"  Analysing chunk {i+1}/{len(chunks)} ({len(chunk)} endpoints)")
            analysis = self._analyse_chunk(chunk)
            if analysis:
                all_analyses.extend(analysis.get("endpoints", []))

        # Merge overall assessments
        overall = self._merge_overalls(all_analyses, endpoints)

        result = {
            "endpoints": all_analyses,
            "overall": overall,
            "total_endpoints_analysed": len(all_analyses),
            "analysis_method": "llm" if self.enabled else "heuristic",
        }

        logger.info(
            f"HAR analysis complete: {len(all_analyses)} endpoints analysed, "
            f"app_type={overall.get('app_type', 'unknown')}"
        )
        return result

    def _analyse_chunk(self, endpoints: list[APIEndpoint]) -> dict[str, Any] | None:
        """Send a chunk of endpoints to the LLM for analysis."""
        # Build concise endpoint summary for the LLM
        summary = self._build_endpoint_summary(endpoints)

        # Check cache
        cache_key = hashlib.md5(summary.encode()).hexdigest()
        if cache_key in self._cache:
            logger.debug("HAR analysis cache hit")
            return self._cache[cache_key]

        client = self._get_client()
        if not client:
            return None

        try:
            if self.provider == "openai":
                result = self._call_openai(client, summary)
            elif self.provider == "anthropic":
                result = self._call_anthropic(client, summary)
            else:
                return None

            if result:
                self._cache[cache_key] = result
            return result

        except Exception as e:
            logger.error(f"HAR LLM analysis failed: {e}")
            return None

    def _build_endpoint_summary(self, endpoints: list[APIEndpoint]) -> str:
        """Build a concise text summary of endpoints for the LLM."""
        lines = [
            f"=== HAR Analysis: {len(endpoints)} API Endpoints ===",
            "",
        ]

        for i, ep in enumerate(endpoints, 1):
            # Truncate body to save tokens
            body_preview = ""
            if ep.request_body:
                body_preview = ep.request_body[:200]

            resp_preview = ""
            if ep.response_body:
                resp_preview = ep.response_body[:200]

            lines.extend([
                f"--- Endpoint {i} ---",
                f"Method: {ep.method.value}",
                f"URL: {ep.url}",
                f"Status: {ep.response_status}",
                f"SF IDs: {ep.sf_ids[:3] if ep.sf_ids else 'none'}",
                f"SF Object: {ep.sf_object_type or 'unknown'}",
                f"SF Version: {ep.sf_api_version or 'unknown'}",
                f"Portal: {ep.portal_name}",
                f"Headers: {json.dumps({k: v[:50] for k, v in list(ep.headers.items())[:5]})}",
                f"Request Body: {body_preview}",
                f"Response Body: {resp_preview}",
                "",
            ])

        return "\n".join(lines)

    def _get_client(self) -> Any:
        if self._client:
            return self._client

        if not self.api_key:
            logger.warning("No API key for HAR analysis")
            return None

        try:
            if self.provider == "openai":
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key, timeout=60)
            elif self.provider == "anthropic":
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key, timeout=60)
            return self._client
        except Exception as e:
            logger.error(f"Failed to init LLM client: {e}")
            return None

    def _call_openai(self, client: Any, user_prompt: str) -> dict | None:
        response = client.chat.completions.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": _HAR_ANALYSIS_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
        raw = response.choices[0].message.content or "{}"
        return self._parse_json_response(raw)

    def _call_anthropic(self, client: Any, user_prompt: str) -> dict | None:
        response = client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=_HAR_ANALYSIS_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        raw = response.content[0].text if response.content else "{}"
        return self._parse_json_response(raw)

    @staticmethod
    def _parse_json_response(raw: str) -> dict | None:
        """3-tier JSON parsing: strip markdown, extract {}, fallback."""
        cleaned = raw.strip()
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.MULTILINE)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass
        logger.warning("Failed to parse LLM JSON response")
        return None

    def _chunk_endpoints(
        self, endpoints: list[APIEndpoint], chunk_size: int
    ) -> list[list[APIEndpoint]]:
        """Split endpoints into chunks for token-efficient LLM calls."""
        return [
            endpoints[i:i + chunk_size]
            for i in range(0, len(endpoints), chunk_size)
        ]

    def _merge_overalls(
        self, analyses: list[dict], endpoints: list[APIEndpoint]
    ) -> dict[str, Any]:
        """Merge overall assessments from multiple LLM chunks."""
        app_types = [a.get("overall", {}).get("app_type", "") for a in analyses if a.get("overall")]
        auth_patterns = [a.get("overall", {}).get("auth_pattern", "") for a in analyses if a.get("overall")]
        data_classes = [a.get("overall", {}).get("data_classification", "") for a in analyses if a.get("overall")]
        notes = [a.get("overall", {}).get("notes", "") for a in analyses if a.get("overall")]
        attack_priorities = []
        for a in analyses:
            attack_priorities.extend(a.get("overall", {}).get("attack_priority", []))

        return {
            "app_type": max(set(app_types), key=app_types.count) if app_types else "unknown",
            "auth_pattern": max(set(auth_patterns), key=auth_patterns.count) if auth_patterns else "unknown",
            "data_classification": max(set(data_classes), key=data_classes.count) if data_classes else "unknown",
            "attack_priority": attack_priorities[:20],
            "notes": " | ".join(filter(None, notes[:3])),
        }

    @staticmethod
    def _heuristic_summary(endpoints: list[APIEndpoint]) -> dict[str, Any]:
        """Fallback heuristic analysis when LLM is disabled."""
        endpoints_analysis = []
        for ep in endpoints:
            risk = "medium"
            attack_surface = []

            if ep.sf_object_type in ("User", "Profile", "PermissionSet"):
                risk = "high"
                attack_surface.append("API3:BFLA")

            if "query" in ep.path.lower():
                attack_surface.append("A03:Injection")
                risk = "high"

            if ep.method.value == "DELETE":
                risk = "high"
                attack_surface.append("API1:BOLA")

            if not attack_surface:
                attack_surface = ["API8:SecurityMisconfig"]

            endpoints_analysis.append({
                "url": ep.url,
                "method": ep.method.value,
                "purpose": f"SF {ep.sf_object_type or 'API'} endpoint",
                "auth_mechanism": "Bearer/Session",
                "sensitive_data": "Unknown (LLM analysis disabled)",
                "risk_level": risk,
                "attack_surface": attack_surface,
                "business_logic": "",
            })

        return {
            "endpoints": endpoints_analysis,
            "overall": {
                "app_type": "Salesforce portal",
                "auth_pattern": "OAuth2/Session",
                "data_classification": "Unknown (LLM disabled)",
                "attack_priority": [ep.url for ep in endpoints[:10]],
                "notes": "Heuristic analysis only — enable llm_config for deep analysis",
            },
            "total_endpoints_analysed": len(endpoints_analysis),
            "analysis_method": "heuristic",
        }
