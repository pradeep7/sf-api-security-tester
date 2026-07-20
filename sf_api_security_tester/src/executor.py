"""Executes mutated HTTP requests and captures raw request/response (V2 with WAF evasion).

V3.1: Added upstream proxy support, smart telemetry headers, and cookie harvesting.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any

import httpx
from loguru import logger

from .models import (
    HttpRequest,
    HttpResponse,
    MutatedRequest,
    MutatedRequest,
)
from .waf_evasion import EvasionClient, SalesforceLimitExceededException, WafEvasion


# Salesforce session expiry detection patterns
_SESSION_EXPIRY_PATTERNS: list[re.Pattern] = [
    re.compile(r"INVALID_SESSION_ID", re.IGNORECASE),
    re.compile(r"session.*expired", re.IGNORECASE),
    re.compile(r"session.*invalid", re.IGNORECASE),
    re.compile(r"SessionId.*invalid", re.IGNORECASE),
    re.compile(r"not.*valid.*session", re.IGNORECASE),
    re.compile(r"authentication.*failure", re.IGNORECASE),
    re.compile(r"invalidated.*token", re.IGNORECASE),
]


class SessionExpiredException(Exception):
    """Raised when a Salesforce session token is detected as expired."""
    pass


class RequestExecutor:
    """Executes mutated HTTP requests with WAF evasion, retry logic, and evidence capture."""

    def __init__(
        self,
        timeout: int = 30,
        retry_count: int = 2,
        retry_delay: float = 2.0,
        ssl_verify: bool = True,
        dry_run: bool = False,
        waf_evasion_config: dict[str, Any] | None = None,
        proxy_config: dict[str, Any] | None = None,
        harvested_cookies: dict[str, str] | None = None,
    ):
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.ssl_verify = ssl_verify
        self.dry_run = dry_run
        self.session_expired = False  # Flag: once set, halt all further requests

        # Harvested cookies from manual auth
        self.harvested_cookies: dict[str, str] = harvested_cookies or {}

        # Initialise WAF evasion
        waf_cfg = waf_evasion_config or {}
        self.waf_evasion = WafEvasion(
            delay_between_requests=waf_cfg.get("delay_between_requests", 1.0),
            max_delay=waf_cfg.get("max_delay", 60.0),
            backoff_multiplier=waf_cfg.get("backoff_multiplier", 2.0),
            max_retries=waf_cfg.get("max_retries", 5),
            rate_limit_cooldown=waf_cfg.get("rate_limit_cooldown", 30.0),
            rotate_user_agent=waf_cfg.get("rotate_user_agent", True),
            enabled=waf_cfg.get("enabled", True),
        )

        # Proxy configuration (Caido / Burp)
        proxy_cfg = proxy_config or {}
        proxy_enabled = proxy_cfg.get("enabled", False)
        self._proxy_url: str | None = None
        if proxy_enabled:
            self._proxy_url = proxy_cfg.get("url", "http://127.0.0.1:8080")
            logger.info(f"Upstream proxy enabled: {self._proxy_url}")

        self._evasion_client: EvasionClient | None = None

    def _get_client(self) -> EvasionClient:
        """Get or create the EvasionClient."""
        if self._evasion_client is None:
            self._evasion_client = EvasionClient(
                evasion=self.waf_evasion,
                timeout=self.timeout,
                ssl_verify=self.ssl_verify,
                proxy_url=self._proxy_url,
            )
        return self._evasion_client

    def close(self):
        """Close the HTTP client."""
        if self._evasion_client:
            self._evasion_client.close()

    def execute(self, mutated_request: MutatedRequest) -> tuple[HttpRequest, HttpResponse, int]:
        """Execute a mutated request and return (request, response, execution_time_ms).

        Raises:
            SessionExpiredException: If Salesforce session is detected as expired.
            SalesforceLimitExceededException: If org API limit is reached.
        """
        # Fast-fail: if session already expired in a prior call, don't even try
        if self.session_expired:
            raise SessionExpiredException(
                "Session expired earlier in this run. Remaining tests skipped."
            )

        if self.dry_run:
            return self._dry_run_execute(mutated_request)

        client = self._get_client()

        # Build headers
        headers = dict(mutated_request.headers)
        if mutated_request.content_type:
            headers["Content-Type"] = mutated_request.content_type

        # Ensure User-Agent is set (EvasionClient rotates if missing)
        if "User-Agent" not in headers:
            headers["User-Agent"] = self.waf_evasion.get_user_agent()

        # --- Smart Telemetry Headers (Feature 2) ---
        telemetry = self._build_telemetry_headers(mutated_request)
        headers.update(telemetry)

        # --- Merge harvested cookies (Feature 4: HAR+Cookie hybrid) ---
        cookies = dict(mutated_request.cookies)
        if self.harvested_cookies:
            cookies.update(self.harvested_cookies)

        # Build request
        http_request = HttpRequest(
            method=mutated_request.method.value,
            url=mutated_request.url,
            headers=headers,
            body=mutated_request.body,
            cookies=cookies,
        )

        last_exception = None
        for attempt in range(self.retry_count + 1):
            try:
                start_time = time.time()
                response = client.request(
                    method=mutated_request.method.value,
                    url=mutated_request.url,
                    headers=headers,
                    content=mutated_request.body.encode("utf-8") if mutated_request.body else None,
                    cookies=cookies,
                )
                elapsed_ms = int((time.time() - start_time) * 1000)

                http_response = HttpResponse(
                    status_code=response.status_code,
                    status_text=response.reason_phrase or "",
                    headers=dict(response.headers),
                    body=response.text[:10000] if response.text else None,
                    http_version=f"HTTP/{response.http_version}",
                    content_length=len(response.content),
                )

                # --- Session expiry detection (401 + body check) ---
                if response.status_code == 401:
                    resp_text = response.text or ""
                    if self._is_session_expired(resp_text):
                        self.session_expired = True
                        logger.error(
                            "Session expired mid-scan (401 + INVALID_SESSION_ID). "
                            "Saving evidence collected so far and halting."
                        )
                        raise SessionExpiredException(
                            f"Salesforce session expired. Response: {resp_text[:500]}"
                        )

                logger.debug(
                    f"Executed {mutated_request.method.value} {mutated_request.url[:80]}... "
                    f"-> {response.status_code} ({elapsed_ms}ms)"
                )
                return http_request, http_response, elapsed_ms

            except (SalesforceLimitExceededException, SessionExpiredException):
                # Do NOT retry — propagate immediately to orchestrator
                raise

            except httpx.TimeoutException as e:
                last_exception = e
                logger.warning(
                    f"Timeout on attempt {attempt + 1}: {mutated_request.url[:80]}..."
                )
                if attempt < self.retry_count:
                    time.sleep(self.retry_delay)

            except httpx.ConnectError as e:
                last_exception = e
                logger.warning(
                    f"Connection error on attempt {attempt + 1}: {e}"
                )
                if attempt < self.retry_count:
                    time.sleep(self.retry_delay)

            except httpx.RequestError as e:
                last_exception = e
                logger.warning(
                    f"Request error on attempt {attempt + 1}: {e}"
                )
                if attempt < self.retry_count:
                    time.sleep(self.retry_delay)

            except Exception as e:
                last_exception = e
                logger.error(f"Unexpected error executing request: {e}")
                break

        # All retries failed
        error_response = HttpResponse(
            status_code=0,
            status_text="Error",
            body=f"Request failed after {self.retry_count + 1} attempts: {last_exception}",
        )
        return http_request, error_response, 0

    @staticmethod
    def _is_session_expired(response_body: str) -> bool:
        """Check if a 401 response indicates Salesforce session expiry."""
        if not response_body:
            return True  # Empty 401 body is almost certainly session expiry
        return any(pat.search(response_body) for pat in _SESSION_EXPIRY_PATTERNS)

    def _build_telemetry_headers(self, mutated_request: MutatedRequest) -> dict[str, str]:
        """Build smart telemetry headers for proxy visibility.

        Headers are added AFTER WAF evasion headers so they appear in proxy logs.
        Raw payloads are NEVER sent — only MD5 hashes.
        """
        headers: dict[str, str] = {}

        # Phase identification
        test_case_id = mutated_request.test_case_id
        if test_case_id.startswith("domxss"):
            headers["X-SecTest-Phase"] = "Phase-0.5-DOM-XSS"
        elif test_case_id.startswith("probe") or "probe" in mutated_request.mutation_description.lower():
            headers["X-SecTest-Phase"] = "Phase-0.5-SafeProbe"
        else:
            headers["X-SecTest-Phase"] = "Phase-3-Mutation"

        # OWASP category from test case ID or mutation type
        mutation_desc = mutated_request.mutation_description.lower()
        owasp_categories = []
        if "soql" in mutation_desc or "sqli" in mutation_desc:
            owasp_categories.append("A03")
        if "bola" in mutation_desc or "idor" in mutation_desc:
            owasp_categories.append("API1")
        if "xss" in mutation_desc:
            owasp_categories.append("A03")
        if "ssrf" in mutation_desc:
            owasp_categories.append("API7")
        if "cors" in mutation_desc:
            owasp_categories.append("API8")
        if "auth" in mutation_desc:
            owasp_categories.append("API2")
        if "admin" in mutation_desc or "bfla" in mutation_desc:
            owasp_categories.append("API3")
        if "mass" in mutation_desc:
            owasp_categories.append("A04")

        if owasp_categories:
            headers["X-SecTest-OWASP"] = ",".join(sorted(set(owasp_categories)))

        # Test category
        if "soql" in mutation_desc:
            headers["X-SecTest-Category"] = "SOQL-Injection"
        elif "sosl" in mutation_desc:
            headers["X-SecTest-Category"] = "SOSL-Injection"
        elif "xss" in mutation_desc:
            headers["X-SecTest-Category"] = "XSS"
        elif "bola" in mutation_desc or "idor" in mutation_desc:
            headers["X-SecTest-Category"] = "BOLA"
        elif "ssrf" in mutation_desc:
            headers["X-SecTest-Category"] = "SSRF"
        elif "cors" in mutation_desc:
            headers["X-SecTest-Category"] = "CORS-Misconfiguration"
        elif "header" in mutation_desc:
            headers["X-SecTest-Category"] = "Security-Headers"
        elif "auth" in mutation_desc:
            headers["X-SecTest-Category"] = "Broken-Auth"
        elif "mass" in mutation_desc:
            headers["X-SecTest-Category"] = "Mass-Assignment"
        elif "admin" in mutation_desc or "bfla" in mutation_desc:
            headers["X-SecTest-Category"] = "BFLA"
        elif "path" in mutation_desc:
            headers["X-SecTest-Category"] = "Path-Traversal"
        else:
            headers["X-SecTest-Category"] = "Generic"

        # Case ID
        headers["X-SecTest-Case-ID"] = test_case_id[:64]

        # Payload hash (MD5 — never send raw payload in headers)
        payload_str = mutated_request.body or mutated_request.url
        payload_hash = hashlib.md5(payload_str.encode("utf-8")).hexdigest()
        headers["X-SecTest-Payload-Hash"] = payload_hash

        # --- V3.2: Injection point metadata ---
        # Target field (truncated to 64 chars to prevent header bloat)
        target_field = mutated_request.injection_field or "N/A"
        headers["X-SecTest-Target-Field"] = target_field[:64]

        # Injection location (query, json_body, form_body, url_path, header, cookie, multipart)
        inject_location = mutated_request.injection_location or "request_metadata"
        headers["X-SecTest-Inject-Location"] = inject_location

        return headers

    def _dry_run_execute(
        self, mutated_request: MutatedRequest
    ) -> tuple[HttpRequest, HttpResponse, int]:
        """Simulate execution in dry-run mode without sending requests."""
        headers = dict(mutated_request.headers)
        if mutated_request.content_type:
            headers["Content-Type"] = mutated_request.content_type

        http_request = HttpRequest(
            method=mutated_request.method.value,
            url=mutated_request.url,
            headers=headers,
            body=mutated_request.body,
            cookies=mutated_request.cookies,
        )

        logger.info(
            f"[DRY RUN] Would send: {mutated_request.method.value} {mutated_request.url[:100]}"
        )

        http_response = HttpResponse(
            status_code=0,
            status_text="Dry Run - Not Executed",
            body="This is a dry run. No request was sent.",
        )

        return http_request, http_response, 0

    def execute_batch(
        self, requests: list[MutatedRequest]
    ) -> list[tuple[MutatedRequest, HttpRequest, HttpResponse, int]]:
        """Execute a batch of mutated requests sequentially."""
        results = []
        for mutated_req in requests:
            http_req, http_resp, elapsed = self.execute(mutated_req)
            results.append((mutated_req, http_req, http_resp, elapsed))
        return results

    def get_waf_stats(self) -> dict[str, Any]:
        """Return WAF evasion statistics."""
        return self.waf_evasion.get_stats()
