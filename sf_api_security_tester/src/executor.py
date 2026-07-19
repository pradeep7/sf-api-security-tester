"""Executes mutated HTTP requests and captures raw request/response (V2 with WAF evasion)."""

from __future__ import annotations

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
    ):
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.ssl_verify = ssl_verify
        self.dry_run = dry_run
        self.session_expired = False  # Flag: once set, halt all further requests

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

        self._evasion_client: EvasionClient | None = None

    def _get_client(self) -> EvasionClient:
        """Get or create the EvasionClient."""
        if self._evasion_client is None:
            self._evasion_client = EvasionClient(
                evasion=self.waf_evasion,
                timeout=self.timeout,
                ssl_verify=self.ssl_verify,
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

        # Build request
        http_request = HttpRequest(
            method=mutated_request.method.value,
            url=mutated_request.url,
            headers=headers,
            body=mutated_request.body,
            cookies=mutated_request.cookies,
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
                    cookies=mutated_request.cookies,
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
