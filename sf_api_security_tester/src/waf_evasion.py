"""WAF detection, rate limiting, and evasion techniques."""

from __future__ import annotations

import random
import re
import time
from typing import Any

import httpx
from loguru import logger


# ---------------------------------------------------------------------------
# Salesforce API limit error codes (must NOT trigger backoff)
# ---------------------------------------------------------------------------
_SF_LIMIT_CODES: list[re.Pattern] = [
    re.compile(r"REQUEST_LIMIT_EXCEEDED", re.IGNORECASE),
    re.compile(r"CONCURRENT_REQUEST_LIMIT", re.IGNORECASE),
    re.compile(r"API_REQUESTS_EXCEEDED", re.IGNORECASE),
    re.compile(r"TotalRequestsLimit", re.IGNORECASE),
    re.compile(r"ConcurrentApexLimit", re.IGNORECASE),
    re.compile(r"ConcurrentAsyncGetReportInstancesLimit", re.IGNORECASE),
    re.compile(r"SingleEmailLimit", re.IGNORECASE),
    re.compile(r"DailyApiRequests", re.IGNORECASE),
    re.compile(r"rate.*limit.*exceeded", re.IGNORECASE),
    re.compile(r"you_have_reached", re.IGNORECASE),
    re.compile(r"Limit exceeded", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# User-Agent rotation pool
# ---------------------------------------------------------------------------
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

# ---------------------------------------------------------------------------
# WAF detection signatures
# ---------------------------------------------------------------------------
_WAF_SIGNATURES: list[re.Pattern] = [
    re.compile(r"access.?denied", re.IGNORECASE),
    re.compile(r"forbidden", re.IGNORECASE),
    re.compile(r"security.?alert", re.IGNORECASE),
    re.compile(r"blocked.?by.?waf", re.IGNORECASE),
    re.compile(r"request.?blocked", re.IGNORECASE),
    re.compile(r"not.?acceptable", re.IGNORECASE),
    re.compile(r"rate.?limit", re.IGNORECASE),
    re.compile(r"too.?many.?requests", re.IGNORECASE),
    re.compile(r"please.?wait", re.IGNORECASE),
    re.compile(r"captcha", re.IGNORECASE),
    re.compile(r"cloudflare", re.IGNORECASE),
    re.compile(r"incapsula", re.IGNORECASE),
    re.compile(r"akamai", re.IGNORECASE),
    re.compile(r"awswaf", re.IGNORECASE),
    re.compile(r"imperva", re.IGNORECASE),
    re.compile(r"barracuda", re.IGNORECASE),
    re.compile(r"f5.?bigip", re.IGNORECASE),
    re.compile(r"fortiweb", re.IGNORECASE),
]

_WAF_HEADER_SIGNATURES: list[re.Pattern] = [
    re.compile(r"x-akamai", re.IGNORECASE),
    re.compile(r"x-sucuri", re.IGNORECASE),
    re.compile(r"x-cdn", re.IGNORECASE),
    re.compile(r"cf-ray", re.IGNORECASE),
    re.compile(r"x-firewall", re.IGNORECASE),
    re.compile(r"x-waf", re.IGNORECASE),
    re.compile(r"x-protected-by", re.IGNORECASE),
    re.compile(r"server.*cloudflare", re.IGNORECASE),
]

# Status codes that commonly indicate WAF blocking
_WAF_STATUS_CODES = {403, 406, 429, 503}


class WafBlockDetected(Exception):
    """Raised when a WAF block is detected."""
    pass


class SalesforceLimitExceededException(Exception):
    """Raised when a Salesforce API limit is reached.

    The framework MUST halt the current test suite immediately to prevent
    org lockout.  Do NOT retry or backoff — the 24-hour limit has been hit.
    """
    pass


class WafEvasion:
    """Wraps httpx execution with WAF detection, rate limiting, and evasion."""

    def __init__(
        self,
        delay_between_requests: float = 1.0,
        max_delay: float = 60.0,
        backoff_multiplier: float = 2.0,
        max_retries: int = 5,
        rate_limit_cooldown: float = 30.0,
        rotate_user_agent: bool = True,
        enabled: bool = True,
    ):
        self.delay_between_requests = delay_between_requests
        self.max_delay = max_delay
        self.backoff_multiplier = backoff_multiplier
        self.max_retries = max_retries
        self.rate_limit_cooldown = rate_limit_cooldown
        self.rotate_user_agent = rotate_user_agent
        self.enabled = enabled

        # State tracking
        self._last_request_time: float = 0.0
        self._current_delay: float = delay_between_requests
        self._waf_block_count: int = 0
        self._total_requests: int = 0
        self._blocked_requests: int = 0
        self._current_user_agent_index: int = random.randint(0, len(_USER_AGENTS) - 1)
        self._detected_waf: str | None = None

        logger.info(
            f"WafEvasion initialised (delay={delay_between_requests}s, "
            f"backoff={backoff_multiplier}x, max_retries={max_retries})"
        )

    def get_user_agent(self) -> str:
        """Get current User-Agent, optionally rotating."""
        if self.rotate_user_agent:
            self._current_user_agent_index = (
                (self._current_user_agent_index + 1) % len(_USER_AGENTS)
            )
        return _USER_AGENTS[self._current_user_agent_index]

    def rotate_user_agent(self) -> str:
        """Force rotate to a new User-Agent and return it."""
        self._current_user_agent_index = random.randint(0, len(_USER_AGENTS) - 1)
        return _USER_AGENTS[self._current_user_agent_index]

    def wait_if_needed(self):
        """Enforce rate limiting by waiting if needed."""
        if not self.enabled:
            return

        elapsed = time.time() - self._last_request_time
        if elapsed < self._current_delay:
            sleep_time = self._current_delay - elapsed
            logger.debug(f"Rate limit: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)

    def record_request(self):
        """Record that a request was made."""
        self._last_request_time = time.time()
        self._total_requests += 1

    def is_waf_block(
        self,
        status_code: int,
        response_body: str | None,
        response_headers: dict[str, str] | None = None,
    ) -> bool:
        """Detect whether a response indicates a WAF block."""
        if not self.enabled:
            return False

        # Status code check
        if status_code in _WAF_STATUS_CODES:
            if response_body:
                body_lower = response_body.lower()
                for sig in _WAF_SIGNATURES:
                    if sig.search(body_lower):
                        return True
            # 403 without body still suspicious
            if status_code == 403:
                return True

        # Header-based detection
        if response_headers:
            for header_name, header_value in response_headers.items():
                combined = f"{header_name}: {header_value}"
                for sig in _WAF_HEADER_SIGNATURES:
                    if sig.search(combined):
                        if status_code in _WAF_STATUS_CODES:
                            return True

        # Body signature check (even on 200)
        if response_body and status_code == 200:
            body_lower = response_body.lower()
            strong_indicators = ["blocked by waf", "security alert", "request blocked"]
            for indicator in strong_indicators:
                if indicator in body_lower:
                    return True

        return False

    def detect_waf_name(
        self,
        response_body: str | None,
        response_headers: dict[str, str] | None = None,
    ) -> str | None:
        """Try to identify which WAF is in use."""
        waf_names = {
            "cloudflare": "Cloudflare",
            "incapsula": "Incapsula/Imperva",
            "akamai": "Akamai",
            "awswaf": "AWS WAF",
            "imperva": "Imperva",
            "barracuda": "Barracuda",
            "f5": "F5 BIG-IP ASM",
            "fortiweb": "FortiWeb",
            "sucuri": "Sucuri",
            "modsecurity": "ModSecurity",
        }

        check_text = ""
        if response_body:
            check_text += response_body.lower()
        if response_headers:
            check_text += " ".join(
                f"{k}:{v}" for k, v in response_headers.items()
            ).lower()

        for keyword, name in waf_names.items():
            if keyword in check_text:
                return name

        return None

    @staticmethod
    def is_salesforce_limit(response_body: str | None) -> bool:
        """Detect Salesforce-specific API limit errors.

        These MUST NOT trigger WAF backoff — they indicate the org's 24-hour
        API request limit has been reached.
        """
        if not response_body:
            return False
        return any(pat.search(response_body) for pat in _SF_LIMIT_CODES)

    def handle_waf_response(
        self,
        status_code: int,
        response_body: str | None,
        response_headers: dict[str, str] | None,
    ) -> tuple[bool, float]:
        """Handle a potential WAF response.

        Returns:
            (should_retry, delay_seconds)
        Raises:
            SalesforceLimitExceededException: If a Salesforce API limit is detected.
        """
        if not self.enabled:
            return False, 0

        # --- CRITICAL: Salesforce limit check BEFORE WAF check ---
        # A 403/429 from Salesforce often means the 24hr API limit was hit,
        # NOT a WAF block.  Retrying/backing off would make it worse.
        if self.is_salesforce_limit(response_body):
            raise SalesforceLimitExceededException(
                "Salesforce 24hr API limit reached. "
                "Stopping execution to prevent org lockout. "
                f"Response body: {(response_body or '')[:500]}"
            )

        if not self.is_waf_block(status_code, response_body, response_headers):
            # Not a WAF block - gradually decrease delay
            self._current_delay = max(
                self.delay_between_requests,
                self._current_delay / self.backoff_multiplier,
            )
            return False, 0

        # WAF block detected
        self._waf_block_count += 1
        self._blocked_requests += 1

        waf_name = self.detect_waf_name(response_body, response_headers)
        if waf_name:
            self._detected_waf = waf_name
            logger.warning(f"WAF detected: {waf_name}")

        # Exponential backoff
        self._current_delay = min(
            self._current_delay * self.backoff_multiplier,
            self.max_delay,
        )

        if self._waf_block_count >= self.max_retries:
            logger.error(
                f"WAF block limit reached ({self._waf_block_count} blocks). "
                f"Current delay: {self._current_delay:.1f}s"
            )
            return False, 0

        logger.warning(
            f"WAF block #{self._waf_block_count}. "
            f"Backing off {self._current_delay:.1f}s. "
            f"Rotating User-Agent."
        )

        # Rotate User-Agent for retry
        new_ua = self.rotate_user_agent()
        logger.debug(f"Rotated to User-Agent: {new_ua[:50]}...")

        return True, self._current_delay

    def reset_backoff(self):
        """Reset the backoff delay to default (e.g. after a success)."""
        self._current_delay = self.delay_between_requests
        self._waf_block_count = 0

    def get_stats(self) -> dict[str, Any]:
        """Return evasion statistics."""
        return {
            "total_requests": self._total_requests,
            "blocked_requests": self._blocked_requests,
            "block_rate": (
                round(self._blocked_requests / self._total_requests * 100, 1)
                if self._total_requests > 0
                else 0
            ),
            "current_delay": round(self._current_delay, 2),
            "detected_waf": self._detected_waf,
            "waf_block_count": self._waf_block_count,
            "current_user_agent": _USER_AGENTS[self._current_user_agent_index][:60] + "...",
        }


class EvasionClient:
    """HTTP client wrapper with built-in WAF evasion, rate limiting, and proxy support.

    Drop-in replacement for the plain httpx.Client in executor.py.
    """

    def __init__(
        self,
        evasion: WafEvasion | None = None,
        timeout: int = 30,
        ssl_verify: bool = True,
        proxy_url: str | None = None,
    ):
        self.evasion = evasion or WafEvasion()
        self._client: httpx.Client | None = None
        self._timeout = timeout
        self._ssl_verify = ssl_verify
        self._proxy_url = proxy_url

    def _get_client(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            if self._proxy_url:
                # Caido/Burp use MITM certificates — must disable SSL verification
                client_kwargs: dict[str, Any] = {
                    "timeout": httpx.Timeout(self._timeout),
                    "verify": False,
                    "follow_redirects": False,
                    "proxy": self._proxy_url,
                }
            else:
                client_kwargs = {
                    "timeout": httpx.Timeout(self._timeout),
                    "verify": self._ssl_verify,
                    "follow_redirects": False,
                }

            try:
                self._client = httpx.Client(**client_kwargs)
                if self._proxy_url:
                    logger.info(f"HTTP client initialised with proxy: {self._proxy_url} (verify=False for MITM)")
            except Exception as e:
                logger.warning(f"Proxy connection failed ({self._proxy_url}): {e}")
                logger.warning("Falling back to direct connection (no proxy)")
                self._client = httpx.Client(
                    timeout=httpx.Timeout(self._timeout),
                    verify=self._ssl_verify,
                    follow_redirects=False,
                )
        return self._client

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | str | None = None,
        cookies: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Execute a request with WAF evasion.

        Retries on WAF blocks with exponential backoff and User-Agent rotation.
        Raises SalesforceLimitExceededException immediately if a Salesforce API
        limit is detected (no retry, no backoff).
        """
        if self.evasion.enabled:
            # Ensure we have a User-Agent
            if headers is None:
                headers = {}
            if "User-Agent" not in headers:
                headers["User-Agent"] = self.evasion.get_user_agent()

        client = self._get_client()

        for attempt in range(self.evasion.max_retries + 1):
            # Rate limit
            self.evasion.wait_if_needed()

            try:
                resp = client.request(
                    method=method,
                    url=url,
                    headers=headers or {},
                    content=content.encode("utf-8") if isinstance(content, str) else content,
                    cookies=cookies,
                )
                self.evasion.record_request()

                # Check for Salesforce limit FIRST (raises immediately)
                resp_body_full = resp.text[:50000] if resp.text else None
                if self.evasion.is_salesforce_limit(resp_body_full):
                    raise SalesforceLimitExceededException(
                        "Salesforce 24hr API limit reached. "
                        "Stopping execution to prevent org lockout."
                    )

                # Check for WAF block
                resp_body = resp.text[:10000] if resp.text else None
                should_retry, delay = self.evasion.handle_waf_response(
                    status_code=resp.status_code,
                    response_body=resp_body,
                    response_headers=dict(resp.headers),
                )

                if should_retry and attempt < self.evasion.max_retries:
                    # Rotate User-Agent for next attempt
                    if headers is not None:
                        headers["User-Agent"] = self.evasion.rotate_user_agent()
                    time.sleep(delay)
                    continue

                return resp

            except SalesforceLimitExceededException:
                # Re-raise immediately — do NOT retry or backoff
                raise

            except httpx.ProxyError as e:
                # Proxy-specific failure — fall back to direct connection
                logger.warning(f"Proxy error: {e}")
                logger.warning("Falling back to direct connection (bypassing proxy)")
                self._proxy_url = None
                self._client = httpx.Client(
                    timeout=httpx.Timeout(self._timeout),
                    verify=self.evasion.enabled and True or True,
                    follow_redirects=False,
                )
                # Retry once with direct connection
                try:
                    resp = self._client.request(
                        method=method,
                        url=url,
                        headers=headers or {},
                        content=content.encode("utf-8") if isinstance(content, str) else content,
                        cookies=cookies,
                    )
                    self.evasion.record_request()
                    return resp
                except Exception:
                    raise

            except httpx.TimeoutException:
                logger.warning(f"Timeout on attempt {attempt + 1}: {url[:80]}")
                if attempt < self.evasion.max_retries:
                    time.sleep(self.evasion.delay_between_requests)
                    continue
                raise

            except httpx.RequestError as e:
                logger.warning(f"Request error on attempt {attempt + 1}: {e}")
                if attempt < self.evasion.max_retries:
                    time.sleep(self.evasion.delay_between_requests)
                    continue
                raise

        # Fallback - should not normally reach here
        raise httpx.RequestError(f"All {self.evasion.max_retries + 1} attempts failed")

    def close(self):
        """Close the underlying client."""
        if self._client and not self._client.is_closed:
            self._client.close()

    @property
    def stats(self) -> dict[str, Any]:
        return self.evasion.get_stats()
