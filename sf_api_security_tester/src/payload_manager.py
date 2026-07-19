"""Smart payload manager that fetches, caches, and deduplicates payloads from external sources."""

from __future__ import annotations

import hashlib
import os
import re
import time
from pathlib import Path
from typing import Any

import requests
from loguru import logger

# ---------------------------------------------------------------------------
# Default payload sources (Swisskyrepo / SecLists raw GitHub URLs)
# ---------------------------------------------------------------------------
DEFAULT_PAYLOAD_SOURCES: dict[str, list[str]] = {
    "sql_injection": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/MySQL/Generic_MySQL_injections.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/MySQL/MySQL_Bypass_waf.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Inband/UNION-based/detection_and_extraction.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Blind/Bool_blind.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Blind/Time_blind.txt",
    ],
    "soql_injection": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Inband/UNION-based/detection_and_extraction.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Generic/Basic_probing.txt",
    ],
    "xss": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Context%20from%20hackerone.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/DOM%20based%20XSS%20Bypassing%20DOMpurify.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/special-chars.txt",
    ],
    "ssrf": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/Generic.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/Cloud%20metadata%20requests.txt",
    ],
    "nosql_injection": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/MongoDB.txt",
    ],
    "path_traversal": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Path%20Traversal/Traversal%20techniques.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Path%20Traversal/Basic%20traversal.txt",
    ],
    "command_injection": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Unix%20wildcards%20tricks.txt",
    ],
    "cors_misconfiguration": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/Generic.txt",
    ],
    "xxe": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XXE%20Injection/PHP%20filter%20wrappers.txt",
    ],
    "mass_assignment": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Insecure%20Direct%20Object%20References/Insecure%20Direct%20Object%20References.txt",
    ],
    "authentication_bypass": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Authentication%20bypass/CVE.txt",
    ],
    "lfi": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Inclusion%20/Path%20Traversal/detection.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Inclusion%20/Path%20Traversal/Basic%20payload.txt",
    ],
}

# Patterns that indicate SOQL-compatible payloads (Salesforce-specific)
SOQL_COMPATIBILITY_PATTERNS = [
    re.compile(r"UNION\s+SELECT", re.IGNORECASE),
    re.compile(r"SELECT\s+.*\s+FROM\s+", re.IGNORECASE),
    re.compile(r"WHERE\s+'.*'\s*=\s*'", re.IGNORECASE),
    re.compile(r"OR\s+'1'\s*=\s*'1'", re.IGNORECASE),
    re.compile(r"'\s*OR\s+1\s*=\s*1", re.IGNORECASE),
    re.compile(r"--\s*$", re.MULTILINE),
    re.compile(r";\s*SELECT", re.IGNORECASE),
]

# Characters that are problematic in SOQL query strings
SOQL_SPECIAL_CHARS = set("';\"\\/\n\r\t")


class PayloadManager:
    """Fetches, caches, deduplicates, and serves payloads from external sources."""

    def __init__(
        self,
        cache_dir: str | Path = "payloads_cache",
        sources: dict[str, list[str]] | None = None,
        max_payloads_per_category: int = 200,
        cache_ttl_days: int = 7,
        request_timeout: int = 15,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.sources = sources or DEFAULT_PAYLOAD_SOURCES
        self.max_payloads_per_category = max_payloads_per_category
        self.cache_ttl_seconds = cache_ttl_days * 86400
        self.request_timeout = request_timeout

        # In-memory cache after first load
        self._memory_cache: dict[str, list[str]] = {}

        logger.info(
            f"PayloadManager initialised (cache_dir={self.cache_dir}, "
            f"max_per_category={self.max_payloads_per_category}, "
            f"cache_ttl={cache_ttl_days}d)"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get_payloads(
        self,
        category: str,
        context_filter: str | None = None,
        limit: int | None = None,
    ) -> list[str]:
        """Return deduplicated payloads for *category*, optionally filtered.

        Args:
            category: Payload category key (e.g. ``"sql_injection"``, ``"soql_injection"``).
            context_filter: Optional keyword – only payloads containing this string are kept.
            limit: Override ``max_payloads_per_category`` for this call.

        Returns:
            List of payload strings (may be empty if fetching failed and cache is cold).
        """
        limit = limit or self.max_payloads_per_category

        # Try memory cache first
        if category in self._memory_cache:
            payloads = self._memory_cache[category]
        else:
            payloads = self._load_category(category)

        if context_filter:
            payloads = [p for p in payloads if context_filter.lower() in p.lower()]

        return payloads[:limit]

    def get_all_categories(self) -> list[str]:
        """Return list of available payload category keys."""
        return list(self.sources.keys())

    def refresh_cache(self, category: str | None = None) -> int:
        """Force-refresh the cache for one or all categories.  Returns count of payloads loaded."""
        if category:
            categories = [category]
        else:
            categories = list(self.sources.keys())

        total = 0
        for cat in categories:
            # Invalidate memory cache
            self._memory_cache.pop(cat, None)
            # Delete file cache
            cache_file = self.cache_dir / f"{cat}.txt"
            if cache_file.exists():
                cache_file.unlink()
            total += len(self._load_category(cat))

        return total

    # ------------------------------------------------------------------
    # Loading logic
    # ------------------------------------------------------------------
    def _load_category(self, category: str) -> list[str]:
        """Load payloads for a category: fetch if needed, else read cache."""
        cache_file = self.cache_dir / f"{cat_file_name(category)}.txt"
        sources = self.sources.get(category, [])

        # Decide whether to fetch
        should_fetch = True
        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < self.cache_ttl_seconds:
                should_fetch = False

        if should_fetch and sources:
            raw_payloads = self._fetch_from_sources(sources)
            if raw_payloads:
                cleaned = self._deduplicate_and_clean(raw_payloads, category)
                self._write_cache(cache_file, cleaned)
                self._memory_cache[category] = cleaned
                logger.info(
                    f"Fetched and cached {len(cleaned)} payloads for '{category}' "
                    f"(from {len(sources)} sources)"
                )
                return cleaned
            else:
                logger.warning(
                    f"All sources failed for '{category}', falling back to cache"
                )

        # Fall back to file cache
        if cache_file.exists():
            payloads = self._read_cache(cache_file)
            self._memory_cache[category] = payloads
            logger.debug(f"Loaded {len(payloads)} cached payloads for '{category}'")
            return payloads

        logger.warning(f"No payloads available for '{category}'")
        return []

    def _fetch_from_sources(self, urls: list[str]) -> list[str]:
        """Fetch payload lines from a list of URLs. Returns raw merged lines."""
        all_lines: list[str] = []
        for url in urls:
            try:
                resp = requests.get(url, timeout=self.request_timeout, headers={
                    "User-Agent": "SF-SecurityTester/2.0-PayloadFetch",
                })
                if resp.status_code == 200:
                    text = resp.text
                    lines = [line.strip() for line in text.splitlines() if line.strip()]
                    all_lines.extend(lines)
                    logger.debug(f"Fetched {len(lines)} lines from {url[:80]}")
                else:
                    logger.warning(f"HTTP {resp.status_code} from {url[:80]}")
            except requests.Timeout:
                logger.warning(f"Timeout fetching {url[:80]}")
            except requests.ConnectionError as e:
                logger.warning(f"Connection error fetching {url[:80]}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error fetching {url[:80]}: {e}")

        return all_lines

    # ------------------------------------------------------------------
    # Cleaning & deduplication
    # ------------------------------------------------------------------
    def _deduplicate_and_clean(
        self, raw_lines: list[str], category: str
    ) -> list[str]:
        """Remove duplicates, comments, blanks, and enforce limit."""
        seen: set[str] = set()
        cleaned: list[str] = []

        for line in raw_lines:
            # Skip comments
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            if stripped.startswith("/*") or stripped.startswith("*"):
                continue

            # Deduplicate (case-sensitive)
            fingerprint = stripped
            if fingerprint in seen:
                continue
            seen.add(fingerprint)

            cleaned.append(stripped)

            if len(cleaned) >= self.max_payloads_per_category:
                break

        return cleaned

    def _write_cache(self, path: Path, payloads: list[str]):
        """Write payloads to cache file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(payloads), encoding="utf-8")

    def _read_cache(self, path: Path) -> list[str]:
        """Read payloads from cache file."""
        text = path.read_text(encoding="utf-8")
        return [line for line in text.splitlines() if line.strip()]

    # ------------------------------------------------------------------
    # SOQL-specific helpers
    # ------------------------------------------------------------------
    def get_soql_safe_payloads(self, limit: int = 100) -> list[str]:
        """Return payloads that are safe to inject into Salesforce SOQL query strings.

        Filters out payloads with characters that break SOQL syntax when used in
        URL query parameters (e.g. ``?q=...``).
        """
        all_soql = self.get_payloads("soql_injection", limit=limit * 3)
        safe: list[str] = []
        for p in all_soql:
            if not any(c in p for c in SOQL_SPECIAL_CHARS):
                safe.append(p)
            elif self._is_soql_compatible(p):
                # URL-encode the problematic chars and still include
                safe.append(p)
            if len(safe) >= limit:
                break
        return safe

    def _is_soql_compatible(self, payload: str) -> bool:
        """Check if payload matches known SOQL injection patterns."""
        return any(pat.search(payload) for pat in SOQL_COMPATIBILITY_PATTERNS)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def cat_file_name(category: str) -> str:
    """Sanitise category name for use as a filename."""
    return re.sub(r"[^a-z0-9_\-]", "_", category.lower())
