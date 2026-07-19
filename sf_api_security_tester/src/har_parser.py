"""HAR file parser that extracts Salesforce-specific API endpoints."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from loguru import logger

from .models import APIEndpoint, HTTPMethod

# Static asset extensions to filter out
STATIC_EXTENSIONS = frozenset({
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webm",
    ".pdf", ".zip", ".tar", ".gz",
})

# Salesforce API path patterns
SF_API_PATTERNS = [
    re.compile(r"/services/data/"),
    re.compile(r"/services/apexrest/"),
    re.compile(r"/services/soap/"),
    re.compile(r"/aura"),
    re.compile(r"/sobjects/"),
    re.compile(r"/query"),
    re.compile(r"/search"),
    re.compile(r"/chatter/"),
    re.compile(r"/connect/"),
    re.compile(r"/tooling/"),
    re.compile(r"/composite/"),
    re.compile(r"/blobs/"),
    re.compile(r"/limits"),
]

# SF API version pattern
SF_VERSION_PATTERN = re.compile(r"/v(\d+\.\d+)/")

# Salesforce 15-char and 18-char ID patterns
SF_ID_15 = re.compile(r"\b[0-9A-Za-z]{15}\b")
SF_ID_18 = re.compile(r"\b[0-9A-Za-z]{18}\b")

# Salesforce object type prefix mapping (common prefixes)
SF_OBJECT_PREFIXES = {
    "001": "Account",
    "003": "Contact",
    "005": "User",
    "006": "Opportunity",
    "00Q": "Lead",
    "500": "Case",
    "800": "Contract",
    "0TO": "FeedItem",
    "069": "ContentVersion",
    "069": "ContentDocument",
    "a00": "Custom__c",
}


class HARParser:
    """Parses HAR files and extracts Salesforce API endpoints."""

    def __init__(self, portal_name: str = "", base_url: str = ""):
        self.portal_name = portal_name
        self.base_url = base_url.rstrip("/") if base_url else ""

    def parse_file(self, har_path: str | Path) -> list[APIEndpoint]:
        """Parse a HAR file and return extracted API endpoints."""
        har_path = Path(har_path)
        if not har_path.exists():
            logger.error(f"HAR file not found: {har_path}")
            return []

        logger.info(f"Parsing HAR file: {har_path.name}")
        with open(har_path, "r", encoding="utf-8") as f:
            har_data = json.load(f)

        return self.parse_har_data(har_data)

    def parse_har_data(self, har_data: dict[str, Any]) -> list[APIEndpoint]:
        """Parse HAR JSON data and extract API endpoints."""
        endpoints: list[APIEndpoint] = []
        entries = har_data.get("log", {}).get("entries", [])

        logger.info(f"Processing {len(entries)} HAR entries")

        for entry in entries:
            endpoint = self._extract_endpoint(entry)
            if endpoint:
                endpoints.append(endpoint)

        logger.info(f"Extracted {len(endpoints)} API endpoints")
        return endpoints

    def _extract_endpoint(self, entry: dict[str, Any]) -> APIEndpoint | None:
        """Extract a single APIEndpoint from a HAR entry."""
        request = entry.get("request", {})
        response = entry.get("response", {})

        url = request.get("url", "")
        method_str = request.get("method", "GET").upper()

        # Filter out static assets
        if self._is_static_asset(url):
            return None

        # Only keep Salesforce API endpoints
        if not self._is_sf_api_endpoint(url):
            return None

        # Parse URL components
        parsed = urlparse(url)
        path = parsed.path
        query_params = self._parse_query_string(request.get("queryString", []))

        # Extract SF API version
        sf_version = self._extract_sf_version(path)

        # Extract Salesforce IDs from URL and body
        body_text = self._get_request_body(request)
        sf_ids = self._extract_sf_ids(url, body_text)

        # Extract object type from path
        sf_object = self._extract_object_type(path)

        # Extract headers
        headers = self._parse_headers(request.get("headers", []))
        resp_headers = self._parse_headers(response.get("headers", []))

        # Extract cookies
        cookies = self._parse_cookies(request.get("headers", []))

        # Build endpoint
        try:
            method = HTTPMethod(method_str)
        except ValueError:
            method = HTTPMethod.GET

        response_body = None
        resp_content = response.get("content", {})
        if resp_content and resp_content.get("text"):
            response_body = resp_content["text"]

        endpoint = APIEndpoint(
            url=url,
            method=method,
            path=path,
            query_string=query_params,
            headers=headers,
            request_body=body_text,
            request_content_type=headers.get("Content-Type"),
            response_status=response.get("status", 0),
            response_body=response_body,
            response_headers=resp_headers,
            cookies=cookies,
            sf_ids=sf_ids,
            sf_api_version=sf_version,
            sf_object_type=sf_object,
            portal_name=self.portal_name,
            timestamp=entry.get("startedDateTime", ""),
            raw_har_entry=entry,
        )

        return endpoint

    def _is_static_asset(self, url: str) -> bool:
        """Check if URL points to a static asset."""
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        return any(path_lower.endswith(ext) for ext in STATIC_EXTENSIONS)

    def _is_sf_api_endpoint(self, url: str) -> bool:
        """Check if URL matches Salesforce API patterns."""
        parsed = urlparse(url)
        path = parsed.path

        # Must match at least one SF API pattern
        for pattern in SF_API_PATTERNS:
            if pattern.search(path):
                return True

        # Also accept /s/ paths (Lightning community pages with API calls)
        if path.startswith("/s/") and any(
            kw in url.lower()
            for kw in ["apexrest", "aura", "services", "sobjects"]
        ):
            return True

        return False

    def _extract_sf_version(self, path: str) -> str | None:
        """Extract Salesforce API version from URL path."""
        match = SF_VERSION_PATTERN.search(path)
        if match:
            return f"v{match.group(1)}"
        return None

    def _extract_sf_ids(self, url: str, body: str | None = None) -> list[str]:
        """Extract Salesforce 15/18-char IDs from URL and request body."""
        ids = set()

        # Check URL
        for match in SF_ID_18.finditer(url):
            ids.add(match.group())
        for match in SF_ID_15.finditer(url):
            candidate = match.group()
            if candidate not in ids:
                ids.add(candidate)

        # Check request body
        if body:
            try:
                body_text = body if isinstance(body, str) else json.dumps(body)
            except (TypeError, ValueError):
                body_text = str(body)

            for match in SF_ID_18.finditer(body_text):
                ids.add(match.group())
            for match in SF_ID_15.finditer(body_text):
                candidate = match.group()
                if candidate not in ids:
                    ids.add(candidate)

        return list(ids)

    def _extract_object_type(self, path: str) -> str | None:
        """Extract Salesforce object type from URL path."""
        # Pattern: /sobjects/ObjectName
        sobjects_match = re.search(r"/sobjects/(\w+)", path)
        if sobjects_match:
            return sobjects_match.group(1)

        # Pattern: /query?q=SELECT ... FROM ObjectName
        query_match = re.search(r"FROM\s+(\w+)", path, re.IGNORECASE)
        if query_match:
            return query_match.group(1)

        # Pattern: /apexrest/namespace/.../ObjectName
        apex_match = re.search(r"/apexrest/[^/]+/[^/]+/(\w+)", path)
        if apex_match:
            return apex_match.group(1)

        return None

    def _parse_query_string(self, query_string: list[dict]) -> dict[str, str]:
        """Parse HAR query string array into a dict."""
        params = {}
        for item in query_string:
            name = item.get("name", "")
            value = item.get("value", "")
            if name:
                params[name] = value
        return params

    def _parse_headers(self, headers: list[dict]) -> dict[str, str]:
        """Parse HAR headers array into a dict."""
        result = {}
        for header in headers:
            name = header.get("name", "")
            value = header.get("value", "")
            if name:
                result[name] = value
        return result

    def _parse_cookies(self, headers: list[dict]) -> dict[str, str]:
        """Extract cookies from Cookie header."""
        cookies = {}
        for header in headers:
            if header.get("name", "").lower() == "cookie":
                cookie_str = header.get("value", "")
                for pair in cookie_str.split(";"):
                    pair = pair.strip()
                    if "=" in pair:
                        key, _, value = pair.partition("=")
                        cookies[key.strip()] = value.strip()
        return cookies

    def _get_request_body(self, request: dict) -> str | None:
        """Extract request body text from HAR request."""
        post_data = request.get("postData", {})
        if post_data:
            return post_data.get("text", None)
        return None


def parse_har_files(
    har_paths: list[str | Path],
    portal_names: list[str] | None = None,
    base_urls: list[str] | None = None,
) -> list[APIEndpoint]:
    """Convenience function to parse multiple HAR files."""
    all_endpoints: list[APIEndpoint] = []

    if portal_names is None:
        portal_names = [f"portal_{i}" for i in range(len(har_paths))]
    if base_urls is None:
        base_urls = [""] * len(har_paths)

    for i, har_path in enumerate(har_paths):
        portal_name = portal_names[i] if i < len(portal_names) else f"portal_{i}"
        base_url = base_urls[i] if i < len(base_urls) else ""

        parser = HARParser(portal_name=portal_name, base_url=base_url)
        endpoints = parser.parse_file(har_path)
        all_endpoints.extend(endpoints)

    return all_endpoints
