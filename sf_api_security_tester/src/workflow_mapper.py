"""Workflow Mapper — Detects multi-step business workflows from SiteMap.

Phase 0.5 of V3.1: Analyzes the SiteMap to identify multi-step workflows
(Salesforce Flows, CPQ wizards, approval chains) and maps them as state
machines for API6 state-transition attack testing.

Uses heuristics first (URL patterns, navigation patterns), then Vision LLM
for confirmation when heuristics are ambiguous.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

from loguru import logger

from .models import PageSnapshot, SiteMap, WorkflowModel, WorkflowStep

# ---------------------------------------------------------------------------
# Vision LLM prompt for workflow confirmation
# ---------------------------------------------------------------------------
_WORKFLOW_CONFIRM_PROMPT = """\
You are analysing screenshots and page descriptions from a Salesforce portal. \
Determine if these pages form a multi-step transactional workflow \
(e.g., checkout wizard, approval chain, multi-step form).

Return a JSON object:
{
  "is_workflow": <true/false>,
  "workflow_name": "<name of the workflow if applicable>",
  "steps": [
    {
      "step_number": 1,
      "action": "<what the user does on this step>",
      "state_change": "<what changes after this step>"
    }
  ]
}

Rules:
- A workflow requires sequential steps where completing Step N enables Step N+1.
- Single-page forms without sequential dependencies are NOT workflows.
- Approval chains, checkout wizards, and multi-step forms ARE workflows.
- Return ONLY the JSON, no markdown.
"""

# ---------------------------------------------------------------------------
# URL pattern heuristics for workflow detection
# ---------------------------------------------------------------------------
_WORKFLOW_URL_PATTERNS = [
    re.compile(r"/flow/", re.IGNORECASE),
    re.compile(r"/wizard", re.IGNORECASE),
    re.compile(r"/step", re.IGNORECASE),
    re.compile(r"/page[0-9]+", re.IGNORECASE),
    re.compile(r"/checkout", re.IGNORECASE),
    re.compile(r"/approval", re.IGNORECASE),
    re.compile(r"/process", re.IGNORECASE),
    re.compile(r"/multi.?step", re.IGNORECASE),
    re.compile(r"/journey", re.IGNORECASE),
    re.compile(r"/onboarding", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Navigation pattern keywords for state transitions
# ---------------------------------------------------------------------------
_NEXT_KEYWORDS = ["next", "continue", "proceed", "next step", "next page"]
_BACK_KEYWORDS = ["back", "previous", "go back", "return"]
_SUBMIT_KEYWORDS = ["submit", "confirm", "complete", "finish", "place order", "approve"]


class WorkflowMapper:
    """Detects multi-step business workflows from the SiteMap."""

    def __init__(self, config: dict[str, Any]):
        vis_cfg = config.get("visual_audit", {})
        self.llm_enabled: bool = vis_cfg.get("enabled", False)
        self.llm_provider: str = vis_cfg.get("provider", "openai")
        self.llm_model: str = vis_cfg.get("model", "gpt-4o")
        api_key_env: str = vis_cfg.get("api_key_env_var", "LLM_API_KEY")
        self.api_key: str = os.environ.get(api_key_env, "")
        if not self.api_key:
            self.api_key = os.environ.get("OPENAI_API_KEY", "")
        self._client: Any = None
        self._cache: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def detect_workflows(self, site_map: SiteMap) -> list[WorkflowModel]:
        """Detect multi-step business workflows from the SiteMap.

        Uses a 3-stage approach:
        1. URL pattern heuristics (fast, zero tokens)
        2. Navigation pattern analysis (fast, zero tokens)
        3. Vision LLM confirmation (only for ambiguous cases)
        """
        if not site_map.pages:
            return []

        logger.info(f"Workflow detection: analysing {len(site_map.pages)} pages")

        workflows: list[WorkflowModel] = []

        # Stage 1: URL pattern heuristics
        url_workflows = self._detect_by_url_patterns(site_map)
        workflows.extend(url_workflows)
        logger.info(f"  URL pattern heuristics: {len(url_workflows)} workflows detected")

        # Stage 2: Navigation pattern analysis
        nav_workflows = self._detect_by_navigation_patterns(site_map)
        # Merge with existing workflows (avoid duplicates)
        existing_urls = {s.url for w in workflows for s in w.steps}
        for nw in nav_workflows:
            new_urls = [s.url for s in nw.steps if s.url not in existing_urls]
            if new_urls:
                workflows.append(nw)
                existing_urls.update(new_urls)
        logger.info(f"  Navigation patterns: {len(nav_workflows)} workflows detected")

        # Stage 3: Vision LLM confirmation (only for ambiguous cases)
        if self.llm_enabled and self.api_key:
            confirmed = self._confirm_with_llm(workflows, site_map)
            workflows = confirmed
            logger.info(f"  LLM confirmed: {len(workflows)} workflows validated")

        logger.info(f"Workflow detection complete: {len(workflows)} workflows found")
        return workflows

    # ------------------------------------------------------------------
    # Stage 1: URL Pattern Heuristics
    # ------------------------------------------------------------------
    def _detect_by_url_patterns(self, site_map: SiteMap) -> list[WorkflowModel]:
        """Detect workflows based on URL patterns (flow/, wizard/, step, etc.)."""
        workflows: list[WorkflowModel] = []
        pattern_groups: dict[str, list[PageSnapshot]] = {}

        for page in site_map.pages:
            for pattern in _WORKFLOW_URL_PATTERNS:
                if pattern.search(page.url):
                    # Group by the matching pattern prefix
                    match = pattern.search(page.url)
                    prefix = match.group() if match else "workflow"
                    if prefix not in pattern_groups:
                        pattern_groups[prefix] = []
                    pattern_groups[prefix].append(page)
                    break

        for prefix, pages in pattern_groups.items():
            if len(pages) < 2:
                continue  # Need at least 2 pages for a workflow

            # Sort by depth (entry point is shallowest)
            pages.sort(key=lambda p: p.depth)

            workflow = WorkflowModel(
                name=f"Workflow: {prefix}",
                steps=[
                    WorkflowStep(
                        step_number=i + 1,
                        url=p.url,
                        action_description=p.page_purpose or p.title or f"Step {i + 1}",
                        state_parameters=self._extract_state_params(p),
                        page_id=p.id,
                    )
                    for i, p in enumerate(pages)
                ],
                entry_point=pages[0].url,
                exit_point=pages[-1].url,
                detected_via="url_pattern",
                confidence=0.7,
            )
            workflows.append(workflow)

        return workflows

    # ------------------------------------------------------------------
    # Stage 2: Navigation Pattern Analysis
    # ------------------------------------------------------------------
    def _detect_by_navigation_patterns(self, site_map: SiteMap) -> list[WorkflowModel]:
        """Detect workflows based on navigation links (Next/Back buttons)."""
        workflows: list[WorkflowModel] = []
        page_by_url = {p.url: p for p in site_map.pages}

        # Build parent-child relationships
        children_of: dict[str, list[str]] = {}
        for page in site_map.pages:
            if page.parent_url:
                if page.parent_url not in children_of:
                    children_of[page.parent_url] = []
                children_of[page.parent_url].append(page.url)

        # Detect workflows: chains of parent-child relationships
        visited_in_chain: set[str] = set()
        for page in site_map.pages:
            if page.url in visited_in_chain:
                continue

            # Check if this page has navigation targets that suggest a workflow
            has_next = self._has_navigation_keyword(page, _NEXT_KEYWORDS)
            has_back = self._has_navigation_keyword(page, _BACK_KEYWORDS)

            if has_next or has_back:
                # Trace the chain
                chain = self._trace_workflow_chain(page, children_of, page_by_url)
                if len(chain) >= 2:
                    for url in chain:
                        visited_in_chain.add(url)

                    pages_in_chain = [page_by_url[u] for u in chain if u in page_by_url]
                    pages_in_chain.sort(key=lambda p: p.depth)

                    workflow = WorkflowModel(
                        name=f"Workflow: {pages_in_chain[0].title or pages_in_chain[0].url[:30]}",
                        steps=[
                            WorkflowStep(
                                step_number=i + 1,
                                url=p.url,
                                action_description=p.page_purpose or p.title or f"Step {i + 1}",
                                state_parameters=self._extract_state_params(p),
                                page_id=p.id,
                            )
                            for i, p in enumerate(pages_in_chain)
                        ],
                        entry_point=pages_in_chain[0].url,
                        exit_point=pages_in_chain[-1].url,
                        detected_via="navigation_pattern",
                        confidence=0.6,
                    )
                    workflows.append(workflow)

        return workflows

    def _has_navigation_keyword(self, page: PageSnapshot, keywords: list[str]) -> bool:
        """Check if a page has navigation keywords in its visible text or features."""
        text = (page.visible_text or "").lower()
        features = [f.lower() for f in page.features] if page.features else []

        for keyword in keywords:
            if keyword in text or any(keyword in f for f in features):
                return True
        return False

    def _trace_workflow_chain(
        self, start_page: PageSnapshot, children_of: dict[str, list[str]],
        page_by_url: dict[str, PageSnapshot], max_depth: int = 5
    ) -> list[str]:
        """Trace a workflow chain starting from a page."""
        chain = [start_page.url]
        current_url = start_page.url

        for _ in range(max_depth):
            children = children_of.get(current_url, [])
            if not children:
                break
            # Take the first child (most likely next step)
            next_url = children[0]
            if next_url in chain:
                break  # Circular reference
            chain.append(next_url)
            current_url = next_url

        return chain

    # ------------------------------------------------------------------
    # Stage 3: Vision LLM Confirmation
    # ------------------------------------------------------------------
    def _confirm_with_llm(
        self, workflows: list[WorkflowModel], site_map: SiteMap
    ) -> list[WorkflowModel]:
        """Use Vision LLM to confirm ambiguous workflows."""
        if not workflows or not self.api_key:
            return workflows

        page_by_url = {p.url: p for p in site_map.pages}
        confirmed: list[WorkflowModel] = []

        for workflow in workflows:
            # Only confirm workflows with low confidence
            if workflow.confidence >= 0.8:
                confirmed.append(workflow)
                continue

            # Get screenshots for the workflow steps
            screenshots = []
            for step in workflow.steps[:5]:  # Limit to 5 steps for token economy
                page = page_by_url.get(step.url)
                if page and page.screenshot_path:
                    try:
                        with open(page.screenshot_path, "rb") as f:
                            screenshots.append(f.read())
                    except Exception:
                        pass

            if not screenshots:
                confirmed.append(workflow)
                continue

            # Send to LLM for confirmation
            result = self._call_llm_for_confirmation(workflow, screenshots)
            if result and result.get("is_workflow"):
                workflow.name = result.get("workflow_name", workflow.name)
                workflow.confidence = 0.95
                workflow.detected_via = "vision_llm"
                confirmed.append(workflow)
                logger.debug(f"  LLM confirmed workflow: {workflow.name}")

        return confirmed

    def _call_llm_for_confirmation(
        self, workflow: WorkflowModel, screenshots: list[bytes]
    ) -> dict | None:
        """Call Vision LLM to confirm if pages form a workflow."""
        client = self._get_client()
        if not client:
            return None

        # Build text description of the workflow
        steps_desc = "\n".join([
            f"Step {s.step_number}: {s.action_description} ({s.url[:60]})"
            for s in workflow.steps[:5]
        ])
        user_prompt = (
            f"Workflow candidate: {workflow.name}\n"
            f"Steps:\n{steps_desc}\n\n"
            f"Are these pages part of a multi-step transactional workflow?"
        )

        # Build image content (first screenshot only for token economy)
        content_parts = [
            {"type": "text", "text": user_prompt},
        ]
        if screenshots:
            import base64
            b64 = base64.b64encode(screenshots[0]).decode()
            content_parts.append({
                "type": "image_url",
                "image_url": {"url": f"data:image/png;base64,{b64}", "detail": "low"},
            })

        try:
            if self.llm_provider == "openai":
                response = client.chat.completions.create(
                    model=self.llm_model,
                    max_tokens=300,
                    temperature=0.1,
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": _WORKFLOW_CONFIRM_PROMPT},
                        {"role": "user", "content": content_parts},
                    ],
                )
                raw = response.choices[0].message.content or "{}"
            else:
                return None

            # Parse response
            cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip(), flags=re.MULTILINE)
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                match = re.search(r"\{.*\}", cleaned, re.DOTALL)
                if match:
                    return json.loads(match.group(0))
                return None

        except Exception as e:
            logger.debug(f"LLM workflow confirmation failed: {e}")
            return None

    def _get_client(self) -> Any:
        if self._client:
            return self._client
        if not self.api_key:
            return None
        try:
            from openai import OpenAI
            self._client = OpenAI(api_key=self.api_key, timeout=30)
            return self._client
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_state_params(page: PageSnapshot) -> list[str]:
        """Extract hidden fields, tokens, or flow IDs from a page."""
        params = []
        for field in page.input_fields:
            # Hidden fields, CSRF tokens, flow interview IDs
            if field.field_type in ("hidden", "text") and any(
                kw in field.name.lower()
                for kw in ["token", "csrf", "flow", "interview", "state", "session", "nonce"]
            ):
                params.append(field.name)
            # Fields with Salesforce flow-related names
            if any(kw in field.name.lower() for kw in ["flow", "interview", "aura"]):
                params.append(field.name)
        return params
