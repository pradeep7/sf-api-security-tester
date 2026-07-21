"""Main orchestration flow for the API Security Testing Framework.

V3.0: Adds Autonomous AI Reconnaissance (Phase 0), Feature Inventory
(Phase 0.5), and Safe Probe Execution before the existing HAR-based
mutation pipeline.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from .auth_handoff import AuthHandoff
from .autonomous_explorer import AutonomousExplorer
from .dom_xss_auditor import DOMXSSAuditor
from .endpoint_classifier import EndpointClassifier
from .har_analyzer import HarAnalyzer
from .har_generator import HarGenerator
from .evidence_collector import EvidenceCollector
from .executor import RequestExecutor
from .feature_inventory import FeatureInventoryBuilder
from .finding_evaluator import FindingEvaluator
from .har_parser import parse_har_files
from .llm_verifier import LLMVerifier
from .models import (
    APIEndpoint,
    ConfidenceLevel,
    ExecutiveSummary,
    Evidence,
    FeatureInventory,
    FindingResult,
    FindingVerdict,
    MutatedRequest,
    Severity,
    SiteMap,
    TestPlan,
    TestReport,
)
from .governance_engine import GovernanceEngine
from .mutation_engine import MutationEngine
from .prompt_generator import PromptGenerator
from .report_generator import ReportGenerator
from .role_manager import RoleManager
from .safe_executor import SafePayloadExecutor
from .screenshot_capture import ScreenshotCapture
from .test_case_engine import TestCaseEngine
from .test_planner import SmartTestPlanner
from .visual_auditor import VisualAuditor
from .workflow_mapper import WorkflowMapper

console = Console()


class Orchestrator:
    """Main orchestrator that runs the full V3.0 security testing pipeline."""

    def __init__(
        self,
        config_path: str | Path,
        har_files: list[str | Path] | None = None,
        explore_only: bool = False,
        skip_explore: bool = False,
        role_compare: bool = False,
        manual_auth: bool = False,
        target_url: str | None = None,
    ):
        self.config_path = Path(config_path)
        self.config: dict[str, Any] = {}
        self.credentials: dict[str, Any] = {}
        self.har_files = har_files or []
        self.explore_only = explore_only
        self.skip_explore = skip_explore
        self.role_compare = role_compare
        self.manual_auth = manual_auth
        self.target_url = target_url

        # V2.x Components
        self.classifier: EndpointClassifier | None = None
        self.test_engine: TestCaseEngine | None = None
        self.mutation_engine: MutationEngine | None = None
        self.executor: RequestExecutor | None = None
        self.screenshot_capture: ScreenshotCapture | None = None
        self.evidence_collector: EvidenceCollector | None = None
        self.evaluator: FindingEvaluator | None = None
        self.report_generator: ReportGenerator | None = None
        self.llm_verifier: LLMVerifier | None = None
        self.visual_auditor: VisualAuditor | None = None

        # V3.0 Components
        self.autonomous_explorer: AutonomousExplorer | None = None
        self.feature_inventory_builder: FeatureInventoryBuilder | None = None
        self.test_planner: SmartTestPlanner | None = None
        self.safe_executor: SafePayloadExecutor | None = None
        self.dom_xss_auditor: DOMXSSAuditor | None = None
        self.role_manager: RoleManager | None = None
        self.auth_handoff: AuthHandoff | None = None
        self.har_generator: HarGenerator | None = None
        self.har_analyzer: HarAnalyzer | None = None
        self.har_intelligence: dict[str, Any] | None = None
        self.workflow_mapper: WorkflowMapper | None = None
        self.governance_engine: GovernanceEngine | None = None
        self.prompt_generator: PromptGenerator | None = None
        self.harvested_cookies: dict[str, str] = {}

        # V3.0 State
        self.site_map: SiteMap | None = None
        self.feature_inventory: FeatureInventory | None = None
        self.test_plan: TestPlan | None = None

        # V2.x State
        self.endpoints: list[APIEndpoint] = []
        self.execution_plan: list[tuple[APIEndpoint, Any]] = []
        self.results: list[FindingResult] = []
        self.scan_start: datetime | None = None
        self.scan_end: datetime | None = None

    def setup(self):
        """Initialize all components from configuration."""
        self._load_config()
        self._initialize_components()

    def _load_config(self):
        """Load settings and credentials YAML files."""
        logger.info(f"Loading config from {self.config_path}")

        with open(self.config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)

        # Load credentials
        creds_path = self.config_path.parent / "credentials.yaml"
        if creds_path.exists():
            with open(creds_path, "r", encoding="utf-8") as f:
                self.credentials = yaml.safe_load(f) or {}
            logger.info("Credentials loaded")
        else:
            logger.warning(f"Credentials file not found: {creds_path}")
            self.credentials = {}

    def _initialize_components(self):
        """Create all engine components from config."""
        general = self.config.get("general", {})
        pw_config = self.config.get("playwright", {})
        evidence_config = self.config.get("evidence", {})
        reporting_config = self.config.get("reporting", {})
        cross_tenant = self.config.get("cross_tenant_ids", {})
        payload_config = self.config.get("payloads", {})
        waf_config = self.config.get("waf_evasion", {})

        # Endpoint classifier
        self.classifier = EndpointClassifier(cross_tenant_ids=cross_tenant)

        # Test case engine
        test_case_dir = Path(__file__).parent.parent / "testcases"
        self.test_engine = TestCaseEngine(test_case_dir)

        # Mutation engine (V2: with PayloadManager and ContextRouter)
        self.mutation_engine = MutationEngine(
            cross_tenant_ids=cross_tenant,
            payload_config=payload_config,
        )

        # Request executor (V3.1: with WAF evasion + proxy + telemetry)
        proxy_config = self.config.get("upstream_proxy", {})
        self.executor = RequestExecutor(
            timeout=general.get("request_timeout_seconds", 30),
            retry_count=general.get("retry_count", 2),
            retry_delay=general.get("retry_delay_seconds", 2),
            ssl_verify=general.get("ssl_verify", True),
            dry_run=general.get("dry_run", False),
            waf_evasion_config=waf_config,
            proxy_config=proxy_config,
        )

        # Screenshot capture
        screenshot_dir = Path(evidence_config.get("output_dir", "output/evidence")) / "screenshots"
        self.screenshot_capture = ScreenshotCapture(
            output_dir=screenshot_dir,
            headless=pw_config.get("headless", True),
            browser_type=pw_config.get("browser", "chromium"),
            viewport_width=pw_config.get("viewport_width", 1920),
            viewport_height=pw_config.get("viewport_height", 1080),
            timeout=pw_config.get("screenshot_timeout", 15000),
            navigation_timeout=pw_config.get("navigation_timeout", 30000),
            full_page=pw_config.get("screenshot_full_page", False),
            user_agent=pw_config.get("user_agent"),
            enabled=pw_config.get("headless", True),
        )

        # Evidence collector
        self.evidence_collector = EvidenceCollector(
            output_dir=evidence_config.get("output_dir", "output/evidence"),
            save_raw_http=evidence_config.get("save_raw_http", True),
        )

        # Finding evaluator
        self.evaluator = FindingEvaluator()

        # Report generator
        self.report_generator = ReportGenerator(
            output_dir=reporting_config.get("output_dir", "output/reports")
        )

        # LLM Verifier (Hybrid AI — only reviews FINDING verdicts)
        self.llm_verifier = LLMVerifier(self.config)

        # Visual Auditor (V2.3 — reviews screenshots via Vision LLM)
        self.visual_auditor = VisualAuditor(self.config)

        # V3.1: Workflow Mapper (API6 state machine detection)
        self.workflow_mapper = WorkflowMapper(self.config)

        # V4.0: Governance Engine (workbook schema enforcement)
        self.governance_engine = GovernanceEngine(self.config)

        # V4.0: Prompt Generator (AI IDE prompt artifacts)
        self.prompt_generator = PromptGenerator(
            self.config.get("reporting", {}).get("output_dir", "output/reports")
            + "/prompts"
        )

        # V3.0: Autonomous Reconnaissance
        self.autonomous_explorer = AutonomousExplorer(self.config)
        self.feature_inventory_builder = FeatureInventoryBuilder()
        self.test_planner = SmartTestPlanner()
        self.safe_executor = SafePayloadExecutor(self.config)
        self.dom_xss_auditor = DOMXSSAuditor(self.config)
        self.role_manager = RoleManager(self.config)
        self.auth_handoff = AuthHandoff(self.config)
        self.auth_handoff.enabled = self.manual_auth
        self.har_generator = HarGenerator(self.config)
        self.har_analyzer = HarAnalyzer(self.config)

    def run(self) -> TestReport:
        """Execute the full V3.0 security testing pipeline."""
        self.scan_start = datetime.utcnow()

        mode_label = "Explore-Only" if self.explore_only else "Full V3.0"
        target_info = f"\n[dim]Target: {self.target_url}[/dim]" if self.target_url else ""
        console.print(Panel.fit(
            "[bold cyan]SF API Security Tester V3.0[/bold cyan]\n"
            f"[dim]Project: {self.config.get('general', {}).get('project_name', 'Unknown')}[/dim]\n"
            f"[dim]Mode: {mode_label}[/dim]"
            f"{target_info}\n"
            f"[dim]Dry Run: {self.config.get('general', {}).get('dry_run', False)}[/dim]",
            border_style="blue",
        ))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:

            # Phase 0: Autonomous AI Reconnaissance (V3.0)
            if not self.skip_explore:
                task = progress.add_task(
                    "[blue]AI Explorer: Mapping application...",
                    total=None,
                )
                self._phase_0_explore()
                progress.update(task, completed=1, total=1)

                # Phase 0.5: Feature Inventory & Safe Probes (V3.0)
                if self.site_map and self.site_map.pages:
                    task = progress.add_task(
                        f"[blue]Planning tests from {self.site_map.total_pages} discovered pages...",
                        total=None,
                    )
                    self._phase_05_plan_and_probe()
                    progress.update(task, completed=1, total=1)

                if self.explore_only:
                    console.print("[yellow]Explore-only mode — skipping attack phases[/yellow]")
                    report = self._generate_reports()
                    self.scan_end = datetime.utcnow()
                    report.executive_summary.scan_start = self.scan_start
                    report.executive_summary.scan_end = self.scan_end
                    self._print_summary(report)
                    return report
            else:
                logger.info("Phase 0 skipped (--skip-explore)")

            # Manual Auth Handoff (--manual-auth)
            if self.manual_auth:
                task = progress.add_task(
                    "[yellow]Manual Auth: Opening browser for SSO login...",
                    total=None,
                )
                self._harvest_manual_cookies()
                progress.update(task, completed=1, total=1)

            # Phase 1: Parse HAR files
            task = progress.add_task("[cyan]Phase 1: Parsing HAR files...", total=None)
            self._parse_har_files()
            progress.update(task, completed=1, total=1)

            # Phase 2: Classify endpoints
            task = progress.add_task("[cyan]Phase 2: Classifying endpoints...", total=None)
            self._classify_endpoints()
            progress.update(task, completed=1, total=1)

            # Phase 2: Load test cases and build execution plan
            task = progress.add_task("[cyan]Phase 2: Building execution plan...", total=None)
            self._build_execution_plan()
            progress.update(task, completed=1, total=1)

            # Phase 3: Execute tests
            task = progress.add_task(
                "[cyan]Phase 3: Executing mutations...",
                total=len(self.execution_plan),
            )
            self._execute_tests(progress, task)
            progress.update(task, completed=len(self.execution_plan))

            # Phase 4: LLM verification of potential findings
            potential_count = sum(
                1 for r in self.results
                if r.verdict == FindingVerdict.POTENTIAL_FINDING
            )

            if potential_count > 0:
                if self.llm_verifier and self.llm_verifier.enabled:
                    task = progress.add_task(
                        f"[magenta]AI Brain: Verifying {potential_count} potential findings...",
                        total=None,
                    )
                    self._verify_potential_findings_with_llm()
                    progress.update(task, completed=1, total=1)
                else:
                    # Fallback: LLM disabled — promote all POTENTIAL to FINDING
                    logger.info(
                        f"LLM disabled: promoting {potential_count} "
                        f"POTENTIAL_FINDINGs to FINDINGs (V2.1 fallback)"
                    )
                    self.results = self.llm_verifier.promote_unverified(
                        self.results
                    ) if self.llm_verifier else self._promote_potential_fallback()
            else:
                logger.info("No POTENTIAL_FINDINGs — LLM verification not needed")

            # Phase 5: Visual DAST — Vision LLM screenshot analysis
            visual_candidates = sum(
                1 for r in self.results
                if r.evidence
                and r.evidence.screenshot_path
                and r.verdict in (
                    FindingVerdict.POTENTIAL_FINDING, FindingVerdict.FINDING
                )
            )

            if visual_candidates > 0 and self.visual_auditor and self.visual_auditor.enabled:
                task = progress.add_task(
                    f"[blue]Visual AI: Analyzing {visual_candidates} screenshots for DOM XSS...",
                    total=None,
                )
                self._audit_screenshots_with_visual_llm()
                progress.update(task, completed=1, total=1)
            else:
                if visual_candidates > 0:
                    logger.info(
                        f"Visual audit skipped ({visual_candidates} candidates, "
                        f"auditor disabled)"
                    )

            # Phase 6: Generate reports
            task = progress.add_task("[cyan]Generating reports...", total=None)
            report = self._generate_reports()
            progress.update(task, completed=1, total=1)

        self.scan_end = datetime.utcnow()
        report.executive_summary.scan_start = self.scan_start
        report.executive_summary.scan_end = self.scan_end

        # Print summary
        self._print_summary(report)

        return report

    # ------------------------------------------------------------------
    # Phase 0: Autonomous AI Reconnaissance
    # ------------------------------------------------------------------
    def _phase_0_explore(self):
        """Autonomously explore the Salesforce portal using Playwright + Vision LLM."""
        # If --target is provided, explore that URL directly
        if self.target_url:
            console.print(f"  [blue]Exploring target: {self.target_url}[/blue]")
            portal_creds = self.credentials.get("portals", {})
            # Try to find matching credentials
            creds = {}
            for portal_key in portal_creds:
                if isinstance(portal_creds[portal_key], dict):
                    creds = portal_creds[portal_key]
                    break

            site_map = self.autonomous_explorer.explore(self.target_url, creds)
            self.site_map = site_map
        else:
            # Explore each configured portal from settings
            portals_config = self.config.get("portals", {})

            for portal_key, portal_cfg in portals_config.items():
                portal_url = portal_cfg.get("base_url", "")
                if not portal_url:
                    continue

                console.print(f"  [blue]Exploring {portal_cfg.get('name', portal_key)}: {portal_url}[/blue]")

                # Get credentials for this portal
                portal_creds = self.credentials.get("portals", {}).get(portal_key, {})

                site_map = self.autonomous_explorer.explore(portal_url, portal_creds)

                if self.site_map is None:
                    self.site_map = site_map
                else:
                    # Merge site maps
                    self.site_map.pages.extend(site_map.pages)
                    self.site_map.total_pages = len(self.site_map.pages)
                    self.site_map.total_input_fields += site_map.total_input_fields
                    for cat, count in site_map.categories.items():
                        self.site_map.categories[cat] = self.site_map.categories.get(cat, 0) + count
                    self.site_map.sensitive_pages.extend(site_map.sensitive_pages)

        # Role comparison: explore with multiple roles and diff
        if self.role_compare:
            self._run_role_comparison(self.config.get("portals", {}))

        if self.site_map:
            console.print(
                f"  [green]Discovered {self.site_map.total_pages} pages, "
                f"{self.site_map.total_input_fields} input fields[/green]"
            )

    def _run_role_comparison(self, portals_config: dict):
        """Explore with multiple roles using RoleManager for isolated sessions."""
        role_cfg = self.config.get("role_comparison", {})
        roles = role_cfg.get("roles", [])
        role_creds = self.credentials.get("role_comparison", credentials_config={})

        if len(roles) < 2 or not role_creds:
            logger.info("Role comparison skipped: need >=2 roles in config")
            return

        console.print(f"  [blue]Running role comparison with {len(roles)} roles...[/blue]")

        # Create isolated sessions via RoleManager
        sessions = self.role_manager.create_sessions(self.credentials)

        role_site_maps: dict[str, SiteMap] = {}

        for role in roles:
            role_name = role.get("name", "unknown")
            cred_key = role.get("credentials_key", role_name)
            creds = role_creds.get(cred_key, {})

            if not creds.get("username"):
                logger.warning(f"Role '{role_name}' has no credentials — skipping")
                continue

            console.print(f"  [blue]  Exploring as {role_name}...[/blue]")

            # Use separate AutonomousExplorer per role (isolated browser context)
            for portal_key, portal_cfg in portals_config.items():
                portal_url = portal_cfg.get("base_url", "")
                if portal_url:
                    explorer = AutonomousExplorer(self.config)
                    site_map = explorer.explore(portal_url, creds)
                    role_site_maps[role_name] = site_map
                    break

        # Collect audit logs from all sessions
        all_audit_logs = self.role_manager.get_all_audit_logs(sessions)
        if all_audit_logs and self.site_map:
            self.site_map.audit_log.extend(all_audit_logs)

        # Compare role site maps
        if len(role_site_maps) >= 2:
            role_names = list(role_site_maps.keys())
            base_role = role_names[0]
            compare_role = role_names[1]

            base_urls = {p.url for p in role_site_maps[base_role].pages}
            compare_urls = {p.url for p in role_site_maps[compare_role].pages}

            base_only = base_urls - compare_urls
            compare_only = compare_urls - base_urls
            common = base_urls & compare_urls

            # Build role differences
            role_diffs = {}
            for rn in role_names:
                role_diffs[rn] = {
                    "total_pages": len(role_site_maps[rn].pages),
                    "total_inputs": role_site_maps[rn].total_input_fields,
                    "categories": role_site_maps[rn].categories,
                }

            role_diffs["comparison"] = {
                f"pages_only_visible_to_{base_role}": list(base_only),
                f"pages_only_visible_to_{compare_role}": list(compare_only),
                "pages_visible_to_both": len(common),
                "access_difference_count": len(base_only) + len(compare_only),
            }

            # Store for report
            if self.feature_inventory:
                self.feature_inventory.role_differences = role_diffs

            console.print(
                f"  [green]Role comparison: {len(base_only)} pages only for {base_role}, "
                f"{len(compare_only)} only for {compare_role}, "
                f"{len(common)} shared[/green]"
            )

    # ------------------------------------------------------------------
    # Phase 0.5: Feature Inventory & Safe Probes
    # ------------------------------------------------------------------
    def _phase_05_plan_and_probe(self):
        """Build feature inventory from site map and execute safe probes."""
        if not self.site_map or not self.site_map.pages:
            return

        # Build feature inventory
        self.feature_inventory = self.feature_inventory_builder.build(self.site_map)
        console.print(
            f"  [green]Feature inventory: {self.feature_inventory.total_risks} "
            f"risk surfaces identified[/green]"
        )

        # Detect multi-step workflows (API6)
        if self.workflow_mapper:
            console.print("  [blue]Mapping business workflows...[/blue]")
            workflows = self.workflow_mapper.detect_workflows(self.site_map)
            self.feature_inventory.workflows = workflows
            if workflows:
                console.print(
                    f"  [green]Detected {len(workflows)} business workflows "
                    f"for API6 testing[/green]"
                )

        # Generate test plan
        self.test_plan = self.test_planner.plan(self.feature_inventory, self.site_map)

        # V3.2: Enforce max total probes cap
        max_probes = self.config.get("safe_execution", {}).get("max_total_probes_per_run", 500)
        if self.test_plan.total_probes > max_probes:
            # Truncate to top N probes by severity
            sorted_tests = sorted(
                self.test_plan.planned_tests,
                key=lambda t: (
                    0 if t.test_type == "safe_probe" else 1,
                    next((i for i, s in enumerate(["Critical", "High", "Medium", "Low"]) if s in t.description), 99),
                ),
            )
            self.test_plan.planned_tests = sorted_tests[:max_probes]
            self.test_plan.total_probes = min(self.test_plan.total_probes, max_probes)
            logger.warning(
                f"Probe plan exceeded safe limits ({max_probes}). "
                f"Truncated to top {max_probes} highest-risk probes to prevent WAF bans."
            )
            console.print(
                f"  [yellow]Truncated to {max_probes} probes (WAF safety limit)[/yellow]"
            )

        console.print(
            f"  [green]Test plan: {self.test_plan.total_probes} safe probes "
            f"ready[/green]"
        )

        # Execute safe probes
        if self.test_plan.planned_tests:
            probe_results = self.safe_executor.execute_probes(self.test_plan, self.site_map)
            self.results.extend(probe_results)

            potential = sum(1 for r in probe_results if r.verdict == FindingVerdict.POTENTIAL_FINDING)
            console.print(
                f"  [green]Safe probes: {potential} potential findings "
                f"from {len(probe_results)} probes[/green]"
            )

        # DOM XSS audit with safe probes
        if self.site_map and self.dom_xss_auditor and self.dom_xss_auditor.enabled:
            console.print("  [blue]DOM XSS: Testing input fields with safe probes...[/blue]")
            try:
                # Create a temporary browser context for DOM XSS audit
                import asyncio
                from playwright.async_api import async_playwright

                async def _run_dom_audit():
                    pw = await async_playwright().start()
                    browser = await pw.chromium.launch(headless=True)
                    context = await browser.new_context(
                        viewport={"width": 1920, "height": 1080},
                    )
                    try:
                        results = self.dom_xss_auditor.audit_site(self.site_map, context)
                        return results
                    finally:
                        await context.close()
                        await browser.close()
                        await pw.stop()

                dom_results = asyncio.run(_run_dom_audit())
                self.results.extend(dom_results)

                dom_potential = sum(1 for r in dom_results if r.verdict == FindingVerdict.POTENTIAL_FINDING)
                console.print(
                    f"  [green]DOM XSS: {dom_potential} potential DOM XSS findings "
                    f"from {len(dom_results)} probes[/green]"
                )
            except Exception as e:
                logger.error(f"DOM XSS audit failed: {e}")

    # ------------------------------------------------------------------
    # Manual Auth Handoff (Feature 3)
    # ------------------------------------------------------------------
    def _harvest_manual_cookies(self):
        """Harvest cookies from manual SSO/JIT login."""
        if not self.auth_handoff:
            return

        # Determine login URL from first portal config
        portals_config = self.config.get("portals", {})
        login_url = ""
        for portal_key, portal_cfg in portals_config.items():
            login_url = portal_cfg.get("login_url", portal_cfg.get("base_url", ""))
            if login_url:
                break

        if not login_url:
            login_url = "https://login.salesforce.com"

        cookies = self.auth_handoff.harvest_cookies(login_url)
        if cookies:
            self.harvested_cookies = cookies
            # Inject cookies into executor
            self.executor.harvested_cookies = cookies
            console.print(
                f"  [green]Harvested {len(cookies)} session cookies — "
                f"using for Phase 3 execution[/green]"
            )
        else:
            console.print(
                "[yellow]No cookies harvested — falling back to HAR tokens[/yellow]"
            )

    # ------------------------------------------------------------------
    # Phase -1: HAR Generation (Feature: Live Traffic Capture)
    # ------------------------------------------------------------------
    def _run_har_generation(self, target_url: str, manual_auth: bool = False):
        """Generate a HAR file from live browser traffic.

        Uses Playwright's native HAR recording while routing through
        the configured upstream proxy (ZAP/Caido/Burp).
        """
        if not self.har_generator:
            return

        output_path = self.har_generator.default_output_path
        console.print(f"  [cyan]Phase -1: Recording live traffic to {output_path}...[/cyan]")

        result = self.har_generator.generate(
            target_url=target_url,
            output_path=output_path,
            use_manual_auth=manual_auth,
        )

        if result:
            console.print(f"  [green]HAR generated: {result}[/green]")
            console.print(
                f"\n  [dim]Run the full attack pipeline:[/dim]\n"
                f"  [cyan]python main.py --har {result} -v[/cyan]"
            )
        else:
            console.print("  [red]HAR generation failed[/red]")

    def _parse_har_files(self):
        """Parse HAR files and extract endpoints, then run LLM analysis."""
        if not self.har_files:
            logger.warning("No HAR files specified")
            # Try to find HAR files in input/ directory
            input_dir = Path(__file__).parent.parent / "input"
            self.har_files = list(input_dir.glob("*.har"))

        portals_config = self.config.get("portals", {})
        portal_names = list(portals_config.keys())
        base_urls = [
            portals_config[p].get("base_url", "")
            for p in portal_names
        ]

        # Ensure we have matching lists
        while len(portal_names) < len(self.har_files):
            portal_names.append(f"portal_{len(portal_names)}")
        while len(base_urls) < len(self.har_files):
            base_urls.append("")

        self.endpoints = parse_har_files(
            har_paths=self.har_files,
            portal_names=portal_names[:len(self.har_files)],
            base_urls=base_urls[:len(self.har_files)],
        )

        console.print(f"  [green]Found {len(self.endpoints)} API endpoints[/green]")

        # Smart HAR Analysis (LLM-powered deep inspection)
        if self.endpoints and self.har_analyzer and self.har_analyzer.enabled:
            console.print("  [cyan]Running deep HAR analysis with LLM...[/cyan]")
            self.har_intelligence = self.har_analyzer.analyse_endpoints(self.endpoints)
            if self.har_intelligence:
                overall = self.har_intelligence.get("overall", {})
                console.print(f"  [green]App type: {overall.get('app_type', 'unknown')}[/green]")
                console.print(f"  [green]Auth pattern: {overall.get('auth_pattern', 'unknown')}[/green]")
                console.print(f"  [green]Data classification: {overall.get('data_classification', 'unknown')}[/green]")
                attack_priority = overall.get("attack_priority", [])
                if attack_priority:
                    console.print(f"  [yellow]Attack priority: {len(attack_priority)} endpoints[/yellow]")

    def _classify_endpoints(self):
        """Classify endpoints by risk category."""
        self.endpoints = self.classifier.classify_all(self.endpoints)
        console.print(f"  [green]Classified {len(self.endpoints)} endpoints[/green]")

    def _build_execution_plan(self):
        """Load test cases and build the execution plan."""
        self.test_engine.load_all()
        self.execution_plan = self.test_engine.build_execution_plan(self.endpoints)
        console.print(
            f"  [green]Execution plan: {len(self.execution_plan)} test-executions[/green]"
        )

    def _execute_tests(self, progress: Progress, task_id):
        """Execute all tests in the plan.

        Gracefully halts if session expires or org API limit is reached,
        preserving all evidence collected so far.
        """
        from .executor import SessionExpiredException
        from .waf_evasion import SalesforceLimitExceededException

        halted = False
        halt_reason = ""

        for i, (endpoint, test_case) in enumerate(self.execution_plan):
            progress.update(
                task_id,
                description=f"[cyan]Testing {test_case.id}: {test_case.name[:40]}...",
            )

            try:
                result = self._execute_single_test(endpoint, test_case)
                self.results.append(result)

            except SessionExpiredException as e:
                halted = True
                halt_reason = str(e)
                logger.error(f"Session expired — halting remaining tests. ({e})")
                # Record this test as error, then break
                from .models import ConfidenceLevel
                self.results.append(FindingResult(
                    test_case_id=test_case.id,
                    test_name=test_case.name,
                    endpoint_id=endpoint.id,
                    endpoint_url=endpoint.url,
                    endpoint_method=endpoint.method.value,
                    portal_name=endpoint.portal_name,
                    owasp_category=test_case.owasp_category,
                    owasp_name=test_case.owasp_name,
                    severity=Severity(test_case.severity),
                    verdict=FindingVerdict.ERROR,
                    confidence=ConfidenceLevel.HIGH,
                    reasoning=f"Session expired mid-scan: {e}",
                    error_message=str(e),
                ))
                break

            except SalesforceLimitExceededException as e:
                halted = True
                halt_reason = str(e)
                logger.error(f"Salesforce API limit — halting remaining tests. ({e})")
                from .models import ConfidenceLevel
                self.results.append(FindingResult(
                    test_case_id=test_case.id,
                    test_name=test_case.name,
                    endpoint_id=endpoint.id,
                    endpoint_url=endpoint.url,
                    endpoint_method=endpoint.method.value,
                    portal_name=endpoint.portal_name,
                    owasp_category=test_case.owasp_category,
                    owasp_name=test_case.owasp_name,
                    severity=Severity(test_case.severity),
                    verdict=FindingVerdict.ERROR,
                    confidence=ConfidenceLevel.HIGH,
                    reasoning=f"Salesforce API limit reached: {e}",
                    error_message=str(e),
                ))
                break

            except Exception as e:
                logger.error(f"Error executing {test_case.id}: {e}")
                from .models import ConfidenceLevel
                error_result = FindingResult(
                    test_case_id=test_case.id,
                    test_name=test_case.name,
                    endpoint_id=endpoint.id,
                    endpoint_url=endpoint.url,
                    endpoint_method=endpoint.method.value,
                    portal_name=endpoint.portal_name,
                    owasp_category=test_case.owasp_category,
                    owasp_name=test_case.owasp_name,
                    severity=Severity(test_case.severity),
                    verdict=FindingVerdict.ERROR,
                    confidence=ConfidenceLevel.HIGH,
                    reasoning=f"Test execution error: {str(e)}",
                    error_message=str(e),
                )
                self.results.append(error_result)

            progress.update(task_id, completed=i + 1)

        if halted:
            remaining = len(self.execution_plan) - (i + 1)
            console.print(
                f"\n[bold red]SCAN HALTED:[/bold red] {halt_reason}\n"
                f"[yellow]{remaining} remaining tests were not executed. "
                f"Evidence collected so far has been saved.[/yellow]"
            )

    def _execute_single_test(self, endpoint: APIEndpoint, test_case) -> FindingResult:
        """Execute a single test case against an endpoint."""
        # Generate mutations
        mutations = self.mutation_engine.generate_mutations(
            endpoint=endpoint,
            test_case_id=test_case.id,
            mutation_type=test_case.mutation_type,
            payloads=test_case.payloads,
        )

        if not mutations:
            # No mutations possible - mark as NA
            return FindingResult(
                test_case_id=test_case.id,
                test_name=test_case.name,
                endpoint_id=endpoint.id,
                endpoint_url=endpoint.url,
                endpoint_method=endpoint.method.value,
                portal_name=endpoint.portal_name,
                owasp_category=test_case.owasp_category,
                owasp_name=test_case.owasp_name,
                severity=Severity(test_case.severity),
                verdict=FindingVerdict.NA,
                confidence=ConfidenceLevel.HIGH,
                reasoning="No mutations could be generated for this test case",
            )

        # Execute mutations and collect evidence
        best_result: FindingResult | None = None

        for mutation in mutations[:3]:  # Limit to 3 mutations per test for efficiency
            # Execute request
            http_request, http_response, execution_time_ms = self.executor.execute(mutation)

            # Capture screenshot + DOM context (V2.3)
            screenshot_path = None
            element_outer_html = None
            try:
                result = asyncio.run(
                    self.screenshot_capture.capture_screenshot(
                        url=mutation.url,
                        test_case_id=test_case.id,
                        endpoint_id=endpoint.id,
                        mutated_request=mutation,
                        label=test_case.name[:30],
                    )
                )
                if result:
                    screenshot_path, element_outer_html = result
            except Exception as e:
                logger.debug(f"Screenshot capture failed: {e}")

            # Collect evidence
            evidence = self.evidence_collector.collect(
                test_case_id=test_case.id,
                endpoint_id=endpoint.id,
                mutated_request=mutation,
                http_request=http_request,
                http_response=http_response,
                execution_time_ms=execution_time_ms,
                screenshot_path=screenshot_path,
            )

            # Evaluate
            finding_result = self.evaluator.evaluate(
                test_case_id=test_case.id,
                test_name=test_case.name,
                test_owasp_category=test_case.owasp_category,
                test_owasp_name=test_case.owasp_name,
                test_severity=test_case.severity,
                endpoint_id=endpoint.id,
                endpoint_url=endpoint.url,
                endpoint_method=endpoint.method.value,
                portal_name=endpoint.portal_name,
                finding_criteria=test_case.finding_criteria,
                evidence=evidence,
                mutation_description=mutation.mutation_description,
            )

            # Attach DOM context for Visual DAST (V2.3)
            if element_outer_html:
                finding_result.element_outer_html = element_outer_html

            # Keep the most severe result
            if best_result is None:
                best_result = finding_result
            elif finding_result.verdict == FindingVerdict.FINDING:
                if best_result.verdict != FindingVerdict.FINDING:
                    best_result = finding_result
                elif self._severity_rank(finding_result.severity) < self._severity_rank(best_result.severity):
                    best_result = finding_result

        return best_result or FindingResult(
            test_case_id=test_case.id,
            test_name=test_case.name,
            endpoint_id=endpoint.id,
            endpoint_url=endpoint.url,
            endpoint_method=endpoint.method.value,
            portal_name=endpoint.portal_name,
            owasp_category=test_case.owasp_category,
            owasp_name=test_case.owasp_name,
            severity=Severity(test_case.severity),
            verdict=FindingVerdict.NA,
            confidence=ConfidenceLevel.HIGH,
            reasoning="No results produced",
        )

    def _severity_rank(self, severity: Severity) -> int:
        """Get numeric rank for severity comparison (lower = more severe)."""
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }.get(severity, 99)

    def _verify_potential_findings_with_llm(self):
        """Send POTENTIAL_FINDING verdicts to the LLM for verification.

        The LLM acts as a "Senior Security Engineer" reviewing each anomaly
        to confirm it's a true positive, mark it as false positive, or flag
        it for manual review.  Only POTENTIAL_FINDING results are sent —
        PASSED/NA/ERROR are never sent (cost control).
        """
        if not self.llm_verifier or not self.llm_verifier.enabled:
            return

        console.print(
            "  [magenta]AI Brain: Running LLM verification on "
            "potential findings...[/magenta]"
        )

        try:
            self.results = self.llm_verifier.verify_batch(self.results)
        except Exception as e:
            logger.error(f"LLM verification batch failed: {e}")
            console.print(f"  [yellow]LLM batch error: {e} — falling back to auto-promote[/yellow]")
            self.results = self._promote_potential_fallback()
            return

        # Print LLM verification summary
        verified = [r for r in self.results if r.llm_verified]
        tp = sum(1 for r in verified if r.llm_verdict == "TRUE_POSITIVE")
        fp = sum(1 for r in verified if r.llm_verdict == "FALSE_POSITIVE")
        mr = sum(1 for r in verified if r.llm_verdict == "NEEDS_MANUAL_REVIEW")

        if verified:
            console.print(
                f"  [green]AI Brain complete: "
                f"{tp} confirmed, {fp} false positives eliminated, "
                f"{mr} needs manual review[/green]"
            )

    def _promote_potential_fallback(self) -> list[FindingResult]:
        """Fallback: promote all POTENTIAL_FINDINGs to FINDINGs when LLM is disabled."""
        for f in self.results:
            if f.verdict == FindingVerdict.POTENTIAL_FINDING:
                f.verdict = FindingVerdict.FINDING
        return self.results

    def _audit_screenshots_with_visual_llm(self):
        """Send screenshots to Vision LLM for visual security analysis.

        Only processes findings that have a screenshot AND whose payload
        was reflected in the HTTP response body.
        """
        if not self.visual_auditor or not self.visual_auditor.enabled:
            return

        console.print(
            "  [blue]Visual AI: Analysing screenshots for "
            "DOM XSS and data exposure...[/blue]"
        )

        try:
            self.results = self.visual_auditor.audit_batch(self.results)
        except Exception as e:
            logger.error(f"Visual audit batch failed: {e}")
            console.print(f"  [yellow]Visual audit error: {e}[/yellow]")
            return

        # Print visual audit summary
        confirmed = sum(
            1 for r in self.results if r.visual_verdict == "CONFIRMED_XSS"
        )
        reflected = sum(
            1 for r in self.results if r.visual_verdict == "REFLECTED_NOT_EXECUTED"
        )
        data_exp = sum(
            1 for r in self.results if r.visual_verdict == "DATA_EXPOSURE"
        )

        if confirmed or reflected or data_exp:
            console.print(
                f"  [blue]Visual AI complete: "
                f"{confirmed} confirmed XSS, "
                f"{reflected} reflected (not executed), "
                f"{data_exp} data exposure[/blue]"
            )

    def _generate_reports(self) -> TestReport:
        """Generate the final report."""
        # Compute LLM verification stats
        llm_tp = sum(1 for r in self.results if r.llm_verdict == "TRUE_POSITIVE")
        llm_fp = sum(1 for r in self.results if r.llm_verdict == "FALSE_POSITIVE")
        llm_mr = sum(1 for r in self.results if r.llm_verdict == "NEEDS_MANUAL_REVIEW")

        # Compute visual audit stats
        visual_xss = sum(
            1 for r in self.results
            if r.visual_verdict in ("CONFIRMED_XSS", "REFLECTED_NOT_EXECUTED", "DATA_EXPOSURE")
        )

        # Build executive summary
        summary = ExecutiveSummary(
            total_tests=len(self.results),
            total_endpoints=len(self.endpoints),
            findings_count=sum(1 for r in self.results if r.verdict == FindingVerdict.FINDING),
            not_findings_count=sum(1 for r in self.results if r.verdict == FindingVerdict.NOT_FINDING),
            potential_findings_count=sum(1 for r in self.results if r.verdict == FindingVerdict.POTENTIAL_FINDING),
            na_count=sum(1 for r in self.results if r.verdict == FindingVerdict.NA),
            errors_count=sum(1 for r in self.results if r.verdict == FindingVerdict.ERROR),
            critical_count=sum(1 for r in self.results if r.verdict == FindingVerdict.FINDING and r.severity == Severity.CRITICAL),
            high_count=sum(1 for r in self.results if r.verdict == FindingVerdict.FINDING and r.severity == Severity.HIGH),
            medium_count=sum(1 for r in self.results if r.verdict == FindingVerdict.FINDING and r.severity == Severity.MEDIUM),
            low_count=sum(1 for r in self.results if r.verdict == FindingVerdict.FINDING and r.severity == Severity.LOW),
            llm_true_positives=llm_tp,
            llm_false_positives=llm_fp,
            llm_manual_review=llm_mr,
            visual_findings_count=visual_xss,
            portals_tested=list({ep.portal_name for ep in self.endpoints}),
        )

        # Separate findings from other results
        findings = [r for r in self.results if r.verdict == FindingVerdict.FINDING]

        report = TestReport(
            project_name=self.config.get("general", {}).get("project_name", "SF Security Assessment"),
            executive_summary=summary,
            findings=findings,
            all_results=self.results,
            site_map=self.site_map,
            feature_inventory=self.feature_inventory,
        )

        # Generate files
        output_files = self.report_generator.generate(report)
        for fmt, path in output_files.items():
            console.print(f"  [green]{fmt.upper()} report: {path}[/green]")

        # V4.0: Generate AI prompt artifacts
        if self.prompt_generator:
            prompt_results = self.prompt_generator.generate_all(report)
            total_prompts = sum(len(v) for v in prompt_results.values())
            if total_prompts > 0:
                console.print(
                    f"  [green]Smart Prompts: {total_prompts} files in "
                    f"{self.prompt_generator.output_dir}/[/green]"
                )
                console.print(
                    f"  [dim]Open these in VS Code and feed to your AI assistant "
                    f"for instant remediation and triage.[/dim]"
                )

        return report

    def _print_summary(self, report: TestReport):
        """Print a summary table to the CLI."""
        summary = report.executive_summary

        table = Table(title="Security Assessment Summary", border_style="blue")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold")

        table.add_row("Total Tests", str(summary.total_tests))
        table.add_row("Endpoints Tested", str(summary.total_endpoints))
        table.add_row("Findings", f"[red]{summary.findings_count}[/red]")
        table.add_row("Potential Findings", f"[yellow]{summary.potential_findings_count}[/yellow]")
        table.add_row("Not Findings", f"[green]{summary.not_findings_count}[/green]")
        table.add_row("N/A", str(summary.na_count))
        table.add_row("Errors", f"[yellow]{summary.errors_count}[/yellow]")
        table.add_row("─" * 20, "─" * 10)
        table.add_row("Critical Findings", f"[bold red]{summary.critical_count}[/bold red]")
        table.add_row("High Findings", f"[red]{summary.high_count}[/red]")
        table.add_row("Medium Findings", f"[yellow]{summary.medium_count}[/yellow]")
        table.add_row("Low Findings", f"[green]{summary.low_count}[/green]")

        # LLM verification stats
        if summary.llm_true_positives or summary.llm_false_positives or summary.llm_manual_review:
            table.add_row("─" * 20, "─" * 10)
            table.add_row("LLM Confirmed (TP)", f"[green]{summary.llm_true_positives}[/green]")
            table.add_row("LLM Eliminated (FP)", f"[cyan]{summary.llm_false_positives}[/cyan]")
            table.add_row("LLM Manual Review", f"[yellow]{summary.llm_manual_review}[/yellow]")

        # Visual audit stats
        if summary.visual_findings_count:
            table.add_row("─" * 20, "─" * 10)
            table.add_row("Visual XSS/Data Exposure", f"[blue]{summary.visual_findings_count}[/blue]")

        console.print()
        console.print(table)

        # Print top findings
        if report.findings:
            console.print()
            findings_table = Table(title="Top Findings", border_style="red")
            findings_table.add_column("Severity", style="bold")
            findings_table.add_column("Test", style="cyan")
            findings_table.add_column("OWASP", style="magenta")
            findings_table.add_column("Endpoint")

            for f in sorted(report.findings, key=lambda x: self._severity_rank(x.severity))[:10]:
                severity_color = {
                    Severity.CRITICAL: "bold red",
                    Severity.HIGH: "red",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "green",
                }.get(f.severity, "white")

                findings_table.add_row(
                    f"[{severity_color}]{f.severity.value}[/{severity_color}]",
                    f.test_name[:40],
                    f.owasp_category,
                    f"{f.endpoint_method} {f.endpoint_url[:50]}...",
                )

            console.print(findings_table)
