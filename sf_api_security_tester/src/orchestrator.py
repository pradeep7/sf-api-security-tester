"""Main orchestration flow for the API Security Testing Framework."""

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

from .endpoint_classifier import EndpointClassifier
from .evidence_collector import EvidenceCollector
from .executor import RequestExecutor
from .finding_evaluator import FindingEvaluator
from .har_parser import parse_har_files
from .models import (
    APIEndpoint,
    ExecutiveSummary,
    Evidence,
    FindingResult,
    FindingVerdict,
    MutatedRequest,
    Severity,
    TestReport,
)
from .mutation_engine import MutationEngine
from .report_generator import ReportGenerator
from .screenshot_capture import ScreenshotCapture
from .test_case_engine import TestCaseEngine

console = Console()


class Orchestrator:
    """Main orchestrator that runs the full security testing pipeline."""

    def __init__(self, config_path: str | Path, har_files: list[str | Path] | None = None):
        self.config_path = Path(config_path)
        self.config: dict[str, Any] = {}
        self.credentials: dict[str, Any] = {}
        self.har_files = har_files or []

        # Components (initialized in setup)
        self.classifier: EndpointClassifier | None = None
        self.test_engine: TestCaseEngine | None = None
        self.mutation_engine: MutationEngine | None = None
        self.executor: RequestExecutor | None = None
        self.screenshot_capture: ScreenshotCapture | None = None
        self.evidence_collector: EvidenceCollector | None = None
        self.evaluator: FindingEvaluator | None = None
        self.report_generator: ReportGenerator | None = None

        # State
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

        # Request executor (V2: with WAF evasion)
        self.executor = RequestExecutor(
            timeout=general.get("request_timeout_seconds", 30),
            retry_count=general.get("retry_count", 2),
            retry_delay=general.get("retry_delay_seconds", 2),
            ssl_verify=general.get("ssl_verify", True),
            dry_run=general.get("dry_run", False),
            waf_evasion_config=waf_config,
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

    def run(self) -> TestReport:
        """Execute the full security testing pipeline."""
        self.scan_start = datetime.utcnow()

        console.print(Panel.fit(
            "[bold cyan]SF API Security Tester[/bold cyan]\n"
            f"[dim]Project: {self.config.get('general', {}).get('project_name', 'Unknown')}[/dim]\n"
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

            # Step 1: Parse HAR files
            task = progress.add_task("[cyan]Parsing HAR files...", total=None)
            self._parse_har_files()
            progress.update(task, completed=1, total=1)

            # Step 2: Classify endpoints
            task = progress.add_task("[cyan]Classifying endpoints...", total=None)
            self._classify_endpoints()
            progress.update(task, completed=1, total=1)

            # Step 3: Load test cases and build execution plan
            task = progress.add_task("[cyan]Building execution plan...", total=None)
            self._build_execution_plan()
            progress.update(task, completed=1, total=1)

            # Step 4: Execute tests
            task = progress.add_task(
                "[cyan]Executing tests...",
                total=len(self.execution_plan),
            )
            self._execute_tests(progress, task)
            progress.update(task, completed=len(self.execution_plan))

            # Step 5: Generate reports
            task = progress.add_task("[cyan]Generating reports...", total=None)
            report = self._generate_reports()
            progress.update(task, completed=1, total=1)

        self.scan_end = datetime.utcnow()
        report.executive_summary.scan_start = self.scan_start
        report.executive_summary.scan_end = self.scan_end

        # Print summary
        self._print_summary(report)

        return report

    def _parse_har_files(self):
        """Parse HAR files and extract endpoints."""
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

            # Capture screenshot
            screenshot_path = None
            try:
                screenshot_path = asyncio.run(
                    self.screenshot_capture.capture_screenshot(
                        url=mutation.url,
                        test_case_id=test_case.id,
                        endpoint_id=endpoint.id,
                        mutated_request=mutation,
                        label=test_case.name[:30],
                    )
                )
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

    def _generate_reports(self) -> TestReport:
        """Generate the final report."""
        # Build executive summary
        summary = ExecutiveSummary(
            total_tests=len(self.results),
            total_endpoints=len(self.endpoints),
            findings_count=sum(1 for r in self.results if r.verdict == FindingVerdict.FINDING),
            not_findings_count=sum(1 for r in self.results if r.verdict == FindingVerdict.NOT_FINDING),
            na_count=sum(1 for r in self.results if r.verdict == FindingVerdict.NA),
            errors_count=sum(1 for r in self.results if r.verdict == FindingVerdict.ERROR),
            critical_count=sum(1 for r in self.results if r.verdict == FindingVerdict.FINDING and r.severity == Severity.CRITICAL),
            high_count=sum(1 for r in self.results if r.verdict == FindingVerdict.FINDING and r.severity == Severity.HIGH),
            medium_count=sum(1 for r in self.results if r.verdict == FindingVerdict.FINDING and r.severity == Severity.MEDIUM),
            low_count=sum(1 for r in self.results if r.verdict == FindingVerdict.FINDING and r.severity == Severity.LOW),
            portals_tested=list({ep.portal_name for ep in self.endpoints}),
        )

        # Separate findings from other results
        findings = [r for r in self.results if r.verdict == FindingVerdict.FINDING]

        report = TestReport(
            project_name=self.config.get("general", {}).get("project_name", "SF Security Assessment"),
            executive_summary=summary,
            findings=findings,
            all_results=self.results,
        )

        # Generate files
        output_files = self.report_generator.generate(report)
        for fmt, path in output_files.items():
            console.print(f"  [green]{fmt.upper()} report: {path}[/green]")

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
        table.add_row("Not Findings", f"[green]{summary.not_findings_count}[/green]")
        table.add_row("N/A", str(summary.na_count))
        table.add_row("Errors", f"[yellow]{summary.errors_count}[/yellow]")
        table.add_row("─" * 20, "─" * 10)
        table.add_row("Critical Findings", f"[bold red]{summary.critical_count}[/bold red]")
        table.add_row("High Findings", f"[red]{summary.high_count}[/red]")
        table.add_row("Medium Findings", f"[yellow]{summary.medium_count}[/yellow]")
        table.add_row("Low Findings", f"[green]{summary.low_count}[/green]")

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
