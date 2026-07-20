#!/usr/bin/env python3
"""
SF API Security Tester - CLI Entry Point
Automated API Security Testing Framework for Salesforce Portals.

Usage:
    python main.py                          # Run with default config
    python main.py --config custom.yaml     # Custom config path
    python main.py --dry-run                # Preview mutations without sending
    python main.py --har file1.har file2.har  # Specify HAR files
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from loguru import logger
from rich.console import Console
from rich.panel import Panel

# Configure logging
logger.remove()
logger.add(
    sys.stderr,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
    level="INFO",
)
logger.add(
    "output/security_tester.log",
    rotation="10 MB",
    retention="7 days",
    level="DEBUG",
)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="SF API Security Tester - Automated API Security Testing for Salesforce Portals",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                              Run with defaults
  python main.py --dry-run                    Preview without sending requests
  python main.py --har input/portal.har       Use specific HAR file
  python main.py --config prod.yaml --har *.har
        """,
    )

    parser.add_argument(
        "--config", "-c",
        type=str,
        default="config/settings.yaml",
        help="Path to settings.yaml config file (default: config/settings.yaml)",
    )
    parser.add_argument(
        "--har",
        nargs="*",
        type=str,
        help="HAR file(s) to analyze (overrides auto-discovery in input/)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview mutations without sending HTTP requests",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    parser.add_argument(
        "--no-screenshots",
        action="store_true",
        help="Disable Playwright screenshot capture",
    )
    parser.add_argument(
        "--portals",
        nargs="*",
        type=str,
        help="Portal names corresponding to HAR files (e.g., --portals assist_portal tenant_portal)",
    )
    parser.add_argument(
        "--explore-only",
        action="store_true",
        help="Run Phase 0 & 0.5 only — map the application without attack testing",
    )
    parser.add_argument(
        "--skip-explore",
        action="store_true",
        help="Skip Phase 0 autonomous exploration — rely purely on HAR files (V2.x behavior)",
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    if args.verbose:
        logger.remove()
        logger.add(sys.stderr, level="DEBUG")
        logger.add("output/security_tester.log", rotation="10 MB", level="DEBUG")

    console = Console()
    console.print(Panel.fit(
        "[bold cyan]SF API Security Tester[/bold cyan]\n"
        "[dim]Automated API Security Testing Framework for Salesforce Portals[/dim]\n"
        "[dim]OWASP API Top 10 (2023) | OWASP Web Top 10 (2021) | OWASP Secure Coding[/dim]",
        border_style="blue",
    ))

    # Resolve paths
    base_dir = Path(__file__).parent
    config_path = base_dir / args.config

    if not config_path.exists():
        console.print(f"[red]Config file not found: {config_path}[/red]")
        return 1

    # Resolve HAR files
    har_files = []
    if args.har:
        har_files = [Path(h) for h in args.har]
    else:
        # Auto-discover from input/ directory
        input_dir = base_dir / "input"
        if input_dir.exists():
            har_files = list(input_dir.glob("*.har"))

    # In explore-only mode, HAR files are optional
    if not har_files and not args.explore_only:
        console.print("[yellow]No HAR files found. Place .har files in the input/ directory.[/yellow]")
        console.print("[dim]Example: Copy browser HAR exports to input/assist_portal.har[/dim]")
        console.print("[dim]Or use --explore-only to map the application first.[/dim]")
        return 1

    if har_files:
        console.print(f"[green]Found {len(har_files)} HAR file(s):[/green]")
        for har in har_files:
            console.print(f"  [dim]{har.name}[/dim]")

    # Import and apply CLI overrides
    from src.orchestrator import Orchestrator

    try:
        orchestrator = Orchestrator(
            config_path=config_path,
            har_files=har_files,
            explore_only=args.explore_only,
            skip_explore=args.skip_explore,
        )
        orchestrator.setup()

        # Apply CLI overrides
        if args.dry_run:
            orchestrator.config.setdefault("general", {})["dry_run"] = True
            orchestrator.executor.dry_run = True
            console.print("[yellow]DRY RUN mode - No requests will be sent[/yellow]")

        if args.no_screenshots:
            orchestrator.screenshot_capture.enabled = False
            console.print("[yellow]Screenshot capture disabled[/yellow]")

        # Run the test
        report = orchestrator.run()

        # Return exit code based on findings
        if report.executive_summary.critical_count > 0:
            return 2  # Critical findings
        elif report.executive_summary.findings_count > 0:
            return 1  # Findings present
        else:
            return 0  # Clean

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        return 130
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        logger.exception("Fatal error during scan")
        return 1


if __name__ == "__main__":
    sys.exit(main())
