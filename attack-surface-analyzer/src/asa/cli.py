"""
Attack Surface Analyzer - CLI entry point
"""
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .scanners.dependencies import DependencyScanner
from .scanners.configs import ConfigScanner
from .scanners.secrets import SecretScanner
from .scanners.endpoints import EndpointScanner
from .reporters.terminal import TerminalReporter
from .reporters.html import HTMLReporter
from .models import ScanResult

console = Console()

BANNER = """[bold red]
  ██████╗  ██████╗ █████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ███████║╚█████╗ ███████║    ███████╗██║     ███████║██╔██╗ ██║
  ██╔══██║ ╚═══██╗██╔══██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║  ██║██████╔╝██║  ██║    ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝[/bold red]
[dim]  Attack Surface Analyzer for Developers — github.com/you/asa[/dim]
"""


@click.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--html", "html_output", default=None, metavar="FILE",
              help="Export HTML report to FILE (e.g. report.html)")
@click.option("--no-deps", is_flag=True, help="Skip dependency CVE scan")
@click.option("--no-configs", is_flag=True, help="Skip config/secrets scan")
@click.option("--no-secrets", is_flag=True, help="Skip hardcoded secrets scan")
@click.option("--no-endpoints", is_flag=True, help="Skip endpoint exposure scan")
@click.option("--min-severity", default="low",
              type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
              help="Minimum severity to report (default: low)")
@click.option("--quiet", "-q", is_flag=True, help="Only print summary")
@click.version_option(version="0.1.0", prog_name="asa")
def main(
    path: str,
    html_output: Optional[str],
    no_deps: bool,
    no_configs: bool,
    no_secrets: bool,
    no_endpoints: bool,
    min_severity: str,
    quiet: bool,
):
    """
    \b
    Analyze the attack surface of your project before pushing to prod.

    PATH is the root directory to scan (default: current directory).

    Examples:
      asa .
      asa ./my-project --html report.html
      asa . --min-severity high --no-endpoints
    """
    console.print(BANNER)

    target = Path(path).resolve()
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Severity filter:[/bold] {min_severity.upper()}+",
        title="[bold cyan]Scan Configuration[/bold cyan]",
        border_style="cyan",
    ))

    start_time = time.time()
    all_findings = []
    scan_meta = {}

    severity_order = ["low", "medium", "high", "critical"]
    min_sev_idx = severity_order.index(min_severity.lower())

    scanners = []
    if not no_deps:
        scanners.append(("dependencies", DependencyScanner(target)))
    if not no_configs:
        scanners.append(("configs", ConfigScanner(target)))
    if not no_secrets:
        scanners.append(("secrets", SecretScanner(target)))
    if not no_endpoints:
        scanners.append(("endpoints", EndpointScanner(target)))

    if not scanners:
        console.print("[yellow]No scanners enabled. Use --help for options.[/yellow]")
        sys.exit(0)

    for name, scanner in scanners:
        findings, meta = scanner.run(quiet=quiet)
        filtered = [
            f for f in findings
            if severity_order.index(f.severity.lower()) >= min_sev_idx
        ]
        all_findings.extend(filtered)
        scan_meta[name] = meta

    elapsed = time.time() - start_time
    result = ScanResult(
        target=str(target),
        findings=all_findings,
        scan_meta=scan_meta,
        elapsed=elapsed,
    )

    # Terminal report
    terminal_reporter = TerminalReporter(console)
    terminal_reporter.render(result)

    # HTML report
    if html_output:
        html_reporter = HTMLReporter()
        html_reporter.write(result, html_output)
        console.print(f"\n[bold green]✔[/bold green] HTML report saved → [underline]{html_output}[/underline]")

    # Exit code for CI/CD
    critical_or_high = [f for f in all_findings if f.severity.lower() in ("critical", "high")]
    if critical_or_high:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
