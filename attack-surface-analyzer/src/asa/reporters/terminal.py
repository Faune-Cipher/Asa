"""
Terminal reporter — renders findings with rich formatting.
"""
from collections import defaultdict
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ..models import Finding, ScanResult

SCANNER_LABELS = {
    "dependencies": "📦 CVE / Dependencies",
    "configs": "⚙️  Misconfigurations",
    "secrets": "🔑 Hardcoded Secrets",
    "endpoints": "🌐 Endpoint Exposure",
}

SEVERITY_STYLE = {
    "critical": ("bold red", "CRITICAL"),
    "high": ("red", "HIGH    "),
    "medium": ("yellow", "MEDIUM  "),
    "low": ("blue", "LOW     "),
    "info": ("dim", "INFO    "),
}


class TerminalReporter:
    def __init__(self, console: Console):
        self.console = console

    def render(self, result: ScanResult):
        self.console.print()
        self.console.print(Rule("[bold]Findings[/bold]", style="dim"))

        if not result.findings:
            self.console.print("\n[bold green]  ✔  No findings above the severity threshold.[/bold green]\n")
        else:
            # Group by scanner
            by_scanner = defaultdict(list)
            for f in result.findings:
                by_scanner[f.scanner].append(f)

            # Sort scanners by priority
            order = ["dependencies", "configs", "secrets", "endpoints"]
            for scanner_name in order:
                findings = by_scanner.get(scanner_name, [])
                if not findings:
                    continue

                label = SCANNER_LABELS.get(scanner_name, scanner_name)
                self.console.print(f"\n[bold cyan]{label}[/bold cyan]  [dim]({len(findings)} finding(s))[/dim]")
                self.console.print()

                # Sort by severity
                sev_order = ["critical", "high", "medium", "low", "info"]
                findings_sorted = sorted(findings, key=lambda f: sev_order.index(f.severity.lower()))

                for finding in findings_sorted:
                    self._render_finding(finding)

        # Summary table
        self._render_summary(result)

    def _render_finding(self, f: Finding):
        style, label = SEVERITY_STYLE.get(f.severity.lower(), ("white", f.severity.upper()))

        # Header line
        sev_badge = f"[{style}][{label.strip()}][/{style}]"
        location = ""
        if f.file:
            location = f"[dim]{f.file}"
            if f.line:
                location += f":{f.line}"
            location += "[/dim]"

        self.console.print(f"  {sev_badge} {f.title}")
        if location:
            self.console.print(f"          {location}")

        # Description (wrapped)
        self.console.print(f"          [dim]{f.description}[/dim]")

        # Remediation
        if f.remediation:
            self.console.print(f"          [green]→ Fix:[/green] {f.remediation}")

        # References
        if f.references:
            for ref in f.references[:2]:
                self.console.print(f"          [dim blue][link={ref}]{ref}[/link][/dim blue]")

        self.console.print()

    def _render_summary(self, result: ScanResult):
        self.console.print(Rule("[bold]Summary[/bold]", style="dim"))
        self.console.print()

        counts = result.counts_by_severity
        score = result.risk_score

        # Severity table
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Severity", style="bold", width=12)
        table.add_column("Count", justify="right", width=8)
        table.add_column("", width=30)

        bars = {
            "critical": ("bold red", "🔴"),
            "high": ("red", "🟠"),
            "medium": ("yellow", "🟡"),
            "low": ("blue", "🔵"),
            "info": ("dim", "⚪"),
        }

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = counts[sev]
            if count == 0:
                continue
            style, emoji = bars[sev]
            bar = emoji * min(count, 20)
            table.add_row(
                f"[{style}]{sev.upper()}[/{style}]",
                f"[{style}]{count}[/{style}]",
                bar,
            )

        self.console.print(table)
        self.console.print()

        # Risk score
        if score >= 80:
            score_style = "bold red"
            verdict = "CRITICAL RISK — Do NOT push to prod"
        elif score >= 50:
            score_style = "red"
            verdict = "HIGH RISK — Fix issues before deploying"
        elif score >= 20:
            score_style = "yellow"
            verdict = "MEDIUM RISK — Review findings carefully"
        elif score > 0:
            score_style = "blue"
            verdict = "LOW RISK — Minor issues to address"
        else:
            score_style = "green"
            verdict = "CLEAN — No significant issues found"

        self.console.print(
            Panel(
                f"[{score_style}]Risk Score: {score}/100[/{score_style}]\n"
                f"[bold]{verdict}[/bold]\n\n"
                f"[dim]Scanned {result.target} in {result.elapsed:.1f}s "
                f"— {result.total} total finding(s)[/dim]",
                border_style=score_style,
                title="[bold]ASA Result[/bold]",
            )
        )
        self.console.print()
