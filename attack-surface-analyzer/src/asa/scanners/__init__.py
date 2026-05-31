"""Base class for all scanners."""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Tuple

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from ..models import Finding

console = Console()


class BaseScanner(ABC):
    """Abstract base scanner."""

    name: str = "base"
    label: str = "Scanner"
    icon: str = "🔍"

    def __init__(self, target: Path):
        self.target = target

    def run(self, quiet: bool = False) -> Tuple[List[Finding], Dict[str, Any]]:
        """Run the scanner and return (findings, meta)."""
        if not quiet:
            with Progress(
                SpinnerColumn(),
                TextColumn(f"[bold cyan]{self.icon}  {self.label}...[/bold cyan]"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task("scan", total=None)
                findings, meta = self._scan()
        else:
            findings, meta = self._scan()

        status = f"[bold green]✔[/bold green]" if not findings else f"[bold red]✘[/bold red]"
        count_str = f"[dim]{len(findings)} finding(s)[/dim]"
        if not quiet:
            console.print(f"  {status} {self.label} {count_str}")

        return findings, meta

    @abstractmethod
    def _scan(self) -> Tuple[List[Finding], Dict[str, Any]]:
        """Implement scan logic here."""
        ...

    def walk_files(self, extensions: List[str] = None, skip_dirs=None):
        """Yield files under target, optionally filtered by extension."""
        skip = skip_dirs or {
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            "dist", "build", ".mypy_cache", ".pytest_cache", "vendor",
        }
        for p in self.target.rglob("*"):
            if p.is_file():
                if any(part in skip for part in p.parts):
                    continue
                if extensions is None or p.suffix.lower() in extensions:
                    yield p
