"""
Shared data models for ASA findings.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime


@dataclass
class Finding:
    """A single security finding."""
    scanner: str              # Which scanner produced this
    title: str                # Short title
    severity: str             # critical | high | medium | low | info
    description: str          # Human-readable explanation
    file: Optional[str] = None        # Relative file path (if applicable)
    line: Optional[int] = None        # Line number (if applicable)
    remediation: Optional[str] = None # How to fix it
    references: List[str] = field(default_factory=list)  # CVE links, docs, etc.
    extra: Dict[str, Any] = field(default_factory=dict)  # Scanner-specific data

    @property
    def severity_color(self) -> str:
        return {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }.get(self.severity.lower(), "white")

    @property
    def severity_emoji(self) -> str:
        return {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }.get(self.severity.lower(), "⚪")


@dataclass
class ScanResult:
    """Aggregated result of a full scan."""
    target: str
    findings: List[Finding]
    scan_meta: Dict[str, Any]
    elapsed: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def counts_by_severity(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def risk_score(self) -> int:
        """Simple weighted risk score 0-100."""
        weights = {"critical": 40, "high": 15, "medium": 5, "low": 1, "info": 0}
        raw = sum(weights.get(f.severity.lower(), 0) for f in self.findings)
        return min(100, raw)
