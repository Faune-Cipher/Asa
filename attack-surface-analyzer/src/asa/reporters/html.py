"""
HTML reporter — generates a standalone, self-contained HTML report.
"""
import json
from typing import Any
from ..models import ScanResult, Finding

SEVERITY_COLOR = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#6b7280",
}

SEVERITY_BG = {
    "critical": "#fef2f2",
    "high": "#fff7ed",
    "medium": "#fefce8",
    "low": "#eff6ff",
    "info": "#f9fafb",
}

SCANNER_ICONS = {
    "dependencies": "📦",
    "configs": "⚙️",
    "secrets": "🔑",
    "endpoints": "🌐",
}


class HTMLReporter:
    def write(self, result: ScanResult, output_path: str):
        html = self._build(result)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    def _build(self, result: ScanResult) -> str:
        counts = result.counts_by_severity
        score = result.risk_score

        if score >= 80:
            score_color = "#ef4444"
            verdict = "CRITICAL RISK"
            verdict_sub = "Do NOT push to production"
        elif score >= 50:
            score_color = "#f97316"
            verdict = "HIGH RISK"
            verdict_sub = "Fix issues before deploying"
        elif score >= 20:
            score_color = "#eab308"
            verdict = "MEDIUM RISK"
            verdict_sub = "Review findings carefully"
        elif score > 0:
            score_color = "#3b82f6"
            verdict = "LOW RISK"
            verdict_sub = "Minor issues to address"
        else:
            score_color = "#22c55e"
            verdict = "CLEAN"
            verdict_sub = "No significant issues found"

        findings_html = self._findings_section(result)
        summary_bars = self._summary_bars(counts)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ASA Report — {result.target}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f172a; color: #e2e8f0; margin: 0; padding: 0; }}
  a {{ color: #60a5fa; }}
  .header {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
             border-bottom: 1px solid #1e293b; padding: 2rem; }}
  .header h1 {{ margin: 0 0 .25rem; font-size: 1.75rem; color: #f8fafc; }}
  .header .meta {{ color: #64748b; font-size: .875rem; }}
  .container {{ max-width: 960px; margin: 0 auto; padding: 2rem; }}
  .score-card {{ background: #1e293b; border-radius: 12px; border: 1px solid #334155;
                 padding: 2rem; margin-bottom: 2rem; display: flex; align-items: center; gap: 2rem; }}
  .score-circle {{ width: 100px; height: 100px; border-radius: 50%;
                   border: 4px solid {score_color}; display: flex; flex-direction: column;
                   align-items: center; justify-content: center; flex-shrink: 0; }}
  .score-num {{ font-size: 2rem; font-weight: 800; color: {score_color}; line-height: 1; }}
  .score-label {{ font-size: .65rem; color: #64748b; }}
  .verdict h2 {{ margin: 0 0 .25rem; color: {score_color}; }}
  .verdict p {{ margin: 0; color: #94a3b8; font-size: .9rem; }}
  .counts {{ display: flex; gap: .75rem; flex-wrap: wrap; margin-top: 1rem; }}
  .badge {{ display: inline-flex; align-items: center; gap: .35rem; padding: .3rem .75rem;
            border-radius: 20px; font-size: .8rem; font-weight: 600; }}
  .section-title {{ font-size: 1.1rem; font-weight: 700; color: #f1f5f9;
                    margin: 2rem 0 1rem; padding-bottom: .5rem; border-bottom: 1px solid #1e293b; }}
  .finding {{ background: #1e293b; border-radius: 8px; border-left: 4px solid;
              padding: 1rem 1.25rem; margin-bottom: .75rem; }}
  .finding-header {{ display: flex; align-items: flex-start; gap: .75rem; margin-bottom: .5rem; }}
  .sev-badge {{ padding: .2rem .55rem; border-radius: 4px; font-size: .7rem;
                font-weight: 700; text-transform: uppercase; letter-spacing: .05em; flex-shrink: 0; }}
  .finding-title {{ font-weight: 600; color: #f1f5f9; font-size: .9rem; }}
  .finding-loc {{ font-size: .78rem; color: #64748b; margin-bottom: .4rem; font-family: monospace; }}
  .finding-desc {{ font-size: .84rem; color: #94a3b8; margin-bottom: .5rem; line-height: 1.5; }}
  .finding-fix {{ font-size: .82rem; color: #86efac; }}
  .finding-refs {{ margin-top: .4rem; }}
  .finding-refs a {{ font-size: .78rem; }}
  .footer {{ text-align: center; color: #334155; font-size: .8rem; padding: 2rem; }}
  @media (max-width: 600px) {{
    .score-card {{ flex-direction: column; }}
    .counts {{ gap: .5rem; }}
  }}
</style>
</head>
<body>
<div class="header">
  <div class="container" style="padding-top:0;padding-bottom:0">
    <h1>🛡️ Attack Surface Analyzer</h1>
    <div class="meta">
      Target: <strong>{result.target}</strong> &nbsp;·&nbsp;
      Scanned: {result.timestamp[:19].replace("T", " ")} &nbsp;·&nbsp;
      Duration: {result.elapsed:.1f}s
    </div>
  </div>
</div>

<div class="container">
  <div class="score-card">
    <div class="score-circle">
      <span class="score-num">{score}</span>
      <span class="score-label">/ 100</span>
    </div>
    <div class="verdict">
      <h2>{verdict}</h2>
      <p>{verdict_sub}</p>
      <div class="counts">{summary_bars}</div>
    </div>
  </div>

  {findings_html}
</div>

<div class="footer">
  Generated by <a href="https://github.com/your-username/attack-surface-analyzer" target="_blank">ASA</a>
  &mdash; Attack Surface Analyzer for Developers
</div>
</body>
</html>"""

    def _summary_bars(self, counts: dict) -> str:
        html = ""
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = counts.get(sev, 0)
            if count == 0:
                continue
            color = SEVERITY_COLOR[sev]
            bg = SEVERITY_BG[sev]
            html += (
                f'<span class="badge" style="background:{bg};color:{color};border:1px solid {color}22">'
                f'{sev.upper()} {count}</span>'
            )
        return html or '<span style="color:#22c55e">No findings</span>'

    def _findings_section(self, result: ScanResult) -> str:
        if not result.findings:
            return '<div style="text-align:center;padding:3rem;color:#22c55e;font-size:1.1rem">✔ No findings detected</div>'

        html = ""
        by_scanner: dict = {}
        for f in result.findings:
            by_scanner.setdefault(f.scanner, []).append(f)

        sev_order = ["critical", "high", "medium", "low", "info"]
        order = ["dependencies", "configs", "secrets", "endpoints"]

        for scanner_name in order:
            findings = by_scanner.get(scanner_name, [])
            if not findings:
                continue
            icon = SCANNER_ICONS.get(scanner_name, "🔍")
            label = scanner_name.replace("_", " ").title()
            html += f'<div class="section-title">{icon} {label} <span style="color:#475569;font-size:.85rem;font-weight:400">({len(findings)})</span></div>\n'

            findings_sorted = sorted(findings, key=lambda f: sev_order.index(f.severity.lower()))
            for f in findings_sorted:
                html += self._finding_card(f)

        return html

    def _finding_card(self, f: Finding) -> str:
        color = SEVERITY_COLOR.get(f.severity.lower(), "#6b7280")
        bg = SEVERITY_BG.get(f.severity.lower(), "#1e293b")

        loc = ""
        if f.file:
            loc = f.file
            if f.line:
                loc += f":{f.line}"
            loc = f'<div class="finding-loc">📄 {loc}</div>'

        fix = ""
        if f.remediation:
            fix = f'<div class="finding-fix">→ {f.remediation}</div>'

        refs = ""
        if f.references:
            links = " ".join(f'<a href="{r}" target="_blank">{r[:60]}...</a>' if len(r) > 60 else f'<a href="{r}" target="_blank">{r}</a>' for r in f.references[:2])
            refs = f'<div class="finding-refs">{links}</div>'

        return f"""<div class="finding" style="border-color:{color}">
  <div class="finding-header">
    <span class="sev-badge" style="background:{bg};color:{color}">{f.severity.upper()}</span>
    <span class="finding-title">{f.title}</span>
  </div>
  {loc}
  <div class="finding-desc">{f.description}</div>
  {fix}
  {refs}
</div>
"""
