"""
Endpoint scanner — detects exposed sensitive routes and debug interfaces.
Supports: Python (Flask, Django, FastAPI), Node (Express), Go (Gin/Mux).
"""
import re
from typing import Any, Dict, List, Tuple

from . import BaseScanner
from ..models import Finding

# Sensitive path patterns to flag
SENSITIVE_ROUTE_PATTERNS = [
    (re.compile(r"""["'`](/admin(?:/\S*)?)['"` ]""", re.IGNORECASE), "Admin endpoint exposed", "high"),
    (re.compile(r"""["'`](/debug(?:/\S*)?)['"` ]""", re.IGNORECASE), "Debug endpoint exposed", "high"),
    (re.compile(r"""["'`](/metrics(?:/\S*)?)['"` ]""", re.IGNORECASE), "Metrics endpoint exposed (check auth)", "medium"),
    (re.compile(r"""["'`](/healthz?(?:/\S*)?)['"` ]|["'`](/health/(?:live|ready)\S*)['"` ]""", re.IGNORECASE), "Health check endpoint (may expose internals)", "low"),
    (re.compile(r"""["'`](/actuator(?:/\S*)?)['"` ]""", re.IGNORECASE), "Spring Actuator endpoint exposed", "high"),
    (re.compile(r"""["'`](/swagger(?:-ui)?(?:/\S*)?)['"` ]|["'`](/openapi\.json)['"` ]|["'`](/api/docs)['"` ]""", re.IGNORECASE), "API docs publicly exposed", "medium"),
    (re.compile(r"""["'`](/graphql(?:/\S*)?)['"` ]""", re.IGNORECASE), "GraphQL endpoint exposed (check introspection)", "medium"),
    (re.compile(r"""["'`](/console(?:/\S*)?)['"` ]|["'`](/shell)['"` ]""", re.IGNORECASE), "Console/shell endpoint exposed", "critical"),
    (re.compile(r"""["'`](/_deb\w+_toolbar\S*)['"` ]|SHOW_TOOLBAR_CALLBACK""", re.IGNORECASE), "Django Debug Toolbar enabled", "high"),
    (re.compile(r"""["'`](/phpmyadmin(?:/\S*)?)['"` ]|["'`](/pma)['"` ]""", re.IGNORECASE), "phpMyAdmin endpoint exposed", "high"),
    (re.compile(r"""["'`](/\.env)['"` ]|["'`](/config\.json)['"` ]|["'`](/secrets\.json)['"` ]""", re.IGNORECASE), "Config/secret file served as route", "critical"),
    (re.compile(r"""CORS_ORIGINS?\s*=\s*["\[]\s*\*\s*["\]]|allow_origins\s*=\s*\[\s*["']\*["']|cors\([^)]*\*[^)]*\)""", re.IGNORECASE), "CORS wildcard (*) configured", "medium"),
    (re.compile(r"""app\.run\s*\([^)]*debug\s*=\s*True""", re.IGNORECASE), "Flask app running with debug=True", "high"),
    (re.compile(r"""app\.run\s*\([^)]*host\s*=\s*['"']0\.0\.0\.0['"']"""), "Flask app bound to 0.0.0.0", "medium"),
]

CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".java",
    ".php", ".cs", ".scala", ".kt", ".rs", ".mjs", ".cjs",
}


class EndpointScanner(BaseScanner):
    name = "endpoints"
    label = "Endpoint Exposure"
    icon = "🌐"

    def _scan(self) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        files_scanned = 0
        seen = set()

        for filepath in self.walk_files(extensions=list(CODE_EXTENSIONS)):
            try:
                text = filepath.read_text(errors="ignore")
            except Exception:
                continue

            files_scanned += 1
            rel = str(filepath.relative_to(self.target))

            for pattern, title, severity in SENSITIVE_ROUTE_PATTERNS:
                for match in pattern.finditer(text):
                    line_no = text[: match.start()].count("\n") + 1
                    key = (rel, title, line_no)
                    if key in seen:
                        continue
                    seen.add(key)

                    # Extract the matched path for context
                    route = match.group(1) if match.lastindex else match.group(0)[:60]

                    findings.append(Finding(
                        scanner=self.name,
                        title=f"{title}: {route}",
                        severity=severity,
                        description=self._describe(title, route),
                        file=rel,
                        line=line_no,
                        remediation=self._remediation(title),
                        references=self._references(title),
                    ))

        return findings, {"files_scanned": files_scanned}

    def _describe(self, title: str, route: str) -> str:
        descs = {
            "Admin endpoint exposed": f"Route '{route}' looks like an admin interface. Ensure it's protected by authentication and not publicly accessible.",
            "Debug endpoint exposed": f"Debug route '{route}' detected. Debug endpoints typically expose internals and should be disabled in production.",
            "CORS wildcard (*) configured": "Wildcard CORS allows any origin to make cross-site requests, potentially leaking authenticated data.",
            "Flask app running with debug=True": "Flask's debug mode enables an interactive debugger accessible via the browser — effectively RCE.",
        }
        return descs.get(title, f"Potentially sensitive endpoint '{route}' detected. Verify it is properly secured.")

    def _remediation(self, title: str) -> str:
        remediations = {
            "Admin endpoint exposed": "Restrict behind auth middleware, use non-guessable paths, or serve on a separate internal port.",
            "Debug endpoint exposed": "Disable in production via environment config. Never expose debug interfaces publicly.",
            "CORS wildcard (*) configured": "Replace '*' with an explicit allowlist of trusted origins.",
            "Flask app running with debug=True": "Set debug=False or use DEBUG=False in your environment config for production.",
            "GraphQL endpoint exposed (check introspection)": "Disable introspection in production: https://www.apollographql.com/docs/apollo-server/security/introspection/",
        }
        return remediations.get(title, "Review whether this endpoint needs public exposure. Add authentication if so.")

    def _references(self, title: str) -> List[str]:
        refs = {
            "CORS wildcard (*) configured": ["https://portswigger.net/web-security/cors"],
            "Flask app running with debug=True": ["https://flask.palletsprojects.com/en/stable/config/#DEBUG"],
            "GraphQL endpoint exposed (check introspection)": ["https://owasp.org/www-project-graphql/"],
        }
        return refs.get(title, [])
