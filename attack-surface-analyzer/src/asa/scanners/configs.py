"""
Config scanner — detects misconfigurations in:
- Dockerfile / docker-compose.yml
- CI/CD (GitHub Actions, GitLab CI, CircleCI)
- .env files and .env.example
- nginx / apache configs
- SSH / SSL config files
"""
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from . import BaseScanner
from ..models import Finding


# ── Rule definitions ───────────────────────────────────────────────────────────

DOCKERFILE_RULES = [
    {
        "id": "DOCKER001",
        "pattern": re.compile(r"^FROM\s+\S+:latest\b", re.MULTILINE | re.IGNORECASE),
        "title": "Dockerfile: FROM uses :latest tag",
        "severity": "medium",
        "description": "Using ':latest' is non-deterministic and can pull untrusted or breaking images.",
        "remediation": "Pin to a specific digest or version tag, e.g. FROM python:3.12.3-slim",
    },
    {
        "id": "DOCKER002",
        "pattern": re.compile(r"^USER\s+root\b", re.MULTILINE | re.IGNORECASE),
        "title": "Dockerfile: container runs as root",
        "severity": "high",
        "description": "Running as root inside a container is a privilege escalation risk.",
        "remediation": "Add 'USER nonroot' or create a dedicated user at the end of your Dockerfile.",
    },
    {
        "id": "DOCKER003",
        "pattern": re.compile(r"(?<!\S)USER\s+\w+", re.MULTILINE | re.IGNORECASE),
        "title": "Dockerfile: no USER directive found",
        "severity": "medium",
        "description": "No USER instruction found — container will default to root.",
        "remediation": "Add a non-root USER instruction before the final CMD/ENTRYPOINT.",
        "inverted": True,  # fire if pattern NOT found
    },
    {
        "id": "DOCKER004",
        "pattern": re.compile(r"ADD\s+https?://", re.MULTILINE | re.IGNORECASE),
        "title": "Dockerfile: ADD fetches remote URL",
        "severity": "medium",
        "description": "ADD with a URL does not verify integrity. Prefer curl + sha256sum or COPY.",
        "remediation": "Use RUN curl -fsSL <url> | sha256sum -c instead of ADD.",
    },
    {
        "id": "DOCKER005",
        "pattern": re.compile(r"--no-check-certificate|--insecure|pip install.*--trusted-host", re.IGNORECASE),
        "title": "Dockerfile: SSL verification disabled",
        "severity": "high",
        "description": "Disabling SSL verification in Dockerfile exposes the build to MITM attacks.",
        "remediation": "Remove --insecure / --no-check-certificate flags.",
    },
]

COMPOSE_RULES = [
    {
        "id": "COMPOSE001",
        "pattern": re.compile(r"privileged:\s*true", re.IGNORECASE),
        "title": "docker-compose: privileged container",
        "severity": "critical",
        "description": "A privileged container has near-root access to the host kernel.",
        "remediation": "Remove 'privileged: true' and use specific capabilities instead (cap_add).",
    },
    {
        "id": "COMPOSE002",
        "pattern": re.compile(r"network_mode:\s*['\"]?host['\"]?", re.IGNORECASE),
        "title": "docker-compose: host network mode",
        "severity": "high",
        "description": "Host networking removes container isolation and exposes all host ports.",
        "remediation": "Define explicit port mappings instead of using host network mode.",
    },
    {
        "id": "COMPOSE003",
        "pattern": re.compile(r"-\s*['\"]?0\.0\.0\.0:\d+:\d+['\"]?"),
        "title": "docker-compose: port bound to 0.0.0.0",
        "severity": "medium",
        "description": "Binding to 0.0.0.0 exposes the port on all network interfaces.",
        "remediation": "Bind to 127.0.0.1 unless external access is intentional.",
    },
    {
        "id": "COMPOSE004",
        "pattern": re.compile(r"docker\.sock"),
        "title": "docker-compose: Docker socket mounted",
        "severity": "critical",
        "description": "Mounting the Docker socket gives the container full Docker daemon control (container escape).",
        "remediation": "Avoid mounting docker.sock unless absolutely necessary. Use Docker-in-Docker patterns carefully.",
    },
]

GH_ACTIONS_RULES = [
    {
        "id": "GHA001",
        "pattern": re.compile(r"uses:\s+\S+@(?!v?\d+\.\d+)(?!sha-)[a-zA-Z]", re.IGNORECASE),
        "title": "GitHub Actions: action pinned to branch (not SHA/tag)",
        "severity": "medium",
        "description": "Pinning actions to a branch name is mutable and susceptible to supply-chain attacks.",
        "remediation": "Pin actions to a full commit SHA, e.g. uses: actions/checkout@a81bbbf",
        "references": ["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"],
    },
    {
        "id": "GHA002",
        "pattern": re.compile(r"permissions:\s*write-all|permissions:\s*\n\s+contents:\s*write.*\n\s+id-token:\s*write", re.IGNORECASE | re.DOTALL),
        "title": "GitHub Actions: overly broad permissions",
        "severity": "high",
        "description": "write-all or broad write permissions increase blast radius of compromised workflows.",
        "remediation": "Apply least-privilege: only grant the permissions your job actually needs.",
    },
    {
        "id": "GHA003",
        "pattern": re.compile(r"\$\{\{\s*github\.event\.\w+\s*\}\}", re.IGNORECASE),
        "title": "GitHub Actions: untrusted input in expression",
        "severity": "high",
        "description": "Using github.event.* directly in run: steps can lead to script injection.",
        "remediation": "Assign to an environment variable first: MY_VAR: ${{ github.event.issue.title }}",
        "references": ["https://securitylab.github.com/research/github-actions-untrusted-input/"],
    },
]

ENV_RULES = [
    {
        "id": "ENV001",
        "pattern": re.compile(r"DEBUG\s*=\s*(?:true|1|yes|on)", re.IGNORECASE),
        "title": ".env: DEBUG mode enabled",
        "severity": "medium",
        "description": "DEBUG=true can expose stack traces, SQL queries and internal config in production.",
        "remediation": "Set DEBUG=false or DEBUG=0 in production environments.",
    },
    {
        "id": "ENV002",
        "pattern": re.compile(r"(?:DB_PASSWORD|DATABASE_URL|DB_PASS)\s*=\s*(?:password|1234|root|admin|changeme)", re.IGNORECASE),
        "title": ".env: weak/default database password",
        "severity": "high",
        "description": "Database credentials use a well-known default password.",
        "remediation": "Generate a strong random password (e.g. openssl rand -hex 32).",
    },
    {
        "id": "ENV003",
        "pattern": re.compile(r"(?:SECRET_KEY|JWT_SECRET|APP_SECRET)\s*=\s*(?:secret|changeme|your[-_]secret|insecure|dev|test)", re.IGNORECASE),
        "title": ".env: weak/placeholder secret key",
        "severity": "high",
        "description": "Application secret key is a well-known placeholder — HMAC/JWT forgery is trivial.",
        "remediation": "Set a cryptographically random secret: python -c \"import secrets; print(secrets.token_hex(64))\"",
    },
    {
        "id": "ENV004",
        "pattern": re.compile(r"SSL_VERIFY\s*=\s*(?:false|0|no)|VERIFY_SSL\s*=\s*(?:false|0)", re.IGNORECASE),
        "title": ".env: SSL verification disabled",
        "severity": "high",
        "description": "Disabling SSL verification exposes your app to MITM attacks.",
        "remediation": "Remove this setting or set to true.",
    },
]

NGINX_RULES = [
    {
        "id": "NGINX001",
        "pattern": re.compile(r"ssl_protocols.*SSLv2|ssl_protocols.*SSLv3|ssl_protocols.*TLSv1\b(?!\.)", re.IGNORECASE),
        "title": "nginx: deprecated SSL/TLS protocol enabled",
        "severity": "high",
        "description": "SSLv2, SSLv3 and TLSv1.0 are deprecated and vulnerable (POODLE, BEAST).",
        "remediation": "Use 'ssl_protocols TLSv1.2 TLSv1.3;' only.",
    },
    {
        "id": "NGINX002",
        "pattern": re.compile(r"server_tokens\s+on", re.IGNORECASE),
        "title": "nginx: server_tokens on (version disclosure)",
        "severity": "low",
        "description": "nginx version is exposed in HTTP headers and error pages.",
        "remediation": "Add 'server_tokens off;' to your http block.",
    },
    {
        "id": "NGINX003",
        "pattern": re.compile(r"autoindex\s+on", re.IGNORECASE),
        "title": "nginx: directory listing enabled",
        "severity": "medium",
        "description": "autoindex on allows browsing directory contents.",
        "remediation": "Remove or set 'autoindex off;'",
    },
]


class ConfigScanner(BaseScanner):
    name = "configs"
    label = "Misconfiguration Scan"
    icon = "⚙️ "

    def _scan(self) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        files_scanned = 0

        ruleset_map = [
            (["Dockerfile", "Dockerfile.*"], DOCKERFILE_RULES, None),
            (["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"], COMPOSE_RULES, None),
            ([".github/workflows/*.yml", ".github/workflows/*.yaml"], GH_ACTIONS_RULES, None),
            ([".env", ".env.*", "*.env"], ENV_RULES, None),
            (["nginx.conf", "*.nginx.conf", "nginx/*.conf"], NGINX_RULES, None),
        ]

        # Gather candidate files
        all_files = list(self.target.rglob("*"))

        for patterns, rules, _ in ruleset_map:
            for pattern in patterns:
                for filepath in self.target.rglob(pattern):
                    if not filepath.is_file():
                        continue
                    if any(skip in filepath.parts for skip in {".git", "node_modules", "__pycache__", ".venv"}):
                        continue
                    files_scanned += 1
                    rel = str(filepath.relative_to(self.target))
                    text = filepath.read_text(errors="ignore")
                    lines = text.splitlines()

                    for rule in rules:
                        inverted = rule.get("inverted", False)
                        match = rule["pattern"].search(text)

                        if inverted:
                            # Fire if pattern NOT found (e.g. no USER in Dockerfile)
                            if not match:
                                findings.append(Finding(
                                    scanner=self.name,
                                    title=rule["title"],
                                    severity=rule["severity"],
                                    description=rule["description"],
                                    file=rel,
                                    remediation=rule.get("remediation"),
                                    references=rule.get("references", []),
                                    extra={"rule_id": rule["id"]},
                                ))
                        else:
                            if match:
                                # Find line number
                                line_no = None
                                for i, line in enumerate(lines, 1):
                                    if rule["pattern"].search(line):
                                        line_no = i
                                        break
                                findings.append(Finding(
                                    scanner=self.name,
                                    title=rule["title"],
                                    severity=rule["severity"],
                                    description=rule["description"],
                                    file=rel,
                                    line=line_no,
                                    remediation=rule.get("remediation"),
                                    references=rule.get("references", []),
                                    extra={"rule_id": rule["id"]},
                                ))

        return findings, {"files_scanned": files_scanned}
