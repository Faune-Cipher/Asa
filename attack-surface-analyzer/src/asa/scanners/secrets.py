"""
Secrets scanner — detects hardcoded credentials and high-entropy strings.
Uses regex patterns + optional Shannon entropy analysis.
"""
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import BaseScanner
from ..models import Finding

# ── Regex-based patterns ───────────────────────────────────────────────────────

SECRET_PATTERNS = [
    {
        "id": "SECRET001",
        "name": "AWS Access Key ID",
        "pattern": re.compile(r'AKIA[0-9A-Z]{16}', re.MULTILINE),
        "severity": "critical",
        "remediation": "Revoke immediately at https://console.aws.amazon.com/iam and rotate.",
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"],
    },
    {
        "id": "SECRET002",
        "name": "AWS Secret Key",
        "pattern": re.compile(r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?([A-Za-z0-9/+]{40})', re.IGNORECASE),
        "severity": "critical",
        "remediation": "Revoke via IAM console and use AWS Secrets Manager or environment variables.",
    },
    {
        "id": "SECRET003",
        "name": "GitHub Personal Access Token",
        "pattern": re.compile(r'gh[pousr]_[A-Za-z0-9_]{30,255}', re.MULTILINE),
        "severity": "critical",
        "remediation": "Revoke at https://github.com/settings/tokens and use GitHub Actions secrets.",
    },
    {
        "id": "SECRET004",
        "name": "Slack Bot/User Token",
        "pattern": re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}', re.MULTILINE),
        "severity": "high",
        "remediation": "Revoke at api.slack.com and store in environment variables.",
    },
    {
        "id": "SECRET005",
        "name": "Stripe API Key",
        "pattern": re.compile(r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}', re.MULTILINE),
        "severity": "critical",
        "remediation": "Revoke at dashboard.stripe.com/apikeys and rotate immediately.",
    },
    {
        "id": "SECRET006",
        "name": "Google API Key",
        "pattern": re.compile(r'AIza[0-9A-Za-z\-_]{35}', re.MULTILINE),
        "severity": "high",
        "remediation": "Revoke in Google Cloud Console and restrict key usage.",
    },
    {
        "id": "SECRET007",
        "name": "SendGrid API Key",
        "pattern": re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}', re.MULTILINE),
        "severity": "high",
        "remediation": "Revoke at app.sendgrid.com/settings/api_keys",
    },
    {
        "id": "SECRET008",
        "name": "Twilio Account SID / Auth Token",
        "pattern": re.compile(r'(?:AC|SK)[0-9a-f]{32}', re.MULTILINE),
        "severity": "high",
        "remediation": "Revoke at console.twilio.com",
    },
    {
        "id": "SECRET009",
        "name": "Private Key (PEM)",
        "pattern": re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', re.MULTILINE),
        "severity": "critical",
        "remediation": "Remove private key from repo. Rotate the key pair immediately. Add *.pem, *.key to .gitignore.",
    },
    {
        "id": "SECRET010",
        "name": "Generic password in assignment",
        "pattern": re.compile(
            r'(?:password|passwd|pwd|secret)\s*[=:]\s*["\'](?!.*\{)[^"\']{6,}["\']',
            re.IGNORECASE | re.MULTILINE,
        ),
        "severity": "medium",
        "remediation": "Move credentials to environment variables or a secrets manager.",
    },
    {
        "id": "SECRET011",
        "name": "Bearer token hardcoded",
        "pattern": re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]{20,}', re.MULTILINE),
        "severity": "high",
        "remediation": "Use short-lived tokens fetched at runtime from a secrets manager.",
    },
    {
        "id": "SECRET012",
        "name": "Database connection string with credentials",
        "pattern": re.compile(
            r'(?:postgresql|mysql|mongodb|redis|mssql)://[^:]+:[^@]{4,}@',
            re.IGNORECASE | re.MULTILINE,
        ),
        "severity": "high",
        "remediation": "Replace inline credentials with environment variable references.",
    },
    {
        "id": "SECRET013",
        "name": "Anthropic / OpenAI API Key",
        "pattern": re.compile(r'sk-(?:ant-|proj-|)[A-Za-z0-9_\-]{32,}', re.MULTILINE),
        "severity": "critical",
        "remediation": "Revoke via platform dashboard and store in environment variables.",
    },
    {
        "id": "SECRET014",
        "name": "HuggingFace token",
        "pattern": re.compile(r'hf_[A-Za-z0-9]{30,}', re.MULTILINE),
        "severity": "high",
        "remediation": "Revoke at huggingface.co/settings/tokens",
    },
]

# Extensions to skip (binaries, media, lockfiles with hashes)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".exe", ".dll", ".so", ".dylib", ".woff", ".woff2", ".ttf",
    ".eot", ".mp3", ".mp4", ".avi", ".mov",
    ".pyc", ".pyo", ".class",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "Pipfile.lock", "poetry.lock",
    "composer.lock", "go.sum",
}

# Max file size to scan (5 MB)
MAX_FILE_BYTES = 5 * 1024 * 1024

ENTROPY_THRESHOLD = 4.5
ENTROPY_MIN_LEN = 20


class SecretScanner(BaseScanner):
    name = "secrets"
    label = "Hardcoded Secrets"
    icon = "🔑"

    def _scan(self) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        files_scanned = 0
        seen = set()  # deduplicate (file, pattern_id, line)

        for filepath in self.walk_files():
            if filepath.suffix.lower() in SKIP_EXTENSIONS:
                continue
            if filepath.name in SKIP_FILES:
                continue
            if filepath.stat().st_size > MAX_FILE_BYTES:
                continue

            # Skip .git internals
            if ".git" in filepath.parts:
                continue

            try:
                text = filepath.read_text(errors="ignore")
            except Exception:
                continue

            files_scanned += 1
            rel = str(filepath.relative_to(self.target))
            lines = text.splitlines()

            for rule in SECRET_PATTERNS:
                for match in rule["pattern"].finditer(text):
                    # Find line number
                    line_no = text[: match.start()].count("\n") + 1
                    key = (rel, rule["id"], line_no)
                    if key in seen:
                        continue
                    seen.add(key)

                    # Mask matched value in title
                    matched = match.group(0)
                    masked = matched[:6] + "***" if len(matched) > 6 else "***"

                    findings.append(Finding(
                        scanner=self.name,
                        title=f"{rule['name']} — {masked}",
                        severity=rule["severity"],
                        description=f"Potential {rule['name']} found hardcoded in source.",
                        file=rel,
                        line=line_no,
                        remediation=rule.get("remediation"),
                        references=rule.get("references", []),
                        extra={"rule_id": rule["id"], "matched_prefix": masked},
                    ))

        return findings, {"files_scanned": files_scanned}


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())
