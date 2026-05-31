"""
Tests for ASA scanners.
"""
import json
import tempfile
from pathlib import Path

import pytest

from asa.models import Finding, ScanResult
from asa.scanners.configs import ConfigScanner
from asa.scanners.secrets import SecretScanner
from asa.scanners.endpoints import EndpointScanner


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_project(tmp_path):
    """Returns a temp directory to build fake projects in."""
    return tmp_path


# ── Secret scanner tests ───────────────────────────────────────────────────────

class TestSecretScanner:
    def test_detects_aws_key(self, tmp_project):
        (tmp_project / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        scanner = SecretScanner(tmp_project)
        findings, _ = scanner._scan()
        assert any("AWS" in f.title for f in findings)

    def test_detects_private_key(self, tmp_project):
        (tmp_project / "key.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ\n-----END RSA PRIVATE KEY-----\n")
        scanner = SecretScanner(tmp_project)
        findings, _ = scanner._scan()
        assert any("Private Key" in f.title for f in findings)
        assert findings[0].severity == "critical"

    def test_skips_lockfiles(self, tmp_project):
        # package-lock.json should not be scanned
        (tmp_project / "package-lock.json").write_text(
            json.dumps({"packages": {"fake": {"version": "1.0", "integrity": "sha512-AKIA" + "A" * 20}}})
        )
        scanner = SecretScanner(tmp_project)
        findings, _ = scanner._scan()
        assert len(findings) == 0

    def test_detects_github_token(self, tmp_project):
        (tmp_project / "ci.py").write_text('TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456"\n')
        scanner = SecretScanner(tmp_project)
        findings, _ = scanner._scan()
        assert any("GitHub" in f.title for f in findings)

    def test_no_false_positive_on_clean_file(self, tmp_project):
        (tmp_project / "clean.py").write_text(
            "import os\nAPI_KEY = os.environ.get('API_KEY')\n"
        )
        scanner = SecretScanner(tmp_project)
        findings, _ = scanner._scan()
        assert len(findings) == 0


# ── Config scanner tests ───────────────────────────────────────────────────────

class TestConfigScanner:
    def test_detects_privileged_compose(self, tmp_project):
        (tmp_project / "docker-compose.yml").write_text(
            "services:\n  app:\n    image: nginx\n    privileged: true\n"
        )
        scanner = ConfigScanner(tmp_project)
        findings, _ = scanner._scan()
        assert any("privileged" in f.title.lower() for f in findings)
        assert findings[0].severity == "critical"

    def test_detects_docker_root(self, tmp_project):
        (tmp_project / "Dockerfile").write_text(
            "FROM python:3.12\nUSER root\nCMD python app.py\n"
        )
        scanner = ConfigScanner(tmp_project)
        findings, _ = scanner._scan()
        assert any("root" in f.title.lower() for f in findings)

    def test_detects_docker_latest(self, tmp_project):
        (tmp_project / "Dockerfile").write_text(
            "FROM python:latest\nUSER appuser\nCMD python app.py\n"
        )
        scanner = ConfigScanner(tmp_project)
        findings, _ = scanner._scan()
        assert any("latest" in f.title.lower() for f in findings)

    def test_detects_docker_socket_mount(self, tmp_project):
        (tmp_project / "docker-compose.yml").write_text(
            "services:\n  agent:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
        )
        scanner = ConfigScanner(tmp_project)
        findings, _ = scanner._scan()
        assert any("socket" in f.title.lower() or "docker.sock" in f.description.lower() for f in findings)

    def test_detects_debug_env(self, tmp_project):
        (tmp_project / ".env").write_text("DEBUG=true\nSECRET_KEY=mykey\n")
        scanner = ConfigScanner(tmp_project)
        findings, _ = scanner._scan()
        assert any("DEBUG" in f.title for f in findings)


# ── Endpoint scanner tests ─────────────────────────────────────────────────────

class TestEndpointScanner:
    def test_detects_flask_debug(self, tmp_project):
        (tmp_project / "app.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n"
        )
        scanner = EndpointScanner(tmp_project)
        findings, _ = scanner._scan()
        assert any("debug" in f.title.lower() for f in findings)

    def test_detects_admin_route(self, tmp_project):
        (tmp_project / "routes.py").write_text(
            'app.route("/admin")\ndef admin(): pass\n'
        )
        scanner = EndpointScanner(tmp_project)
        findings, _ = scanner._scan()
        assert any("admin" in f.title.lower() for f in findings)

    def test_detects_cors_wildcard(self, tmp_project):
        (tmp_project / "app.py").write_text(
            'from fastapi.middleware.cors import CORSMiddleware\n'
            'app.add_middleware(CORSMiddleware, allow_origins=["*"])\n'
        )
        scanner = EndpointScanner(tmp_project)
        findings, _ = scanner._scan()
        assert any("CORS" in f.title for f in findings)


# ── Model tests ────────────────────────────────────────────────────────────────

class TestModels:
    def test_risk_score_caps_at_100(self):
        findings = [
            Finding(scanner="test", title=f"f{i}", severity="critical", description="x")
            for i in range(20)
        ]
        result = ScanResult(target="/tmp", findings=findings, scan_meta={}, elapsed=0.1)
        assert result.risk_score == 100

    def test_risk_score_zero_clean(self):
        result = ScanResult(target="/tmp", findings=[], scan_meta={}, elapsed=0.1)
        assert result.risk_score == 0

    def test_counts_by_severity(self):
        findings = [
            Finding(scanner="test", title="a", severity="critical", description="x"),
            Finding(scanner="test", title="b", severity="high", description="x"),
            Finding(scanner="test", title="c", severity="high", description="x"),
        ]
        result = ScanResult(target="/tmp", findings=findings, scan_meta={}, elapsed=0.1)
        counts = result.counts_by_severity
        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["medium"] == 0
