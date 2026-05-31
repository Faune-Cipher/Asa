"""
Dependency CVE scanner.
Supports: Python (requirements.txt, Pipfile, pyproject.toml), Node (package.json), Go (go.mod)
Uses OSV.dev batch API — no API key required.
"""
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from . import BaseScanner
from ..models import Finding

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
BATCH_SIZE = 50  # OSV allows up to 1000 but we stay conservative


class DependencyScanner(BaseScanner):
    name = "dependencies"
    label = "CVE / Dependency Audit"
    icon = "📦"

    def _scan(self) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        all_packages = []
        sources_found = []

        # Collect packages from all lockfiles / manifests
        for collector in [
            self._collect_requirements_txt,
            self._collect_pyproject_toml,
            self._collect_pipfile_lock,
            self._collect_package_json,
            self._collect_go_mod,
        ]:
            pkgs, source = collector()
            if pkgs:
                all_packages.extend(pkgs)
                sources_found.append(source)

        if not all_packages:
            return [], {"sources": [], "packages_checked": 0, "note": "No manifest files found"}

        if not HAS_REQUESTS:
            return [Finding(
                scanner=self.name,
                title="requests library not installed",
                severity="info",
                description="Install 'requests' to enable CVE scanning: pip install requests",
            )], {"sources": sources_found, "packages_checked": 0}

        # Query OSV in batches
        vulns = self._query_osv(all_packages)
        for pkg, vuln_list in vulns:
            for vuln in vuln_list:
                severity = self._osv_severity(vuln)
                aliases = vuln.get("aliases", [])
                cve_ids = [a for a in aliases if a.startswith("CVE-")]
                refs = [r["url"] for r in vuln.get("references", [])[:3]]

                findings.append(Finding(
                    scanner=self.name,
                    title=f"{pkg['name']}=={pkg.get('version','?')} — {vuln.get('id', 'UNKNOWN')}",
                    severity=severity,
                    description=vuln.get("summary", "No description available."),
                    file=pkg.get("source_file"),
                    remediation=self._remediation(pkg, vuln),
                    references=[f"https://osv.dev/vulnerability/{vuln.get('id')}"] + refs,
                    extra={
                        "package": pkg["name"],
                        "version": pkg.get("version"),
                        "vuln_id": vuln.get("id"),
                        "cve_ids": cve_ids,
                        "ecosystem": pkg.get("ecosystem"),
                    },
                ))

        return findings, {
            "sources": sources_found,
            "packages_checked": len(all_packages),
        }

    # ── Collectors ─────────────────────────────────────────────────────────────

    def _collect_requirements_txt(self):
        pkgs = []
        for p in self.target.rglob("requirements*.txt"):
            if any(skip in p.parts for skip in {".git", "node_modules", "__pycache__", ".venv", "venv"}):
                continue
            rel = str(p.relative_to(self.target))
            for line in p.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                name, version = self._parse_req_line(line)
                if name:
                    pkgs.append({"name": name, "version": version,
                                 "ecosystem": "PyPI", "source_file": rel})
        return pkgs, "requirements.txt"

    def _collect_pyproject_toml(self):
        pkgs = []
        if tomllib is None:
            return pkgs, "pyproject.toml"
        for p in self.target.rglob("pyproject.toml"):
            if any(skip in p.parts for skip in {".git", ".venv", "venv"}):
                continue
            rel = str(p.relative_to(self.target))
            try:
                data = tomllib.loads(p.read_text())
                deps = (data.get("project", {}).get("dependencies", []) or
                        data.get("tool", {}).get("poetry", {}).get("dependencies", {}).keys())
                for dep in deps:
                    if isinstance(dep, str):
                        name, version = self._parse_req_line(dep)
                    else:
                        name, version = str(dep), None
                    if name and name.lower() != "python":
                        pkgs.append({"name": name, "version": version,
                                     "ecosystem": "PyPI", "source_file": rel})
            except Exception:
                pass
        return pkgs, "pyproject.toml"

    def _collect_pipfile_lock(self):
        pkgs = []
        p = self.target / "Pipfile.lock"
        if not p.exists():
            return pkgs, "Pipfile.lock"
        rel = str(p.relative_to(self.target))
        try:
            data = json.loads(p.read_text())
            for section in ("default", "develop"):
                for name, info in data.get(section, {}).items():
                    version = info.get("version", "").lstrip("=")
                    pkgs.append({"name": name, "version": version or None,
                                 "ecosystem": "PyPI", "source_file": rel})
        except Exception:
            pass
        return pkgs, "Pipfile.lock"

    def _collect_package_json(self):
        pkgs = []
        # Prefer package-lock.json for exact versions
        lock = self.target / "package-lock.json"
        if lock.exists():
            rel = str(lock.relative_to(self.target))
            try:
                data = json.loads(lock.read_text())
                # npm v2/v3 lockfile
                for name, info in data.get("packages", {}).items():
                    if not name or name == "":
                        continue
                    pkg_name = name.replace("node_modules/", "").split("/")[-1]
                    version = info.get("version")
                    if pkg_name and version:
                        pkgs.append({"name": pkg_name, "version": version,
                                     "ecosystem": "npm", "source_file": rel})
                return pkgs, "package-lock.json"
            except Exception:
                pass

        # Fallback to package.json
        pjson = self.target / "package.json"
        if pjson.exists():
            rel = str(pjson.relative_to(self.target))
            try:
                data = json.loads(pjson.read_text())
                for section in ("dependencies", "devDependencies"):
                    for name, ver in data.get(section, {}).items():
                        clean_ver = re.sub(r"[^0-9.]", "", ver.lstrip("^~>=<"))
                        pkgs.append({"name": name, "version": clean_ver or None,
                                     "ecosystem": "npm", "source_file": rel})
            except Exception:
                pass
        return pkgs, "package.json"

    def _collect_go_mod(self):
        pkgs = []
        p = self.target / "go.mod"
        if not p.exists():
            return pkgs, "go.mod"
        rel = str(p.relative_to(self.target))
        for line in p.read_text(errors="ignore").splitlines():
            line = line.strip()
            m = re.match(r'^require\s+(\S+)\s+(v[\d.]+)', line)
            if not m:
                m = re.match(r'^(\S+)\s+(v[\d.]+)', line)
            if m:
                pkgs.append({"name": m.group(1), "version": m.group(2).lstrip("v"),
                             "ecosystem": "Go", "source_file": rel})
        return pkgs, "go.mod"

    # ── OSV API ────────────────────────────────────────────────────────────────

    def _query_osv(self, packages: List[Dict]) -> List[Tuple[Dict, List[Dict]]]:
        results = []
        for i in range(0, len(packages), BATCH_SIZE):
            batch = packages[i:i + BATCH_SIZE]
            queries = []
            for pkg in batch:
                q: Dict[str, Any] = {"package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]}}
                if pkg.get("version"):
                    q["version"] = pkg["version"]
                queries.append(q)

            try:
                resp = requests.post(
                    OSV_BATCH_URL,
                    json={"queries": queries},
                    timeout=30,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json()
                for pkg, result in zip(batch, data.get("results", [])):
                    vulns = result.get("vulns", [])
                    if vulns:
                        results.append((pkg, vulns))
                time.sleep(0.1)  # be polite
            except Exception:
                pass  # network unavailable, skip silently
        return results

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _parse_req_line(self, line: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse 'package==1.2.3' or 'package>=1.0' → (name, version|None)."""
        line = line.split(";")[0].split("#")[0].strip()
        m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([\d\.]+(?:\.\w+)?)', line)
        if m:
            return m.group(1), m.group(2)
        m = re.match(r'^([A-Za-z0-9_\-\.]+)', line)
        if m:
            return m.group(1), None
        return None, None

    def _osv_severity(self, vuln: Dict) -> str:
        """Map OSV severity to our levels."""
        for sev in vuln.get("severity", []):
            score_str = sev.get("score", "")
            if sev.get("type") == "CVSS_V3":
                try:
                    score = float(score_str.split("/")[0].split(":")[-1])
                    if score >= 9.0:
                        return "critical"
                    if score >= 7.0:
                        return "high"
                    if score >= 4.0:
                        return "medium"
                    return "low"
                except (ValueError, IndexError):
                    pass
        # fallback: use OSV database_specific
        db = vuln.get("database_specific", {})
        sev_str = db.get("severity", "").lower()
        if sev_str in ("critical",):
            return "critical"
        if sev_str in ("high",):
            return "high"
        if sev_str in ("moderate", "medium"):
            return "medium"
        return "medium"  # default unknown → medium

    def _remediation(self, pkg: Dict, vuln: Dict) -> str:
        affected = vuln.get("affected", [])
        for aff in affected:
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        return f"Upgrade {pkg['name']} to >= {ev['fixed']}"
        return f"Review {vuln.get('id')} and update {pkg['name']} to the latest version."
