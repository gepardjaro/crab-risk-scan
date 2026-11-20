"""Normalize local detections and saved Trivy filesystem dependency reports."""
import hashlib
import json
import re
import stat
from pathlib import PurePosixPath, PureWindowsPath

LEVELS = ("critical", "high", "medium", "low", "unknown")
REPORT_LIMIT = 16 * 1024 * 1024


def token(value):
    if not isinstance(value, str) or not re.fullmatch(r"[\w@.+:/~^!-]{1,256}", value, re.ASCII):
        raise ValueError("invalid identifier")
    return value


def relative_path(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise ValueError("invalid path")
    path = PurePosixPath(value.replace("\\", "/"))
    if not path.parts or path.is_absolute() or PureWindowsPath(value).drive or ".." in path.parts:
        raise ValueError("invalid path")
    return path.as_posix()


def fingerprint(parts):
    encoded = json.dumps(parts, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def trivy_findings(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("expected a regular report")
    with path.open("rb") as stream:
        data = stream.read(REPORT_LIMIT + 1)
    if len(data) > REPORT_LIMIT:
        raise ValueError("report too large")
    report = json.loads(data)
    if report["SchemaVersion"] != 2 or report["ArtifactType"] != "filesystem":
        raise ValueError("unsupported Trivy report")
    results = report.get("Results", [])
    if not isinstance(results, list):
        raise ValueError("invalid results")
    version = report.get("Trivy", {}).get("Version")
    if version is not None:
        version = token(version)
    findings = []
    for result in results:
        if result["Class"] != "lang-pkgs":
            raise ValueError("expected a dependency-only report")
        target = relative_path(result["Target"])
        ecosystem = token(result["Type"])
        vulns = result.get("Vulnerabilities", [])
        if vulns is None:
            vulns = []
        if not isinstance(vulns, list):
            raise ValueError("invalid vulnerabilities")
        for item in vulns:
            advisory = token(item["VulnerabilityID"])
            name = token(item["PkgName"])
            installed = token(item["InstalledVersion"])
            level = token(item["Severity"])
            normalized = level.lower()
            location = relative_path(item["PkgPath"]) if item.get("PkgPath") else target
            key = ["trivy", ecosystem, target, location, advisory, name, installed]
            findings.append({
                "fingerprint": fingerprint(key), "producer": "trivy", "producer_version": version,
                "module": "Shell", "rule": advisory, "path": location, "line": None,
                "severity": normalized if normalized in LEVELS else "unknown",
                "original_severity": level, "manifest": target,
                "package": {"ecosystem": ecosystem, "name": name, "version": installed},
                "message": "Review the installed dependency against this advisory.",
            })
    return findings, len(results)


def collect(local, paths):
    findings = []
    for hit in local["findings"]:
        key = ["crab", hit["path"], hit["line"], hit["rule"]]
        module = "Claws" if hit["rule"] == "CRAB-PY-001" else "Burrow"
        findings.append(dict(hit, fingerprint=fingerprint(key), producer="crab",
                             producer_version="0.1.0", module=module,
                             original_severity=hit["severity"]))
    errors = list(local["errors"])
    imports = []
    for index, path in enumerate(paths, 1):
        try:
            hits, targets = trivy_findings(path)
        except (KeyError, TypeError, AttributeError, ValueError, OSError, RecursionError):
            errors.append({"input": index, "producer": "trivy", "reason": "invalid_report"})
        else:
            findings.extend(hits)
            imports.append({"input": index, "producer": "trivy", "targets": targets})
    # Ordering also chooses the highest severity when two reports disagree.
    findings.sort(key=lambda f: (LEVELS.index(f["severity"]), f["path"], f.get("line") or 0,
                                 f["rule"], f["fingerprint"], json.dumps(f, sort_keys=True)))
    unique = {}
    for finding in findings:
        unique.setdefault(finding["fingerprint"], finding)
    return {"schema_version": 2, "files_scanned": local["files_scanned"], "imports": imports,
            "findings": list(unique.values()), "errors": errors}
