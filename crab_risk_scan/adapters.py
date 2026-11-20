"""Read untrusted scanner JSON. Only explicitly selected fields leave an adapter."""
import re
from dataclasses import dataclass, field

from .evidence import (LEVELS, array, fingerprint, package_url, positive_integer, relative_path,
                       token)


@dataclass
class ImportResult:
    findings: list = field(default_factory=list)
    version: str | None = None
    partial: bool = False
    targets: int | None = None


def source(producer, module, rule, path, start, end, severity, *, columns=None, identity=None):
    start, end = positive_integer(start), positive_integer(end)
    if end < start:
        raise ValueError("invalid span")
    rule, original = token(rule), token(severity)
    normalized = {"error": "high", "warning": "medium", "note": "info",
                  "information": "info", "style": "info"}.get(original.lower(), original.lower())
    result = {"producer": producer, "module": module, "rule": rule, "path": path,
              "line": start, "end_line": end, "original_severity": original,
              "severity": normalized if normalized in LEVELS else "unknown",
              "message": f"Review {producer} rule {rule} at the reported location."}
    if columns:
        left, right = map(positive_integer, columns)
        if start == end and right < left:
            raise ValueError("invalid columns")
        result.update(column=left, end_column=right)
    result["fingerprint"] = fingerprint([producer, rule, path, start, end, columns, identity])
    return result


def bandit(doc, root):
    result = ImportResult(partial=bool(array(doc["errors"])))
    for row in array(doc["results"]):
        line = positive_integer(row["line_number"])
        span = array(row.get("line_range", []))
        end = max(map(positive_integer, span), default=line)
        hit = source("bandit", "Claws", row["test_id"], relative_path(row["filename"], root),
                     line, end, row["issue_severity"], identity=row.get("col_offset"))
        hit["confidence"] = token(row["issue_confidence"])
        # Bandit AST offsets count bytes. Do not export them as SARIF character columns.
        if "col_offset" in row:
            col = row["col_offset"]
            if type(col) is not int or col < 0:
                raise ValueError("invalid offset")
            hit["byte_offset"] = col
            if type(row.get("end_col_offset")) is int and row["end_col_offset"] >= 0:
                hit["end_byte_offset"] = row["end_col_offset"]
        result.findings.append(hit)
    return result


def opengrep(doc, root):
    result = ImportResult(version=token(doc["version"]), partial=bool(array(doc["errors"])))
    for row in array(doc["results"]):
        start, end = row["start"], row["end"]
        hit = source("opengrep", "Claws", row["check_id"], relative_path(row["path"], root),
                     start["line"], end["line"], row["extra"]["severity"],
                     columns=(start["col"], end["col"]))
        result.findings.append(hit)
    return result


def gitleaks(doc, root):
    result = ImportResult()
    for row in array(doc):
        # Do not ingest Match, Secret, Fingerprint, commit messages or author metadata.
        rule = token(row["RuleID"])
        cols = (row["StartColumn"], positive_integer(row["EndColumn"]) + 1) if row.get("StartColumn") else None
        hit = source("gitleaks", "Sniffer", rule, relative_path(row["File"], root),
                     row["StartLine"], row["EndLine"], "unknown", columns=cols)
        hit["message"] = "Review the credential detector match and rotate any exposed credential."
        result.findings.append(hit)
    return result


def checkov(doc, root):
    result = ImportResult()
    for block in doc if isinstance(doc, list) else [doc]:
        checks = block["results"]
        result.partial |= bool(array(checks.get("parsing_errors", [])))
        for row in array(checks["failed_checks"]):
            # Checkov's file_path is prefixed with slash relative to its scan root.
            path = row.get("repo_file_path") or row["file_path"].removeprefix("/")
            start, end = array(row["file_line_range"])
            resource = token(row["resource"])
            hit = source("checkov", "Burrow", row["check_id"], relative_path(path, root),
                         start, end, row.get("severity") or "unknown", identity=resource)
            hit.update(resource=resource, framework=token(block["check_type"]))
            result.findings.append(hit)
    return result


def shellcheck(doc, root):
    result = ImportResult()
    for row in array(doc):
        code = positive_integer(row["code"])
        if code not in {2086, 2046, 2068, 2294}:
            continue
        result.findings.append(source("shellcheck", "Claws", f"SC{code}",
                                      relative_path(row["file"], root), row["line"], row["endLine"],
                                      row["level"], columns=(row["column"], row["endColumn"])))
    return result


def psscriptanalyzer(doc, root):
    result = ImportResult()
    for row in array(doc):
        extent = row["Extent"]
        result.findings.append(source("psscriptanalyzer", "Claws", row["RuleName"],
                                      relative_path(row["ScriptPath"], root), extent["StartLineNumber"],
                                      extent["EndLineNumber"], row["Severity"],
                                      columns=(extent["StartColumnNumber"], extent["EndColumnNumber"])))
    return result


def dependency(producer, advisory, name, version, ecosystem, target, location, level, digest=None):
    advisory, name, version, ecosystem, level = map(token, (advisory, name, version, ecosystem, level))
    key = [producer, ecosystem, target, location, advisory, name, version]
    if digest:
        key.append(digest)
    result = {"producer": producer, "rule": advisory, "path": location, "line": None,
              "module": "Exoskeleton" if digest else "Shell", "fingerprint": fingerprint(key),
              "original_severity": level, "severity": level.lower() if level.lower() in LEVELS else "unknown",
              "package": {"ecosystem": ecosystem, "name": name, "version": version},
              "manifest": target, "message": "Review the installed dependency against this advisory."}
    if digest:
        result["image_digest"] = digest
    return result


def trivy(doc, root, *, image=False):
    expected = "container_image" if image else "filesystem"
    if doc["SchemaVersion"] != 2 or doc["ArtifactType"] != expected:
        raise ValueError("unsupported Trivy document")
    digest = None
    if image:
        # RepoDigests identify image manifests, unlike the local image configuration ID.
        digests = {s.rsplit("@", 1)[-1] for s in array(doc["Metadata"]["RepoDigests"])}
        if len(digests) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", next(iter(digests))):
            raise ValueError("missing or ambiguous manifest digest")
        digest = digests.pop()
    version = doc.get("Trivy", {}).get("Version")
    results = array(doc.get("Results", []))
    result = ImportResult(version=token(version) if version else None, targets=len(results))
    for group in results:
        if group["Class"] not in ({"os-pkgs", "lang-pkgs"} if image else {"lang-pkgs"}):
            raise ValueError("expected vulnerability-only report")
        target = relative_path(group["Target"], root) if not image or group["Class"] == "lang-pkgs" else None
        vulnerabilities = group.get("Vulnerabilities")
        for row in array([] if vulnerabilities is None else vulnerabilities):
            location = relative_path(row["PkgPath"], root) if row.get("PkgPath") else target
            hit = dependency("trivy", row["VulnerabilityID"], row["PkgName"], row["InstalledVersion"],
                             group["Type"], target, location, row["Severity"], digest)
            hit["package"]["purl"] = purl_for(row.get("PkgIdentifier", {}).get("PURL"), hit["package"])
            result.findings.append(hit)
    return result


def purl_for(value, package):
    if value is None:
        return package_url(package["ecosystem"], package["name"], package["version"])
    if not isinstance(value, str) or not re.fullmatch(r"pkg:[a-z0-9.+-]+/[^\s\x00-\x1f]{1,1024}", value):
        raise ValueError("invalid package URL")
    return value


def osv(doc, root):
    groups = array(doc["results"])
    result = ImportResult(targets=len(groups))
    for group in groups:
        if group["source"]["type"] != "lockfile":
            raise ValueError("expected OSV lockfile")
        path = relative_path(group["source"]["path"], root)
        for row in array(group["packages"]):
            pkg = row["package"]
            for advisory in array(row.get("vulnerabilities", [])):
                level = advisory.get("database_specific", {}).get("severity") or "unknown"
                hit = dependency("osv", advisory["id"], pkg["name"], pkg["version"], pkg["ecosystem"],
                                 path, path, level)
                hit["package"]["purl"] = purl_for(pkg.get("purl"), hit["package"])
                hit["aliases"] = sorted({token(a) for a in array(advisory.get("aliases", []))})
                result.findings.append(hit)
    return result


ADAPTERS = {"bandit": bandit, "opengrep": opengrep, "gitleaks": gitleaks, "checkov": checkov,
            "shellcheck": shellcheck, "psscriptanalyzer": psscriptanalyzer, "trivy": trivy,
            "trivy-image": lambda doc, root: trivy(doc, root, image=True), "osv": osv}
