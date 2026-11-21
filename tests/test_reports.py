import gzip
import json
import os
from datetime import date
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import jsonschema

from crab_risk_scan.reporting import collect

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "examples/trivy-fs.json"
SCHEMA = json.loads((ROOT / "crab_risk_scan/schemas/report-v3.schema.json").read_text(encoding="utf-8"))


def cli(*args):
    return subprocess.run([sys.executable, "-m", "crab_risk_scan", *map(str, args)],
                          capture_output=True, text=True, cwd=ROOT)


def validate(report):
    jsonschema.Draft202012Validator(SCHEMA).validate(report)
    return report


def save(folder, name, doc):
    path = Path(folder) / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def trivy_row(**extra):
    return dict({"VulnerabilityID": "CVE-2099-0001", "PkgName": "widget", "InstalledVersion": "1.0.0",
                 "Severity": "CRITICAL", "Description": "SYNTHETIC_CANARY", "Title": "SYNTHETIC_CANARY"}, **extra)


def trivy_doc(rows, *, image=None):
    doc = {"SchemaVersion": 2, "ArtifactType": "container_image" if image else "filesystem",
           "Trivy": {"Version": "0.72.0"},
           "Results": [{"Class": "lang-pkgs", "Type": "npm", "Target": "package-lock.json",
                        "Vulnerabilities": rows}]}
    if image:
        doc["Metadata"] = {"RepoDigests": ["registry.example/app@sha256:" + image * 64]}
    return doc


def osv_doc(path, vulnerabilities, name="widget", version="1.0.0"):
    return {"results": [{"source": {"path": path, "type": "lockfile"}, "packages": [
        {"package": {"name": name, "version": version, "ecosystem": "npm"},
         "vulnerabilities": vulnerabilities}]}]}


def cyclonedx(components, dependencies=None, root_ref="app"):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6",
           "metadata": {"component": {"name": "app", "bom-ref": root_ref}}, "components": components}
    if dependencies is not None:
        doc["dependencies"] = dependencies
    return doc


class ReportTests(unittest.TestCase):
    def scan(self, expected, *args):
        run = cli("scan", *args[:1], "--engines", "none", *args[1:])
        self.assertEqual(run.returncode, expected, run.stderr + run.stdout[:2000])
        self.assertNotIn("SYNTHETIC_CANARY", run.stdout + run.stderr)
        return validate(json.loads(run.stdout))

    def test_duplicate_import_and_priority(self):
        args = ("examples/demo", "--trivy", REPORT, "--trivy", REPORT)
        data = self.scan(1, *args)
        self.assertEqual(json.dumps(data), json.dumps(self.scan(1, *args)))
        self.assertEqual(data["files_scanned"], 2)
        self.assertEqual(len(data["findings"]), 3)
        self.assertEqual(data["findings"][0]["rule"], "CRAB-DEMO-001")
        self.assertEqual(data["findings"][0]["inputs"], [1, 2])
        self.assertIsNone(data["findings"][0]["line"])
        self.assertEqual(len(data["imports"]), 2)
        self.assertEqual(data["target"], "demo")
        self.assertEqual(data["tool"]["name"], "crab-risk-scan")

    def test_invalid_and_clean_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            report = json.loads(REPORT.read_text())
            report["Results"][0]["Target"] = "../SYNTHETIC_CANARY"
            path.write_text(json.dumps(report))
            data = self.scan(2, "examples/demo", "--trivy", path)
            self.assertEqual(len(data["findings"]), 2)
            self.assertEqual((data["imports"][0]["status"], data["imports"][0]["reason"]),
                             ("failed", "invalid_report"))
            report["Results"] = []
            path.write_text(json.dumps(report))
            self.assertEqual(self.scan(0, tmp, "--trivy", path)["imports"][0]["targets"], 0)

    def test_unknown_severity_and_source_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            report = json.loads(REPORT.read_text())
            vuln = report["Results"][0]["Vulnerabilities"][0]
            vuln.update(Severity="UNRATED", Description="SYNTHETIC_CANARY")
            path.write_text(json.dumps(report))
            hit = self.scan(1, tmp, "--trivy", path)["findings"][0]
            self.assertEqual((hit["original_severity"], hit["severity"]), ("UNRATED", "unknown"))

    def test_trivy_cvss_cwe_and_fixed_version_are_retained(self):
        # Regression: docs/gap-analysis.md section 2, Trivy fields were dropped.
        with tempfile.TemporaryDirectory() as tmp:
            row = trivy_row(CweIDs=["CWE-79", "CWE-79", "NVD-CWE-noinfo"], FixedVersion="1.0.1, 1.1.0",
                            PrimaryURL="https://avd.aquasec.com/nvd/cve-2099-0001",
                            CVSS={"ghsa": {"V3Score": 8.1, "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                                  "nvd": {"V2Score": 7.5, "V3Score": 9.8,
                                          "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}})
            other = trivy_row(VulnerabilityID="CVE-2099-0002", CVSS={"redhat": {"V3Score": "bad"},
                                                                      "ghsa": {"V3Score": 5.3}},
                              PrimaryURL="javascript:alert(1)")
            path = save(tmp, "trivy.json", trivy_doc([row, other]))
            hits = {f["rule"]: f for f in self.scan(1, tmp, "--trivy", path)["findings"]}
            first, second = hits["CVE-2099-0001"], hits["CVE-2099-0002"]
            self.assertEqual(first["cwe"], ["CWE-79"])
            self.assertEqual(first["fixed_version"], "1.0.1")
            self.assertEqual(first["cvss"], {"score": 9.8, "source": "nvd",
                                             "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
            self.assertEqual(first["help_uri"], "https://avd.aquasec.com/nvd/cve-2099-0001")
            self.assertEqual(first["risk_type"], "vulnerability")
            self.assertEqual(second["cvss"], {"score": 5.3, "vector": None, "source": "ghsa"})
            self.assertNotIn("help_uri", second)
            self.assertNotIn("fixed_version", second)

    def test_malicious_osv_advisory_is_critical(self):
        # Regression: docs/gap-analysis.md section 2, MAL-* advisories had severity unknown.
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "package-lock.json").write_text("{}")
            advisories = [
                {"id": "MAL-2026-1234", "summary": "SYNTHETIC_CANARY", "details": "SYNTHETIC_CANARY"},
                {"id": "GHSA-demo-0001", "aliases": ["CVE-2099-0003"],
                 "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-1321"]},
                 "affected": [{"package": {"name": "other", "ecosystem": "npm"},
                               "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]},
                              {"package": {"name": "widget", "ecosystem": "npm"},
                               "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}]}]}]
            path = save(tmp, "osv.json", osv_doc("package-lock.json", advisories))
            data = self.scan(1, tmp, "--osv", path, "--fail-on", "critical")
            malicious, advisory = data["findings"]
            self.assertEqual((malicious["rule"], malicious["severity"], malicious["original_severity"],
                              malicious["risk_type"]), ("MAL-2026-1234", "critical", "unknown", "malicious"))
            self.assertEqual(malicious["message"], "Remove this package. It is listed as malicious.")
            self.assertEqual((advisory["severity"], advisory["risk_type"], advisory["cwe"],
                              advisory["fixed_version"]), ("medium", "vulnerability", ["CWE-1321"], "1.2.0"))
            self.assertIn({"gate": "malicious", "count": 1}, data["policy"]["violations"])

    def test_cyclonedx_licenses_and_direct_dependencies_are_retained(self):
        # Regression: docs/gap-analysis.md section 2, licenses and dependencies were ignored.
        with tempfile.TemporaryDirectory() as tmp:
            components = [
                {"name": "widget", "version": "1.0.0", "purl": "pkg:npm/widget@1.0.0", "bom-ref": "w",
                 "licenses": [{"license": {"id": "MIT"}}, {"license": {"name": "Custom License"}}]},
                {"name": "leaf", "version": "2.0.0", "purl": "pkg:npm/leaf@2.0.0?vcs_url=x#lib", "bom-ref": "l",
                 "licenses": [{"expression": "Apache-2.0 OR MIT"}]},
                {"name": "loose", "version": "0.1.0"}]
            graph = [{"ref": "app", "dependsOn": ["w"]}, {"ref": "w", "dependsOn": ["l"]}]
            bom = save(tmp, "bom.json", cyclonedx(components, graph))
            row = trivy_row(PkgName="leaf", InstalledVersion="2.0.0", PkgIdentifier={"PURL": "pkg:npm/leaf@2.0.0"})
            trivy = save(tmp, "trivy.json", trivy_doc([row]))
            data = self.scan(1, tmp, "--inventory", bom, "--trivy", trivy)
            inventory = data["inventory"]
            self.assertEqual(inventory["format"], "cyclonedx")
            self.assertEqual([(c["licenses"], c["direct"]) for c in inventory["components"]],
                             [(["MIT", "Custom License"], True), (["Apache-2.0 OR MIT"], False), ([], None)])
            # Qualifiers and subpaths are dropped from the join key, not from the output.
            self.assertEqual(inventory["components"][1]["purl"], "pkg:npm/leaf@2.0.0?vcs_url=x#lib")
            self.assertEqual(len(inventory["components"][1]["observations"]), 1)
            self.assertEqual(data["findings"][0]["inventory_components"], [1])
            bom = save(tmp, "bom.json", cyclonedx(components))
            self.assertEqual({c["direct"] for c in self.scan(1, tmp, "--inventory", bom,
                                                            "--trivy", trivy)["inventory"]["components"]}, {None})

    def test_combined_multi_producer_report_validates(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder, root = Path(tmp), Path(tmp) / "service"
            root.mkdir()
            (root / "app.py").write_text("import ssl\n\nctx = ssl._create_unverified_context()\n")
            (root / "web.ts").write_text("el.innerHTML = value;\n")
            (root / "config.env").write_text("TOKEN=SYNTHETIC_CANARY\n")
            (root / "main.tf").write_text('resource "aws_security_group" "demo" {\n}\n')
            (root / "run.sh").write_text("#!/bin/sh\necho $1\n")
            (root / "x.ps1").write_text("param($Password)\n")
            (root / "cmd.go").write_text("package main\n\nfunc main() { exec(arg) }\n")
            (root / "Dockerfile").write_text("FROM scratch\nUSER root\n")
            (root / "package-lock.json").write_text("{}")
            reports = {
                "bandit": {"errors": [], "results": [
                    {"test_id": "B323", "filename": "app.py", "line_number": 3, "line_range": [3],
                     "col_offset": 6, "end_col_offset": 38, "issue_severity": "MEDIUM", "issue_confidence": "HIGH",
                     "issue_text": "SYNTHETIC_CANARY", "code": "SYNTHETIC_CANARY",
                     "issue_cwe": {"id": 295, "link": "https://cwe.mitre.org/data/definitions/295.html"},
                     "more_info": "https://bandit.readthedocs.io/en/1.8.6/plugins/b323_unverified_context.html"}]},
                "opengrep": {"version": "2.0.0", "errors": [], "results": [
                    {"check_id": "crab-dom-html", "path": "web.ts", "start": {"line": 1, "col": 1},
                     "end": {"line": 1, "col": 22},
                     "extra": {"severity": "WARNING", "message": "SYNTHETIC_CANARY", "lines": "SYNTHETIC_CANARY",
                               "metadata": {"cwe": "CWE-79: Improper Neutralization",
                                            "references": ["not a url", "https://owasp.org/Top10/A03_2021-Injection/"]}}}]},
                "gitleaks": [{"RuleID": "aws-access-token", "File": "config.env", "StartLine": 1, "EndLine": 1,
                              "StartColumn": 7, "EndColumn": 23, "Secret": "SYNTHETIC_CANARY",
                              "Match": "SYNTHETIC_CANARY", "Commit": "SYNTHETIC_CANARY"}],
                "checkov": {"check_type": "terraform", "results": {"failed_checks": [
                    {"check_id": "CKV_AWS_24", "file_path": "/main.tf", "repo_file_path": "/main.tf",
                     "resource": "aws_security_group.demo", "file_line_range": [1, 2], "severity": None,
                     "guideline": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference",
                     "code_block": [[1, "SYNTHETIC_CANARY"]]}]}},
                "shellcheck": [{"code": 2086, "level": "info", "file": "run.sh", "line": 2, "endLine": 2,
                                "column": 6, "endColumn": 8, "message": "SYNTHETIC_CANARY"}],
                "psscriptanalyzer": [{"RuleName": "PSAvoidUsingPlainTextForPassword", "ScriptPath": "x.ps1",
                                      "Severity": "Warning", "Message": "SYNTHETIC_CANARY", "Extent": {
                                          "StartLineNumber": 1, "EndLineNumber": 1, "StartColumnNumber": 7,
                                          "EndColumnNumber": 16}}],
                "trivy": trivy_doc([trivy_row(CweIDs=["CWE-79"], FixedVersion="1.0.1",
                                              CVSS={"nvd": {"V3Score": 9.8}})]),
                "trivy-image": trivy_doc([trivy_row(VulnerabilityID="CVE-2099-0002", Severity="HIGH")], image="a"),
                "osv": osv_doc(str(root / "package-lock.json"), [
                    {"id": "GHSA-demo-0001", "aliases": ["CVE-2099-0001"]}, {"id": "MAL-2026-0001"}]),
                "sarif": {"version": "2.1.0", "runs": [{
                    "tool": {"driver": {"name": "gosec", "version": "2.22.0", "rules": [
                        {"id": "G204", "helpUri": "https://securego.io/docs/rules/g204.html",
                         "properties": {"tags": ["security", "CWE-78"], "security-severity": "8.8"}}]}},
                    "results": [{"ruleId": "G204", "level": "warning", "message": {"text": "SYNTHETIC_CANARY"},
                                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "cmd.go"},
                                                                     "region": {"startLine": 3, "startColumn": 15,
                                                                                "endColumn": 24}}}]}]}]},
            }
            inputs = [(name, save(folder, name + ".json", doc), {"origin": "report"}) for name, doc in reports.items()]
            inputs.append(("checkov", None, {"origin": "engine", "status": "skipped", "reason": "not_installed"}))
            bom = cyclonedx([{"name": "widget", "version": "1.0.0", "purl": "pkg:npm/widget@1.0.0", "bom-ref": "w",
                              "licenses": [{"license": {"id": "MIT"}}]},
                             {"name": "agpl-lib", "version": "2.0.0", "purl": "pkg:npm/agpl-lib@2.0.0",
                              "bom-ref": "a", "licenses": [{"expression": "AGPL-3.0-only"}]}],
                            [{"ref": "app", "dependsOn": ["w", "a"]}])
            policy = save(folder, "policy.json", {"version": 1, "fail_on": "high", "gates": {"epss": 0.5},
                                                  "licenses": {"deny": ["AGPL-3.0-only"]}})
            epss = folder / "epss.csv.gz"
            epss.write_bytes(gzip.compress(b"#model_version:v2025.03.14,score_date:2026-11-19T00:00:00Z\n"
                                           b"cve,epss,percentile\nCVE-2099-0001,0.97310,0.99930\n"))
            kev = save(folder, "kev.json", {"vulnerabilities": [{"cveID": "CVE-2099-0001"}]})
            from crab_risk_scan.pipeline import scan as builtin_scan
            local = builtin_scan(root)
            report = collect(local, root=root, inputs=inputs, revision="4f1c2e9", branch="main",
                             repository="https://ci:SYNTHETIC_CANARY@git.example/demo.git", inventory=bom,
                             policy=policy, epss=epss, kev=kev, today=date(2026, 11, 20))
            validate(report)
            base = save(folder, "base.json", report)
            exceptions = save(folder, "exceptions.json", {"version": 2, "exceptions": [
                {"fingerprint": f["fingerprint"], "status": "not_affected", "justification": "protected_at_runtime",
                 "reason": "Synthetic review", "reviewer": "platform-team"}
                for f in report["findings"] if f["rule"] == "CRAB-CTR-001"]})
            again = collect(local, root=root, inputs=inputs, revision="4f1c2e9", inventory=bom, policy=policy,
                            exceptions=exceptions, new_since=base, epss=epss, kev=kev, today=date(2026, 11, 20))
            validate(again)
            text = json.dumps(report) + json.dumps(again)
            self.assertNotIn("SYNTHETIC_CANARY", text)
            self.assertNotIn(folder.as_posix(), text)
            self.assertNotIn(json.dumps(str(folder))[1:-1], text)
            self.assertEqual(report["repository"], "https://git.example/demo.git")
            self.assertEqual(report["errors"], [])
            self.assertEqual(sorted({f["producer"] for f in report["findings"]}),
                             ["bandit", "checkov", "crab", "gitleaks", "gosec", "opengrep", "osv",
                              "psscriptanalyzer", "shellcheck", "trivy"])
            self.assertEqual(sorted({f["category"] for f in report["findings"]}),
                             ["container", "iac", "sast", "sca", "secrets"])
            by_rule = {f["rule"]: f for f in report["findings"]}
            self.assertEqual(by_rule["B323"]["cwe"], ["CWE-295"])
            self.assertEqual(by_rule["crab-dom-html"]["kind"], "review")
            self.assertEqual(by_rule["crab-dom-html"]["help_uri"], "https://owasp.org/Top10/A03_2021-Injection/")
            self.assertEqual(by_rule["G204"]["severity"], "high")
            self.assertEqual(by_rule["CKV_AWS_24"]["help_uri"],
                             "https://docs.prismacloud.io/en/enterprise-edition/policy-reference")
            self.assertEqual(by_rule["SC2086"]["help_uri"], "https://www.shellcheck.net/wiki/SC2086")
            self.assertTrue(by_rule["PSAvoidUsingPlainTextForPassword"]["help_uri"].endswith(
                "/rules/avoidusingplaintextforpassword"))
            self.assertEqual(by_rule["CVE-2099-0001"]["epss"],
                             {"score": 0.9731, "percentile": 0.9993, "date": "2026-11-19"})
            self.assertTrue(by_rule["CVE-2099-0001"]["kev"])
            self.assertEqual(by_rule["CRAB-LIC-001"]["license"], "AGPL-3.0-only")
            self.assertEqual({v["gate"] for v in report["policy"]["violations"]},
                             {"severity", "secrets", "malicious", "kev", "epss", "licenses"})
            self.assertEqual(again["comparison"]["new"], 0)
            self.assertEqual(again["comparison"]["fixed"], [])
            self.assertEqual(again["policy"]["suppressed"], 1)

    def test_sbom_failure_preserves_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "bom.json"
            output.write_text("previous")
            result = cli("sbom", tmp, "--syft", Path(tmp) / "missing", "--output", output)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(output.read_text(), "previous")
            self.assertEqual(result.stdout, "")

    @unittest.skipUnless(os.environ.get("CRAB_TEST_SYFT"), "set CRAB_TEST_SYFT to run with real Syft")
    def test_sbom_from_lockfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "bom.json"
            result = cli("sbom", "examples/inventory", "--syft", os.environ["CRAB_TEST_SYFT"],
                         "--output", output)
            self.assertEqual(result.returncode, 0, result.stderr)
            bom = json.loads(output.read_bytes())
            self.assertEqual(bom["bomFormat"], "CycloneDX")
            self.assertIn(("crab-demo-leaf", "1.0.0"),
                          [(pkg["name"], pkg.get("version")) for pkg in bom["components"]])
