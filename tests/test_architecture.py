import json
import os
import tempfile
import unittest
from pathlib import Path

from test_reports import cli


class ArchitectureTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.folder = Path(scratch.name)
        self.root = self.folder / "repo"
        self.root.mkdir()

    def save(self, name, doc):
        path = self.folder / name
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def collect(self, expected, *args):
        run = cli("collect", self.root, *args)
        self.assertEqual(run.returncode, expected, run.stderr + run.stdout[:2000])
        self.assertNotIn("SYNTHETIC_CANARY", run.stdout + run.stderr)
        return json.loads(run.stdout)

    def test_scanner_contracts_clean_malformed_partial_and_redaction(self):
        cases = {
            "bandit": ({"results": [], "errors": []}, {"test_id": "B323", "filename": "x.py",
                "line_number": 3, "issue_severity": "MEDIUM", "issue_confidence": "HIGH"}),
            "opengrep": ({"version": "2.0.0", "errors": [], "results": []},
                {"path": "x.ts", "check_id": "test", "extra": {"severity": "WARNING"},
                 "start": {"line": 2, "col": 1}, "end": {"line": 2, "col": 8}}),
            "gitleaks": ([], {"RuleID": "test", "File": "x.env", "StartLine": 1, "EndLine": 1,
                               "Secret": "SYNTHETIC_CANARY", "Match": "SYNTHETIC_CANARY"}),
            "checkov": ({"check_type": "terraform", "results": {"failed_checks": []}},
                {"check_id": "CKV_DEMO_1", "file_path": "/main.tf", "resource": "aws.example",
                 "file_line_range": [1, 3], "code_block": [[1, "SYNTHETIC_CANARY"]]}),
            "shellcheck": ([], {"code": 2086, "level": "info", "file": "run.sh", "line": 2,
                                "endLine": 2, "column": 1, "endColumn": 3}),
            "psscriptanalyzer": ([], {"RuleName": "PSAvoidUsingPlainTextForPassword",
                "ScriptPath": "x.ps1", "Severity": "Warning", "Extent": {
                    "StartLineNumber": 2, "EndLineNumber": 2, "StartColumnNumber": 1, "EndColumnNumber": 3}})
        }
        for engine, (doc, row) in cases.items():
            with self.subTest(engine=engine):
                path = self.save("report.json", doc)
                self.collect(0, "--" + engine, path)
                rows = doc if isinstance(doc, list) else doc["results"]
                if engine == "checkov":
                    rows = rows["failed_checks"]
                rows.append(row)
                self.save("report.json", doc)
                hit, = self.collect(1, "--" + engine, path)["findings"]
                self.assertEqual(hit["producer"], engine)
                rows.append({})
                self.save("report.json", doc)
                self.assertEqual(self.collect(2, "--" + engine, path)["findings"], [])

    def test_source_grouping_and_producer_partial(self):
        call = "ssl._create_unverified_context()"
        (self.root / "x.py").write_text(f"({call}, {call})")
        start = 1
        row = {"test_id": "B323", "filename": "x.py", "line_number": 1, "line_range": [1],
               "col_offset": start, "end_col_offset": start + len(call),
               "issue_severity": "MEDIUM", "issue_confidence": "HIGH", "code": "SYNTHETIC_CANARY"}
        path = self.save("bandit.json", {"results": [row], "errors": [{"reason": "SYNTHETIC_CANARY"}]})
        doc = self.collect(2, "--bandit", path)
        self.assertEqual(sorted(len(g["observations"]) for g in doc["groups"]), [1, 2])
        self.assertEqual(doc["imports"][0]["status"], "partial")

    def test_correlation_inventory_image_scope_and_baseline(self):
        trivy = {"SchemaVersion": 2, "ArtifactType": "filesystem", "Results": [
            {"Class": "lang-pkgs", "Type": "npm", "Target": "package-lock.json", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2099-1000", "PkgName": "widget", "InstalledVersion": "1", "Severity": "HIGH"}]}]}
        fs = self.save("trivy.json", trivy)
        osv = {"results": [{"source": {"path": str(self.root / "package-lock.json"), "type": "lockfile"},
               "packages": [{"package": {"name": "widget", "version": "1", "ecosystem": "npm"},
                             "vulnerabilities": [{"id": "GHSA-demo", "aliases": ["CVE-2099-1000"]}]}]}]}
        other = self.save("osv.json", osv)
        images = []
        for char in "ab":
            trivy.update(ArtifactType="container_image", Metadata={"RepoDigests": ["registry/img@sha256:" + char*64]})
            images += ["--trivy-image", self.save(char+".json", trivy)]
        bom = self.save("inventory.json", {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"name": name, "version": "1", "purl": "pkg:npm/" + name + "@1"} for name in ("widget", "clean")]})
        # Supply this source SBOM only to the corresponding source reports.
        args = ["--trivy", fs, "--osv", other, "--inventory", bom]
        doc = self.collect(1, *args)
        self.assertEqual(len(doc["groups"]), 1)
        self.assertEqual([len(c["observations"]) for c in doc["inventory"]["components"]], [2, 0])
        doc = self.collect(1, *args, *images)
        self.assertEqual(sorted(len(g["observations"]) for g in doc["groups"]), [1, 1, 2])
        keys = [f["fingerprint"] for f in doc["findings"]]
        baseline = self.save("baseline.json", {"version": 1, "suppressions": [
            {"fingerprint": k, "reviewer": "maintainer", "reason": "reviewed fixture"} for k in keys]})
        self.collect(0, *args, *images, "--baseline", baseline)
        self.collect(0, *args, "--fail-on", "critical")
        data = self.collect(2, *args, *images, "--baseline", baseline, "--bandit", self.folder/"missing",
                            "--format", "sarif")
        run, = data["runs"]
        self.assertFalse(run["invocations"][0]["executionSuccessful"])
        self.assertEqual(sum("locations" in x for x in run["results"]), 2)
        self.assertTrue(all(x["suppressions"] for x in run["results"]))
        osv["results"][0]["source"]["path"] = "elsewhere/package-lock.json"
        self.save("osv.json", osv)
        self.assertEqual(len(self.collect(1, *args)["groups"]), 2)

    def test_manifest_provenance_and_failed_producer(self):
        self.save("leaks.json", [])
        entry = {"producer": "gitleaks", "version": "8.24.3", "rule_pack": "team-v1",
                 "status": "complete", "file": "leaks.json"}
        manifest = self.save("run.json", {"version": 1, "revision": "abc", "reports": [
            entry, dict(entry, status="failed", file="missing.json")]})
        doc = self.collect(2, "--run-manifest", manifest)
        self.assertEqual(doc["revision"], "abc")
        self.assertEqual(doc["imports"][0]["rule_pack"], "team-v1")
        self.assertEqual(doc["errors"][0]["reason"], "producer_failed")

    def test_html_forms(self):
        (self.root / "form.html").write_text('<!-- <form action="http://test"> -->\n<form action="/save">')
        self.collect(0)
        (self.root / "form.html").write_text('<FORM action="http://example.invalid/save">')
        hit, = self.collect(1)["findings"]
        self.assertEqual(hit["rule"], "CRAB-HTML-001")

    @unittest.skipUnless(os.getenv("CRAB_MOJO_GRAMMAR"), "requires optional Pinch parsers")
    def test_parser_gates(self):
        flags = ["--mojo-grammar", os.environ["CRAB_MOJO_GRAMMAR"]]
        sql = self.root / "table.sql"
        sql.write_text("GRANT SELECT ON TABLE sample TO reader;")
        mojo = self.root / "demo.mojo"
        mojo.write_text('fn main():\n    # external_call["demo", Int]()\n    pass\n')
        self.collect(0, *flags)
        sql.write_text("GRANT SELECT ON TABLE sample TO PUBLIC;")
        mojo.write_text('fn main():\n    external_call["demo", Int]()\n')
        doc = self.collect(1, *flags)
        self.assertEqual({f["rule"] for f in doc["findings"]}, {"CRAB-SQL-001", "CRAB-MOJO-001"})
        sql.write_text("GRANT SELECT ON TABLE")
        mojo.write_text("fn main(:\n")
        self.assertEqual(len(self.collect(2, *flags)["errors"]), 2)
