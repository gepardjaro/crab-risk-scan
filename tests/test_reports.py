import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "examples/trivy-fs.json"


def cli(*args):
    return subprocess.run([sys.executable, "-m", "crab_risk_scan", *map(str, args)],
                          capture_output=True, text=True, cwd=ROOT)


class ReportTests(unittest.TestCase):
    def test_duplicate_import_and_priority(self):
        args = ("collect", "examples/demo", "--trivy", REPORT, "--trivy", REPORT)
        run = cli(*args)
        self.assertEqual(run.returncode, 1)
        self.assertEqual(run.stdout, cli(*args).stdout)
        data = json.loads(run.stdout)
        self.assertEqual(data["files_scanned"], 2)
        self.assertEqual(len(data["findings"]), 3)
        self.assertEqual(data["findings"][0]["rule"], "CRAB-DEMO-001")
        self.assertIsNone(data["findings"][0]["line"])
        self.assertEqual(len(data["imports"]), 2)

    def test_invalid_and_clean_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            report = json.loads(REPORT.read_text())
            report["Results"][0]["Target"] = "../SYNTHETIC_CANARY"
            path.write_text(json.dumps(report))
            result = cli("collect", "examples/demo", "--trivy", path)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(len(json.loads(result.stdout)["findings"]), 2)
            self.assertNotIn("SYNTHETIC_CANARY", result.stdout + result.stderr)
            report["Results"] = []
            path.write_text(json.dumps(report))
            result = cli("collect", tmp, "--trivy", path)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)["imports"][0]["targets"], 0)

    def test_unknown_severity_and_source_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            report = json.loads(REPORT.read_text())
            vuln = report["Results"][0]["Vulnerabilities"][0]
            vuln.update(Severity="UNRATED", Description="SYNTHETIC_CANARY")
            path.write_text(json.dumps(report))
            result = cli("collect", tmp, "--trivy", path)
            self.assertEqual(result.returncode, 1)
            hit = json.loads(result.stdout)["findings"][0]
            self.assertEqual((hit["original_severity"], hit["severity"]), ("UNRATED", "unknown"))
            self.assertNotIn("SYNTHETIC_CANARY", result.stdout + result.stderr)

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
