import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ScanTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def run_scan(self, status):
        result = subprocess.run([sys.executable, "-m", "crab_risk_scan", "scan", str(self.root)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, status, result.stderr + result.stdout)
        return json.loads(result.stdout)

    def test_demo(self):
        self.root = Path(__file__).resolve().parents[1] / "examples/demo"
        report = self.run_scan(1)
        self.assertEqual(report["files_scanned"], 2)
        self.assertEqual([(f["path"], f["line"], f["rule"]) for f in report["findings"]],
                         [("Dockerfile", 2, "CRAB-CTR-001"), ("client.py", 4, "CRAB-PY-001")])
        self.assertEqual(report, self.run_scan(1))

    def test_clean(self):
        (self.root / "safe.py").write_text('# ssl._create_unverified_context()\nssl.create_default_context()')
        (self.root / "Dockerfile").write_text("FROM builder\nUSER root\nFROM final\nUSER app")
        report = self.run_scan(0)
        self.assertEqual(report["files_scanned"], 2)
        self.assertEqual(report["findings"], [])

    def test_incomplete_takes_priority(self):
        (self.root / "bad.py").write_bytes(b"\xff")
        (self.root / "Dockerfile").write_text("FROM base\nUSER root:root")
        report = self.run_scan(2)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["errors"], [{"path": "bad.py", "reason": "UnicodeDecodeError"}])

    def test_missing(self):
        self.root /= "absent"
        self.assertEqual(self.run_scan(2)["errors"][0]["reason"], "expected_directory")

    def test_exclusions(self):
        (self.root / ".git").mkdir()
        (self.root / ".git/hidden.py").write_text("invalid syntax")
        self.assertEqual(self.run_scan(0)["files_scanned"], 0)

    def test_symlink(self):
        (self.root / "ignored.txt").write_text("invalid syntax")
        try:
            (self.root / "copy.py").symlink_to(self.root / "ignored.txt")
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows symlink creation privilege unavailable")
            raise
        self.assertEqual(self.run_scan(0)["files_scanned"], 0)

    def test_limits(self):
        (self.root / "large.py").write_bytes(b" " * (1024 * 1024 + 1))
        (self.root / "broken.py").write_text("if (")
        report = self.run_scan(2)
        self.assertEqual([e["reason"] for e in report["errors"]], ["SyntaxError", "size_limit"])
