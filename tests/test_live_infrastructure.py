import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_reports import ROOT, cli


@unittest.skipUnless(os.getenv("CRAB_CHECKOV"), "requires external infrastructure engines")
class InfrastructureTests(unittest.TestCase):
    def test_terraform_powershell_and_redacted_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Path(tmp)
            target = host / "src"
            target.mkdir()
            tf = '''resource "aws_security_group" "demo" {
  ingress {
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = ["NETWORK"]
  }
}
'''
            (target / "exposed.tf").write_text(tf.replace("NETWORK", "0.0.0.0/0"))
            (target / "restricted.tf").write_text(tf.replace('"demo"', '"internal"').replace("NETWORK", "10.0.0.0/24"))
            (target / "plain.ps1").write_text("param([string] $Password)\n")
            (target / "secure.ps1").write_text("param([SecureString] $Password)\n")
            (target / "demo.env").write_text("test_key=CRAB_SYNTHETIC_CANARY_0001\n")
            config = host / "leaks.toml"
            config.write_text('[[rules]]\nid="crab-test"\ndescription="fixture"\nregex="CRAB_SYNTHETIC_CANARY_[0-9]{4}"\n')
            check = subprocess.run([os.environ["CRAB_CHECKOV"], "-d", ".", "--framework", "terraform",
                                    "--check", "CKV_AWS_24", "--output", "json", "--soft-fail"],
                                   cwd=target, capture_output=True, check=True)
            (host / "iac.json").write_bytes(check.stdout)
            ps = host / "ps.json"
            subprocess.run(["pwsh", "-NoProfile", "-File", str(ROOT/"examples/export-psscriptanalyzer.ps1"),
                            str(target), str(ps)], cwd=host, check=True)
            leaks = host / "leaks.json"
            subprocess.run([os.environ["CRAB_GITLEAKS"], "dir", ".", "--config", str(config),
                            "--redact", "--exit-code", "0", "--report-format", "json",
                            "--report-path", str(leaks)], cwd=target, check=True)
            run = cli("collect", target, "--checkov", host/"iac.json", "--psscriptanalyzer", ps,
                      "--gitleaks", leaks)
            self.assertEqual(run.returncode, 1, run.stdout)
            self.assertNotIn("SYNTHETIC_CANARY", run.stdout + run.stderr)
            hits = json.loads(run.stdout)["findings"]
            self.assertEqual({(f["producer"], f["path"]) for f in hits},
                             {("checkov", "exposed.tf"), ("psscriptanalyzer", "plain.ps1"),
                              ("gitleaks", "demo.env")})
