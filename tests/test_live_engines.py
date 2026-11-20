"""Run pinned upstream producers in CI and round-trip their native reports."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_reports import cli


@unittest.skipUnless(os.getenv("CRAB_OPENGREP"), "requires the external engine job")
class LiveEngineTests(unittest.TestCase):
    def test_opengrep_language_pack(self):
        files = {
            "browser.js": ("node.innerHTML = html;", "node.textContent = html;"),
            "server.js": ("child_process.exec(command);", "child_process.execFile(file, args);"),
            "wrapper.ts": ("function render(x: string) { node.innerHTML = x; }",
                           "function render(x: string) { node.textContent = x; }"),
            "widget.tsx": ("const el = <div dangerouslySetInnerHTML={{__html: html}} />;",
                           "const el = <div>{html}</div>;"),
            "lib.rs": ("unsafe fn cast(x: u32) -> f32 { std::mem::transmute(x) }",
                       "fn cast(x: u32) -> f32 { f32::from_bits(x) }"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "src"
            target.mkdir()
            for name, (positive, clean) in files.items():
                (target / name).write_text(positive)
                (target / ("safe_" + name)).write_text(clean)
            report = Path(tmp) / "engine.json"
            subprocess.run([os.environ["CRAB_OPENGREP"], "scan", "--config", cli("rules").stdout.strip(),
                            "--json", "--output", str(report), "--no-git-ignore", "."],
                           cwd=target, check=True)
            result = cli("collect", target, "--opengrep", report)
            self.assertEqual(result.returncode, 1, result.stdout)
            hits = json.loads(result.stdout)["findings"]
            self.assertEqual({hit["path"] for hit in hits}, set(files))
            self.assertEqual(len(hits), len(files))

    def test_bandit_and_shellcheck(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "client.py").write_text("import ssl\nssl._create_unverified_context()\n")
            (root / "script.sh").write_text('#!/bin/bash\necho $HOME\necho "$HOME"\n')
            raw = root / "bandit.json"
            subprocess.run([sys.executable, "-m", "bandit", "-q", "--exit-zero", "-f", "json",
                            "-o", str(raw), "client.py"], cwd=root, check=True)
            check = subprocess.run(["shellcheck", "--format=json", "script.sh"], cwd=root,
                                   capture_output=True)
            self.assertEqual(check.returncode, 1)
            shell = root / "shell.json"
            shell.write_bytes(check.stdout)
            run = cli("collect", root, "--bandit", raw, "--shellcheck", shell)
            self.assertEqual(run.returncode, 1, run.stdout)
            report = json.loads(run.stdout)
            self.assertEqual({f["producer"] for f in report["findings"]}, {"crab", "shellcheck", "bandit"})
            self.assertIn(2, [len(g["observations"]) for g in report["groups"]])
