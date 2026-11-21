import argparse
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from crab_risk_scan import worker as worker_module
from crab_risk_scan.worker import Client, Heartbeat, JobError, Worker

ROOT = Path(__file__).resolve().parents[1]
ADMIN_PASSWORD = "admin-password-1"

try:
    import uvicorn

    from crab_risk_scan.server.app import create_app
    from crab_risk_scan.server.config import Settings
    SERVER = True
except ImportError:  # the server extra is optional
    SERVER = False


class WorkerUnitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(os.path.realpath(self.temp.name)) / "repos"
        (self.root / "demo").mkdir(parents=True)
        self.worker = Worker(Client("http://127.0.0.1:9", "crab_x"), "unit", scan_roots=[self.root],
                             stream=io.StringIO())

    def tearDown(self):
        self.temp.cleanup()

    def test_path_sources_are_confined(self):
        self.assertEqual(self.worker.resolve_path(str(self.root / "demo")), self.root / "demo")
        for path in (str(self.root / "demo" / ".." / ".."), "relative", str(self.root / "missing")):
            with self.subTest(path=path), self.assertRaises(JobError):
                self.worker.resolve_path(path)
        closed = Worker(Client("http://127.0.0.1:9", "crab_x"), "unit", stream=io.StringIO())
        with self.assertRaisesRegex(JobError, "disabled"):
            closed.resolve_path(str(self.root / "demo"))

    def test_git_requires_opt_in_and_safe_inputs(self):
        beat = Heartbeat(None, 1, "unit", 30, io.StringIO())
        with self.assertRaisesRegex(JobError, "--allow-git"):
            self.worker.checkout("https://example.com/r.git", None, self.root / "c", beat)
        git = Worker(Client("http://127.0.0.1:9", "crab_x"), "unit", allow_git=True, stream=io.StringIO())
        for url, ref in (("file:///etc", None), ("https://u:p@example.com/r.git", None),
                         ("https://example.com/r.git", "--upload-pack=x"), ("https://example.com/r.git", "a/../b")):
            with self.subTest(url=url, ref=ref), self.assertRaises(JobError):
                git.checkout(url, ref, self.root / "c", beat)

    def test_scan_command(self):
        output = Path(self.temp.name) / "out"
        command = self.worker.command(self.root / "demo", output, {"engines": "none", "sbom": True, "fail_on": "high"},
                                      revision="a" * 40, branch="main", repository="https://example.com/r")
        self.assertEqual(command[:5], [sys.executable, "-m", "crab_risk_scan", "scan", str(self.root / "demo")])
        self.assertEqual(command[5:], ["--output", str(output / "report.json"), "--sbom", "--output",
                                       str(output / "sbom.cdx.json"), "--engines", "none", "--fail-on", "high",
                                       "--revision", "a" * 40, "--branch", "main", "--repository",
                                       "https://example.com/r"])
        with self.assertRaises(JobError):
            self.worker.command(self.root, output, {"engines": "auto --policy x"})
        with self.assertRaises(JobError):
            self.worker.command(self.root, output, {"fail_on": "severe"})

    def test_cli_requires_token_and_http_server(self):
        args = argparse.Namespace(server="http://127.0.0.1:9", token=None, name=None, once=True, poll_interval=1,
                                  allow_git=False, scan_root=[], timeout=10)
        env = dict(os.environ)
        env.pop("CRAB_WORKER_TOKEN", None)
        result = subprocess.run([sys.executable, "-m", "crab_risk_scan", "worker", "--server", "http://127.0.0.1:9",
                                 "--once"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2)
        self.assertIn("CRAB_WORKER_TOKEN", result.stderr)
        args.token, args.server = "crab_x", "ftp://example.com"
        self.assertEqual(worker_module.run(args), 2)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@unittest.skipUnless(SERVER, "server extra not installed")
class WorkerEndToEndTests(unittest.TestCase):
    """A live uvicorn server and the real worker command running `scan --engines none`."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        base = Path(cls.temp.name)
        cls.roots = Path(os.path.realpath(base)) / "repos"
        repo = cls.roots / "service"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "app.py").write_text("import subprocess\n\nsubprocess.call('ls', shell=True)\n",
                                             encoding="utf-8")
        (repo / "README.md").write_text("# Synthetic service\n", encoding="utf-8")
        cls.repo = repo
        cls.settings = Settings(database_url=f"sqlite:///{(base / 'crab.db').as_posix()}", data_dir=base,
                                scan_roots=(cls.roots,), admin_password=ADMIN_PASSWORD, scheduler=False,
                                lease_seconds=3, static_dir=base / "static")
        cls.app = create_app(cls.settings)
        cls.port = free_port()
        cls.server = uvicorn.Server(uvicorn.Config(cls.app, host="127.0.0.1", port=cls.port, log_level="warning",
                                                   lifespan="on"))
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        deadline = time.monotonic() + 30
        while not cls.server.started:
            if time.monotonic() > deadline or not cls.thread.is_alive():
                raise RuntimeError("uvicorn did not start")
            time.sleep(0.05)
        cls.url = f"http://127.0.0.1:{cls.port}"
        cls.admin = Client(cls.url, cls.login())
        cls.admin.request("POST", "/projects", {"key": "service", "name": "Service",
                                                "repository_url": "https://example.com/service"})
        cls.token = cls.admin.request("POST", "/tokens", {"name": "worker", "scopes": ["worker"]})[1]["token"]

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(30)
        cls.app.state.engine.dispose()
        cls.temp.cleanup()

    @classmethod
    def login(cls):
        import urllib.request
        request = urllib.request.Request(cls.url + "/api/v1/auth/login", method="POST",
                                         data=json.dumps({"username": "admin", "password": ADMIN_PASSWORD}).encode(),
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())["token"]

    def enqueue(self, path, options=None):
        return self.admin.request("POST", "/projects/service/jobs",
                                  {"source": {"type": "path", "path": str(path)},
                                   "options": options or {"engines": "none"}})[1]

    def run_worker(self, *extra):
        return subprocess.run([sys.executable, "-m", "crab_risk_scan", "worker", "--server", self.url,
                               "--token", self.token, "--name", "e2e", "--once", "--poll-interval", "1", *extra],
                              cwd=ROOT, capture_output=True, text=True, timeout=600)

    def test_worker_runs_a_scan_and_uploads_the_report(self):
        job = self.enqueue(self.repo)
        result = self.run_worker("--scan-root", str(self.roots))
        self.assertEqual(result.returncode, 0, result.stderr)
        detail = self.admin.request("GET", f"/jobs/{job['id']}")[1]
        self.assertEqual(detail["status"], "succeeded", detail)
        self.assertEqual(detail["worker"], "e2e")
        scan = self.admin.request("GET", f"/scans/{detail['scan_id']}")[1]
        self.assertEqual(scan["source"], "job")
        self.assertEqual(scan["target"], "service")
        self.assertEqual(scan["repository"], "https://example.com/service")
        self.assertNotIn(str(self.roots), json.dumps(scan))
        self.assertIn(scan["status"], ("passed", "failed"))
        report = self.admin.request("GET", f"/scans/{detail['scan_id']}/report?format=json")
        self.assertEqual(report[1]["schema_version"], 3)
        workers = self.admin.request("GET", "/workers")[1]["items"]
        self.assertIn(("e2e", None), [(w["name"], w["current_job"]) for w in workers])

    def test_worker_rejects_paths_outside_its_scan_roots(self):
        other = self.roots / "narrow"
        other.mkdir(exist_ok=True)
        job = self.enqueue(self.repo)
        result = self.run_worker("--scan-root", str(other))
        self.assertEqual(result.returncode, 1)
        detail = self.admin.request("GET", f"/jobs/{job['id']}")[1]
        self.assertEqual(detail["status"], "failed")
        self.assertIn("outside this worker's scan roots", detail["error"])

    def test_empty_queue_exits_cleanly(self):
        result = self.run_worker("--scan-root", str(self.roots))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_heartbeat_observes_cancellation(self):
        job = self.enqueue(self.repo)
        client = Client(self.url, self.token)
        status, claim = client.request("POST", "/workers/claim", {"worker": "hb", "capabilities": {"git": False}})
        self.assertEqual((status, claim["job"]["id"]), (200, job["id"]))
        beat = Heartbeat(client, job["id"], "hb", claim["lease_seconds"], io.StringIO())
        beat.start()
        try:
            time.sleep(1.5)
            self.assertEqual(self.admin.request("GET", f"/jobs/{job['id']}")[1]["status"], "running")
            self.admin.request("POST", f"/jobs/{job['id']}/cancel")
            self.assertTrue(beat.cancelled.wait(10))
            self.assertFalse(beat.lost)
        finally:
            beat.stop()


if __name__ == "__main__":
    unittest.main()
