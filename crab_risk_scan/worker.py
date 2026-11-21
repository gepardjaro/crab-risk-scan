"""Distributed scan worker: claims jobs from a CRAB server and runs the CLI in a subprocess.

Standard library only, so the stock scanner image can run workers without server dependencies.
"""
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__

LOG_LIMIT = 64 * 1024
ERROR_LIMIT = 2000
GIT_TIMEOUT = 600
GIT_REF = re.compile(r"[A-Za-z0-9._/][A-Za-z0-9._/-]{0,199}")
COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
ENGINES = re.compile(r"auto|all|none|[a-z][a-z-]{0,31}(,[a-z][a-z-]{0,31}){0,15}")
LEVELS = ("critical", "high", "medium", "low", "info", "unknown", "none")
NAME = re.compile(r"[^A-Za-z0-9._-]+")


class ServerError(Exception):
    def __init__(self, status, detail):
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status
        self.detail = detail


class JobError(Exception):
    def __init__(self, message, log=""):
        super().__init__(message)
        self.log = log


def http_url(value):
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return isinstance(value, str) and parts.scheme in ("http", "https") and bool(parts.hostname)


def tail(text, limit=LOG_LIMIT):
    return text[-limit:]


class Client:
    """Minimal JSON client for the worker endpoints of API v1."""

    def __init__(self, server, token, timeout=120):
        self.base = server.rstrip("/") + "/api/v1"
        self.token = token
        self.timeout = timeout

    def request(self, method, path, body=None):
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
            "Accept": "application/json", "User-Agent": f"crab-risk-scan-worker/{__version__}"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = response.read()
                return response.status, (json.loads(payload) if payload else None)
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = json.loads(exc.read(65536) or b"{}").get("detail", "")
            except (ValueError, AttributeError):
                pass
            raise ServerError(exc.code, str(detail)[:500]) from None


class Heartbeat(threading.Thread):
    """Extends the job lease until stopped; flags cancellation or a lost lease."""

    def __init__(self, client, job_id, worker, lease_seconds, stream):
        super().__init__(name=f"crab-heartbeat-{job_id}", daemon=True)
        self.client = client
        self.job_id = job_id
        self.worker = worker
        self.interval = max(1.0, lease_seconds / 3)
        self.stream = stream
        self.cancelled = threading.Event()
        self.lost = False
        self._stop = threading.Event()

    def run(self):
        while not self._stop.wait(self.interval):
            try:
                _, body = self.client.request("POST", f"/jobs/{self.job_id}/heartbeat", {"worker": self.worker})
            except ServerError as exc:
                if exc.status in (401, 403, 404, 409):
                    self.lost = True
                    self.cancelled.set()
                    return
                print(f"worker: heartbeat for job {self.job_id} failed: {exc}", file=self.stream)
                continue
            except OSError as exc:
                print(f"worker: heartbeat for job {self.job_id} failed: {type(exc).__name__}", file=self.stream)
                continue
            if body.get("cancelled"):
                self.cancelled.set()
                return
            self.interval = max(1.0, float(body.get("lease_seconds") or 30) / 3)

    def stop(self):
        self._stop.set()
        if self.is_alive():
            self.join(timeout=5)


class Worker:
    def __init__(self, client, name, *, allow_git=False, scan_roots=(), timeout=3600, stream=None):
        self.client = client
        self.name = name
        self.allow_git = allow_git
        self.scan_roots = tuple(scan_roots)
        self.timeout = timeout
        self.stream = stream or sys.stderr

    def say(self, message):
        print(f"worker {self.name}: {message}", file=self.stream, flush=True)

    def claim(self):
        status, body = self.client.request("POST", "/workers/claim",
                                           {"worker": self.name, "capabilities": {"git": self.allow_git}})
        return None if status == 204 else body

    # Sources ----------------------------------------------------------------------------------

    def resolve_path(self, path):
        if not self.scan_roots:
            raise JobError("path sources are disabled on this worker; pass --scan-root or set CRAB_SCAN_ROOTS")
        if not isinstance(path, str) or not os.path.isabs(path):
            raise JobError("source path must be absolute")
        real = Path(os.path.realpath(path))
        if not any(real == root or real.is_relative_to(root) for root in self.scan_roots):
            raise JobError("source path is outside this worker's scan roots")
        if not real.is_dir():
            raise JobError("source path is not a directory on this worker")
        return real

    def checkout(self, url, ref, directory, heartbeat):
        if not self.allow_git:
            raise JobError("git sources need a worker started with --allow-git")
        parts = urlsplit(url) if isinstance(url, str) else None
        if parts is None or not http_url(url) or parts.username or parts.password:
            raise JobError("git source URL must be http or https without credentials")
        if ref is not None and (not isinstance(ref, str) or not GIT_REF.fullmatch(ref) or ".." in ref):
            raise JobError("git ref is not a valid branch, tag or commit name")
        git = shutil.which("git")
        if git is None:
            raise JobError("git is not installed on this worker")
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="", GCM_INTERACTIVE="never")
        safe = ["-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never", "-c", "core.symlinks=false",
                "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull]
        steps = [[git, "init", "--quiet", str(directory)],
                 [git, "-C", str(directory), *safe, "fetch", "--depth", "1", "--no-tags", "--quiet", "--", url,
                  ref or "HEAD"],
                 [git, "-C", str(directory), *safe, "checkout", "--quiet", "--detach", "FETCH_HEAD"]]
        for step in steps:
            if heartbeat.cancelled.is_set():
                raise JobError("cancelled")
            try:
                result = subprocess.run(step, env=env, capture_output=True, text=True, errors="replace",
                                        timeout=GIT_TIMEOUT, stdin=subprocess.DEVNULL)
            except subprocess.TimeoutExpired:
                raise JobError("git checkout timed out") from None
            if result.returncode != 0:
                raise JobError(f"git {step[3] if step[1] == '-C' else step[1]} failed with status {result.returncode}",
                               tail(result.stderr))
        revision = subprocess.run([git, "-C", str(directory), "rev-parse", "HEAD"], capture_output=True, text=True,
                                  timeout=60, stdin=subprocess.DEVNULL).stdout.strip()
        return revision if COMMIT.fullmatch(revision) else None

    # Scan -------------------------------------------------------------------------------------

    def command(self, directory, output, options, revision=None, branch=None, repository=None):
        command = [sys.executable, "-m", "crab_risk_scan", "scan", str(directory),
                   "--output", str(output / "report.json")]
        if options.get("sbom"):
            command += ["--sbom", "--output", str(output / "sbom.cdx.json")]
        engines = options.get("engines")
        if engines:
            if not ENGINES.fullmatch(engines):
                raise JobError("invalid engines option")
            command += ["--engines", engines]
        if options.get("fail_on"):
            if options["fail_on"] not in LEVELS:
                raise JobError("invalid fail_on option")
            command += ["--fail-on", options["fail_on"]]
        if revision:
            command += ["--revision", revision]
        if branch:
            command += ["--branch", branch]
        if repository and http_url(repository) and not urlsplit(repository).password:
            command += ["--repository", repository]
        return command

    def run_scan(self, command, workdir, heartbeat):
        """Run the CLI with the private temp directory as cwd, so the target never lands on sys.path."""
        log_path = workdir / "scan.log"
        deadline = time.monotonic() + self.timeout
        with log_path.open("wb") as log:
            process = subprocess.Popen(command, cwd=workdir, stdout=log, stderr=subprocess.STDOUT,
                                       stdin=subprocess.DEVNULL)
            try:
                while True:
                    try:
                        code = process.wait(timeout=1)
                        break
                    except subprocess.TimeoutExpired:
                        if heartbeat.cancelled.is_set():
                            raise JobError("cancelled") from None
                        if time.monotonic() > deadline:
                            raise JobError(f"scan timed out after {self.timeout} seconds") from None
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        return code, tail(log_path.read_bytes().decode("utf-8", "replace"))

    def execute(self, job, workdir, heartbeat):
        source, options = job.get("source") or {}, job.get("options") or {}
        revision = branch = None
        repository = job.get("repository_url")
        if source.get("type") == "path":
            directory = self.resolve_path(source.get("path"))
        elif source.get("type") == "git":
            directory = workdir / "checkout"
            revision = self.checkout(source.get("url"), source.get("ref"), directory, heartbeat)
            ref = source.get("ref")
            branch = ref if ref and not COMMIT.fullmatch(ref) else None
            repository = source.get("url")
        else:
            raise JobError("unsupported source type")
        output = workdir / "out"
        output.mkdir()
        code, log = self.run_scan(self.command(directory, output, options, revision, branch, repository),
                                  workdir, heartbeat)
        report_path = output / "report.json"
        if code not in (0, 1, 2) or not report_path.is_file():
            raise JobError(f"scan exited with status {code} without a report", log)
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            sbom_path = output / "sbom.cdx.json"
            sbom = json.loads(sbom_path.read_text(encoding="utf-8")) if sbom_path.is_file() else None
        except (OSError, ValueError, RecursionError):
            raise JobError("scan produced an unreadable report", log) from None
        return report, sbom, log

    def send(self, path, body, attempts=3):
        for attempt in range(attempts):
            try:
                return self.client.request("POST", path, body)
            except ServerError as exc:
                if exc.status < 500 or attempt == attempts - 1:
                    raise
            except OSError:
                if attempt == attempts - 1:
                    raise
            time.sleep(2 ** attempt)

    def process(self, claim):
        """Run one claimed job. Returns "succeeded", "failed" or "cancelled"."""
        job = claim["job"]
        job_id = job["id"]
        self.say(f"claimed job {job_id} for project {job.get('project')}")
        heartbeat = Heartbeat(self.client, job_id, self.name, float(claim.get("lease_seconds") or 300), self.stream)
        heartbeat.start()
        result = error = None
        try:
            with tempfile.TemporaryDirectory(prefix="crab-job-") as tmp:
                try:
                    result = self.execute(job, Path(tmp), heartbeat)
                except JobError as exc:
                    error = exc
        finally:
            heartbeat.stop()
        if heartbeat.cancelled.is_set():
            self.say(f"job {job_id} {'lease was lost' if heartbeat.lost else 'was cancelled'}; stopped")
            return "cancelled"
        try:
            if result is not None:
                report, sbom, log = result
                body = {"report": report, "log": log, "worker": self.name}
                if sbom is not None:
                    body["sbom"] = sbom
                try:
                    _, response = self.send(f"/jobs/{job_id}/complete", body)
                except ServerError as exc:
                    if exc.status != 413:
                        raise
                    error = JobError("report exceeds the server upload limit", log)
                else:
                    self.say(f"job {job_id} completed as scan {response['scan_id']}")
                    return "succeeded"
            self.send(f"/jobs/{job_id}/fail", {"error": str(error)[:ERROR_LIMIT], "log": tail(error.log) or None,
                                               "worker": self.name})
            self.say(f"job {job_id} failed: {str(error)[:200]}")
        except (ServerError, OSError) as exc:
            self.say(f"could not report the result of job {job_id}: {exc}")
        return "failed"


def default_name():
    return (NAME.sub("-", socket.gethostname()).strip("-.") or "worker")[:64]


def add_arguments(parser):
    parser.add_argument("--server", required=True, metavar="URL", help="CRAB server base URL")
    parser.add_argument("--token", help="worker-scope API token (default: CRAB_WORKER_TOKEN)")
    parser.add_argument("--name", help="worker name shown in the queue (default: host name)")
    parser.add_argument("--once", action="store_true", help="process at most one job, then exit")
    parser.add_argument("--poll-interval", type=float, default=10.0, metavar="SECONDS",
                        help="wait between empty claims (default 10)")
    parser.add_argument("--allow-git", action="store_true", help="accept jobs that clone git repositories")
    parser.add_argument("--scan-root", action="append", default=[], type=Path, metavar="DIR",
                        help="directory that path sources must resolve inside (repeatable; default: CRAB_SCAN_ROOTS)")
    parser.add_argument("--timeout", type=int, default=3600, metavar="SECONDS",
                        help="maximum duration of one scan subprocess (default 3600)")


def scan_roots(values):
    if not values:
        values = [Path(part) for part in os.environ.get("CRAB_SCAN_ROOTS", "").split(os.pathsep) if part.strip()]
    roots = []
    for value in values:
        if not value.is_absolute():
            raise ValueError(f"scan roots must be absolute paths: {value}")
        roots.append(Path(os.path.realpath(value)))
    return roots


def run(args):
    token = args.token or os.environ.get("CRAB_WORKER_TOKEN")
    if not token:
        print("worker: pass --token or set CRAB_WORKER_TOKEN", file=sys.stderr)
        return 2
    if not http_url(args.server):
        print("worker: --server must be an http or https URL", file=sys.stderr)
        return 2
    name = args.name or default_name()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name):
        print("worker: --name must be 1-64 letters, digits, '.', '_' or '-'", file=sys.stderr)
        return 2
    try:
        roots = scan_roots(args.scan_root)
    except ValueError as exc:
        print(f"worker: {exc}", file=sys.stderr)
        return 2
    worker = Worker(Client(args.server, token), name, allow_git=args.allow_git, scan_roots=roots,
                    timeout=max(1, args.timeout))
    stopping = threading.Event()
    if threading.current_thread() is threading.main_thread():
        def stop(signum, _frame):
            worker.say("stopping after the current job")
            stopping.set()
        signal.signal(signal.SIGTERM, stop)
    worker.say(f"polling {args.server} (git {'enabled' if args.allow_git else 'disabled'})")
    backoff = args.poll_interval
    while not stopping.is_set():
        try:
            claim = worker.claim()
        except (ServerError, OSError) as exc:
            worker.say(f"claim failed: {exc}")
            if args.once or isinstance(exc, ServerError) and exc.status in (401, 403):
                return 1
            stopping.wait(min(backoff, 300))
            backoff = min(backoff * 2, 300)
            continue
        backoff = args.poll_interval
        if claim is None:
            if args.once:
                return 0
            stopping.wait(args.poll_interval)
            continue
        outcome = worker.process(claim)
        if args.once:
            return 0 if outcome == "succeeded" else 1
    return 0
