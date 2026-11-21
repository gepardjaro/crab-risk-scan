import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "report-v3.json"
CANARY = "SYNTHETIC_CANARY_7f3a"
ADMIN_PASSWORD = "admin-password-1"
PASSWORD = "member-password-1"

try:
    from fastapi.testclient import TestClient
    from sqlalchemy import update

    from crab_risk_scan.server.app import bootstrap_admin, create_app
    from crab_risk_scan.server.config import UPLOAD_LIMIT, Settings
    from crab_risk_scan.server.db import Job, SessionToken, utcnow
except ImportError as exc:  # the server extra is optional
    raise unittest.SkipTest(f"server extra not installed: {exc.name}")


def fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def fingerprint(rule):
    return next(f["fingerprint"] for f in fixture()["findings"] if f["rule"] == rule)


class ServerCase(unittest.TestCase):
    """A fresh SQLite-backed app per test with a signed-in administrator."""

    settings_overrides = {}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.base = Path(self.temp.name)
        self.repos = self.base / "repos"
        (self.repos / "demo").mkdir(parents=True)
        values = dict(database_url=f"sqlite:///{(self.base / 'crab.db').as_posix()}", data_dir=self.base,
                      scan_roots=(Path(os.path.realpath(self.repos)),), admin_password=ADMIN_PASSWORD,
                      scheduler=False, static_dir=self.base / "static", lease_seconds=30)
        values.update(self.settings_overrides)
        self.settings = Settings(**values)
        self.app = create_app(self.settings)
        self.client = TestClient(self.app)
        self.admin = self.login("admin", ADMIN_PASSWORD)

    def tearDown(self):
        self.client.close()
        self.app.state.engine.dispose()
        self.temp.cleanup()

    def login(self, username, password):
        response = self.client.post("/api/v1/auth/login", json={"username": username, "password": password})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["token"]

    def call(self, method, path, token=None, **kwargs):
        token = self.admin if token is None else token
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.client.request(method, "/api/v1" + path, headers=headers, **kwargs)

    def ok(self, method, path, token=None, status=200, **kwargs):
        response = self.call(method, path, token, **kwargs)
        self.assertEqual(response.status_code, status, response.text)
        return response.json() if response.content and "json" in response.headers.get("content-type", "") else response

    def user(self, username, role="member"):
        created = self.ok("POST", "/users", json={"username": username, "password": PASSWORD, "role": role},
                          status=201)
        return created["id"], self.login(username, PASSWORD)

    def project(self, key="demo", name="Demo"):
        return self.ok("POST", "/projects", json={"key": key, "name": name,
                                                  "repository_url": "https://example.com/demo"}, status=201)

    def member(self, key, user_id, role):
        return self.ok("PUT", f"/projects/{key}/members/{user_id}", json={"role": role})

    def upload(self, key="demo", report=None, token=None, status=201, **extra):
        body = {"report": fixture() if report is None else report, **extra}
        return self.ok("POST", f"/projects/{key}/scans", token, status=status, json=body)

    def token(self, scopes, project=None, token=None):
        body = {"name": "test", "scopes": scopes}
        if project:
            body["project"] = project
        return self.ok("POST", "/tokens", token, status=201, json=body)["token"]


class HealthAndAuthTests(ServerCase):
    def test_health_needs_no_credentials(self):
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")

    def test_missing_and_invalid_credentials(self):
        response = self.client.get("/api/v1/auth/me")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["www-authenticate"], "Bearer")
        self.assertEqual(self.call("GET", "/auth/me", "not-a-session").status_code, 401)
        bad = self.client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong-password"})
        self.assertEqual(bad.status_code, 401)

    def test_login_me_logout(self):
        user_id, token = self.user("alice")
        self.project()
        self.member("demo", user_id, "viewer")
        me = self.ok("GET", "/auth/me", token)
        self.assertEqual(me["username"], "alice")
        self.assertEqual(me["role"], "member")
        self.assertEqual(me["memberships"], [{"project": "demo", "role": "viewer"}])
        self.assertEqual(self.call("POST", "/auth/logout", token).status_code, 204)
        self.assertEqual(self.call("GET", "/auth/me", token).status_code, 401)

    def test_expired_session_is_rejected(self):
        _, token = self.user("bob")
        with self.app.state.sessions() as db:
            db.execute(update(SessionToken).values(expires_at=utcnow() - timedelta(minutes=1)))
            db.commit()
        self.assertEqual(self.call("GET", "/auth/me", token).status_code, 401)

    def test_login_throttling_after_repeated_failures(self):
        self.user("carol")
        for _ in range(self.settings.login_max_failures):
            response = self.client.post("/api/v1/auth/login", json={"username": "carol", "password": "nope-nope-1"})
            self.assertEqual(response.status_code, 401)
        locked = self.client.post("/api/v1/auth/login", json={"username": "carol", "password": PASSWORD})
        self.assertEqual(locked.status_code, 429)
        self.assertGreater(int(locked.headers["retry-after"]), 0)

    def test_bootstrap_prints_generated_password_once(self):
        settings = Settings(database_url=f"sqlite:///{(self.base / 'boot.db').as_posix()}", data_dir=self.base,
                            scheduler=False, static_dir=self.base / "static")
        from crab_risk_scan.server.db import initialize, make_engine
        engine = make_engine(settings.database_url)
        try:
            sessions = initialize(engine)
            stream = io.StringIO()
            self.assertEqual(bootstrap_admin(sessions, settings, stream), "admin")
            password = stream.getvalue().rsplit(": ", 1)[1].strip()
            self.assertGreaterEqual(len(password), 20)
            again = io.StringIO()
            self.assertIsNone(bootstrap_admin(sessions, settings, again))
            self.assertEqual(again.getvalue(), "")
            from crab_risk_scan.server.db import User
            from crab_risk_scan.server.security import verify_password
            with sessions() as db:
                stored = db.query(User).one()
                self.assertNotIn(password, stored.password_hash)
                self.assertTrue(verify_password(password, stored.password_hash))
        finally:
            engine.dispose()

    def test_user_administration(self):
        user_id, token = self.user("dave")
        self.assertEqual(self.call("POST", "/users", json={"username": "dave", "password": PASSWORD}).status_code,
                         409)
        self.assertEqual(self.call("POST", "/users", json={"username": "erin", "password": "short"}).status_code, 422)
        listed = self.ok("GET", "/users")
        self.assertEqual({u["username"] for u in listed["items"]}, {"admin", "dave"})
        self.ok("PATCH", f"/users/{user_id}", json={"active": False})
        self.assertEqual(self.call("GET", "/auth/me", token).status_code, 401)
        admin_id = self.ok("GET", "/auth/me")["id"]
        self.assertEqual(self.call("DELETE", f"/users/{admin_id}").status_code, 409)
        self.assertEqual(self.call("PATCH", f"/users/{admin_id}", json={"role": "member"}).status_code, 409)
        self.assertEqual(self.call("DELETE", f"/users/{user_id}").status_code, 204)


class RbacTests(ServerCase):
    def setUp(self):
        super().setUp()
        self.project("demo")
        self.project("other", "Other")
        self.viewer_id, self.viewer = self.user("viewer")
        self.maintainer_id, self.maintainer = self.user("maintainer")
        self.outsider_id, self.outsider = self.user("outsider")
        self.member("demo", self.viewer_id, "viewer")
        self.member("demo", self.maintainer_id, "maintainer")

    def test_members_see_only_their_projects(self):
        self.assertEqual([p["key"] for p in self.ok("GET", "/projects", self.viewer)["items"]], ["demo"])
        self.assertEqual(self.ok("GET", "/projects", self.outsider)["items"], [])
        self.assertEqual(self.call("GET", "/projects/demo", self.outsider).status_code, 404)
        self.assertEqual(self.ok("GET", "/projects/demo", self.viewer)["role"], "viewer")

    def test_viewer_cannot_write(self):
        fp = fingerprint("aws-access-token")
        denied = [
            self.call("POST", "/projects/demo/scans", self.viewer, json={"report": fixture()}),
            self.call("PUT", f"/projects/demo/exceptions/{fp}", self.viewer,
                      json={"status": "accepted", "reason": "x"}),
            self.call("POST", "/projects/demo/jobs", self.viewer,
                      json={"source": {"type": "path", "path": str(self.repos / "demo")}}),
            self.call("PATCH", "/projects/demo", self.viewer, json={"name": "Renamed"}),
            self.call("GET", "/projects/demo/members", self.viewer),
            self.call("GET", "/projects/demo/schedules", self.viewer),
        ]
        self.assertEqual([r.status_code for r in denied], [403] * len(denied))

    def test_member_cannot_administer(self):
        self.assertEqual(self.call("POST", "/projects", self.maintainer, json={"key": "x", "name": "X"}).status_code,
                         403)
        self.assertEqual(self.call("DELETE", "/projects/demo", self.maintainer).status_code, 403)
        self.assertEqual(self.call("GET", "/users", self.maintainer).status_code, 403)
        self.assertEqual(self.call("GET", "/jobs", self.maintainer).status_code, 403)
        self.assertEqual(self.call("GET", "/workers", self.maintainer).status_code, 403)
        self.assertEqual(self.call("POST", "/workers/claim", self.maintainer, json={"worker": "w"}).status_code, 403)

    def test_maintainer_powers(self):
        self.upload(token=self.maintainer)
        self.ok("PATCH", "/projects/demo", self.maintainer, json={"name": "Renamed"})
        members = self.ok("GET", "/projects/demo/members", self.maintainer)["items"]
        self.assertEqual({m["username"]: m["role"] for m in members}, {"viewer": "viewer", "maintainer": "maintainer"})
        candidates = self.ok("GET", "/projects/demo/candidates?q=OUT", self.maintainer)["items"]
        self.assertEqual(candidates, [{"id": self.outsider_id, "username": "outsider"}])
        self.assertEqual(len(self.ok("GET", "/projects/demo/candidates", self.maintainer)["items"]), 4)
        self.assertEqual(self.call("GET", "/projects/demo/candidates?q=o", self.viewer).status_code, 403)
        self.member("demo", self.outsider_id, "viewer")
        self.ok("PUT", f"/projects/demo/members/{self.outsider_id}", self.maintainer, json={"role": "viewer"})
        self.assertEqual(self.call("DELETE", f"/projects/demo/members/{self.outsider_id}",
                                   self.maintainer).status_code, 204)
        self.assertEqual(self.call("POST", "/projects/other/scans", self.maintainer,
                                   json={"report": fixture()}).status_code, 404)

    def test_token_scopes(self):
        self.assertEqual(self.call("POST", "/tokens", self.maintainer,
                                   json={"name": "w", "scopes": ["worker"]}).status_code, 403)
        self.assertEqual(self.call("POST", "/tokens", self.maintainer,
                                   json={"name": "g", "scopes": ["read"]}).status_code, 403)
        upload = self.token(["scan:upload"], "demo", self.maintainer)
        listed = self.ok("GET", "/tokens", self.maintainer)["items"]
        self.assertEqual(len(listed), 1)
        self.assertNotIn("token", listed[0])
        self.assertEqual(listed[0]["project"], "demo")
        self.upload(token=upload, source="runner", ci={"platform": "github", "run_url": "https://ci.example/1"})
        self.assertEqual(self.call("POST", "/projects/other/scans", upload, json={"report": fixture()}).status_code,
                         404)
        self.assertEqual(self.call("GET", "/projects/demo", upload).status_code, 404)
        self.assertEqual(self.call("GET", "/auth/me", upload).status_code, 403)
        read = self.token(["read"], "demo")
        self.assertEqual(self.ok("GET", "/projects", read)["total"], 1)
        self.assertEqual(self.call("GET", "/projects/other", read).status_code, 404)
        self.assertEqual(self.call("PUT", f"/projects/demo/exceptions/{'a' * 64}", read,
                                   json={"status": "accepted", "reason": "x"}).status_code, 403)
        self.assertEqual(self.call("POST", "/tokens", json={"name": "w", "scopes": ["worker"],
                                                            "project": "demo"}).status_code, 422)
        token_id = listed[0]["id"]
        self.assertEqual(self.call("DELETE", f"/tokens/{token_id}", self.outsider).status_code, 404)
        self.assertEqual(self.call("DELETE", f"/tokens/{token_id}", self.maintainer).status_code, 204)
        self.assertEqual(self.call("POST", "/projects/demo/scans", upload, json={"report": fixture()}).status_code,
                         401)


class UploadTests(ServerCase):
    def setUp(self):
        super().setUp()
        self.project()

    def test_summary_counts_only_unsuppressed(self):
        scan = self.upload()
        self.assertEqual(scan["counts"], {"critical": 3, "high": 3, "medium": 3, "low": 0, "info": 0, "unknown": 1})
        self.assertEqual(scan["categories"], {"sast": 4, "secrets": 1, "iac": 1, "sca": 3, "container": 1})
        self.assertEqual((scan["total"], scan["suppressed"], scan["new"]), (10, 2, 4))
        self.assertEqual(scan["status"], "failed")
        self.assertFalse(scan["policy"]["passed"])
        self.assertTrue(scan["url"].endswith(f"/scans/{scan['id']}"))
        detail = self.ok("GET", f"/scans/{scan['id']}")
        self.assertEqual(detail["target"], "demo-service")
        self.assertEqual(len(detail["imports"]), 10)
        self.assertEqual(detail["producers"], sorted({f["producer"] for f in fixture()["findings"]}))
        self.assertFalse(detail["has_sbom"])
        self.assertEqual(detail["comparison"]["new"], 4)
        self.assertEqual(detail["policy"]["minimum_severity"], "high")
        history = self.ok("GET", "/projects/demo/scans")
        self.assertEqual(history["total"], 1)
        self.assertEqual(self.ok("GET", "/projects/demo")["latest_scan"]["id"], scan["id"])

    def test_incomplete_status_when_report_has_errors(self):
        report = fixture()
        report["errors"] = [{"reason": "timeout", "producer": "bandit"}]
        self.assertEqual(self.upload(report=report)["status"], "incomplete")

    def test_schema_validation_does_not_echo_values(self):
        report = fixture()
        report["findings"][0]["severity"] = CANARY
        response = self.call("POST", "/projects/demo/scans", json={"report": report})
        self.assertEqual(response.status_code, 422)
        self.assertIn("schema 3", response.json()["detail"])
        self.assertIn("/findings/0/severity", response.json()["detail"])
        self.assertNotIn(CANARY, response.text)
        old = fixture()
        old["schema_version"] = 2
        self.assertEqual(self.call("POST", "/projects/demo/scans", json={"report": old}).status_code, 422)
        self.assertEqual(self.call("POST", "/projects/demo/scans", json={"report": fixture(), "extra": 1}).status_code,
                         422)
        self.assertEqual(self.call("POST", "/projects/demo/scans", json={"report": fixture(),
                                                                         "sbom": {"x": 1}}).status_code, 422)
        self.assertEqual(self.call("POST", "/projects/demo/scans", json={"report": fixture(),
                                                                         "source": "worker"}).status_code, 422)
        raw = self.client.post("/api/v1/projects/demo/scans", content=b"{not json",
                               headers={"Authorization": f"Bearer {self.admin}"})
        self.assertEqual(raw.status_code, 400)
        self.assertEqual(self.ok("GET", "/projects/demo/scans")["total"], 0)

    def test_report_larger_than_32_mib_is_rejected(self):
        self.assertEqual(self.settings.upload_limit, 32 * 1024 * 1024)
        report = fixture()
        report["target"] = "x" * (UPLOAD_LIMIT + 1)
        response = self.call("POST", "/projects/demo/scans", json={"report": report})
        self.assertEqual(response.status_code, 413)
        self.assertIn("32 MiB", response.json()["detail"])

    def test_sbom_storage(self):
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
        with_sbom = self.upload(sbom=sbom)
        without = self.upload()
        response = self.call("GET", f"/scans/{with_sbom['id']}/sbom")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), sbom)
        self.assertIn("sbom.cdx.json", response.headers["content-disposition"])
        self.assertEqual(self.call("GET", f"/scans/{without['id']}/sbom").status_code, 404)


class SmallLimitTests(ServerCase):
    settings_overrides = {"upload_limit": 64 * 1024}

    def test_request_body_over_the_limit_stops_early(self):
        self.project()
        payload = b'{"report": "' + b"x" * (3 * 64 * 1024) + b'"}'
        response = self.client.post("/api/v1/projects/demo/scans", content=payload,
                                    headers={"Authorization": f"Bearer {self.admin}",
                                             "content-type": "application/json"})
        self.assertEqual(response.status_code, 413)
        report = fixture()
        report["groups"] = report["groups"] * 200
        self.assertEqual(self.call("POST", "/projects/demo/scans", json={"report": report}).status_code, 413)


class FindingTests(ServerCase):
    def setUp(self):
        super().setUp()
        self.project()
        self.scan = self.upload()["id"]

    def findings(self, query="", token=None):
        return self.ok("GET", f"/scans/{self.scan}/findings{query}", token)

    def test_filters(self):
        self.assertEqual(self.findings()["total"], 12)
        self.assertEqual(self.findings("?severity=critical")["total"], 3)
        self.assertEqual(self.findings("?severity=critical,high")["total"], 6)
        self.assertEqual(self.findings("?category=sast")["total"], 5)
        self.assertEqual(self.findings("?status=suppressed")["total"], 2)
        self.assertEqual(self.findings("?status=open")["total"], 10)
        self.assertEqual(self.findings("?producer=trivy")["total"], 2)
        self.assertEqual(self.findings("?kind=review")["total"], 3)
        self.assertEqual(self.findings("?new=true")["total"], 4)
        self.assertEqual(self.findings("?new=false")["total"], 8)
        widget = self.findings("?q=WIDGET")
        self.assertEqual([f["rule"] for f in widget["items"]], ["CVE-2099-0001"])
        self.assertEqual(self.findings("?q=src/client")["total"], 2)
        self.assertEqual(self.findings("?q=%25")["total"], 0)
        page = self.findings("?page=2&page_size=5")
        self.assertEqual((len(page["items"]), page["total"]), (5, 12))
        self.assertEqual(page["items"][0]["fingerprint"], fixture()["findings"][5]["fingerprint"])
        self.assertEqual(self.call("GET", f"/scans/{self.scan}/findings?severity=severe").status_code, 422)
        self.assertEqual(self.call("GET", f"/scans/{self.scan}/findings?status=closed").status_code, 422)
        suppressed = self.findings("?status=suppressed")["items"]
        self.assertTrue(all(f["status"] == "suppressed" and f["exception"] for f in suppressed))
        opened = self.findings("?status=open&page_size=1")["items"][0]
        self.assertEqual((opened["status"], opened["exception"]), ("open", None))

    def test_compare(self):
        base = fixture()
        head = fixture()
        removed = head["findings"].pop(0)
        added = copy.deepcopy(head["findings"][0])
        added["fingerprint"] = "a" * 64
        head["findings"].append(added)
        base_id = self.upload(report=base)["id"]
        head_id = self.upload(report=head)["id"]
        result = self.ok("GET", f"/scans/{head_id}/compare?base={base_id}")
        self.assertEqual(result["base"]["id"], base_id)
        self.assertEqual(result["head"]["id"], head_id)
        self.assertEqual([f["fingerprint"] for f in result["new"]], ["a" * 64])
        self.assertEqual([f["fingerprint"] for f in result["fixed"]], [removed["fingerprint"]])
        self.assertEqual(result["unchanged"], 11)
        self.project("other", "Other")
        foreign = self.upload("other")["id"]
        self.assertEqual(self.call("GET", f"/scans/{head_id}/compare?base={foreign}").status_code, 422)

    def test_exceptions_round_trip_and_export(self):
        secret = fingerprint("aws-access-token")
        body = {"status": "accepted", "reason": "Rotated", "expires": "2999-01-01", "ticket": "SEC-1"}
        created = self.ok("PUT", f"/projects/demo/exceptions/{secret}", json=body)
        self.assertEqual((created["reviewer"], created["status"], created["justification"]), ("admin", "accepted", None))
        summary = self.ok("GET", f"/scans/{self.scan}")
        self.assertEqual((summary["counts"]["critical"], summary["suppressed"]), (2, 3))
        item = self.findings("?q=config/app.env")["items"][0]
        self.assertEqual(item["status"], "suppressed")
        self.assertEqual(item["exception"]["reviewer"], "admin")

        # A project exception overrides the report's own exception; an expired one does not suppress.
        embedded = fingerprint("SC2086")
        self.ok("PUT", f"/projects/demo/exceptions/{embedded}",
                json={"status": "false_positive", "reason": "Old", "expires": "2000-01-01"})
        self.assertEqual(self.findings("?q=deploy.sh")["items"][0]["status"], "open")
        self.assertEqual(self.ok("GET", f"/scans/{self.scan}")["counts"]["info"], 1)

        invalid = [
            self.call("PUT", f"/projects/demo/exceptions/{secret}", json={"status": "not_affected", "reason": "x"}),
            self.call("PUT", "/projects/demo/exceptions/XYZ", json={"status": "accepted", "reason": "x"}),
            self.call("PUT", f"/projects/demo/exceptions/{secret}", json={"status": "accepted", "reason": ""}),
            self.call("PUT", f"/projects/demo/exceptions/{secret}",
                      json={"status": "accepted", "reason": "x", "expires": "2027-02-30"}),
        ]
        self.assertEqual([r.status_code for r in invalid], [422] * 4)
        self.ok("PUT", f"/projects/demo/exceptions/{'b' * 64}",
                json={"status": "not_affected", "justification": "code_not_reachable", "reason": "Dead code"})
        listed = self.ok("GET", "/projects/demo/exceptions")
        self.assertEqual(listed["total"], 3)
        export = self.call("GET", "/projects/demo/exceptions/export")
        self.assertIn("attachment", export.headers["content-disposition"])
        document = export.json()
        self.assertEqual(document["version"], 2)
        by_fp = {e["fingerprint"]: e for e in document["exceptions"]}
        self.assertEqual(by_fp[secret], {"fingerprint": secret, "status": "accepted", "reason": "Rotated",
                                         "reviewer": "admin", "expires": "2999-01-01", "ticket": "SEC-1"})
        self.assertEqual(by_fp["b" * 64]["justification"], "code_not_reachable")
        self.assertEqual(self.call("DELETE", f"/projects/demo/exceptions/{secret}").status_code, 204)
        self.assertEqual(self.call("DELETE", f"/projects/demo/exceptions/{secret}").status_code, 404)
        self.assertEqual(self.ok("GET", f"/scans/{self.scan}")["counts"]["critical"], 3)

    def test_report_download_applies_current_exceptions(self):
        secret = fingerprint("aws-access-token")
        self.ok("PUT", f"/projects/demo/exceptions/{secret}", json={"status": "false_positive", "reason": "Test"})
        response = self.call("GET", f"/scans/{self.scan}/report?format=json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response.headers["content-disposition"])
        finding = next(f for f in response.json()["findings"] if f["fingerprint"] == secret)
        self.assertTrue(finding["suppressed"])
        self.assertEqual(finding["exception"], {"status": "false_positive", "reason": "Test", "reviewer": "admin"})
        sarif = self.call("GET", f"/scans/{self.scan}/report?format=sarif")
        self.assertEqual(sarif.status_code, 200)
        self.assertEqual(sarif.json()["version"], "2.1.0")
        for fmt in ("markdown", "csv", "codequality", "vex"):
            self.assertEqual(self.call("GET", f"/scans/{self.scan}/report?format={fmt}").status_code, 200, fmt)
        html = self.call("GET", f"/scans/{self.scan}/report?format=html")
        self.assertEqual(html.status_code, 200)
        self.assertTrue(html.headers["content-security-policy"].startswith("sandbox"))
        docx = self.call("GET", f"/scans/{self.scan}/report?format=docx&template=executive")
        self.assertEqual(docx.status_code, 200, docx.text[:200])
        self.assertTrue(docx.content.startswith(b"PK"))
        self.assertEqual(self.call("GET", f"/scans/{self.scan}/report?format=pdf").status_code, 422)
        self.assertEqual(self.call("GET", f"/scans/{self.scan}/report?format=docx&template=../x.docx").status_code, 422)


class JobTests(ServerCase):
    def setUp(self):
        super().setUp()
        self.project()
        self.worker = self.token(["worker"])
        self.worker2 = self.token(["worker"])

    def job(self, source=None, status=201):
        source = source or {"type": "path", "path": str(self.repos / "demo")}
        return self.ok("POST", "/projects/demo/jobs", status=status, json={"source": source,
                                                                            "options": {"engines": "none"}})

    def claim(self, token=None, name="w1", git=False):
        response = self.call("POST", "/workers/claim", token or self.worker,
                             json={"worker": name, "capabilities": {"git": git}})
        self.assertIn(response.status_code, (200, 204), response.text)
        return response.json() if response.status_code == 200 else None

    def expire(self, job_id):
        with self.app.state.sessions() as db:
            db.execute(update(Job).where(Job.id == job_id).values(lease_expires_at=utcnow() - timedelta(seconds=1)))
            db.commit()

    def test_source_validation(self):
        outside = self.base / "elsewhere"
        outside.mkdir()
        self.assertEqual(self.call("POST", "/projects/demo/jobs", json={
            "source": {"type": "path", "path": str(outside)}}).status_code, 422)
        self.assertEqual(self.call("POST", "/projects/demo/jobs", json={
            "source": {"type": "path", "path": str(self.repos / "demo" / ".." / ".." / "elsewhere")}}).status_code, 422)
        self.assertEqual(self.call("POST", "/projects/demo/jobs", json={
            "source": {"type": "path", "path": "relative/dir"}}).status_code, 422)
        self.assertEqual(self.call("POST", "/projects/demo/jobs", json={
            "source": {"type": "git", "url": "file:///etc"}}).status_code, 422)
        self.assertEqual(self.call("POST", "/projects/demo/jobs", json={
            "source": {"type": "git", "url": "https://user:pw@example.com/r.git"}}).status_code, 422)
        self.assertEqual(self.call("POST", "/projects/demo/jobs", json={
            "source": {"type": "git", "url": "https://example.com/r.git", "ref": "--upload-pack=x"}}).status_code, 422)
        self.assertEqual(self.call("POST", "/projects/demo/jobs", json={
            "source": {"type": "path", "path": str(self.repos / "demo")},
            "options": {"engines": "auto; rm"}}).status_code, 422)

    def test_claim_heartbeat_complete(self):
        job = self.job()
        self.assertEqual(job["status"], "queued")
        claimed = self.claim()
        self.assertEqual(claimed["job"]["id"], job["id"])
        self.assertEqual(claimed["job"]["repository_url"], "https://example.com/demo")
        self.assertEqual(claimed["lease_seconds"], 30)
        self.assertIsNone(self.claim(name="w2"))
        beat = self.ok("POST", f"/jobs/{job['id']}/heartbeat", self.worker, json={"worker": "w1"})
        self.assertEqual(beat, {"lease_seconds": 30, "cancelled": False})
        self.assertEqual(self.call("POST", f"/jobs/{job['id']}/heartbeat", self.worker2).status_code, 409)
        self.assertEqual(self.call("POST", f"/jobs/{job['id']}/heartbeat", self.worker,
                                   json={"worker": "w2"}).status_code, 409)
        done = self.ok("POST", f"/jobs/{job['id']}/complete", self.worker,
                       json={"report": fixture(), "log": "scan finished", "worker": "w1"})
        scan = self.ok("GET", f"/scans/{done['scan_id']}")
        self.assertEqual(scan["source"], "job")
        detail = self.ok("GET", f"/jobs/{job['id']}")
        self.assertEqual((detail["status"], detail["scan_id"], detail["attempts"], detail["log"]),
                         ("succeeded", done["scan_id"], 1, "scan finished"))
        self.assertEqual(self.call("POST", f"/jobs/{job['id']}/complete", self.worker,
                                   json={"report": fixture()}).status_code, 409)
        workers = self.ok("GET", "/workers")
        self.assertEqual([(w["name"], w["active"], w["current_job"]) for w in workers["items"]],
                         [("w1", True, None), ("w2", True, None)])

    def test_git_jobs_go_only_to_git_workers(self):
        git_job = self.job({"type": "git", "url": "https://example.com/r.git", "ref": "main"})
        self.assertIsNone(self.claim(git=False))
        self.assertEqual(self.claim(git=True)["job"]["id"], git_job["id"])

    def test_lease_expiry_requeues_until_attempts_run_out(self):
        job = self.job()
        for attempt in range(1, self.settings.max_attempts + 1):
            claimed = self.claim(name=f"w{attempt}")
            self.assertEqual((claimed["job"]["id"], claimed["job"]["attempts"]), (job["id"], attempt))
            self.expire(job["id"])
            self.assertEqual(self.call("POST", f"/jobs/{job['id']}/complete", self.worker2,
                                       json={"report": fixture()}).status_code, 409)
        self.assertIsNone(self.claim(name="late"))
        detail = self.ok("GET", f"/jobs/{job['id']}")
        self.assertEqual(detail["status"], "failed")
        self.assertIn("lease expired", detail["error"])

    def test_cancel_and_fail(self):
        queued = self.job()
        cancelled = self.ok("POST", f"/jobs/{queued['id']}/cancel")
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(self.call("POST", f"/jobs/{queued['id']}/cancel").status_code, 409)
        running = self.job()
        self.claim()
        self.ok("POST", f"/jobs/{running['id']}/cancel")
        self.assertEqual(self.ok("POST", f"/jobs/{running['id']}/heartbeat", self.worker),
                         {"lease_seconds": 0, "cancelled": True})
        self.assertEqual(self.call("POST", f"/jobs/{running['id']}/complete", self.worker,
                                   json={"report": fixture()}).status_code, 409)
        failing = self.job()
        self.claim()
        self.ok("POST", f"/jobs/{failing['id']}/fail", self.worker,
                json={"error": "scan timed out", "log": "x" * 100000})
        detail = self.ok("GET", f"/jobs/{failing['id']}")
        self.assertEqual((detail["status"], detail["error"], len(detail["log"])), ("failed", "scan timed out", 65536))
        queue = self.ok("GET", "/jobs?status=cancelled")
        self.assertEqual(queue["total"], 2)
        self.assertEqual(self.ok("GET", "/projects/demo/jobs")["total"], 3)
        self.assertEqual(self.call("GET", "/jobs?status=bogus").status_code, 422)

    def test_invalid_report_fails_the_job(self):
        job = self.job()
        self.claim()
        bad = fixture()
        bad["schema_version"] = 2
        self.assertEqual(self.call("POST", f"/jobs/{job['id']}/complete", self.worker,
                                   json={"report": bad}).status_code, 422)
        self.assertEqual(self.ok("GET", f"/jobs/{job['id']}")["status"], "failed")

    def test_viewer_reads_single_job_only(self):
        job = self.job()
        viewer_id, viewer = self.user("viewer")
        self.member("demo", viewer_id, "viewer")
        self.assertEqual(self.ok("GET", f"/jobs/{job['id']}", viewer)["id"], job["id"])
        self.assertEqual(self.call("POST", f"/jobs/{job['id']}/cancel", viewer).status_code, 403)
        self.assertEqual(self.call("GET", "/projects/demo/jobs", viewer).status_code, 403)
        _, outsider = self.user("outsider")
        self.assertEqual(self.call("GET", f"/jobs/{job['id']}", outsider).status_code, 404)


class ScheduleApiTests(ServerCase):
    def test_schedule_crud(self):
        self.project()
        source = {"type": "path", "path": str(self.repos / "demo")}
        self.assertEqual(self.call("POST", "/projects/demo/schedules",
                                   json={"cron": "61 * * * *", "source": source}).status_code, 422)
        created = self.ok("POST", "/projects/demo/schedules", status=201,
                          json={"cron": "0 3 * * mon-fri", "source": source, "options": {"sbom": True}})
        self.assertTrue(created["next_run_at"].endswith("T03:00:00Z"))
        self.assertIsNone(created["last_run_at"])
        listed = self.ok("GET", "/projects/demo/schedules")
        self.assertEqual(listed["total"], 1)
        disabled = self.ok("PATCH", f"/schedules/{created['id']}", json={"enabled": False})
        self.assertIsNone(disabled["next_run_at"])
        enabled = self.ok("PATCH", f"/schedules/{created['id']}", json={"enabled": True, "cron": "*/15 * * * *"})
        self.assertEqual(enabled["cron"], "*/15 * * * *")
        self.assertIsNotNone(enabled["next_run_at"])
        viewer_id, viewer = self.user("viewer")
        self.member("demo", viewer_id, "viewer")
        self.assertEqual(self.call("PATCH", f"/schedules/{created['id']}", viewer, json={"enabled": False}).status_code,
                         403)
        self.assertEqual(self.call("DELETE", f"/schedules/{created['id']}").status_code, 204)
        self.assertEqual(self.call("DELETE", f"/schedules/{created['id']}").status_code, 404)


class DashboardTests(ServerCase):
    def test_organization_and_project_dashboards(self):
        self.project("demo")
        self.project("other", "Other")
        self.upload("demo")
        self.upload("other")
        latest = self.upload("other")
        member_id, member = self.user("member")
        self.member("demo", member_id, "viewer")

        org = self.ok("GET", "/dashboard")
        self.assertEqual((org["projects"], org["scans"]), (2, 3))
        self.assertEqual(org["counts"], {"critical": 6, "high": 6, "medium": 6, "low": 0, "info": 0, "unknown": 2})
        self.assertEqual(org["categories"]["sast"], 8)
        self.assertEqual(org["policy"], {"passed": 0, "failed": 2, "incomplete": 0})
        self.assertEqual([p["key"] for p in org["projects_summary"]], ["demo", "other"])
        self.assertEqual(org["projects_summary"][1]["latest_scan"]["id"], latest["id"])
        self.assertEqual(len(org["trend"]), 30)
        self.assertEqual(org["trend"][-1]["counts"]["critical"], 6)
        self.assertEqual(org["trend"][0]["counts"]["critical"], 0)
        self.assertTrue(all(rule["count"] == 2 for rule in org["top_rules"]))
        self.assertEqual(len(org["top_rules"]), 10)
        packages = {p["name"]: p["count"] for p in org["top_packages"]}
        self.assertEqual(packages["widget"], 2)

        scoped = self.ok("GET", "/dashboard?days=7", member)
        self.assertEqual((scoped["projects"], scoped["scans"], len(scoped["trend"])), (1, 1, 7))
        self.assertEqual(scoped["counts"]["critical"], 3)

        self.ok("PUT", f"/projects/demo/exceptions/{fingerprint('aws-access-token')}",
                json={"status": "accepted", "reason": "Rotated"})
        project = self.ok("GET", "/projects/other/dashboard")
        self.assertEqual(project["project"], "other")
        self.assertEqual(project["latest_scan"]["id"], latest["id"])
        self.assertEqual(len(project["recent_scans"]), 2)
        self.assertEqual(project["policy"], {"passed": 0, "failed": 1, "incomplete": 0})
        self.assertEqual(self.ok("GET", "/projects/demo/dashboard")["counts"]["critical"], 2)
        self.assertEqual(self.call("GET", "/projects/other/dashboard", member).status_code, 404)


class WebUiTests(ServerCase):
    def test_placeholder_without_assets(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("npm run build", response.text)
        self.assertEqual(self.client.get("/projects/demo").status_code, 404)
        self.assertEqual(self.client.get("/api/v1/nothing").json(), {"detail": "Not Found"})

    def test_spa_fallback(self):
        static = self.settings.static_dir
        (static / "assets").mkdir(parents=True)
        (static / "index.html").write_text("<!doctype html><div id=root></div>", encoding="utf-8")
        (static / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
        (self.base / "secret.txt").write_text(CANARY, encoding="utf-8")
        self.assertIn("id=root", self.client.get("/").text)
        self.assertIn("id=root", self.client.get("/projects/demo/findings").text)
        asset = self.client.get("/assets/app.js")
        self.assertEqual(asset.text, "console.log(1)")
        self.assertIn("immutable", asset.headers["cache-control"])
        self.assertEqual(self.client.get("/assets/missing.js").status_code, 404)
        self.assertNotIn(CANARY, self.client.get("/..%2fsecret.txt").text)
        self.assertEqual(self.client.get("/api/v1/unknown").status_code, 404)


class CliTests(unittest.TestCase):
    def run_cli(self, *args, stdin=None, env=None):
        return subprocess.run([sys.executable, "-m", "crab_risk_scan", *args], cwd=ROOT, input=stdin,
                              capture_output=True, text=True, timeout=120, env=env)

    def test_cli_import_loads_only_the_standard_library(self):
        code = ("import sys, crab_risk_scan.__main__ as m; m.build_parser(); "
                "print(sorted(n for n in ('fastapi', 'sqlalchemy', 'uvicorn', 'jsonschema') if n in sys.modules))")
        result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.stdout.strip(), "[]", result.stderr)

    def test_admin_commands(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            env = dict(os.environ, CRAB_ADMIN_PASSWORD=ADMIN_PASSWORD)
            common = ("--data-dir", temp)
            created = self.run_cli("admin", "create-user", "frank", "--role", "admin", "--password-stdin", *common,
                                   stdin=PASSWORD + "\n", env=env)
            self.assertEqual(created.returncode, 0, created.stderr)
            duplicate = self.run_cli("admin", "create-user", "frank", "--password-stdin", *common,
                                     stdin=PASSWORD + "\n", env=env)
            self.assertEqual(duplicate.returncode, 2)
            changed = self.run_cli("admin", "set-password", "frank", "--password-stdin", *common,
                                   stdin="another-password-1\n", env=env)
            self.assertEqual(changed.returncode, 0, changed.stderr)
            token = self.run_cli("admin", "create-token", "ci-worker", "--scope", "worker", *common, env=env)
            self.assertEqual(token.returncode, 0, token.stderr)
            secret = token.stdout.strip()
            self.assertTrue(secret.startswith("crab_"))
            listed = self.run_cli("admin", "list-tokens", *common, env=env)
            self.assertIn("ci-worker", listed.stdout)
            self.assertIn(secret[:12], listed.stdout)
            self.assertNotIn(secret, listed.stdout)
            settings = Settings.from_env(data_dir=temp, environ={})
            app = create_app(settings)
            try:
                with TestClient(app) as client:
                    login = client.post("/api/v1/auth/login",
                                        json={"username": "frank", "password": "another-password-1"})
                    self.assertEqual(login.status_code, 200)
                    claim = client.post("/api/v1/workers/claim", json={"worker": "w"},
                                        headers={"Authorization": f"Bearer {secret}"})
                    self.assertEqual(claim.status_code, 204)
            finally:
                app.state.engine.dispose()


if __name__ == "__main__":
    unittest.main()
