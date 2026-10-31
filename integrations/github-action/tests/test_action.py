"""Contract tests drive the real omp executable against a mock HTTP portal."""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("action", ROOT / "run.py")
action = importlib.util.module_from_spec(spec)
spec.loader.exec_module(action)
ID = "11111111-1111-4111-8111-111111111111"
TOKEN = "omppub_" + "a" * 43
SECRET = "sentinel-private-header-912345"
BINARY = os.environ.get("OMP_ACTION_TEST_CLI", "/tmp/omp-action-test")


class Portal(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def do_PATCH(self):
        self.respond()

    def respond(self):
        state = self.server.state
        path = self.path.split("?")[0]
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        state["calls"].append((self.command, path, body, self.headers.get("If-Match")))
        status, data = 200, {}
        error = state.get("error")
        if error and self.command == "PATCH":
            status = error
            data = {"error": {"code": "token_not_allowed", "message": TOKEN + SECRET}}
        elif path == "/v1/token":
            data = {"kind": "team_publisher", "team": {"id": ID, "slug": "bravo", "name": "Bravo"},
                    "scopes": ["servers:read", "servers:write"], "status": "active",
                    "id": ID, "createdAt": "2026-01-01T00:00:00Z", "expiresAt": "2027-01-01T00:00:00Z"}
        elif path.endswith("/test"):
            data = {"ok": True, "latencyMs": 1}
        elif path.endswith("/refresh"):
            state["server"]["pendingChanges"] = state.get("changed", 0)
            data = {"added": 0, "changed": state.get("changed", 0), "gone": 0, "listed": 1}
        elif path.endswith("/publish"):
            if state.get("stale"):
                status, data = 409, {"error": {"code": "changed_since_review", "message": SECRET}}
            else:
                state["server"]["publishState"] = "pending"
                data = state["server"]
        elif path.endswith("/" + ID):
            if self.command == "PATCH":
                self.server.test.assertEqual(self.headers.get("If-Match"), '"1"')
                state["server"].update(body)
                state["server"]["revision"] += 1
            data = state["server"]
        elif path.endswith("/mcp-servers"):
            if self.command == "POST":
                status = 201
                state["server"] = base_server()
                state["server"].update(body)
                data = {"server": state["server"], "refresh": {"listed": 1}}
            else:
                data = {"items": [state["server"]] if state.get("server") else [], "nextCursor": None}
        else:
            status = 404
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if status < 400:
            data = {"data": data}
        self.wfile.write(json.dumps(data).encode())


def base_server():
    return dict(id=ID, slug="status", name="Status", teamSlug="bravo", teamId=ID,
                url="https://upstream.example/mcp", enabled=True, timeoutSeconds=30,
                authMode="none", hasAuth=False, description="", revision=1,
                publishState="private", pendingChanges=0, reviewDigest="omp-review-v3:abc",
                health={"status": "healthy"}, counts={"tools": 1, "prompts": 0,
                "resources": 0, "resourceTemplates": 0})


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / "server.json"
        self.output = self.root / "output"
        self.output.touch()
        self.doc = {"schema": "omp/v1", "servers": [{"team": "bravo", "slug": "status",
                    "name": "Status", "url": "https://upstream.example/mcp"}]}
        self.state = {"server": base_server(), "calls": []}
        self.portal = ThreadingHTTPServer(("127.0.0.1", 0), Portal)
        self.portal.state, self.portal.test = self.state, self
        threading.Thread(target=self.portal.serve_forever, daemon=True).start()
        self.addCleanup(self.portal.server_close)
        self.addCleanup(self.portal.shutdown)
        self.env = dict(os.environ, ACTION_TEAM="bravo", ACTION_SLUG="status",
                        ACTION_URL="https://portal.example", ACTION_TOKEN=TOKEN,
                        ACTION_REFRESH="true", ACTION_PUBLISH="none", ACTION_FAIL_ON_CHANGES="true",
                        GITHUB_WORKSPACE=str(self.root), ACTION_CONFIG="server.json",
                        GITHUB_OUTPUT=str(self.output), ACTION_CLI=BINARY, OMP_SECRET_HEADER=SECRET)
        # Production requires HTTPS. Only the test substitutes the child URL to loopback;
        # the real CLI still enforces its loopback-only HTTP exception.
        self.real_cli = action.cli
        self.real_run = action.subprocess.run

    def run_action(self):
        self.config.write_text(json.dumps(self.doc))
        def local(binary, env, *args):
            env = dict(env, OMP_URL=f"http://127.0.0.1:{self.portal.server_port}")
            return self.real_cli(binary, env, *args)
        def private_process(argv, **kwargs):
            self.assertNotIn(TOKEN, " ".join(argv))
            self.assertNotIn(SECRET, " ".join(argv))
            self.assertNotIn("ACTION_TOKEN", kwargs["env"])
            self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
            return self.real_run(argv, **kwargs)
        log = io.StringIO()
        with patch.object(action.subprocess, "run", private_process), patch.dict(os.environ, self.env, clear=True), patch.object(action, "cli", local), contextlib.redirect_stdout(log):
            try:
                result = action.main()
            except action.Refused as exc:
                log.write(str(exc))
                result = 1
        for secret in (TOKEN, SECRET):
            self.assertNotIn(secret, log.getvalue() + self.output.read_text())
        return result, log.getvalue()

    def test_new_and_identical_do_not_bump_revision(self):
        self.state["server"] = None
        self.assertEqual(self.run_action()[0], 0)
        self.assertEqual(self.state["server"]["revision"], 1)
        self.assertEqual(self.run_action()[0], 0)
        self.assertFalse(any(c[0] == "PATCH" for c in self.state["calls"]))
        self.assertIn("server-id=" + ID, self.output.read_text())

    def test_update_preserves_omissions_and_uses_if_match(self):
        self.state["server"]["description"] = "Keep"
        self.doc["servers"][0]["name"] = "Updated"
        self.assertEqual(self.run_action()[0], 0)
        self.assertEqual(self.state["server"]["revision"], 2)
        self.assertEqual(self.state["server"]["description"], "Keep")
        self.assertEqual(self.run_action()[0], 0)
        self.assertEqual(self.state["server"]["revision"], 2)

    def test_changed_and_preexisting_pending_fail_or_warn(self):
        for changed in (0, 2):
            self.state.update(changed=changed)
            self.state["server"].update(pendingChanges=3, publishState="pending")
            self.assertEqual(self.run_action()[0], 1)
            self.env["ACTION_FAIL_ON_CHANGES"] = "false"
            code, log = self.run_action()
            self.assertEqual(code, 0)
            self.assertIn("Review: https://portal.example/", log)
            self.env["ACTION_FAIL_ON_CHANGES"] = "true"

    def test_publication_is_only_request_and_digest_guarded(self):
        self.env["ACTION_PUBLISH"] = "request"
        self.assertEqual(self.run_action()[0], 1)
        posts = [c for c in self.state["calls"] if c[1].endswith("/publish")]
        self.assertEqual(posts[0][2]["expectedDigest"], "omp-review-v3:abc")
        self.assertIn("needs-approval=true", self.output.read_text())

    def test_scope_stale_and_origin_errors_are_safe(self):
        self.doc["servers"][0]["name"] = "Updated"
        for status, hint in ((403, "servers:write"), (409, "Live conflict"),
                             (412, "Live conflict"), (422, "freshly entered")):
            self.state["error"] = status
            code, log = self.run_action()
            self.assertEqual(code, 1)
            self.assertIn(hint, log)
        self.state.pop("error")
        self.doc["servers"][0]["name"] = "Status"
        self.env["ACTION_PUBLISH"] = "request"
        self.state["stale"] = True
        self.assertIn("Live conflict", self.run_action()[1])

    def test_injections_and_unsupported_policy_refuse_before_writes(self):
        self.doc["servers"][0]["name"] = "$(touch /tmp/omp-action-injected)\n::error::fake"
        self.assertEqual(self.run_action()[0], 0)
        self.assertFalse(Path("/tmp/omp-action-injected").exists())
        self.state["calls"].clear()
        self.doc["servers"][0]["governance"] = {"sensitivity": "restricted",
                        "lifecycle": "active", "sunsetAt": ""}
        self.assertEqual(self.run_action()[0], 1)
        self.assertFalse(any(c[0] != "GET" for c in self.state["calls"]))
        self.doc["servers"][0].pop("governance")
        self.doc["servers"][0]["authValueEnv"] = "OMP_TOKEN"
        self.state["calls"].clear()
        self.assertEqual(self.run_action()[0], 1)
        self.assertEqual(self.state["calls"], [])
        self.env["ACTION_CONFIG"] = "../escape"
        self.assertEqual(self.run_action()[0], 1)

    def test_refresh_disabled_still_checks_pending(self):
        self.env["ACTION_REFRESH"] = "false"
        self.state["server"]["pendingChanges"] = 1
        self.assertEqual(self.run_action()[0], 1)
        self.assertFalse(any(c[1].endswith("/refresh") for c in self.state["calls"]))
        self.assertIn("changed-capabilities=0", self.output.read_text())

    def test_no_credentials_redirect_or_non_https_input(self):
        for url in ("http://portal.example", "https://user:password@portal.example",
                    "https://portal.example?token=secret", "https://portal.example/\n::error::x"):
            self.env["ACTION_URL"] = url
            self.assertEqual(self.run_action()[0], 1)
            self.assertEqual(self.state["calls"], [])

    def test_invalid_output_symlink_refused_before_mutation(self):
        self.output.unlink()
        self.output.symlink_to(self.config)
        self.assertEqual(self.run_action()[0], 1)
        self.assertEqual(self.state["calls"], [])

    def test_static_secret_not_in_output_or_arguments(self):
        self.state["server"] = None
        self.doc["servers"][0].update(authMode="static_header", authHeaderName="X-Key",
                                     authValueEnv="OMP_SECRET_HEADER")
        self.assertEqual(self.run_action()[0], 0)
        creates = [c for c in self.state["calls"] if c[0] == "POST" and c[1].endswith("/mcp-servers")]
        self.assertEqual(creates[0][2]["authValue"], SECRET)


if __name__ == "__main__":
    unittest.main()
