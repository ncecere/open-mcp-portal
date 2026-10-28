"""Exercise only the smoke script's port-forward helpers; no cluster is used.

Run: python3 -m unittest discover -s scripts/tests -p 'test_k8s_smoke_port_forward.py' -v
K8S_SMOKE_SCRIPT may point at a temporary old-script copy for regression proof.
"""

import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import URLError
from urllib.request import build_opener, ProxyHandler


SCRIPT = Path(os.environ.get(
    "K8S_SMOKE_SCRIPT", Path(__file__).resolve().parents[1] / "k8s-smoke.sh"
))

FAKE_KUBECTL = r'''
import json
import os
from pathlib import Path
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

pid = os.getpid()
record = {"pid": pid, "argv": sys.argv[1:]}
Path(os.environ["TMP"], "kubectl-%s.json" % pid).write_text(json.dumps(record))

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = str(pid).encode()
        self.send_response(200 if self.path == "/healthz" else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

port = int(sys.argv[-1].split(":")[0])
HTTPServer(("127.0.0.1", port), Handler).serve_forever()
'''


def wait_health(port):
    """Bounded readiness polling, ignoring proxy environment variables."""
    opener = build_opener(ProxyHandler({}))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with opener.open("http://127.0.0.1:%s/healthz" % port, timeout=0.2):
                return
        except (URLError, OSError):
            time.sleep(0.01)
    raise RuntimeError("fake kubectl did not answer /healthz within 5s")


class PortForwardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="omp-pf-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.owned_pids = set()
        self.shell = None
        self.addCleanup(self.cleanup_processes)
        # An ephemeral OS-assigned port, never one of the repository's dev ports.
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.assertNotIn(self.port, (8088, 8091, 8092, 8093))
        fake = self.root / "kubectl"
        fake.write_text("#!%s\n%s" % (sys.executable, FAKE_KUBECTL))
        fake.chmod(0o755)
        source = SCRIPT.read_text()
        helpers = []
        for name in ("pf_stop", "pf_start"):
            matches = re.findall(r"^%s\(\) \{\n.*?^\}" % name, source, re.M | re.S)
            self.assertEqual(len(matches), 1, "expected exactly one %s helper" % name)
            helpers.append(matches[0])
        harness = r'''
set -euo pipefail
PF_PID=""
fail() { printf '%s\n' "$*" >&2; exit 1; }
k() {
  [ "$CLUSTER_UP" = 1 ] || fail "internal error: kubectl called before the cluster exists"
  kubectl --kubeconfig "$KUBECONFIG_FILE" --context "$CONTEXT" "$@"
}
kn() { k -n "$NS" "$@"; }
wait_until() { "$PYTHON" "$TEST_FILE" --wait-health "$PORT"; }
'''
        harness += "\n".join(helpers)
        harness += '\ntrap pf_stop EXIT\nwhile IFS= read -r command; do eval "$command"; done\n'
        harness_path = self.root / "harness.sh"
        harness_path.write_text(harness)
        env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"],
                   TMP=str(self.root), PORT=str(self.port), CLUSTER_UP="1",
                   KUBECONFIG_FILE=str(self.root / "private kubeconfig"),
                   CONTEXT="kind-test-context", NS="test-namespace",
                   PYTHON=sys.executable, TEST_FILE=str(Path(__file__).resolve()))
        self.stderr = (self.root / "harness.stderr").open("w+")
        self.addCleanup(self.stderr.close)
        self.shell = subprocess.Popen(
            ["bash", str(harness_path)], env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=self.stderr, text=True, bufsize=1,
        )

    def command(self, command):
        self.shell.stdin.write(command + '\n')
        self.shell.stdin.flush()
        ready, _, _ = select.select([self.shell.stdout], [], [], 8)
        self.assertTrue(ready, "Bash harness command timed out: " + command)
        line = self.shell.stdout.readline()
        self.assertTrue(line, "Bash harness exited: " + (self.root / "harness.stderr").read_text())
        return line.strip()

    def start(self):
        pid = int(self.command('pf_start; printf "%s\\n" "$PF_PID"'))
        self.owned_pids.add(pid)
        return pid

    def record(self, pid):
        records = [json.loads(p.read_text()) for p in self.root.glob("kubectl-*.json")]
        self.assertIn(pid, [r["pid"] for r in records],
                      "PF_PID must own kubectl, not a background shell function; records=%r" % records)
        opener = build_opener(ProxyHandler({}))
        with opener.open("http://127.0.0.1:%s/healthz" % self.port, timeout=1) as response:
            self.assertEqual(response.read().decode(), str(pid),
                             "health check must reach the new forward, not an orphan")
        return next(r for r in records if r["pid"] == pid)

    def assert_reaped(self, pid):
        with self.assertRaises(ProcessLookupError, msg="port-forward process must be gone and reaped"):
            os.kill(pid, 0)

    def assert_listener_released(self):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", self.port))
            sock.listen(1)

    def stop(self):
        self.assertEqual(self.command('pf_stop; printf "stopped:%s\\n" "$PF_PID"'), "stopped:")

    def cleanup_processes(self):
        # Stop/reap our Bash child first; its EXIT trap runs the real pf_stop.
        if self.shell is not None:
            try:
                self.shell.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                self.shell.kill()
                self.shell.communicate(timeout=3)
        # The old helper can orphan a server. Kill ONLY PIDs this fixture created,
        # never discover/kill listeners by port, name, or process group.
        for path in self.root.glob("kubectl-*.json"):
            self.owned_pids.add(json.loads(path.read_text())["pid"])
        for pid in self.owned_pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_pf_pid_is_kubectl_with_explicit_cluster_and_namespace(self):
        pid = self.start()
        self.assertEqual(self.record(pid)["argv"], [
            "--kubeconfig", str(self.root / "private kubeconfig"),
            "--context", "kind-test-context", "-n", "test-namespace",
            "port-forward", "svc/open-mcp-portal", "%s:80" % self.port,
        ])

    def test_stop_releases_listener_reaps_process_and_is_idempotent(self):
        pid = self.start()
        self.stop()
        self.assert_reaped(pid)
        self.assert_listener_released()
        self.stop()

    def test_restart_replaces_live_forward_and_can_restart_after_stop(self):
        first = self.start()
        self.record(first)
        second = self.start()  # pf_start must itself stop an existing forward.
        self.assertNotEqual(first, second)
        self.assert_reaped(first)
        self.record(second)
        self.stop()
        self.assert_reaped(second)
        self.assert_listener_released()
        third = self.start()
        self.record(third)
        self.stop()
        self.assert_reaped(third)
        self.assert_listener_released()
        self.assertEqual(len(list(self.root.glob("kubectl-*.json"))), 3)

    def test_start_before_cluster_exists_fails_without_launching_kubectl(self):
        self.shell.stdin.write("CLUSTER_UP=0; pf_start\n")
        self.shell.stdin.flush()
        self.assertEqual(self.shell.wait(timeout=8), 1)
        self.assertIn("kubectl called before the cluster exists",
                      (self.root / "harness.stderr").read_text())
        self.assertEqual(list(self.root.glob("kubectl-*.json")), [])
        self.assert_listener_released()


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--wait-health":
        wait_health(sys.argv[2])
    else:
        unittest.main()
