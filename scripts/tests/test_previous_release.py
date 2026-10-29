"""Tests of scripts/previous-release.sh against a throwaway git repository and a
stub registry on a loopback port; no network, no cluster.

Run: python3 -m unittest discover -s scripts/tests -p 'test_previous_release.py' -v
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

SCRIPT = Path(__file__).resolve().parents[1] / "previous-release.sh"
REPO = "ncecere/open-mcp-portal"
DIGESTS = {
    "v0.7.0": "sha256:" + "a" * 64,
    "v0.8.0": "sha256:" + "b" * 64,
}


class Registry(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/token"):
            body = b'{"token":"stub-token"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_HEAD(self):
        prefix = "/v2/%s/manifests/" % REPO
        tag = self.path[len(prefix):] if self.path.startswith(prefix) else ""
        if self.headers.get("Authorization") != "Bearer stub-token" or tag not in DIGESTS:
            self.send_response(401 if tag in DIGESTS else 404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Docker-Content-Digest", DIGESTS[tag])
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


def git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false",
         "-c", "tag.gpgsign=false", *args],
        cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class PreviousReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Registry)
        cls.url = "http://127.0.0.1:%d" % cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="omp-prev-test-")
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        (self.repo / "scripts").mkdir()
        shutil.copy(SCRIPT, self.repo / "scripts" / "previous-release.sh")
        git(self.repo, "init", "-q", "-b", "main")
        self.commit("one")

    def commit(self, name):
        (self.repo / name).write_text(name)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", name)

    def pin_example(self, tag, digest):
        d = self.repo / "deploy" / "kubernetes" / "overlays" / "example"
        d.mkdir(parents=True, exist_ok=True)
        (d / "kustomization.yaml").write_text(
            "images:\n  - name: ghcr.io/ncecere/open-mcp-portal\n    newTag: %s\n    digest: %s\n" % (tag, digest))

    def run_script(self, *args):
        env = dict(os.environ, OMP_REGISTRY_URL=self.url, OMP_IMAGE_REPO=REPO, NO_PROXY="127.0.0.1",
                   no_proxy="127.0.0.1")
        return subprocess.run(["bash", str(self.repo / "scripts" / "previous-release.sh"), *args],
                              env=env, capture_output=True, text=True, timeout=30)

    def test_newest_final_tag_reachable_from_head(self):
        git(self.repo, "tag", "v0.7.0")
        self.commit("two")
        git(self.repo, "tag", "v0.8.0")
        self.commit("three")
        git(self.repo, "tag", "v0.9.0-rc.1")  # a pre-release is not "the previous release"
        self.commit("four")
        r = self.run_script("--tag-only")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "v0.8.0"), r.stderr)

    def test_a_release_tag_at_head_is_skipped(self):
        git(self.repo, "tag", "v0.7.0")
        self.commit("two")
        git(self.repo, "tag", "v0.8.0")
        r = self.run_script("--tag-only")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "v0.7.0"), r.stderr)

    def test_tags_not_reachable_from_head_are_ignored(self):
        git(self.repo, "tag", "v0.7.0")
        git(self.repo, "checkout", "-q", "-b", "side")
        self.commit("side")
        git(self.repo, "tag", "v0.9.0")
        git(self.repo, "checkout", "-q", "main")
        self.commit("two")
        r = self.run_script("--tag-only")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "v0.7.0"), r.stderr)

    def test_versions_sort_numerically(self):
        for tag in ("v0.9.0", "v0.10.0", "v0.2.1"):
            self.commit("c" + tag)
            git(self.repo, "tag", tag)
        self.commit("later")
        r = self.run_script("--tag-only")
        self.assertEqual(r.stdout.strip(), "v0.10.0", r.stderr)

    def test_no_tag_fails_with_a_hint(self):
        r = self.run_script("--tag-only")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("fetch tags", r.stderr)

    def test_prints_tag_and_digest_reference(self):
        git(self.repo, "tag", "v0.8.0")
        self.commit("two")
        r = self.run_script()
        host = self.url.split("://", 1)[1]
        self.assertEqual((r.returncode, r.stdout.strip()),
                         (0, "v0.8.0 %s/%s@%s" % (host, REPO, DIGESTS["v0.8.0"])), r.stderr)

    def test_explicit_tag(self):
        r = self.run_script("--tag", "v0.7.0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.strip().endswith("@" + DIGESTS["v0.7.0"]))

    def test_a_tag_that_is_not_a_release_is_refused(self):
        r = self.run_script("--tag", "main")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not a release tag", r.stderr)

    def test_unknown_tag_on_the_registry_fails(self):
        r = self.run_script("--tag", "v9.9.9")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not read the manifest", r.stderr)

    def test_example_overlay_pin_must_agree_with_the_registry(self):
        git(self.repo, "tag", "v0.8.0")
        self.commit("two")
        self.pin_example("v0.8.0", DIGESTS["v0.8.0"])
        self.assertEqual(self.run_script().returncode, 0)
        self.pin_example("v0.8.0", "sha256:" + "c" * 64)
        r = self.run_script()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("the tag moved, or the pin is wrong", r.stderr)

    def test_a_pin_for_another_tag_is_not_compared(self):
        git(self.repo, "tag", "v0.7.0")
        self.commit("two")
        self.pin_example("v0.8.0", "sha256:" + "c" * 64)
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
