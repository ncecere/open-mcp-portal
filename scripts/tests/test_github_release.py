"""Dry-run tests of scripts/github-release.sh: the notes, the assets (the image's
SBOM, the digest and the cross-compiled omp binaries), their cosign bundles
(with a stub cosign) and checksums.txt. No network, no GitHub, no registry:
RELEASE_DRY_RUN=1 with RELEASE_SBOM_FILE.

Run: python3 -m unittest discover -s scripts/tests -p 'test_github_release.py' -v
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "github-release.sh"
TAG = "v0.9.0"
DIGEST = "sha256:" + "a" * 64
# Three targets keep the test fast; the script's default builds all six.
TARGETS = "linux/amd64 darwin/arm64 windows/arm64"
STUB_COSIGN = """#!/usr/bin/env bash
# Records its arguments and writes the bundle named by --bundle.
echo "$*" >> "$COSIGN_LOG"
bundle=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--bundle" ]; then bundle="$2"; shift; fi
  shift
done
[ -n "$bundle" ] && echo '{"stub":"bundle"}' > "$bundle"
"""


def host_target():
    out = subprocess.run(["go", "env", "GOHOSTOS", "GOHOSTARCH"], check=True, capture_output=True, text=True).stdout.split()
    return "%s/%s" % tuple(out)


class GithubReleaseDryRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("go") is None or shutil.which("jq") is None:
            raise unittest.SkipTest("go and jq are needed")
        cls.tmp = Path(tempfile.mkdtemp(prefix="omp-release-test-"))
        cls.sbom = cls.tmp / "sbom.json"
        cls.sbom.write_text(json.dumps({"linux/amd64": {"SPDX": {"spdxVersion": "SPDX-2.3"}}}))
        cls.cosign = cls.tmp / "cosign-stub"
        cls.cosign.write_text(STUB_COSIGN)
        cls.cosign.chmod(0o755)
        cls.log = cls.tmp / "cosign.log"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_script(self, out, sign=False, **extra):
        env = dict(os.environ, RELEASE_DRY_RUN="1", TAG=TAG, DIGEST=DIGEST, RELEASE_SBOM_FILE=str(self.sbom),
                   RELEASE_OUT=str(out), RELEASE_CLI_TARGETS=TARGETS, GITHUB_SHA="0123456789abcdef0123456789abcdef01234567",
                   COSIGN_LOG=str(self.log))
        env.pop("RELEASE_COSIGN", None)
        if sign:
            env["RELEASE_COSIGN"] = str(self.cosign)
        env.update(extra)
        return subprocess.run(["bash", str(SCRIPT)], cwd=ROOT, env=env, capture_output=True, text=True, timeout=600)

    def test_dry_run_builds_the_omp_binaries_without_signing_them(self):
        out = self.tmp / "unsigned"
        res = self.run_script(out)
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
        assets = out / "assets"
        names = sorted(p.name for p in assets.iterdir())
        self.assertEqual(names, sorted([
            "checksums.txt",
            "omp-v0.9.0-darwin-arm64",
            "omp-v0.9.0-linux-amd64",
            "omp-v0.9.0-windows-arm64.exe",
            "open-mcp-portal-v0.9.0-linux-amd64.sbom.spdx.json",
            "open-mcp-portal-v0.9.0.digest.txt",
        ]))
        # Real executables for each platform.
        self.assertEqual((assets / "omp-v0.9.0-linux-amd64").read_bytes()[:4], b"\x7fELF")
        self.assertEqual((assets / "omp-v0.9.0-windows-arm64.exe").read_bytes()[:2], b"MZ")
        self.assertIn(bytes.fromhex("cffaedfe"), (assets / "omp-v0.9.0-darwin-arm64").read_bytes()[:4])
        # checksums.txt covers every file but itself, and matches.
        sums = dict(reversed(line.split("  ", 1)) for line in (assets / "checksums.txt").read_text().splitlines())
        self.assertEqual(sorted(sums), sorted(n for n in names if n != "checksums.txt"))
        for name, digest in sums.items():
            self.assertEqual(hashlib.sha256((assets / name).read_bytes()).hexdigest(), digest, name)
        # The host's binary reports the tag's version and the commit.
        if host_target() == "linux/amd64":
            ver = subprocess.run([str(assets / "omp-v0.9.0-linux-amd64"), "version"], capture_output=True, text=True)
            self.assertEqual(ver.stdout.strip(), "omp 0.9.0 (0123456789ab)")
        notes = (out / "notes.md").read_text()
        for want in ["## omp command line", "cosign verify-blob omp-v0.9.0-linux-amd64",
                     "--bundle omp-v0.9.0-linux-amd64.sigstore.json",
                     "--certificate-identity https://github.com/ncecere/open-mcp-portal/.github/workflows/image.yml@refs/tags/v0.9.0",
                     "--certificate-oidc-issuer https://token.actions.githubusercontent.com",
                     "`omp-v0.9.0-<os>-<arch>`", "cosign verify ghcr.io/ncecere/open-mcp-portal@" + DIGEST]:
            self.assertIn(want, notes)

    def test_binaries_are_signed_when_a_cosign_is_given(self):
        out = self.tmp / "signed"
        self.log.write_text("")
        res = self.run_script(out, sign=True)
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
        assets = out / "assets"
        for name in ["omp-v0.9.0-linux-amd64", "omp-v0.9.0-darwin-arm64", "omp-v0.9.0-windows-arm64.exe"]:
            self.assertTrue((assets / (name + ".sigstore.json")).is_file(), name)
        calls = self.log.read_text().splitlines()
        self.assertEqual(len(calls), 3)
        for call in calls:
            self.assertTrue(call.startswith("sign-blob --yes --bundle "), call)
        sums = (assets / "checksums.txt").read_text()
        self.assertIn("omp-v0.9.0-linux-amd64.sigstore.json", sums)
        self.assertEqual(len(sums.splitlines()), 3 * 2 + 2)

    def test_a_failing_signature_stops_the_release(self):
        broken = self.tmp / "cosign-broken"
        broken.write_text("#!/usr/bin/env bash\nexit 1\n")
        broken.chmod(0o755)
        res = self.run_script(self.tmp / "broken", RELEASE_COSIGN=str(broken))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("could not sign omp-v0.9.0-", res.stderr)

    def test_unknown_targets_and_bad_tags_are_refused(self):
        res = self.run_script(self.tmp / "badtarget", RELEASE_CLI_TARGETS="plan9/amd64")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("unsupported target", res.stderr)
        res = self.run_script(self.tmp / "badtag", TAG="v1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TAG is not a vX.Y.Z tag", res.stderr)

    def test_the_script_does_not_publish_in_a_dry_run(self):
        # gh is not needed (and a failing one proves it is not called).
        fake_bin = self.tmp / "bin"
        fake_bin.mkdir(exist_ok=True)
        gh = fake_bin / "gh"
        gh.write_text("#!/usr/bin/env bash\necho gh was called >&2\nexit 1\n")
        gh.chmod(0o755)
        res = self.run_script(self.tmp / "nogh", PATH=str(fake_bin) + os.pathsep + os.environ["PATH"])
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("gh was called", res.stderr)


if __name__ == "__main__":
    unittest.main()
