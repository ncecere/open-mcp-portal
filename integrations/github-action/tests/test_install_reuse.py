"""Regression: several Action instances can install within one runner job."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("install_reuse", Path(__file__).resolve().parents[1] / "install.py")
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)


class InstallReuseTests(unittest.TestCase):
    def test_multiple_action_instances_have_separate_verified_installations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.touch()
            name = "omp-v0.10.1-linux-amd64"
            binary = b"verified-test-binary"
            assets = {name: binary, name + ".sigstore.json": b"test-bundle",
                      "checksums.txt": (hashlib.sha256(binary).hexdigest() + "  " + name + "\n").encode()}
            def download(request, timeout):
                return io.BytesIO(assets[request.full_url.rsplit("/", 1)[1]])
            with patch.dict(os.environ, RUNNER_TEMP=directory, GITHUB_OUTPUT=str(output)), \
                 patch.object(install.platform, "machine", return_value="x86_64"), \
                 patch.object(install.platform, "system", return_value="Linux"), \
                 patch.object(install.urllib.request, "urlopen", side_effect=download), \
                 patch.object(install.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as verify:
                install.main()
                install.main()
                paths = [Path(line.split("=", 1)[1]) for line in output.read_text().splitlines()]
                self.assertEqual(len(paths), 2)
                self.assertNotEqual(paths[0], paths[1])
                for path in paths:
                    self.assertEqual(path.read_bytes(), binary)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o700)
                self.assertEqual(verify.call_count, 2)


if __name__ == "__main__":
    unittest.main()
