"""Offline installation tests: exact signed identity, checksum, fail closed."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("install", Path(__file__).resolve().parents[1] / "install.py")
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)


class InstallTests(unittest.TestCase):
    def install(self, checksum=True, signature=True):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.touch()
            name = "omp-v0.10.1-linux-amd64"
            digest = hashlib.sha256(b"binary").hexdigest() if checksum else "0" * 64
            assets = {name: b"binary", name + ".sigstore.json": b"bundle",
                      "checksums.txt": f"{digest}  {name}\n".encode()}
            def download(request, timeout):
                self.assertEqual(timeout, 60)
                self.assertTrue(request.full_url.startswith(
                    "https://github.com/ncecere/open-mcp-portal/releases/download/v0.10.1/"))
                return io.BytesIO(assets[request.full_url.rsplit("/", 1)[1]])
            with patch.dict(os.environ, RUNNER_TEMP=directory, GITHUB_OUTPUT=str(output)), \
                 patch.object(install.platform, "machine", return_value="x86_64"), \
                 patch.object(install.platform, "system", return_value="Linux"), \
                 patch.object(install.urllib.request, "urlopen", side_effect=download), \
                 patch.object(install.subprocess, "run", return_value=subprocess.CompletedProcess([], 0 if signature else 1)) as verify:
                if not checksum or not signature:
                    with self.assertRaises(ValueError):
                        install.main()
                    self.assertEqual(output.read_text(), "")
                    self.assertNotEqual((root / "omp-action-cli" / name).stat().st_mode & 0o111, 0o111)
                else:
                    install.main()
                    self.assertEqual((root / "omp-action-cli" / name).stat().st_mode & 0o777, 0o700)
                    args = verify.call_args.args[0]
                    self.assertIn("verify-blob", args)
                    self.assertIn("https://github.com/ncecere/open-mcp-portal/.github/workflows/image.yml@refs/tags/v0.10.1", args)
                    self.assertIn("https://token.actions.githubusercontent.com", args)
                    self.assertIn("cli=", output.read_text())

    def test_signed_exact_release(self):
        self.install()

    def test_checksum_failure(self):
        self.install(checksum=False)

    def test_signature_failure(self):
        self.install(signature=False)
