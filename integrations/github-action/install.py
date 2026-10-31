#!/usr/bin/env python3
"""Install only a pinned release; verify its bundle and exact checksum entry."""
import hashlib
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile
import urllib.request

VERSION = "v0.10.1"


def main():
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    if platform.system() != "Linux":
        raise ValueError("Linux required")
    temporary = Path(os.environ["RUNNER_TEMP"])
    output = Path(os.environ["GITHUB_OUTPUT"])
    if (not temporary.is_absolute() or any(ord(c) < 33 for c in str(temporary))
            or not output.is_absolute() or output.is_symlink()
            or not stat.S_ISREG(output.stat().st_mode)):
        raise ValueError("unsafe runner paths")
    # A job may invoke the Action for several servers. Never reuse an earlier
    # installation or fail merely because another invocation used RUNNER_TEMP.
    root = Path(tempfile.mkdtemp(prefix="omp-action-cli-", dir=temporary.resolve(strict=True)))
    name = f"omp-{VERSION}-linux-{arch}"
    for asset in (name, name + ".sigstore.json", "checksums.txt"):
        request = urllib.request.Request(
            f"https://github.com/ncecere/open-mcp-portal/releases/download/{VERSION}/{asset}")
        with urllib.request.urlopen(request, timeout=60) as response:
            (root / asset).write_bytes(response.read(64 << 20))
    lines = (root / "checksums.txt").read_text().splitlines()
    entries = [line for line in lines if re.fullmatch(r"[0-9a-f]{64}  " + re.escape(name), line)]
    if len(entries) != 1 or hashlib.sha256((root / name).read_bytes()).hexdigest() != entries[0][:64]:
        raise ValueError("checksum")
    result = subprocess.run([
        "cosign", "verify-blob", str(root / name),
        "--bundle", str(root / (name + ".sigstore.json")),
        "--certificate-identity",
        f"https://github.com/ncecere/open-mcp-portal/.github/workflows/image.yml@refs/tags/{VERSION}",
        "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
    ], capture_output=True, timeout=120, check=False)
    if result.returncode:
        raise ValueError("signature")
    (root / name).chmod(0o700)
    with output.open("a") as stream:
        stream.write(f"cli={root / name}\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("::error::Pinned omp installation/verification failed; no portal operation attempted.")
        sys.exit(1)
