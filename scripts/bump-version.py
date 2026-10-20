#!/usr/bin/env python3
"""Bump the version strings a release changes, and list every other mention of the old version.

    scripts/bump-version.py NEW [--date YYYY-MM-DD] [--check]

It edits only the places that name "the current version": internal/buildinfo, api/openapi.yaml, web/package.json and its
lock, the Kustomize base and example overlay (the overlay's digest goes back to the all-zeros placeholder until the
release exists), docs/deploy.md, README.md, SECURITY.md, the issue-form placeholders, and CHANGELOG.md (`## Unreleased`
becomes `## [NEW] - DATE`). It prints the remaining mentions of the old version for a human to judge (history, notes and
links to older release pages are meant to stay). Write docs/releases/vNEW.md yourself: image.yml refuses a tag without it.
`--check` changes nothing and only prints what would change. Run from the repository root.
"""
import argparse
import datetime
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ZERO = "sha256:" + "0" * 64


def current() -> str:
    m = re.search(r'Version = "([^"]+)"', (ROOT / "internal/buildinfo/buildinfo.go").read_text())
    if not m:
        sys.exit("cannot read the current version from internal/buildinfo")
    return m.group(1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("new")
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    if not re.fullmatch(r"\d+\.\d+\.\d+", a.new):
        sys.exit("NEW must look like 0.2.2")
    old, new = current(), a.new
    if old == new:
        sys.exit(f"already at {new}")
    changes: list[tuple[str, str]] = []

    def edit(path: str, subs: list[tuple[str, str]], count: int = 1, required: bool = True) -> None:
        p = ROOT / path
        s = p.read_text()
        for pat, rep in subs:
            s2, n = re.subn(pat, rep, s, count=count, flags=re.M)
            if n == 0 and required:
                sys.exit(f"{path}: pattern not found: {pat}")
            s = s2
        changes.append((path, "edited"))
        if not a.check:
            p.write_text(s)

    o, n_ = re.escape(old), new
    edit("internal/buildinfo/buildinfo.go", [(rf'Version = "{o}"', f'Version = "{n_}"')])
    edit("api/openapi.yaml", [(rf"^  version: {o}$", f"  version: {n_}")])
    edit("web/package.json", [(rf'"version": "{o}",', f'"version": "{n_}",')])
    edit("web/package-lock.json", [(rf'"version": "{o}",', f'"version": "{n_}",')], count=2)
    edit("deploy/kubernetes/base/kustomization.yaml", [(rf"newTag: v{o}", f"newTag: v{n_}")], count=0)
    edit("deploy/kubernetes/overlays/example/kustomization.yaml", [(rf"newTag: v{o}\n    digest: sha256:[0-9a-f]{{64}}", f"newTag: v{n_}\n    digest: {ZERO}")])
    edit("docs/deploy.md", [(rf"open-mcp-portal:v{o}", f"open-mcp-portal:v{n_}"), (rf"open-mcp-portal {o} \(<commit>\)", f"open-mcp-portal {n_} (<commit>)"),
                            (rf"refs/tags/v{o}", f"refs/tags/v{n_}"), (rf"sets its tag to `v{o}`", f"sets its tag to `v{n_}`"), (rf"newTag: v{o}", f"newTag: v{n_}")], count=0, required=False)
    edit("README.md", [(rf"\*\*Development software \(v{o}\)\.\*\*", f"**Development software (v{n_}).**"), (rf"open-mcp-portal:v{o}", f"open-mcp-portal:v{n_}"),
                       (rf"refs/tags/v{o}", f"refs/tags/v{n_}"), (rf"what comes after v{o}", f"what comes after v{n_}")], count=0, required=False)
    edit("SECURITY.md", [(rf"latest release \(v{o}\)", f"latest release (v{n_})")])
    edit(".github/ISSUE_TEMPLATE/client_compatibility.yml", [(rf'placeholder: "{o}"', f'placeholder: "{n_}"')])
    edit(".github/ISSUE_TEMPLATE/bug_report.yml", [(rf'placeholder: "open-mcp-portal {o} \(', f'placeholder: "open-mcp-portal {n_} (')])
    edit("CHANGELOG.md", [(r"^## Unreleased$", f"## [{n_}] - {a.date}")])

    print(("would change" if a.check else "changed") + f" ({old} -> {new}):")
    for path, what in changes:
        print(f"  {path}")
    print("\nStill mentioning the old version (review: history and older release pages should stay):")
    out = subprocess.run(["grep", "-rnI", "--exclude-dir=node_modules", "--exclude-dir=.git", "--exclude-dir=dist", "--exclude=go.sum", "--exclude=package-lock.json",
                          "--exclude=schema.gen.ts", "-e", f"v{old}", "-e", f'"{old}"', "."], cwd=ROOT, capture_output=True, text=True).stdout
    for line in out.splitlines():
        if "docs/releases/" in line or "CHANGELOG.md" in line:
            continue
        print("  " + line[:170])
    if not (ROOT / f"docs/releases/v{n_}.md").exists():
        print(f"\nNOTE: docs/releases/v{n_}.md does not exist yet; write it before tagging.")


if __name__ == "__main__":
    main()
