#!/usr/bin/env python3
"""Size and complexity guard for the hand-written Go code ("no hell files, no
hell functions"); the Go counterpart of web/scripts/check-size.mjs. Fails
(exit 1), one line per problem, when:

  - a source file is longer than 600 lines, or a test file longer than 1,000;
  - a function's cyclomatic complexity is over 30 and it is not listed in
    scripts/go-complexity-allow.txt, or it is listed and has grown; or
  - a listed function is no longer over the limit (remove its line: the list
    only ever shrinks).

Generated code is skipped (*.gen.go, internal/store/dbgen). Aim lower when you
write code: about 400 lines per file and a complexity of 15 per function.
Split a file by what its declarations are about; split a function into named
steps.

The allowlist records the functions that were over the limit when the guard
was added, each with its score then. `--update` rewrites it from the current
tree: use it only after making a listed function simpler.

Usage: scripts/check-go-quality.py [--update] [--sizes-only]
Complexity is measured by gocyclo (GOCYCLO, default: `go run` of the pinned
version, which needs the module cache or the network).
"""

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOW = ROOT / "scripts" / "go-complexity-allow.txt"
MAX_SOURCE = 600
MAX_TEST = 1000
MAX_COMPLEXITY = 30
GOCYCLO_VERSION = "v0.6.0"
GENERATED = re.compile(r"(\.gen\.go$|^internal/store/dbgen/)")


def go_files():
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.go"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout.split()
    return [f for f in out if not GENERATED.search(f) and (ROOT / f).is_file()]


def size_problems(files):
    problems = []
    for f in files:
        with open(ROOT / f, "rb") as fh:
            lines = sum(1 for _ in fh)
        limit = MAX_TEST if f.endswith("_test.go") else MAX_SOURCE
        if lines > limit:
            problems.append(f"{f}: {lines} lines (limit {limit})")
    return problems


def measure():
    """The functions over the limit: {"pkg func file": score}."""
    tool = os.environ.get("GOCYCLO")
    cmd = shlex.split(tool) if tool else [
        os.environ.get("GO", "go"), "run", f"github.com/fzipp/gocyclo/cmd/gocyclo@{GOCYCLO_VERSION}"]
    # gocyclo exits 1 when anything is over the limit; its output is the result.
    res = subprocess.run(
        cmd + ["-over", str(MAX_COMPLEXITY), "-ignore", r"(_test\.go$|\.gen\.go$|internal/store/dbgen/)",
               "cmd", "internal", "pkg", "examples"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if res.returncode not in (0, 1):
        sys.exit(f"gocyclo failed:\n{res.stderr}")
    over = {}
    for line in res.stdout.splitlines():
        score, pkg, func, pos = line.split(" ", 3)
        over[f"{pkg} {func} {pos.split(':')[0]}"] = int(score)
    return over


def read_allow():
    allowed = {}
    if ALLOW.exists():
        for line in ALLOW.read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                score, key = line.split(" ", 1)
                allowed[key] = int(score)
    return allowed


def write_allow(over):
    lines = [
        "# Functions over the complexity limit when scripts/check-go-quality.py was",
        "# added, with their score then. The list only shrinks: simplify a function,",
        "# then run scripts/check-go-quality.py --update. Never add a line by hand.",
    ]
    lines += [f"{score} {key}" for key, score in sorted(over.items(), key=lambda kv: (-kv[1], kv[0]))]
    ALLOW.write_text("\n".join(lines) + "\n")


def complexity_problems(over, allowed):
    problems = []
    for key, score in sorted(over.items(), key=lambda kv: -kv[1]):
        if key not in allowed:
            problems.append(f"{key}: complexity {score} (limit {MAX_COMPLEXITY}): split it into named steps")
        elif score > allowed[key]:
            problems.append(f"{key}: complexity grew from {allowed[key]} to {score}")
    for key in sorted(set(allowed) - set(over)):
        problems.append(f"{key}: no longer over the limit: run scripts/check-go-quality.py --update")
    return problems


def main():
    args = set(sys.argv[1:])
    problems = size_problems(go_files())
    if "--sizes-only" not in args:
        over = measure()
        if "--update" in args:
            write_allow(over)
            print(f"{ALLOW.relative_to(ROOT)}: {len(over)} functions over the limit")
        else:
            problems += complexity_problems(over, read_allow())
    for p in problems:
        print(p)
    if problems:
        print(f"\n{len(problems)} problem(s). See the header of scripts/check-go-quality.py.")
        sys.exit(1)


if __name__ == "__main__":
    main()
