#!/usr/bin/env bash
# Proves that the upgrade scenario fails when it should: a migration that
# breaks the previous release's code.
#
#   scripts/k8s-upgrade-canary.sh        # about 5 minutes; same tools as make k8s-smoke
#
# It copies the working tree to a scratch directory and, in the copy only:
#   - adds a throwaway migration that turns on row-level security on api_keys with
#     a policy that hides every row from a connection whose application_name is
#     "open-mcp-portal" (what the previous release, and this tree, connect as);
#   - changes the application_name the copy connects as to "open-mcp-portal-canary",
#     so the copy's own code is not affected: it stands for a new release whose
#     code was written for the new schema.
# The repository is never touched: no file under migrations/ is added, and the
# throwaway migration exists only in the scratch directory and in the image built
# from it. The image is then run through `SMOKE_SCENARIO=upgrade`, which must FAIL,
# at the request loop of the rollout (the previous release's pods, still serving
# while the new pod migrates, lose every API key), not for another reason.
#
# Exit status 0 means "the gate caught the breakage". Settings: SMOKE_CNI,
# SMOKE_CLUSTER (must start with omp-smoke), SMOKE_ARTIFACTS, SMOKE_FROM_TAG.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/omp-upgrade-canary.XXXXXX")"
LOG="$SCRATCH/upgrade.log"
cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT

SRC="$SCRATCH/tree"
mkdir -p "$SRC"
# Tracked files (with their working-tree content) and untracked files that are
# not ignored; a file deleted in the working tree is skipped.
(cd "$ROOT" && git ls-files -z --cached --others --exclude-standard | tar --null --ignore-failed-read -T - -cf -) | tar -xf - -C "$SRC"

latest="$(find "$SRC/migrations" -maxdepth 1 -name '[0-9]*_*.sql' -exec basename {} \; | sed -n 's/^\([0-9]*\)_.*/\1/p' | sort -n | tail -n 1)"
next="$(printf '%05d' $((10#$latest + 1)))"
migration="$SRC/migrations/${next}_canary_hide_api_keys_from_the_previous_release.sql"
cat >"$migration" <<'EOF'
-- +goose Up
-- THROWAWAY: written by scripts/k8s-upgrade-canary.sh into a scratch copy of the
-- tree, never committed. It breaks the previous release's code on purpose: its
-- connections (application_name 'open-mcp-portal') see no API key and can write none.
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY canary_new_code_only ON public.api_keys
    USING (current_setting('application_name', true) <> 'open-mcp-portal');

-- +goose Down
DROP POLICY canary_new_code_only ON public.api_keys;
ALTER TABLE public.api_keys DISABLE ROW LEVEL SECURITY;
EOF
store="$SRC/internal/store/store.go"
grep -q 'RuntimeParams\["application_name"\] = "open-mcp-portal"' "$store" || { echo "canary: the application_name line in internal/store/store.go changed; update this script" >&2; exit 2; }
sed 's|RuntimeParams\["application_name"\] = "open-mcp-portal"|RuntimeParams["application_name"] = "open-mcp-portal-canary"|' "$store" >"$store.new" && mv "$store.new" "$store"
echo "canary: scratch tree $SRC with throwaway migration ${next} (not in the repository: $(git -C "$ROOT" status --porcelain -- migrations | wc -l | tr -d ' ') changes under migrations/)"

set +e
SMOKE_SCENARIO=upgrade SMOKE_BUILD_CONTEXT="$SRC" "$ROOT/scripts/k8s-smoke.sh" 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
set -e

if [ "$rc" -eq 0 ]; then
  echo "canary: FAIL: the upgrade scenario PASSED although the migration breaks the previous release" >&2
  exit 1
fi
# It must fail where the breakage shows: the request loop of the rollout.
if ! grep -Eq 'smoke: FAIL: upgrade rollout: [0-9]+ of [0-9]+ requests failed' "$LOG"; then
  echo "canary: FAIL: the scenario failed (exit $rc), but not at the rollout's request loop; see $LOG (kept)" >&2
  trap - EXIT
  exit 1
fi
echo "canary: PASS: the upgrade scenario failed as it should ($(grep -E 'smoke: FAIL' "$LOG" | head -n 1))"
