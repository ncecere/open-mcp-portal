#!/usr/bin/env bash
# Only point this at a NEW disposable local PostgreSQL. Never use the dev DB.
set -euo pipefail
: "${OMP_TEST_DATABASE_URL:?Set the NEW disposable local PostgreSQL URL}"
case "$OMP_TEST_DATABASE_URL" in
  postgres://*@127.0.0.1:*/postgres|postgres://*@127.0.0.1:*/postgres\?sslmode=disable) ;;
  *) echo 'Refusing: use a disposable loopback PostgreSQL /postgres URL' >&2; exit 1 ;;
esac
[[ "$(go env GOVERSION)" == go1.26.10 ]] || { echo 'Go 1.26.10 required' >&2; exit 1; }
for mode in 0 1; do
  OMP_TEST_REQUIRE_DB=1 OMP_TEST_SPLIT_ROLES="$mode" \
    go test -p=2 -timeout=20m ./internal/httpapi -run '^TestOmp(CLI|ActionWorkflowAgainstThePortal)' -count=1
done
