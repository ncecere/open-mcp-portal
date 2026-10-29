#!/usr/bin/env bash
# SMOKE_SELFTEST=1 scripts/k8s-smoke.sh: runs the Kubernetes scenarios'
# assertion helpers (assert.sh) and cluster helpers (lib.sh) against fixtures
# and stub kubectl/curl programs. No cluster, no Docker, no network. Every
# helper gets inputs it must accept and inputs it must refuse: a gate that
# stopped checking would fail here, not silently pass in a real run.
#
# Needs bash, jq, openssl and awk. CI runs it in the `k8s` job.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SELF_TMP="$(mktemp -d "${TMPDIR:-/tmp}/omp-smoke-selftest.XXXXXX")"
trap 'rm -rf "$SELF_TMP"' EXIT
STUBS="$SELF_TMP/stubs"
mkdir -p "$STUBS"

# The scenarios' own definitions, as the real script has them.
fail() {
  printf 'smoke: FAIL: %s\n' "$*" >&2
  exit 1
}
log() { :; }
ok() { :; }
# shellcheck source=assert.sh
. "$ROOT/scripts/smoke/assert.sh"
# shellcheck source=lib.sh
. "$ROOT/scripts/smoke/lib.sh"

NS=omp-smoke
NS_CLIENT=omp-smoke-ingress
TMP="$SELF_TMP"
k() { kubectl "$@"; }
kn() { k -n "$NS" "$@"; }

PASSED=0
FAILED=0
ERR="$SELF_TMP/err"

# expect_ok NAME COMMAND...: the helper must accept.
expect_ok() {
  local name=$1
  shift
  if (
    "$@"
  ) >"$SELF_TMP/out" 2>"$ERR"; then
    PASSED=$((PASSED + 1))
  else
    FAILED=$((FAILED + 1))
    printf 'selftest: %s: should have passed, but: %s\n' "$name" "$(head -c 300 "$ERR")" >&2
  fi
}
# expect_fail NAME REGEX COMMAND...: the helper must refuse, with a message
# matching REGEX.
expect_fail() {
  local name=$1 regex=$2
  shift 2
  if (
    "$@"
  ) >"$SELF_TMP/out" 2>"$ERR"; then
    FAILED=$((FAILED + 1))
    printf 'selftest: %s: should have failed, but passed\n' "$name" >&2
  elif grep -Eq "$regex" "$ERR"; then
    PASSED=$((PASSED + 1))
  else
    FAILED=$((FAILED + 1))
    printf 'selftest: %s: failed with the wrong message (want /%s/): %s\n' "$name" "$regex" "$(head -c 300 "$ERR")" >&2
  fi
}
# expect_out NAME WANT COMMAND...: stdout must equal WANT.
expect_out() {
  local name=$1 want=$2 got
  shift 2
  got="$("$@" 2>"$ERR")"
  if [ "$got" = "$want" ]; then
    PASSED=$((PASSED + 1))
  else
    FAILED=$((FAILED + 1))
    printf 'selftest: %s: got "%s", want "%s"\n' "$name" "$got" "$want" >&2
  fi
}

# ---------------------------------------------------------------- generic
expect_ok "check_eq equal" check_eq x a a
expect_fail "check_eq different" "x: got 'a', want 'b'" check_eq x a b
expect_ok "check_lt" check_lt p95 120.5 400
expect_fail "check_lt over" "is not below" check_lt p95 450 400
expect_ok "check_ge" check_ge n 5 5
expect_fail "check_ge under" "is below" check_ge n 4 5
expect_ok "check_contains" check_contains w "hello world" "lo wo"
expect_fail "check_contains missing" "does not contain" check_contains w "hello" "xyz"
expect_ok "check_not_contains" check_not_contains w "hello" "xyz"
expect_fail "check_not_contains present" "contains" check_not_contains w "hello" "ell"

# ---------------------------------------------------------------- schema version
cat >"$SELF_TMP/doctor-ok.out" <<'EOF'
open-mcp-portal doctor (open-mcp-portal 0.8.0 (unknown); configuration checked for serve)

ok    postgres connect            13.2ms  PostgreSQL 17.11
ok    postgres migrations                 current (version 47)
EOF
cat >"$SELF_TMP/doctor-pending.out" <<'EOF'
FAIL  postgres migrations                 pending: the database is at version 46, this binary has 47
EOF
cat >"$SELF_TMP/doctor-newer.out" <<'EOF'
info  postgres migrations                 the database (version 48) is newer than this binary (47): an older binary during a rollout?
EOF
expect_out "doctor_version current" 47 doctor_version "$SELF_TMP/doctor-ok.out"
expect_out "doctor_version pending" 46 doctor_version "$SELF_TMP/doctor-pending.out"
expect_out "doctor_version newer" 48 doctor_version "$SELF_TMP/doctor-newer.out"
mkdir -p "$SELF_TMP/migrations"
touch "$SELF_TMP/migrations/00001_init.sql" "$SELF_TMP/migrations/00047_x.sql" "$SELF_TMP/migrations/00048_y.sql" "$SELF_TMP/migrations/embed.go"
expect_out "tree_latest_migration" 48 tree_latest_migration "$SELF_TMP/migrations"
expect_ok "schema advanced" check_schema_advanced 46 47 47
expect_ok "schema unchanged when the tree has no newer migration" check_schema_advanced 47 47 47
expect_fail "schema backwards" "went backwards" check_schema_advanced 47 46 46
expect_fail "schema behind the image" "carries migrations up to 48" check_schema_advanced 46 47 48
expect_fail "schema not a number" "not a number" check_schema_advanced 46 "" 47

# ---------------------------------------------------------------- request loops
expect_ok "probe clean" check_probe roll 120 0 20
expect_fail "probe failures" "3 of 120 requests failed" check_probe roll 120 3 20
expect_fail "probe too short" "did not run" check_probe roll 4 0 20
expect_fail "probe without summary" "reported no total" check_probe roll "" "" 20

# ---------------------------------------------------------------- Prometheus text
leader_file() { # FILE RETENTION ROLLUP NOTIFICATIONS
  cat >"$1" <<EOF
# HELP omp_loop_leader 1 when this replica led the loop's latest run
omp_loop_leader{loop="notifications"} $4
omp_loop_leader{loop="retention"} $2
omp_loop_leader{loop="usage_rollup"} $3
omp_http_requests_total{code="2xx",method="POST",route="POST /mcp/{slug}"} 40
EOF
}
leader_file "$SELF_TMP/m1.txt" 1 0 0
leader_file "$SELF_TMP/m2.txt" 0 1 1
leader_file "$SELF_TMP/m3.txt" 0 0 0
leader_file "$SELF_TMP/m-two.txt" 1 0 0
expect_out "prom_sum metric" 40 prom_sum "$SELF_TMP/m1.txt" omp_http_requests_total
expect_out "prom_sum label" 1 prom_sum "$SELF_TMP/m1.txt" omp_loop_leader 'loop="retention"'
expect_out "prom_sum none" 0 prom_sum "$SELF_TMP/m1.txt" omp_nothing
expect_out "loop_leaders sums the replicas" 1 loop_leaders retention "$SELF_TMP/m1.txt" "$SELF_TMP/m2.txt" "$SELF_TMP/m3.txt"
expect_out "loop_leaders missing" missing loop_leaders health "$SELF_TMP/m1.txt"
expect_ok "every loop has a leader" check_loop_leaders "retention usage_rollup notifications" "$SELF_TMP/m1.txt" "$SELF_TMP/m2.txt" "$SELF_TMP/m3.txt"
expect_ok "several replicas may report leading" check_loop_leaders "retention" "$SELF_TMP/m1.txt" "$SELF_TMP/m-two.txt"
expect_fail "no leader" 'loop="notifications"\} adds up to 0' check_loop_leaders "notifications" "$SELF_TMP/m3.txt" "$SELF_TMP/m3.txt"
expect_fail "loop not reported" 'no replica reports omp_loop_leader\{loop="health"\}' check_loop_leaders "health" "$SELF_TMP/m1.txt"
expect_ok "no leader while the lock is held elsewhere" check_no_leader_while_locked "retention usage_rollup notifications" "$SELF_TMP/m3.txt" "$SELF_TMP/m3.txt"
expect_fail "a leader although the lock is held" 'adds up to 1 while its advisory lock was held elsewhere' check_no_leader_while_locked "retention" "$SELF_TMP/m1.txt" "$SELF_TMP/m3.txt"

# ---------------------------------------------------------------- streaming
cat >"$SELF_TMP/sse-stream.txt" <<'EOF'
1000 event: message
1000 data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1,"progressToken":"t"}}
1000
1002 event: message
1002 data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":2,"progressToken":"t"}}
1002
1004 data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":3,"progressToken":"t"}}
1006 data: {"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"done"}]}}
EOF
# The same events, all delivered at the end: what a buffering proxy does.
sed 's/^[0-9]* /1006 /' "$SELF_TMP/sse-stream.txt" >"$SELF_TMP/sse-buffered.txt"
grep -v 'notifications/progress' "$SELF_TMP/sse-stream.txt" >"$SELF_TMP/sse-noprogress.txt"
grep -v '"id":7' "$SELF_TMP/sse-stream.txt" >"$SELF_TMP/sse-nofinal.txt"
expect_ok "sse streamed" check_sse_stream "$SELF_TMP/sse-stream.txt" 3 3 7
expect_fail "sse buffered" "proxy buffered the stream" check_sse_stream "$SELF_TMP/sse-buffered.txt" 3 3 7
expect_fail "sse without progress" "carried 0 progress" check_sse_stream "$SELF_TMP/sse-noprogress.txt" 3 3 7
expect_fail "sse without the response" "ended without the response" check_sse_stream "$SELF_TMP/sse-nofinal.txt" 3 3 7

# ---------------------------------------------------------------- shared rate limit
expect_ok "shared limit" check_shared_limit 60 60 120 60
expect_fail "per-replica limits" "counters are not shared" check_shared_limit 120 0 120 60
expect_fail "uncounted answers" "other answers" check_shared_limit 60 50 120 60
expect_ok "counter rows" check_counter_rows 120 120
expect_fail "counter rows differ" "got '90', want '120'" check_counter_rows 90 120

# ---------------------------------------------------------------- client address
expect_ok "client ip" check_client_ip x 10.244.1.5 10.244.1.5 203.0.113.9
expect_fail "client ip is the proxy" "audit client_ip is '10.244.2.2'" check_client_ip x 10.244.2.2 10.244.1.5 203.0.113.9
expect_fail "client ip spoofed" "spoofed" check_client_ip x 203.0.113.9 203.0.113.9 203.0.113.9

# ---------------------------------------------------------------- HTTP text
printf 'HTTP/2 302 \r\nLocation: /oauth/consent?client_id=a&state=b\r\nSet-Cookie: x=1\r\n\r\n' >"$SELF_TMP/headers.txt"
expect_out "header_value" "/oauth/consent?client_id=a&state=b" header_value "$SELF_TMP/headers.txt" location
expect_out "query_param" "b" query_param "/oauth/consent?client_id=a&state=b" state
expect_out "query_param first" "a" query_param "http://x/cb?client_id=a&state=b" client_id
# RFC 7636 appendix B.
expect_out "pkce_challenge" "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" pkce_challenge "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

# ---------------------------------------------------------------- k6 summary
write_k6() { # FILE FAILED_REQUESTS FAILED_CHECKS P95
  cat >"$1" <<EOF
{"metrics":{"http_reqs":{"count":900,"rate":30.1},
"http_req_failed":{"passes":$2,"fails":900,"value":0},
"checks":{"fails":$3,"passes":1800,"value":1},
"http_req_duration":{"avg":135.4,"min":19,"med":77,"max":1496,"p(90)":140,"p(95)":$4,"p(99)":1489}}}
EOF
}
write_k6 "$SELF_TMP/k6-ok.json" 0 0 560.4
write_k6 "$SELF_TMP/k6-failed.json" 3 0 560.4
write_k6 "$SELF_TMP/k6-checks.json" 0 5 560.4
write_k6 "$SELF_TMP/k6-slow.json" 0 0 4100.2
echo '{"metrics":{"http_reqs":{"count":10}}}' >"$SELF_TMP/k6-nop95.json"
echo 'not json' >"$SELF_TMP/k6-bad.json"
expect_ok "k6 summary ok" check_k6_summary "$SELF_TMP/k6-ok.json" 3000 500
expect_fail "k6 failed requests" "saw 3 failed requests" check_k6_summary "$SELF_TMP/k6-failed.json" 3000 500
expect_fail "k6 failed checks" "saw 5 failed checks" check_k6_summary "$SELF_TMP/k6-checks.json" 3000 500
expect_fail "k6 slow p95" "p\\(95\\) in ms: 4100.2 is not below 3000" check_k6_summary "$SELF_TMP/k6-slow.json" 3000 500
expect_fail "k6 too few requests" "k6 requests: 900 is below 5000" check_k6_summary "$SELF_TMP/k6-ok.json" 3000 5000
expect_fail "k6 without p95" "no http_req_duration" check_k6_summary "$SELF_TMP/k6-nop95.json" 3000 5
expect_fail "k6 not json" "has no metrics" check_k6_summary "$SELF_TMP/k6-bad.json" 3000 5

# ---------------------------------------------------------------- ingress scenario helpers
# shellcheck source=ingress.sh
. "$ROOT/scripts/smoke/ingress.sh"
expect_out "dex_subject (user 6a0f3c1e..., connector local)" "CiQ2YTBmM2MxZS0yYjRkLTRjOGEtOWU3Zi0wZDFhMmIzYzRkNWUSBWxvY2Fs" dex_subject 6a0f3c1e-2b4d-4c8a-9e7f-0d1a2b3c4d5e local
cat >"$SELF_TMP/cm.yaml" <<'EOF'
        image: "quay.io/jetstack/cert-manager-controller:v1.21.3"
        image: "quay.io/jetstack/cert-manager-cainjector:v1.21.3"
        image: "quay.io/jetstack/cert-manager-webhook:v1.21.3"
EOF
cat >"$SELF_TMP/eg.yaml" <<'EOF'
          image: envoyproxy/gateway:v1.9.3
        image: envoyproxy/gateway:v1.9.3
EOF
cp "$SELF_TMP/cm.yaml" "$SELF_TMP/cm.orig"
expect_ok "pin_images" pin_images "$SELF_TMP/cm.yaml" "$SELF_TMP/eg.yaml"
expect_out "pinned controller" '        image: "quay.io/jetstack/cert-manager-controller:v1.21.3@sha256:9f4f96a33c7774cef24466fcd85031997531a03a8d117f151126baa8d1290dcc"' sed -n 1p "$SELF_TMP/cm.yaml"
expect_out "pinned gateway (both occurrences)" 2 grep -c 'envoyproxy/gateway:v1.9.3@sha256:192fc9bd' "$SELF_TMP/eg.yaml"
cp "$SELF_TMP/cm.orig" "$SELF_TMP/cm2.yaml"
expect_fail "pin_images with a manifest that lacks an image" "no manifest has the image envoyproxy/gateway" pin_images "$SELF_TMP/cm2.yaml"

# ---------------------------------------------------------------- stub kubectl and curl
# kubectl: prints what STUB_KUBECTL_OUT says (default "42") and exits
# STUB_KUBECTL_RC; records its arguments.
cat >"$STUBS/kubectl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$STUB_LOG"
printf '%b\n' "${STUB_KUBECTL_OUT-42}"
exit "${STUB_KUBECTL_RC:-0}"
EOF
# curl: writes STUB_CURL_BODY to the -o file and prints the status like -w
# '%{http_code}' would.
cat >"$STUBS/curl" <<'EOF'
#!/usr/bin/env bash
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift ;;
  esac
  shift
done
body='{"data":1}'
[ -z "${STUB_CURL_BODY+x}" ] || body=$STUB_CURL_BODY
[ -z "$out" ] || printf '%s' "$body" >"$out"
printf '%s' "${STUB_CURL_CODE:-200}"
EOF
chmod +x "$STUBS/kubectl" "$STUBS/curl"
export STUB_LOG="$SELF_TMP/stub.log"
OLD_PATH="$PATH"
export PATH="$STUBS:$PATH"

: >"$STUB_LOG"
expect_out "pg_scalar" 42 pg_scalar omp "SELECT 42"
expect_ok "pg_sql arguments" grep -q -- "-n omp-smoke exec postgres-0 -- psql -U postgres -d omp -v ON_ERROR_STOP=1 -X -tAq -c SELECT 42" "$STUB_LOG"
STUB_KUBECTL_RC=1 STUB_KUBECTL_OUT='ERROR: relation "nope" does not exist' expect_fail "pg_sql error" 'psql on database omp failed: ERROR: relation "nope"' pg_sql omp "SELECT * FROM nope"
expect_out "pg_sql keeps rows" $'a|1\nb|2' env STUB_KUBECTL_OUT='a|1\nb|2' bash -c ". '$ROOT/scripts/smoke/lib.sh'; fail() { echo \"\$*\" >&2; exit 1; }; NS=x; k() { kubectl \"\$@\"; }; kn() { k -n x \"\$@\"; }; pg_sql db 'select'"

TRANSPORT=host
API_CODE=""
STUB_CURL_BODY='{"data":{"x":7}}' STUB_CURL_CODE=201 http_do "$SELF_TMP/body.out" -sS "http://x/y"
expect_out "http_do host: status" 201 echo "$API_CODE"
expect_out "http_do host: body" '{"data":{"x":7}}' cat "$SELF_TMP/body.out"
TRANSPORT=pod
POD_CURL_POD=curl-pod
POD_CURL_ARGS=(--resolve omp.smoke.test:443:10.96.0.9 --cacert /ca/ca.crt)
: >"$STUB_LOG"
STUB_KUBECTL_OUT='{"data":{"y":8}}\n404' http_do "$SELF_TMP/body2.out" -sS "https://omp.smoke.test/v1/me"
expect_out "http_do pod: status" 404 echo "$API_CODE"
expect_out "http_do pod: body" '{"data":{"y":8}}' cat "$SELF_TMP/body2.out"
expect_ok "http_do pod: runs curl in the client pod with the resolve and CA" grep -q -- "-n omp-smoke-ingress exec -i curl-pod -- curl --resolve omp.smoke.test:443:10.96.0.9 --cacert /ca/ca.crt -sS https://omp.smoke.test/v1/me -w" "$STUB_LOG"
TRANSPORT=host
export PATH="$OLD_PATH"

# ---------------------------------------------------------------- result
if [ "$FAILED" -ne 0 ]; then
  printf 'smoke selftest: FAILED (%s passed, %s failed)\n' "$PASSED" "$FAILED" >&2
  exit 1
fi
printf 'smoke selftest: PASS (%s cases)\n' "$PASSED"
