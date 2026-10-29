#!/usr/bin/env bash
# shellcheck disable=SC2034 # globals shared with scripts/k8s-smoke.sh and the other sourced files
# Assertion helpers of the Kubernetes scenarios (scripts/k8s-smoke.sh). Sourced,
# never run. Every helper works on values and files it is given, needs no
# cluster, and reports a violation through `fail MESSAGE` (the caller defines
# it: scripts/k8s-smoke.sh exits; selftest.sh runs each case in a subshell).
# `SMOKE_SELFTEST=1 scripts/k8s-smoke.sh` feeds them good and bad inputs, so a
# gate that stopped checking anything is caught without a cluster.
#
# Bash 3.2 compatible (macOS), like the script.

# ---------------------------------------------------------------- generic
# check_eq WHAT GOT WANT
check_eq() {
  [ "$2" = "$3" ] || fail "$1: got '$2', want '$3'"
}
# check_lt WHAT GOT LIMIT (integers or decimals): GOT must be below LIMIT.
check_lt() {
  awk -v a="$2" -v b="$3" 'BEGIN { exit !(a + 0 < b + 0) }' || fail "$1: $2 is not below $3"
}
# check_ge WHAT GOT WANT_MIN
check_ge() {
  awk -v a="$2" -v b="$3" 'BEGIN { exit !(a + 0 >= b + 0) }' || fail "$1: $2 is below $3"
}
# check_contains WHAT TEXT NEEDLE
check_contains() {
  case "$2" in *"$3"*) ;; *) fail "$1: '$(printf '%s' "$2" | head -c 300)' does not contain '$3'" ;; esac
}
# check_not_contains WHAT TEXT NEEDLE
check_not_contains() {
  case "$2" in *"$3"*) fail "$1: '$(printf '%s' "$2" | head -c 300)' contains '$3'" ;; esac
}

# ---------------------------------------------------------------- schema version
# doctor_version FILE: the schema version `doctor` printed on its
# "postgres migrations" line ("current (version 47)", "pending: the database
# is at version 46, ...", "the database (version 47) is newer than ...").
doctor_version() {
  grep 'postgres migrations' "$1" | sed -n 's/.*version \([0-9][0-9]*\).*/\1/p' | head -n 1
}
# tree_latest_migration DIR: the highest migration number in DIR (NNNNN_name.sql).
tree_latest_migration() {
  find "$1" -maxdepth 1 -name '[0-9][0-9]*_*.sql' -exec basename {} \; | sed -n 's/^0*\([0-9][0-9]*\)_.*/\1/p' | sort -n | tail -n 1
}
# check_schema_advanced BEFORE AFTER TREE_LATEST: after an upgrade the schema
# must be at the version the new image carries, never behind where it was. It
# need not move when the new image has no newer migration than the old one:
# then the assertion is "unchanged", and the log line says so.
check_schema_advanced() {
  local before=$1 after=$2 tree=$3
  [[ "$before" =~ ^[0-9]+$ ]] || fail "schema version before the upgrade is not a number: '$before'"
  [[ "$after" =~ ^[0-9]+$ ]] || fail "schema version after the upgrade is not a number: '$after'"
  [[ "$tree" =~ ^[0-9]+$ ]] || fail "the working tree's latest migration is not a number: '$tree'"
  [ "$after" -ge "$before" ] || fail "the schema went backwards: $before -> $after"
  [ "$after" -eq "$tree" ] || fail "after the upgrade doctor reports schema version $after, but the new image carries migrations up to $tree"
  if [ "$after" -gt "$before" ]; then
    SCHEMA_NOTE="schema advanced $before -> $after"
  else
    SCHEMA_NOTE="schema unchanged at $after (the previous release already carried every migration of this tree)"
  fi
}

# ---------------------------------------------------------------- request loops
# check_probe WHAT TOTAL FAILS MIN_TOTAL: the in-cluster request loop ran
# (MIN_TOTAL requests at least, so a loop that never started cannot pass) and
# no request failed.
check_probe() {
  local what=$1 total=$2 fails=$3 min=$4
  [[ "$total" =~ ^[0-9]+$ ]] || fail "$what: the request loop reported no total ('$total')"
  [[ "$fails" =~ ^[0-9]+$ ]] || fail "$what: the request loop reported no failure count ('$fails')"
  [ "$total" -ge "$min" ] || fail "$what: the request loop made only $total requests (want at least $min); it did not run"
  [ "$fails" -eq 0 ] || fail "$what: $fails of $total requests failed"
}

# ---------------------------------------------------------------- Prometheus text
# prom_sum FILE METRIC [LABEL_FRAGMENT]: the sum of METRIC's samples in a
# Prometheus text exposition file, optionally only those whose label set
# contains LABEL_FRAGMENT (for example 'loop="retention"'). 0 when none.
prom_sum() {
  awk -v m="$2" -v frag="${3-}" '
    $0 ~ "^" m "[{ ]" {
      if (frag != "" && index($0, frag) == 0) next
      v = $NF
      sum += v
    }
    END { printf "%.10g\n", sum + 0 }' "$1"
}
# loop_leaders LOOP FILE...: the sum of omp_loop_leader{loop="LOOP"} over the
# replicas' metrics files, or "missing" when no file reports the loop. The
# gauge is 1 when a replica led the loop's LATEST run (it got the advisory lock),
# so the sum is not "1 leader at all times": runs are short, each replica
# usually finds the lock free at its own tick, and several replicas can show 1
# at once. What the lock guarantees is that runs never overlap, which
# check_no_leader_while_locked proves by holding the lock.
loop_leaders() {
  local loop=$1
  shift
  cat "$@" | awk -v frag="loop=\"$loop\"" '$0 ~ "^omp_loop_leader[{]" && index($0, frag) { s += $NF; n++ } END { if (n == 0) print "missing"; else printf "%d\n", s }'
}
# check_loop_leaders "LOOP LOOP ..." FILE...: every loop is led by at least one
# replica (the "no loop leader" alert's condition would not fire).
check_loop_leaders() {
  local loops=$1 loop total
  shift
  [ "$#" -ge 1 ] || fail "check_loop_leaders: no metrics files"
  for loop in $loops; do
    total="$(loop_leaders "$loop" "$@")"
    [ "$total" != missing ] || fail "no replica reports omp_loop_leader{loop=\"$loop\"}"
    [ "$total" -ge 1 ] || fail "omp_loop_leader{loop=\"$loop\"} adds up to $total over $# replicas: no replica leads the loop"
  done
}
# check_no_leader_while_locked "LOOP LOOP ..." FILE...: taken while something else
# holds the loops' advisory locks, no replica may report leading: the lock, not
# the replica count, decides who runs a loop.
check_no_leader_while_locked() {
  local loops=$1 loop total
  shift
  for loop in $loops; do
    total="$(loop_leaders "$loop" "$@")"
    [ "$total" != missing ] || fail "no replica reports omp_loop_leader{loop=\"$loop\"}"
    [ "$total" -eq 0 ] || fail "omp_loop_leader{loop=\"$loop\"} adds up to $total while its advisory lock was held elsewhere: a replica ran the loop without the lock"
  done
}

# ---------------------------------------------------------------- streaming (SSE)
# check_sse_stream FILE MIN_EVENTS MIN_SPREAD_SECONDS REQUEST_ID: FILE holds the
# stream a client read, every line prefixed with the epoch second it arrived
# in ("<epoch> data: {...}"). A proxy that streams delivers the progress
# notifications while the call runs: at least MIN_EVENTS of them, the first
# one MIN_SPREAD_SECONDS or more before the final response. A proxy that buffers
# delivers everything together at the end (spread 0).
check_sse_stream() {
  local file=$1 min_events=$2 min_spread=$3 id=$4 n first last
  n="$(grep -c 'notifications/progress' "$file" || true)"
  [ "$n" -ge "$min_events" ] || fail "the stream carried $n progress notification(s), want at least $min_events: $(head -c 400 "$file")"
  first="$(grep 'notifications/progress' "$file" | head -n 1 | cut -d' ' -f1)"
  last="$(grep "\"id\":${id}," "$file" | grep '"result"' | tail -n 1 | cut -d' ' -f1)"
  [ -n "$last" ] || fail "the stream ended without the response for request id $id: $(tail -c 400 "$file")"
  [[ "$first" =~ ^[0-9]+$ && "$last" =~ ^[0-9]+$ ]] || fail "unreadable timestamps in the stream file"
  [ $((last - first)) -ge "$min_spread" ] ||
    fail "the first progress event arrived $((last - first))s before the response, want at least ${min_spread}s: the proxy buffered the stream"
}

# ---------------------------------------------------------------- k6
# check_k6_summary FILE MAX_P95_MS MIN_REQUESTS: a `k6 --summary-export` file
# (k6 v1+/v2: flat metric objects) shows no failed request and no failed
# check, enough requests, and a p95 under the loose bound.
check_k6_summary() {
  local file=$1 max_p95=$2 min_reqs=$3 reqs failed checks_failed p95
  jq -e '.metrics' "$file" >/dev/null 2>&1 || fail "k6 summary $file has no metrics"
  reqs="$(jq -r '.metrics.http_reqs.count // 0' "$file")"
  failed="$(jq -r '(.metrics.http_req_failed.passes // 0)' "$file")"
  checks_failed="$(jq -r '(.metrics.checks.fails // 0)' "$file")"
  p95="$(jq -r '.metrics.http_req_duration["p(95)"] // empty' "$file")"
  [ -n "$p95" ] || fail "k6 summary has no http_req_duration p(95)"
  check_ge "k6 requests" "$reqs" "$min_reqs"
  [ "$failed" = 0 ] || fail "k6 saw $failed failed requests of $reqs"
  [ "$checks_failed" = 0 ] || fail "k6 saw $checks_failed failed checks"
  check_lt "k6 http_req_duration p(95) in ms" "$p95" "$max_p95"
}

# ---------------------------------------------------------------- rate limits
# check_shared_limit OK LIMITED SENT LIMIT: SENT requests went through the
# Service (so over every replica) against a limit of LIMIT per window. One
# shared counter admits LIMIT of them and refuses the rest. Counters kept per
# replica would admit up to LIMIT on each replica, so more than LIMIT requests
# would succeed.
check_shared_limit() {
  local ok=$1 limited=$2 sent=$3 limit=$4
  [ $((ok + limited)) -eq "$sent" ] || fail "rate limit run: $ok accepted + $limited limited != $sent sent (other answers?)"
  [ "$ok" -eq "$limit" ] || fail "with a limit of $limit per minute shared by every replica exactly $limit requests should pass, but $ok did ($limited were limited): the counters are not shared"
}
# check_counter_rows SUM EXPECTED: the rate_limit_counters rows of the
# gateway's bucket add up to the number of requests counted.
check_counter_rows() {
  check_eq "rate_limit_counters count for the gateway's bucket" "$1" "$2"
}

# ---------------------------------------------------------------- client address
# check_client_ip WHAT GOT WANT SPOOFED: the audited address is the real
# caller's, never the proxy's and never the one the caller put in
# X-Forwarded-For.
check_client_ip() {
  local what=$1 got=$2 want=$3 spoofed=${4-}
  [ "$got" = "$want" ] || fail "$what: audit client_ip is '$got', want '$want'"
  if [ -n "$spoofed" ] && [ "$got" = "$spoofed" ]; then
    fail "$what: audit client_ip is the spoofed X-Forwarded-For value $spoofed"
  fi
}

# ---------------------------------------------------------------- HTTP text
# header_value FILE NAME: the (last) value of a response header in a
# `curl -D` dump, without the trailing CR.
header_value() {
  tr -d '\r' <"$1" | awk -v n="$2" 'tolower($1) == tolower(n) ":" { sub(/^[^:]*: */, ""); v = $0 } END { print v }'
}
# query_param URL NAME: a query parameter of a URL, as it is written in it
# (codes and states of this portal and Dex need no decoding).
query_param() {
  printf '%s' "$1" | sed -n "s/.*[?&]$2=\\([^&#]*\\).*/\\1/p" | head -n 1
}
# pkce_challenge VERIFIER: the S256 code challenge.
pkce_challenge() {
  printf '%s' "$1" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
}
