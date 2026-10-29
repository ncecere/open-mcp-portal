#!/usr/bin/env bash
# shellcheck disable=SC2034 # globals shared with scripts/k8s-smoke.sh and the other sourced files
# Helpers shared by the Kubernetes scenarios that talk to the cluster through
# kubectl or curl. Sourced by scripts/k8s-smoke.sh, which defines `k`, `kn`,
# `fail`, `log`, `ok`, `NS`, `NS_CLIENT` and TMP. They are kept apart from the
# script so SMOKE_SELFTEST=1 can run them against a stub kubectl and stub curl
# (scripts/smoke/selftest.sh).

# ---------------------------------------------------------------- transport
# The two ways a request reaches the portal. Host (default): curl on this
# machine, through the port-forward. Pod (the ingress scenario): curl in a pod
# of the cluster that resolves omp.smoke.test to the gateway's Service and
# trusts the self-signed CA, so the request takes the path a client's does,
# TLS included, and the portal sees that pod's address.
TRANSPORT=host
COOKIES=""            # the cookie jar: a file here, or in the pod (/tmp/cookies)
POD_CURL_ARGS=()      # set by the ingress scenario: --resolve, --cacert
POD_CURL_POD=""
curl_run() {
  if [ "$TRANSPORT" = pod ]; then
    k -n "$NS_CLIENT" exec -i "$POD_CURL_POD" -- curl "${POD_CURL_ARGS[@]}" "$@"
  else
    curl "$@"
  fi
}
# http_do OUTFILE CURL-ARGS...: one request; the status in API_CODE and the
# body in OUTFILE, with either transport.
http_do() {
  local out=$1
  shift
  if [ "$TRANSPORT" = pod ]; then
    curl_run "$@" -w '\n%{http_code}' >"$TMP/http.raw" || return 1
    API_CODE="$(tail -n 1 "$TMP/http.raw")"
    sed '$d' "$TMP/http.raw" >"$out"
  else
    API_CODE="$(curl "$@" -o "$out" -w '%{http_code}')" || return 1
  fi
}

# ---------------------------------------------------------------- PostgreSQL
# pg_sql DATABASE SQL: runs SQL as the bootstrap superuser (over the pod's
# local socket) and prints the rows unaligned, tuples only. The smoke database
# is throwaway; the portal never connects as this role.
pg_sql() {
  local db=$1 sql=$2 out
  out="$(kn exec postgres-0 -- psql -U postgres -d "$db" -v ON_ERROR_STOP=1 -X -tAq -c "$sql" 2>&1)" ||
    fail "psql on database $db failed: $(printf '%s' "$out" | head -c 400) (SQL: $(printf '%s' "$sql" | head -c 200))"
  printf '%s\n' "$out"
}
# pg_scalar DATABASE SQL: the one value the query returns.
pg_scalar() {
  pg_sql "$1" "$2" | head -n 1
}

# ---------------------------------------------------------------- per-pod metrics
# pod_forward NAMESPACE POD REMOTE_PORT LOCAL_PORT: starts a port-forward to
# one pod in the background (its PID in FWD_PID). A port-forward reaches the
# pod whatever the NetworkPolicies say, so metrics can be read per replica
# without opening a policy for the test.
FWD_PID=""
pod_forward() {
  kubectl --kubeconfig "$KUBECONFIG_FILE" --context "$CONTEXT" -n "$1" port-forward "pod/$2" "$4:$3" >"$TMP/fwd-$2.log" 2>&1 &
  FWD_PID=$!
}
pod_forward_stop() {
  if [ -n "$FWD_PID" ]; then
    kill "$FWD_PID" 2>/dev/null || true
    wait "$FWD_PID" 2>/dev/null || true
    FWD_PID=""
  fi
}
# pod_metrics POD LOCAL_PORT OUTFILE: /metrics of one portal pod (METRICS_ADDR).
pod_metrics() {
  local pod=$1 port=$2 out=$3 end=$((SECONDS + 20))
  pod_forward "$NS" "$pod" 9090 "$port"
  until curl -fsS --max-time 3 -o "$out" "http://127.0.0.1:${port}/metrics" 2>/dev/null; do
    if [ "$SECONDS" -ge "$end" ]; then
      pod_forward_stop
      fail "could not read /metrics of pod $pod through a port-forward in 20s: $(tail -n 3 "$TMP/fwd-$pod.log" 2>/dev/null)"
    fi
    sleep 1
  done
  pod_forward_stop
}
