#!/usr/bin/env bash
# shellcheck disable=SC2034 # globals shared with scripts/k8s-smoke.sh and the other sourced files
# Scenario "load" (SMOKE_SCENARIO=load): three replicas under a ramp of
# tools/call, checking what a single replica cannot show:
#
#   - zero errors and a loose p95 (k6, a pinned checksum-verified binary run in a
#     pod of the cluster against the Service, so the requests spread over every
#     replica)
#   - the rate limit counters are shared: a gateway limit of 60 a minute admits
#     exactly 60 of 120 requests that went through three replicas, and the
#     counter row in PostgreSQL holds all 120
#   - every background loop has a leader (omp_loop_leader over the replicas' own
#     /metrics), and the advisory lock alone decides it: with the notification and
#     retention locks held from outside, no replica leads either loop, and
#     both are led again once the lock is released. (The gauge says whether a replica led its
#     latest run, so it can be 1 on several replicas at once: runs are short and
#     the lock only keeps them from overlapping.)
#   - the database connections stay below max_connections
#
# It writes a JSON summary (SMOKE_SUMMARY, bin/k8s-load-summary.json): the
# workflow uploads it. This is a regression gate with loose bounds, not a
# benchmark.
#
# Sourced by scripts/k8s-smoke.sh.

LOAD_REPLICAS=3
LOAD_LIMIT=60          # the gateway's requests per minute in the shared-limit phase
LOAD_LIMIT_SENT=120    # requests sent against it
LOAD_P95_MS="${SMOKE_LOAD_P95_MS:-3000}"
LOAD_STAGES='[{"duration":"20s","target":8},{"duration":"30s","target":24},{"duration":"40s","target":24},{"duration":"10s","target":0}]'
LOAD_MIN_REQUESTS=800
# Governance is sampled at startup and every five minutes. Include its live
# leader signal here; the short external-lock exclusion below deliberately
# exercises notifications/retention only (governance exclusion is DB-tested).
LOOPS="notifications retention usage_rollup governance"

# start_load_client: a pod in the client namespace with the k6 binary and script.
start_load_client() {
  local k6bin="${SMOKE_K6:-$(command -v k6 || true)}"
  [ -n "$k6bin" ] && [ -x "$k6bin" ] || fail "k6 not found (scripts/install-smoke-tools.sh DIR k6, or SMOKE_K6=/path/to/k6)"
  K6_VERSION_LINE="$("$k6bin" version | head -n 1)"
  k -n "$NS_CLIENT" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: k6-load
  labels:
    app.kubernetes.io/name: omp-smoke-k6
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  enableServiceLinks: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 70
    runAsGroup: 70
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: k6
      image: ${PROBE_IMAGE}
      imagePullPolicy: IfNotPresent
      command: [sleep, "3600"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
      volumeMounts:
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: tmp
      emptyDir: {}
EOF
  wait_until "the k6 pod to run" 90 has_value "$NS_CLIENT" pod/k6-load '{.status.phase}' Running
  k -n "$NS_CLIENT" cp "$k6bin" k6-load:/tmp/k6 >/dev/null || fail "could not copy k6 into the pod"
  k -n "$NS_CLIENT" cp "$ROOT/scripts/smoke/load.js" k6-load:/tmp/load.js >/dev/null || fail "could not copy load.js into the pod"
  k -n "$NS_CLIENT" exec k6-load -- chmod +x /tmp/k6
}

# run_k6 MODE SUMMARY_FILE [ENV=VALUE...]: runs the script in the pod against
# the Service; the summary comes back to SUMMARY_FILE. Returns k6's exit status
# (non-zero when a threshold fails).
run_k6() {
  local mode=$1 out=$2 rc=0
  shift 2
  k -n "$NS_CLIENT" exec k6-load -- env "MODE=${mode}" "BASE=http://open-mcp-portal.${NS}.svc.cluster.local" "KEY=${API_KEY}" "GATEWAY=${GW_SLUG}" \
    "P95_MS=${LOAD_P95_MS}" "$@" /tmp/k6 run --quiet --no-usage-report --summary-export "/tmp/summary-${mode}.json" /tmp/load.js >"$TMP/k6-${mode}.log" 2>&1 || rc=$?
  k -n "$NS_CLIENT" cp "k6-load:/tmp/summary-${mode}.json" "$out" >/dev/null 2>&1 || true
  return "$rc"
}

# scrape_all PREFIX: /metrics of every portal pod into PREFIX-<pod>.txt;
# prints the files, one per line.
scrape_all() {
  local prefix=$1 pod port=19090
  for pod in $(portal_pods); do
    pod_metrics "$pod" "$port" "${prefix}-${pod}.txt"
    echo "${prefix}-${pod}.txt"
    port=$((port + 1))
  done
}

# advisory_locks_held N: at least N advisory locks are held by a session that is
# not a portal replica (the test's own psql).
advisory_locks_held() {
  [ "$(pg_scalar omp "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE l.locktype = 'advisory' AND l.granted AND a.application_name = 'psql'")" -ge "$1" ]
}

# wait_for_window_start: waits for the start of a fresh one-minute window on the
# database clock (the counters use date_trunc('minute', now())) so a 60-per-
# minute test is not split by a boundary.
wait_for_window_start() {
  local end=$((SECONDS + 75)) s
  while [ "$SECONDS" -lt "$end" ]; do
    s="$(pg_scalar omp "SELECT extract(second FROM now())::int")"
    if [ "$s" -ge 1 ] && [ "$s" -le 5 ]; then return 0; fi
    sleep 1
  done
  fail "no fresh minute window on the database clock within 75s"
}

# set_platform_limits VALUE: person and credential limits (600 and 300 a minute
# by default, Admin › Limits) would throttle one load generator; raise them.
set_platform_limits() {
  local rev
  api_ok GET /v1/admin/settings/limits
  rev="$(jq -r '.data.revision' "$TMP/api.out")"
  api_ok PUT /v1/admin/settings/limits "$(jq -nc --argjson v "$1" '{items:[{key:"person_per_minute",default:$v,ceiling:null},{key:"credential_per_minute",default:$v,ceiling:null}]}')" "$rev"
}
set_gateway_limit() { # VALUE-OR-null
  local rev
  api_ok GET "/v1/teams/smoke/gateways/${GW_ID}"
  rev="$(data .data.revision)"
  api_ok PATCH "/v1/teams/smoke/gateways/${GW_ID}" "$(jq -nc --argjson v "$1" '{rateLimitPerMinute:$v}')" "$rev"
}

scenario_load() {
  local pod
  REPLICAS=$LOAD_REPLICAS
  # cmd/fakemcp keeps every request it receives (it is a test double): at the
  # smoke overlay's 128Mi it is OOM-killed after about 6000 calls (found by the
  # first run of this scenario: its failed calls came back as HTTP 200 JSON-RPC
  # errors and k6's "returned the echoed text" check caught them).
  FAKEMCP_MEMORY=1Gi
  step "Install the working-tree image with ${LOAD_REPLICAS} replicas and metrics"
  create_namespaces
  create_secrets
  # NOTIFICATION_INTERVAL and RETENTION_INTERVAL at their minimums: the
  # leader check below needs every replica to try the loops' locks often.
  apply_overlay "METRICS_ADDR=:9090" "NOTIFICATION_INTERVAL=5s" "RETENTION_INTERVAL=1m"
  wait_for_stack
  check_eq "ready replicas" "$(kn get deploy open-mcp-portal -o jsonpath='{.status.readyReplicas}')" "$LOAD_REPLICAS"
  ok "${LOAD_REPLICAS} replicas are Ready on $(portal_nodes | wc -l | tr -d ' ') nodes, METRICS_ADDR=:9090"
  pf_start
  dev_signin
  seed_data
  start_load_client
  ok "k6 ($K6_VERSION_LINE) is in the cluster, next to the Service"
  mcp_tools_ok "the API key before the load" "" 2

  step "Shared rate limit counters: ${LOAD_LIMIT} a minute on the gateway, ${LOAD_LIMIT_SENT} requests over ${LOAD_REPLICAS} replicas"
  set_gateway_limit "$LOAD_LIMIT"
  wait_for_window_start
  local before_files=() after_files=() i
  # shellcheck disable=SC2207 # one file name per line, no spaces
  before_files=($(scrape_all "$TMP/m-before"))
  run_k6 limit "$TMP/summary-limit.json" "ITERATIONS=${LOAD_LIMIT_SENT}" || fail "k6 (limit phase) failed: $(tail -n 8 "$TMP/k6-limit.log")"
  # shellcheck disable=SC2207
  after_files=($(scrape_all "$TMP/m-after"))
  local accepted limited others
  accepted="$(jq -r '.metrics.omp_accepted.count // 0' "$TMP/summary-limit.json")"
  limited="$(jq -r '.metrics.omp_limited.count // 0' "$TMP/summary-limit.json")"
  others="$(jq -r '.metrics.omp_other_status.count // 0' "$TMP/summary-limit.json")"
  check_eq "requests answered with anything but 200 or 429" "$others" 0
  check_shared_limit "$accepted" "$limited" "$LOAD_LIMIT_SENT" "$LOAD_LIMIT"
  ok "${accepted} of ${LOAD_LIMIT_SENT} requests passed, ${limited} got 429: one counter for ${LOAD_REPLICAS} replicas"
  check_counter_rows "$(pg_scalar omp "SELECT coalesce(sum(count), 0) FROM rate_limit_counters WHERE bucket = 'g:${GW_ID}'")" "$LOAD_LIMIT_SENT"
  ok "rate_limit_counters holds all ${LOAD_LIMIT_SENT} requests in the gateway's bucket (refused ones count too)"
  local served=() delta total=0
  for i in "${!before_files[@]}"; do
    delta="$(awk -v a="$(prom_sum "${after_files[$i]}" omp_http_requests_total 'route="POST /mcp/{slug}"')" -v b="$(prom_sum "${before_files[$i]}" omp_http_requests_total 'route="POST /mcp/{slug}"')" 'BEGIN { printf "%d", a - b }')"
    served+=("$delta")
    total=$((total + delta))
    [ "$delta" -gt 0 ] || fail "replica $i served none of the ${LOAD_LIMIT_SENT} requests (served: ${served[*]}): the load did not reach every replica"
  done
  check_eq "requests the replicas counted together" "$total" "$LOAD_LIMIT_SENT"
  ok "every replica served part of them (${served[*]}), together ${total}"
  LIMIT_SERVED="${served[*]}"

  step "Ramp: tools/call echo, up to 24 virtual users, ${LOAD_REPLICAS} replicas"
  set_gateway_limit null
  set_platform_limits 1000000
  log "the platform limits apply on every replica within 30 s"
  sleep 35
  local peak=0 conns k6pid k6rc=0
  k -n "$NS_CLIENT" exec k6-load -- env "MODE=ramp" "BASE=http://open-mcp-portal.${NS}.svc.cluster.local" "KEY=${API_KEY}" "GATEWAY=${GW_SLUG}" \
    "P95_MS=${LOAD_P95_MS}" "STAGES=${LOAD_STAGES}" /tmp/k6 run --quiet --no-usage-report --summary-export /tmp/summary-ramp.json /tmp/load.js >"$TMP/k6-ramp.log" 2>&1 &
  k6pid=$!
  LOG_PIDS="$LOG_PIDS $k6pid"
  while kill -0 "$k6pid" 2>/dev/null; do
    conns="$(pg_scalar postgres "SELECT count(*) FROM pg_stat_activity WHERE datname = 'omp'")"
    [ "$conns" -le "$peak" ] || peak="$conns"
    sleep 4
  done
  wait "$k6pid" || k6rc=$?
  k -n "$NS_CLIENT" cp "k6-load:/tmp/summary-ramp.json" "$TMP/summary-ramp.json" >/dev/null 2>&1 || true
  [ -s "$TMP/summary-ramp.json" ] || fail "k6 produced no summary: $(tail -n 8 "$TMP/k6-ramp.log")"
  check_k6_summary "$TMP/summary-ramp.json" "$LOAD_P95_MS" "$LOAD_MIN_REQUESTS"
  [ "$k6rc" = 0 ] || fail "k6 exited $k6rc (a threshold failed): $(tail -n 12 "$TMP/k6-ramp.log")"
  ok "$(jq -r '.metrics.http_reqs.count' "$TMP/summary-ramp.json") requests, 0 failed, 0 failed checks, p95 $(jq -r '.metrics.http_req_duration["p(95)"] | floor' "$TMP/summary-ramp.json") ms (bound ${LOAD_P95_MS} ms)"

  step "Background loops: a leader each, and the advisory lock decides"
  local leader_files=()
  # shellcheck disable=SC2207
  leader_files=($(scrape_all "$TMP/m-leader"))
  check_loop_leaders "$LOOPS" "${leader_files[@]}"
  local leaders=""
  for pod in $LOOPS; do
    leaders="${leaders}${pod}=$(loop_leaders "$pod" "${leader_files[@]}") "
  done
  ok "every loop has a leader over ${#leader_files[@]} replicas (omp_loop_leader summed: ${leaders% }; the gauge says which replica led its latest run, so it can exceed 1)"
  # Hold the notification and retention locks from outside: no replica may run
  # either loop meanwhile (their ticks are 5 s and 1 min), and both run again
  # once the lock is free.
  kn exec postgres-0 -- psql -U postgres -d omp -X -q \
    -c "SELECT pg_advisory_lock(hashtextextended('omp.notifications', 0)), pg_advisory_lock(hashtextextended('omp.retention', 0)); SELECT pg_sleep(85)" \
    >"$TMP/lock-holder.out" 2>&1 &
  local holder=$!
  LOG_PIDS="$LOG_PIDS $holder"
  wait_until "the advisory locks to be held" 30 advisory_locks_held 2
  log "holding omp.notifications and omp.retention for 85 s; waiting for every replica's next tick (1 min for retention)"
  sleep 66
  # shellcheck disable=SC2207
  leader_files=($(scrape_all "$TMP/m-locked"))
  check_no_leader_while_locked "notifications retention" "${leader_files[@]}"
  ok "with both locks held elsewhere no replica led notifications or retention in its latest run"
  wait "$holder" || fail "the lock-holding psql failed: $(cat "$TMP/lock-holder.out")"
  local recover_end=$((SECONDS + 100)) recovered=0
  while [ "$SECONDS" -lt "$recover_end" ]; do
    # shellcheck disable=SC2207
    leader_files=($(scrape_all "$TMP/m-recovered"))
    if (check_loop_leaders "notifications retention" "${leader_files[@]}") 2>/dev/null; then
      recovered=1
      break
    fi
    sleep 5
  done
  [ "$recovered" = 1 ] || fail "after the locks were released no replica led notifications and retention again within 100 s"
  ok "released, the loops are led again: the lock alone decides who runs a loop"

  step "The database's connections"
  local maxc pool_sum=0 pool_max=0 p
  maxc="$(pg_scalar postgres "SHOW max_connections")"
  conns="$(pg_scalar postgres "SELECT count(*) FROM pg_stat_activity WHERE datname = 'omp'")"
  [ "$conns" -le "$peak" ] || peak="$conns"
  check_lt "database connections at the peak of the ramp (max_connections ${maxc})" "$peak" "$maxc"
  for p in "${leader_files[@]}"; do
    pool_sum=$((pool_sum + $(prom_sum "$p" omp_db_pool_connections)))
    pool_max=$((pool_max + $(prom_sum "$p" omp_db_pool_max_connections)))
  done
  check_lt "the replicas' pools together (their limits add up to ${pool_max}; max_connections ${maxc})" "$pool_sum" "$maxc"
  ok "database connections: peak ${peak} during the ramp, ${conns} now, replicas' pools hold ${pool_sum} (limits ${pool_max}); max_connections ${maxc}"

  write_load_summary "$peak" "$maxc" "$pool_sum" "$pool_max" "$leaders" "$accepted" "$limited"
  ok "summary written to ${SMOKE_SUMMARY:-$ROOT/bin/k8s-load-summary.json}"
}

write_load_summary() { # PEAK MAX_CONNECTIONS POOL_SUM POOL_MAX LEADERS ACCEPTED LIMITED
  local out="${SMOKE_SUMMARY:-$ROOT/bin/k8s-load-summary.json}"
  mkdir -p "$(dirname "$out")"
  jq -n --arg scenario load --arg cni "$CNI" --arg k6 "$K6_VERSION_LINE" --arg commit "$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)" \
    --argjson replicas "$LOAD_REPLICAS" --argjson p95bound "$LOAD_P95_MS" --argjson minreq "$LOAD_MIN_REQUESTS" \
    --argjson peak "$1" --argjson maxc "$2" --argjson poolsum "$3" --argjson poolmax "$4" --arg leaders "$5" \
    --argjson accepted "$6" --argjson limited "$7" --arg served "$LIMIT_SERVED" --arg stages "$LOAD_STAGES" \
    --slurpfile ramp "$TMP/summary-ramp.json" \
    '{scenario:$scenario, cni:$cni, commit:$commit, k6:$k6, replicas:$replicas,
      ramp:{stages:($stages|fromjson), requests:$ramp[0].metrics.http_reqs.count, failedRequests:$ramp[0].metrics.http_req_failed.passes,
            failedChecks:$ramp[0].metrics.checks.fails, p95Ms:$ramp[0].metrics.http_req_duration["p(95)"],
            p99Ms:$ramp[0].metrics.http_req_duration["p(99)"], avgMs:$ramp[0].metrics.http_req_duration.avg,
            maxMs:$ramp[0].metrics.http_req_duration.max, ratePerSecond:$ramp[0].metrics.http_reqs.rate, p95BoundMs:$p95bound},
      sharedRateLimit:{limitPerMinute:60, sent:($accepted+$limited), accepted:$accepted, limited:$limited, servedPerReplica:($served|split(" ")|map(tonumber))},
      leaders:($leaders|split(" ")|map(select(length>0)|split("=")|{(.[0]):(.[1]|tonumber)})|add),
      database:{peakConnectionsDuringRamp:$peak, maxConnections:$maxc, poolConnectionsAfter:$poolsum, poolLimitsTotal:$poolmax},
      passed:true}' >"$out"
}
