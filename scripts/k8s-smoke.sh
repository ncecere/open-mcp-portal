#!/usr/bin/env bash
# Kubernetes smoke test: applies the Kustomize base (through overlays/smoke) to
# a throwaway multi-node kind cluster and checks that it works. docs/deploy.md,
# "Smoke test", says what this proves and what it does not.
#
#   make k8s-smoke                      # kindnet, the default CNI (no NetworkPolicy enforcement)
#   SMOKE_CNI=calico make k8s-smoke     # Calico: the NetworkPolicies are enforced and tested
#   SMOKE_SCENARIO=upgrade make k8s-smoke   # also: ingress, restore, load (below)
#   SMOKE_SELFTEST=1 scripts/k8s-smoke.sh   # the assertion helpers against stubs, no cluster
#
# Scenarios (SMOKE_SCENARIO; each one is a fresh cluster):
#   base     the single fresh install, a rolling update, pod deletion, PDB, NetworkPolicy
#   upgrade  install the previous release by digest, create data, roll to the working
#            tree under a request loop, then roll back (scripts/smoke/upgrade.sh)
#   ingress  Envoy Gateway + cert-manager TLS, APP_URL=https://omp.smoke.test, OIDC
#            through Dex, TRUSTED_PROXIES and SSE streaming (scripts/smoke/ingress.sh)
#   restore  pg_dump, more data, restore into a second database, repoint the portal
#            (scripts/smoke/restore.sh)
#   load     three replicas under a k6 ramp: errors, p95, shared rate limits, leaders,
#            connections (scripts/smoke/load.sh)
#
# What it does: builds the portal and fake MCP server images from the working
# tree, creates a cluster (1 control plane + 2 workers, node image pinned by
# tag and digest, its own kubeconfig in a temp directory), loads the images,
# applies the overlay, runs the assertions below through the real API, a
# rolling update and pod deletions, and deletes the cluster, the images and
# the temp directory (also when an assertion fails).
#
# It never touches ~/.kube or another cluster: every kubectl call names this
# script's kubeconfig and context, and KUBECONFIG points at it too.
#
# Settings (environment):
#   SMOKE_SCENARIO   base, upgrade, ingress, restore or load            (base)
#   SMOKE_CLUSTER    kind cluster name, must start with "omp-smoke"  (omp-smoke)
#   SMOKE_CNI        kindnet or calico                                (kindnet)
#   SMOKE_KEEP       1: keep the cluster, images and temp directory   (0)
#   SMOKE_ARTIFACTS  where a failed run leaves pods, events, logs     (bin/k8s-smoke-artifacts)
#   SMOKE_NODE_IMAGE the kind node image                              (pinned below)
#   SMOKE_TIMEOUT    seconds for the whole run, checked at each wait  (900; 1500 for
#                    upgrade, ingress and load)
#   SMOKE_BUILD_CONTEXT  the directory the portal image is built from (the repository;
#                    scripts/k8s-upgrade-canary.sh points it at a scratch copy)
#   SMOKE_FROM_IMAGE upgrade: the image to start from, a digest reference (default: the
#                    previous release, scripts/previous-release.sh)
#   SMOKE_FROM_TAG   upgrade: start from this release tag instead of the previous one
#   SMOKE_SUMMARY    load: where the JSON summary goes (bin/k8s-load-summary.json)
#
# Needs docker, kind, kubectl, curl and jq. Bash 3.2 compatible (macOS).
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The assertion helpers against stubs, no cluster, no Docker (scripts/smoke/selftest.sh).
if [ "${SMOKE_SELFTEST:-0}" = 1 ]; then
  exec bash "$ROOT/scripts/smoke/selftest.sh"
fi
SCENARIO="${SMOKE_SCENARIO:-base}"
BUILD_CONTEXT="${SMOKE_BUILD_CONTEXT:-$ROOT}"
CLUSTER="${SMOKE_CLUSTER:-omp-smoke}"
CNI="${SMOKE_CNI:-kindnet}"
KEEP="${SMOKE_KEEP:-0}"
ARTIFACTS="${SMOKE_ARTIFACTS:-${ROOT}/bin/k8s-smoke-artifacts}"
# kind v0.33.0's own default node image (Kubernetes 1.37.0). Tag and digest, as
# its release notes require; the digest is the multi-arch index.
NODE_IMAGE="${SMOKE_NODE_IMAGE:-kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5}"
# Calico, for SMOKE_CNI=calico: the release's manifest, checked against this
# digest before it is applied.
CALICO_VERSION="v3.33.0"
CALICO_MANIFEST_SHA256="2de8f47595fb9c41b3f47d7b767a1f8e72ecf84057af834738ff12689a234da5"
# The throwaway PostgreSQL's image (overlays/smoke/postgres.yaml). The probe
# pods reuse it: it is already on the nodes and has busybox wget.
PROBE_IMAGE="mirror.gcr.io/library/postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24"
case "$SCENARIO" in
  upgrade | ingress | load) DEADLINE_SECONDS="${SMOKE_TIMEOUT:-1500}" ;;
  *) DEADLINE_SECONDS="${SMOKE_TIMEOUT:-900}" ;;
esac

NS=omp-smoke           # the portal, PostgreSQL and the fake MCP server
NS_CLIENT=omp-smoke-ingress   # stands in for the ingress controller's namespace
NS_OTHER=omp-smoke-other      # a namespace the policies do not allow (calico)
CONTEXT="kind-${CLUSTER}"
RUN_ID="$(date +%s)"
PORTAL_IMAGE="omp-smoke/portal:${RUN_ID}"
FAKEMCP_IMAGE="omp-smoke/fakemcp:${RUN_ID}"
POD_SEL="app.kubernetes.io/name=open-mcp-portal,app.kubernetes.io/component=server"
GW_SLUG="smoke"

TMP=""
WRAP=""
KUBECONFIG_FILE=""
CLUSTER_UP=0
IMAGES_BUILT=0
PF_PID=""
BUILD_PID=""
LOG_PIDS=""
PASSED=0
CSRF=""
API_CODE=""
API_KEY=""
PORT=""
APP_URL=""
OVERLAY=smoke           # the overlay under deploy/kubernetes/overlays
PORTAL_NAME="omp-smoke/portal"      # what the portal image is called in the render
PORTAL_TAG="$RUN_ID"                # its tag (the working tree's image) ...
PORTAL_DIGEST=""                    # ... or, when set, the digest of a published release
OIDC_SECRET="smoke-unused"          # OIDC_CLIENT_SECRET in the runtime secret
EXTRA_NS=""                         # more namespaces whose pods and logs a failed run collects
PROBE_TOTAL=""
PROBE_FAILS=""
PROBE_READY503=""
SCHEMA_NOTE=""
FAKEMCP_MEMORY=""                   # the fake MCP server's memory limit when the scenario raises it (it records every request)
REPLICAS=""                         # the portal Deployment's replica count when the scenario sets it

# ---------------------------------------------------------------- output
# shellcheck source=smoke/assert.sh
. "$ROOT/scripts/smoke/assert.sh"
# shellcheck source=smoke/lib.sh
. "$ROOT/scripts/smoke/lib.sh"
# shellcheck source=smoke/data.sh
. "$ROOT/scripts/smoke/data.sh"
log() { printf '[%4ss] %s\n' "$SECONDS" "$*"; }
step() { printf '\n[%4ss] == %s\n' "$SECONDS" "$*"; }
ok() { PASSED=$((PASSED + 1)); printf '[%4ss]   ok  %s\n' "$SECONDS" "$*"; }
fail() {
  printf '\nsmoke: FAIL: %s\n' "$*" >&2
  exit 1
}
trap 'printf "smoke: command failed (line %s): %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

# k runs kubectl against this script's cluster only.
k() {
  [ "$CLUSTER_UP" = 1 ] || fail "internal error: kubectl called before the cluster exists"
  kubectl --kubeconfig "$KUBECONFIG_FILE" --context "$CONTEXT" "$@"
}
kn() { k -n "$NS" "$@"; }

# ---------------------------------------------------------------- cleanup
collect_artifacts() {
  [ "$CLUSTER_UP" = 1 ] || return 0
  rm -rf "$ARTIFACTS"
  mkdir -p "$ARTIFACTS"
  log "collecting pods, events and logs into $ARTIFACTS"
  {
    k get nodes -o wide
    for ns in "$NS" "$NS_CLIENT" "$NS_OTHER" $EXTRA_NS; do
      echo; echo "### namespace $ns"
      k -n "$ns" get pods,events -o wide 2>&1 || true
    done
    echo; echo "### workloads, PDB, policies, volumes"
    k -n "$NS" get deploy,rs,sts,svc,endpointslices,pdb,netpol,pvc,cm,secret -o wide 2>&1 || true
  } >"$ARTIFACTS/cluster.txt" 2>&1 || true
  k get events -A --sort-by=.lastTimestamp >"$ARTIFACTS/events-all.txt" 2>&1 || true
  k -n "$NS" describe pods >"$ARTIFACTS/describe-pods.txt" 2>&1 || true
  local pod
  for pod in $(k -n "$NS" get pods -o name 2>/dev/null | sed 's|^pod/||'); do
    k -n "$NS" logs "$pod" --all-containers --prefix --timestamps >"$ARTIFACTS/logs-$pod.txt" 2>&1 || true
    k -n "$NS" logs "$pod" --all-containers --prefix --timestamps --previous >"$ARTIFACTS/logs-$pod.previous.txt" 2>&1 || rm -f "$ARTIFACTS/logs-$pod.previous.txt"
  done
  for pod in $(k -n "$NS_CLIENT" get pods -o name 2>/dev/null | sed 's|^pod/||'); do
    k -n "$NS_CLIENT" logs "$pod" >"$ARTIFACTS/logs-client-$pod.txt" 2>&1 || true
  done
  local ns
  for ns in $EXTRA_NS; do
    for pod in $(k -n "$ns" get pods -o name 2>/dev/null | sed 's|^pod/||'); do
      k -n "$ns" logs "$pod" --all-containers --prefix --timestamps >"$ARTIFACTS/logs-$ns-$pod.txt" 2>&1 || true
    done
  done
  [ -d "$TMP" ] && cp "$TMP"/*.log "$TMP"/*.out "$TMP"/*.h "$TMP"/summary-*.json "$TMP"/m-*.txt "$TMP"/sse*.txt "$ARTIFACTS"/ 2>/dev/null || true
}

cleanup() {
  local status=$?
  trap - ERR EXIT INT TERM
  set +e
  if [ "$status" -ne 0 ]; then
    collect_artifacts
  fi
  [ -n "$BUILD_PID" ] && kill "$BUILD_PID" 2>/dev/null
  pf_stop
  pod_forward_stop
  for p in $LOG_PIDS; do kill "$p" 2>/dev/null; done
  if [ "$KEEP" = 1 ]; then
    log "SMOKE_KEEP=1: leaving cluster $CLUSTER, the images and $TMP"
    log "  kubectl --kubeconfig $KUBECONFIG_FILE --context $CONTEXT get pods -A"
    log "  clean up: kind delete cluster --name $CLUSTER --kubeconfig $KUBECONFIG_FILE"
  else
    if kind get clusters 2>/dev/null | grep -qx "$CLUSTER" && [ -n "$KUBECONFIG_FILE" ]; then
      log "deleting kind cluster $CLUSTER"
      kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG_FILE" >/dev/null 2>&1
    fi
    if [ "$IMAGES_BUILT" = 1 ]; then
      docker rmi "$PORTAL_IMAGE" "$FAKEMCP_IMAGE" >/dev/null 2>&1
    fi
    [ -n "$WRAP" ] && rm -rf "$WRAP"
    [ -n "$TMP" ] && rm -rf "$TMP"
  fi
  if [ "$status" -eq 0 ]; then
    rm -rf "$ARTIFACTS"
    printf '\nsmoke: PASS (%s assertions, %ss, CNI %s)\n' "$PASSED" "$SECONDS" "$CNI"
  else
    printf '\nsmoke: FAILED after %ss; pods, events and logs: %s\n' "$SECONDS" "$ARTIFACTS" >&2
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---------------------------------------------------------------- helpers
# wait_until DESCRIPTION SECONDS COMMAND...: polls the command (quietly) until
# it succeeds; fails with a message naming what was awaited.
wait_until() {
  local what=$1 timeout=$2
  shift 2
  local end=$((SECONDS + timeout))
  until "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -lt "$end" ] || fail "timed out after ${timeout}s waiting for: $what"
    [ "$SECONDS" -lt "$DEADLINE_SECONDS" ] || fail "overall SMOKE_TIMEOUT of ${DEADLINE_SECONDS}s exceeded while waiting for: $what"
    sleep 2
  done
}

# has_value NAMESPACE KIND/NAME JSONPATH WANT, gone NAMESPACE KIND/NAME: for
# wait_until, which must re-run the check (not a command substitution that is
# evaluated once, before the loop).
has_value() { [ "$(k -n "$1" get "$2" -o "jsonpath=$3" 2>/dev/null)" = "$4" ]; }
gone() { ! k -n "$1" get "$2" >/dev/null 2>&1; }

nettest_pods_running() {
  has_value "$NS_CLIENT" pod/client '{.status.phase}' Running &&
    has_value "$NS_OTHER" pod/outsider '{.status.phase}' Running &&
    has_value "$NS_OTHER" pod/listener '{.status.phase}' Running &&
    has_value "$NS" pod/neighbour '{.status.phase}' Running &&
    has_value "$NS" pod/portal-lookalike '{.status.phase}' Running
}

need() { command -v "$1" >/dev/null 2>&1 || fail "$1 not found on PATH ($2)"; }

pick_port() {
  local p
  for p in 18088 $(seq 18100 18199); do
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
      echo "$p"
      return 0
    fi
  done
  return 1
}

pf_stop() {
  if [ -n "$PF_PID" ]; then
    kill "$PF_PID" 2>/dev/null || true
    wait "$PF_PID" 2>/dev/null || true
    PF_PID=""
  fi
}

# pf_start: kubectl port-forward pins to ONE pod, so it is restarted whenever
# that pod may be gone.
pf_start() {
  pf_stop
  [ "$CLUSTER_UP" = 1 ] || fail "internal error: kubectl called before the cluster exists"
  # Launch kubectl directly so PF_PID owns the listener, not a shell wrapper.
  kubectl --kubeconfig "$KUBECONFIG_FILE" --context "$CONTEXT" -n "$NS" port-forward "svc/open-mcp-portal" "${PORT}:80" >"$TMP/port-forward.log" 2>&1 &
  PF_PID=$!
  wait_until "kubectl port-forward to answer /healthz on localhost:${PORT}" 30 curl -fsS --max-time 2 "http://localhost:${PORT}/healthz"
}

# api METHOD PATH [JSON] [IF-MATCH-REVISION]: the management API with the
# session in $COOKIES; HTTP status in API_CODE, body in $TMP/api.out.
api() {
  local method=$1 path=$2 body=${3-} ifmatch=${4-}
  local -a a
  [ -n "$COOKIES" ] || COOKIES="$TMP/cookies"
  a=(-sS --max-time 30 -b "$COOKIES" -c "$COOKIES"
    -X "$method" -H "Origin: ${APP_URL}" -H 'Content-Type: application/json')
  if [ -n "$CSRF" ]; then a+=(-H "X-CSRF-Token: ${CSRF}"); fi
  if [ -n "$ifmatch" ]; then a+=(-H "If-Match: \"${ifmatch}\""); fi
  if [ -n "$body" ]; then a+=(--data "$body"); fi
  http_do "$TMP/api.out" "${a[@]}" "${APP_URL}${path}" || fail "$method $path: curl failed (port-forward down?)"
}
api_ok() {
  api "$@"
  case "$API_CODE" in
    200 | 201 | 204) ;;
    *) fail "$1 $2: HTTP $API_CODE: $(head -c 600 "$TMP/api.out")" ;;
  esac
}
data() { jq -er "$1" "$TMP/api.out"; }

# mcp ERA METHOD PARAMS-JSON [NAME]: one JSON-RPC request to the gateway with
# the API key. Status in API_CODE, body in $TMP/mcp.out.
#   legacy: MCP-Protocol-Version 2025-11-25, nothing else required
#   modern: MCP-Protocol-Version 2026-07-28, Mcp-Method (and Mcp-Name for
#           calls) and the _meta fields (docs/mcp-protocol.md)
mcp() {
  local era=$1 method=$2 params=${3:-\{\}} name=${4-}
  local body
  local -a h
  h=(-H "Authorization: Bearer ${MCP_BEARER:-$API_KEY}" -H 'Content-Type: application/json'
    -H 'Accept: application/json, text/event-stream')
  if [ "$era" = modern ]; then
    body="$(jq -nc --arg m "$method" --argjson p "$params" \
      '{jsonrpc:"2.0",id:1,method:$m,params:($p + {_meta:{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}})}')"
    h+=(-H 'MCP-Protocol-Version: 2026-07-28' -H "Mcp-Method: ${method}")
    if [ -n "$name" ]; then h+=(-H "Mcp-Name: ${name}"); fi
  else
    body="$(jq -nc --arg m "$method" --argjson p "$params" '{jsonrpc:"2.0",id:1,method:$m,params:$p}')"
    h+=(-H 'MCP-Protocol-Version: 2025-11-25')
  fi
  http_do "$TMP/mcp.out" -sS --max-time 30 -X POST "${h[@]}" --data "$body" "${APP_URL}/mcp/${GW_SLUG}" ||
    fail "POST /mcp/${GW_SLUG} ($era $method): curl failed"
}
mcp_ok() {
  mcp "$@"
  [ "$API_CODE" = 200 ] || fail "$1 $2 on /mcp/${GW_SLUG}: HTTP $API_CODE: $(head -c 600 "$TMP/mcp.out")"
  if jq -e '.error' "$TMP/mcp.out" >/dev/null 2>&1; then
    fail "$1 $2 on /mcp/${GW_SLUG}: JSON-RPC error: $(head -c 600 "$TMP/mcp.out")"
  fi
}
mcp_json() { jq -er "$1" "$TMP/mcp.out"; }

# The portal pods that are running and not terminating (a pod that is being
# deleted is still "Running" for its drain delay).
portal_pods() {
  kn get pods -l "$POD_SEL" -o json | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name'
}
portal_nodes() { # the distinct nodes of those pods, one per line
  kn get pods -l "$POD_SEL" -o json | jq -r '.items[] | select(.metadata.deletionTimestamp == null) | .spec.nodeName' | sort -u
}

# ---------------------------------------------------------------- the overlay
# kustomization in a scratch directory next to the overlays (kustomize refuses
# paths outside its root): the overlay plus this run's image tags, APP_URL
# (the port-forward's port) and any extra config literals. The portal image is
# this tree's (PORTAL_TAG) or, with PORTAL_DIGEST, a published release by digest.
render() { # [KEY=VALUE]...
  {
    cat <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../overlays/${OVERLAY}
images:
  - name: omp-smoke/portal
    newName: "${PORTAL_NAME}"
EOF
    if [ -n "$PORTAL_DIGEST" ]; then
      echo "    digest: \"${PORTAL_DIGEST}\""
    else
      echo "    newTag: \"${PORTAL_TAG}\""
    fi
    cat <<EOF
  - name: omp-smoke/fakemcp
    newTag: "${RUN_ID}"
EOF
    if [ -n "$REPLICAS" ]; then
      printf 'replicas:\n  - name: open-mcp-portal\n    count: %s\n' "$REPLICAS"
    fi
    if [ -n "$FAKEMCP_MEMORY" ]; then
      cat <<EOF
patches:
  - target:
      kind: Deployment
      name: fakemcp
    patch: |-
      - op: replace
        path: /spec/template/spec/containers/0/resources/limits/memory
        value: ${FAKEMCP_MEMORY}
EOF
    fi
    cat <<EOF
configMapGenerator:
  - name: open-mcp-portal-config
    behavior: merge
    literals:
      - APP_URL=${APP_URL}
EOF
    local kv
    for kv in "$@"; do echo "      - ${kv}"; done
  } >"$WRAP/kustomization.yaml"
  kubectl kustomize "$WRAP"
}

# ---------------------------------------------------------------- in-cluster client
# A pod in the "ingress controller" namespace that calls the Service in a loop
# (/healthz and a real tools/list through the gateway with the API key) until
# /tmp/stop appears, then prints "SUMMARY total=N fail=M". It is the only way to
# see what a rollout looks like to clients: a port-forward pins to one pod.
start_probe() { # NAME
  local name=$1
  cat >"$TMP/probe.sh" <<'EOS'
total=0; fails=0; ready503=0
body='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
while [ ! -f /tmp/stop ]; do
  # What a client sees: /healthz (up whatever the pod's drain state) and a real
  # tools/list through the gateway. /readyz is NOT a client request: a pod
  # that got SIGTERM answers it 503 on purpose, and for a moment (until
  # kube-proxy drops it from the Service) a request can still land on it.
  # Those are counted apart, never as failures.
  total=$((total + 1))
  if ! wget -q -T 3 -O /dev/null "$BASE/healthz" 2>/tmp/err; then
    fails=$((fails + 1)); echo "FAIL $(date +%T) healthz: $(cat /tmp/err)"
  fi
  if ! wget -q -T 3 -O /dev/null "$BASE/readyz" 2>/tmp/err; then
    ready503=$((ready503 + 1)); echo "note $(date +%T) readyz: $(cat /tmp/err)"
  fi
  total=$((total + 1))
  out=$(wget -q -T 10 -O - --header "Authorization: Bearer $KEY" --header 'Content-Type: application/json' \
    --header 'Accept: application/json, text/event-stream' --header 'MCP-Protocol-Version: 2025-11-25' \
    --post-data "$body" "$BASE/mcp/$SLUG" 2>/tmp/err) || out=""
  case "$out" in
    *fake__echo*) ;;
    *) fails=$((fails + 1)); echo "FAIL $(date +%T) tools/list: $(cat /tmp/err) $(echo "$out" | head -c 200)" ;;
  esac
  sleep 0.4
done
echo "SUMMARY total=$total fail=$fails ready503=$ready503"
EOS
  k -n "$NS_CLIENT" create configmap "${name}-script" --from-file=probe.sh="$TMP/probe.sh" >/dev/null
  k -n "$NS_CLIENT" create secret generic "${name}-key" --from-literal=KEY="$API_KEY" >/dev/null
  k -n "$NS_CLIENT" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  labels:
    app.kubernetes.io/name: omp-smoke-probe
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
    - name: probe
      image: ${PROBE_IMAGE}
      imagePullPolicy: IfNotPresent
      command: [sh, /script/probe.sh]
      env:
        - name: BASE
          value: http://open-mcp-portal.${NS}.svc.cluster.local
        - name: SLUG
          value: ${GW_SLUG}
        - name: KEY
          valueFrom:
            secretKeyRef:
              name: ${name}-key
              key: KEY
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
      volumeMounts:
        - name: script
          mountPath: /script
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: script
      configMap:
        name: ${name}-script
    - name: tmp
      emptyDir: {}
EOF
  wait_until "probe pod $name to run" 90 has_value "$NS_CLIENT" "pod/$name" '{.status.phase}' Running
}

# stop_probe NAME: ends the loop, prints its log, sets PROBE_TOTAL/PROBE_FAILS.
stop_probe() {
  local name=$1
  k -n "$NS_CLIENT" exec "$name" -- touch /tmp/stop >/dev/null
  wait_until "probe pod $name to finish" 60 has_value "$NS_CLIENT" "pod/$name" '{.status.phase}' Succeeded
  k -n "$NS_CLIENT" logs "$name" >"$TMP/${name}.log"
  local summary
  summary="$(grep '^SUMMARY' "$TMP/${name}.log" || true)"
  [ -n "$summary" ] || fail "probe $name printed no summary: $(tail -n 5 "$TMP/${name}.log")"
  PROBE_TOTAL="$(echo "$summary" | sed -n 's/.*total=\([0-9]*\).*/\1/p')"
  PROBE_FAILS="$(echo "$summary" | sed -n 's/.*fail=\([0-9]*\).*/\1/p')"
  PROBE_READY503="$(echo "$summary" | sed -n 's/.*ready503=\([0-9]*\).*/\1/p')"
  if [ "$PROBE_FAILS" != 0 ]; then
    grep '^FAIL' "$TMP/${name}.log" | head -n 10 >&2 || true
  fi
}

# ---------------------------------------------------------------- start
need docker "https://docs.docker.com/get-docker/"
need kind "https://kind.sigs.k8s.io/docs/user/quick-start/"
need kubectl "https://kubernetes.io/docs/tasks/tools/"
need curl "needed to call the portal"
need jq "needed to read API answers"
case "$CLUSTER" in omp-smoke*) ;; *) fail "SMOKE_CLUSTER must start with omp-smoke (got '$CLUSTER'): this script deletes the cluster it creates" ;; esac
case "$CNI" in kindnet | calico) ;; *) fail "SMOKE_CNI must be kindnet or calico (got '$CNI')" ;; esac
docker info >/dev/null 2>&1 || fail "the Docker daemon is not reachable"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  fail "a kind cluster named $CLUSTER already exists; delete it (kind delete cluster --name $CLUSTER) or set SMOKE_CLUSTER"
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/omp-smoke.XXXXXX")"
KUBECONFIG_FILE="$TMP/kubeconfig"
export KUBECONFIG="$KUBECONFIG_FILE" # whatever else runs here cannot reach ~/.kube
WRAP="$(mktemp -d "${ROOT}/deploy/kubernetes/.tmp.smoke.XXXXXX")"
PORT="$(pick_port)" || fail "no free local port in 18088, 18100-18199"
APP_URL="http://localhost:${PORT}"
log "cluster $CLUSTER (CNI $CNI), node image $NODE_IMAGE"
log "APP_URL $APP_URL, images omp-smoke/{portal,fakemcp}:$RUN_ID, temp dir $TMP"

# ---------------------------------------------------------------- images
step "Build the portal and fake MCP server images from the working tree (in the background)"
(
  commit="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
  cd "$BUILD_CONTEXT"
  docker build --build-arg VERSION="smoke-${commit}" --build-arg COMMIT="$commit" -t "$PORTAL_IMAGE" . >"$TMP/build-portal.log" 2>&1
  docker build --target fakemcp -t "$FAKEMCP_IMAGE" . >"$TMP/build-fakemcp.log" 2>&1
) &
BUILD_PID=$!

# ---------------------------------------------------------------- cluster
step "Create the kind cluster (1 control plane + 2 workers)"
{
  echo "kind: Cluster"
  echo "apiVersion: kind.x-k8s.io/v1alpha4"
  if [ "$CNI" = calico ]; then
    echo "networking:"
    echo "  disableDefaultCNI: true"
    echo "  podSubnet: 192.168.0.0/16"
  fi
  echo "nodes:"
  echo "  - role: control-plane"
  echo "  - role: worker"
  echo "  - role: worker"
} >"$TMP/kind.yaml"
CLUSTER_UP=1 # from here on a failure collects artifacts and deletes the cluster
if [ "$CNI" = calico ]; then
  kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --config "$TMP/kind.yaml" --kubeconfig "$KUBECONFIG_FILE" >"$TMP/kind-create.log" 2>&1 ||
    fail "kind create cluster failed: $(tail -n 5 "$TMP/kind-create.log")"
  step "Install Calico $CALICO_VERSION (NetworkPolicy enforcement)"
  curl -fsSL --max-time 60 -o "$TMP/calico.yaml" "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml" ||
    fail "could not download Calico's manifest"
  if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$TMP/calico.yaml" | cut -d' ' -f1)"; else got="$(shasum -a 256 "$TMP/calico.yaml" | cut -d' ' -f1)"; fi
  [ "$got" = "$CALICO_MANIFEST_SHA256" ] || fail "Calico manifest checksum mismatch: got $got, want $CALICO_MANIFEST_SHA256"
  k apply -f "$TMP/calico.yaml" >/dev/null
  k -n kube-system rollout status ds/calico-node --timeout=240s >/dev/null || fail "calico-node did not become ready in 240s"
  k wait --for=condition=Ready nodes --all --timeout=120s >/dev/null || fail "nodes not Ready 120s after Calico"
  ok "Calico $CALICO_VERSION runs on all nodes"
else
  kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --config "$TMP/kind.yaml" --kubeconfig "$KUBECONFIG_FILE" --wait 180s >"$TMP/kind-create.log" 2>&1 ||
    fail "kind create cluster failed: $(tail -n 5 "$TMP/kind-create.log")"
fi
# `kind create --wait` waits for the control plane only. Pods applied while a
# worker still carries the not-ready taint all land on the other one (the
# base's topology spread ignores nodes whose taints it does not tolerate), so
# wait for every node, and for cluster DNS, first.
k wait --for=condition=Ready nodes --all --timeout=180s >/dev/null || fail "not all nodes became Ready in 180s: $(k get nodes --no-headers)"
k -n kube-system rollout status deploy/coredns --timeout=180s >/dev/null || fail "CoreDNS not ready in 180s"
[ "$(k get nodes --no-headers | wc -l | tr -d ' ')" = 3 ] || fail "expected 3 nodes, got: $(k get nodes --no-headers)"
ok "cluster has 3 nodes ($(k version -o json | jq -r '.serverVersion.gitVersion'))"

step "Wait for the images, load them into the cluster"
wait "$BUILD_PID" || {
  BUILD_PID=""
  fail "image build failed: $(tail -n 15 "$TMP/build-portal.log" "$TMP/build-fakemcp.log" 2>/dev/null)"
}
BUILD_PID=""
IMAGES_BUILT=1
kind load docker-image "$PORTAL_IMAGE" "$FAKEMCP_IMAGE" --name "$CLUSTER" >"$TMP/kind-load.log" 2>&1 ||
  fail "kind load failed: $(tail -n 5 "$TMP/kind-load.log")"
ok "images $PORTAL_IMAGE and $FAKEMCP_IMAGE loaded"

# ---------------------------------------------------------------- apply
# The pieces every scenario uses; scenario_base (below) and the scenario files
# call them in their own order.
create_namespaces() {
  k apply -f "$ROOT/deploy/kubernetes/overlays/smoke/namespace.yaml" >/dev/null
  local ns
  for ns in "$NS_CLIENT" "$NS_OTHER"; do
    k create namespace "$ns" >/dev/null
    k label namespace "$ns" pod-security.kubernetes.io/enforce=restricted >/dev/null
  done
}

# Random secrets, never in git or in the manifests. ENCRYPTION_KEY and
# API_KEY_PEPPER differ (the portal refuses equal values). OIDC_SECRET is the
# OIDC client secret (a placeholder unless the scenario signs in through Dex).
create_secrets() {
  local old_umask
  old_umask="$(umask)"
  umask 077
  PG_PASSWORD="$(openssl rand -hex 16)"
  OWNER_PASSWORD="$(openssl rand -hex 16)"
  RUNTIME_PASSWORD="$(openssl rand -hex 16)"
  ENC_KEY="$(openssl rand -base64 32)"
  PEPPER="$(openssl rand -base64 32)"
  [ "$ENC_KEY" != "$PEPPER" ] || fail "random ENCRYPTION_KEY equals API_KEY_PEPPER"
  printf 'password=%s\nowner_password=%s\nruntime_password=%s\n' "$PG_PASSWORD" "$OWNER_PASSWORD" "$RUNTIME_PASSWORD" >"$TMP/postgres.env"
  printf 'DATABASE_MIGRATE_URL=postgres://omp_owner:%s@postgres.%s.svc.cluster.local:5432/omp?sslmode=disable\n' "$OWNER_PASSWORD" "$NS" >"$TMP/migrate.env"
  {
    printf 'DATABASE_URL=postgres://omp_app:%s@postgres.%s.svc.cluster.local:5432/omp?sslmode=disable\n' "$RUNTIME_PASSWORD" "$NS"
    printf 'ENCRYPTION_KEY=%s\nAPI_KEY_PEPPER=%s\n' "$ENC_KEY" "$PEPPER"
    # The base requires the key; dev sign-in never uses it.
    printf 'OIDC_CLIENT_SECRET=%s\n' "$OIDC_SECRET"
  } >"$TMP/runtime.env"
  kn create secret generic omp-smoke-postgres --from-env-file="$TMP/postgres.env" >/dev/null
  kn create secret generic open-mcp-portal-runtime --from-env-file="$TMP/runtime.env" >/dev/null
  kn create secret generic open-mcp-portal-migrate --from-env-file="$TMP/migrate.env" >/dev/null
  rm -f "$TMP/postgres.env" "$TMP/runtime.env" "$TMP/migrate.env"
  umask "$old_umask"
  ok "secrets created at run time (DATABASE_URL, ENCRYPTION_KEY, API_KEY_PEPPER, OIDC_CLIENT_SECRET)"
}

# apply_overlay [KEY=VALUE]...: render (extra config literals) and apply.
# shellcheck disable=SC2120 # most callers pass no literals
apply_overlay() {
  render "$@" >"$TMP/rendered.yaml"
  if grep -q '^kind: Secret$' "$TMP/rendered.yaml"; then fail "the rendered overlay contains a Secret"; fi
  k apply -f "$TMP/rendered.yaml" >/dev/null
}

wait_for_stack() {
  kn rollout status sts/postgres --timeout=180s >/dev/null || fail "PostgreSQL's StatefulSet not ready in 180s (storage class? image pull?)"
  kn get pvc data-postgres-0 -o jsonpath='{.status.phase}' | grep -qx Bound || fail "PostgreSQL's PVC is not Bound"
  ok "PostgreSQL 17 is ready on a bound PVC ($(kn get pvc data-postgres-0 -o jsonpath='{.spec.storageClassName}'))"
  kn rollout status deploy/fakemcp --timeout=120s >/dev/null || fail "fake MCP server not ready in 120s"
  wait_portal_rollout 240
}
wait_portal_rollout() { # [SECONDS]
  kn rollout status deploy/open-mcp-portal --timeout="${1:-300}s" >/dev/null ||
    fail "portal Deployment not rolled out in ${1:-300}s (see artifacts; startup probe allows 4 minutes)"
}


# ---------------------------------------------------------------- scenarios
# Every scenario but base lives in scripts/smoke/<name>.sh as scenario_<name>.
if [ "$SCENARIO" != base ]; then
  [ -f "$ROOT/scripts/smoke/${SCENARIO}.sh" ] || fail "no such scenario: ${SCENARIO}"
  # shellcheck disable=SC1090 # the file is named by SMOKE_SCENARIO (checked above)
  . "$ROOT/scripts/smoke/${SCENARIO}.sh"
  "scenario_${SCENARIO}"
  step "Done"
  exit 0
fi

step "Namespaces, secrets, overlay"
create_namespaces
create_secrets
apply_overlay
ok "overlay applied"

step "Wait for PostgreSQL, the fake MCP server and the portal"
wait_for_stack

# ---------------------------------------------------------------- deployment assertions
step "Deployment"
for pod in $(portal_pods); do
  code="$(kn get pod "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="migrate")].state.terminated.exitCode}')"
  reason="$(kn get pod "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="migrate")].state.terminated.reason}')"
  [ "$code" = 0 ] && [ "$reason" = Completed ] || fail "pod $pod: migrate init container exit code '$code' reason '$reason'"
done
ok "the migrate init container completed (exit 0) in every pod"
kn logs "$(portal_pods | head -n 1)" -c migrate >"$TMP/migrate.log" 2>&1 || true

ready="$(kn get deploy open-mcp-portal -o jsonpath='{.status.readyReplicas}')"
[ "$ready" = 2 ] || fail "expected 2 ready replicas, got '$ready'"
ok "both replicas are Ready"

nodes="$(portal_nodes)"
[ "$(echo "$nodes" | wc -l | tr -d ' ')" = 2 ] || fail "replicas share a node: $nodes"
if echo "$nodes" | grep -q control-plane; then fail "a replica runs on the control plane: $nodes"; fi
ok "the replicas run on different nodes ($(echo "$nodes" | tr '\n' ' '))"

endpoints="$(kn get endpointslices -l kubernetes.io/service-name=open-mcp-portal -o jsonpath='{range .items[*].endpoints[*]}{.conditions.ready}{"\n"}{end}' | grep -c true || true)"
[ "$endpoints" = 2 ] || fail "the Service has $endpoints ready endpoints, want 2"
ok "the Service has 2 ready endpoints"

pdb="$(kn get pdb open-mcp-portal -o jsonpath='{.spec.maxUnavailable}/{.spec.unhealthyPodEvictionPolicy}')" || fail "PodDisruptionBudget open-mcp-portal not found"
[ "$pdb" = "1/AlwaysAllow" ] || fail "PodDisruptionBudget is '$pdb', want 1/AlwaysAllow"
wait_until "the PodDisruptionBudget to count 2 healthy pods" 30 has_value "$NS" pdb/open-mcp-portal '{.status.currentHealthy}' 2
ok "the PodDisruptionBudget exists (maxUnavailable 1) and sees 2 healthy pods"

doctor_pod="$(portal_pods | head -n 1)"
kn exec "$doctor_pod" -c portal -- /open-mcp-portal doctor >"$TMP/doctor.out" 2>&1 || fail "doctor failed:
$(cat "$TMP/doctor.out")"
ok "doctor passes in the pod"
# Authenticate over TCP as runtime, never SET ROLE from the bootstrap superuser.
for sql in 'UPDATE audit_log SET action=action' 'DELETE FROM audit_log' 'TRUNCATE audit_log' \
  'UPDATE mcp_calls SET method=method' 'DELETE FROM mcp_calls' 'TRUNCATE mcp_calls' 'TRUNCATE teams CASCADE'; do
  # shellcheck disable=SC2016 # $RUNTIME_PASSWORD and $1 expand in the pod's shell, on purpose
  if kn exec postgres-0 -- sh -c 'PGPASSWORD="$RUNTIME_PASSWORD" psql -h 127.0.0.1 -U omp_app -d omp -v ON_ERROR_STOP=1 -c "$1"' sh "$sql" >"$TMP/denial.out" 2>&1; then
    fail "runtime SQL unexpectedly allowed: $sql"
  fi
  grep -q 'permission denied' "$TMP/denial.out" || fail "runtime denial was not a permission error"
done
for pod in $(portal_pods); do
  env_names="$(kn get pod "$pod" -o jsonpath='{.spec.containers[?(@.name=="portal")].env[*].name}')"
  case "$env_names" in *DATABASE_MIGRATE_URL*) fail "portal has owner URL" ;; esac
done
ok "runtime direct SQL writes/TRUNCATE refused; portal has no owner URL"
sed 's/^/        /' "$TMP/doctor.out"

# ---------------------------------------------------------------- API
step "Health through the port-forward"
pf_start
for p in healthz readyz; do
  body="$(curl -sS --max-time 5 "${APP_URL}/${p}" || true)"
  [ "$(echo "$body" | jq -r .data.status 2>/dev/null)" = ok ] || fail "/${p} did not answer ok: '$body'"
done
ok "/healthz and /readyz answer ok on $APP_URL"

step "The real API: sign in, team, server, gateway, key"
dev_signin
ok "dev sign-in works (POST /auth/dev as admin)"
seed_data

step "MCP through /mcp/${GW_SLUG}, legacy era (MCP-Protocol-Version 2025-11-25)"
mcp_ok legacy initialize '{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"omp-smoke","version":"0"}}'
[ "$(mcp_json .result.protocolVersion)" = 2025-11-25 ] || fail "legacy initialize answered another version: $(cat "$TMP/mcp.out")"
mcp_ok legacy tools/list
[ "$(mcp_json '[.result.tools[].name] | sort | join(",")')" = "fake__check_outage,fake__echo" ] || fail "legacy tools/list is not exactly the two selected tools: $(cat "$TMP/mcp.out")"
if jq -e '.result | has("resultType")' "$TMP/mcp.out" >/dev/null; then fail "a legacy answer carries resultType: $(cat "$TMP/mcp.out")"; fi
mcp_ok legacy tools/call '{"name":"fake__echo","arguments":{"text":"hello-legacy"}}'
[ "$(mcp_json .result.content[0].text)" = hello-legacy ] || fail "legacy echo returned: $(cat "$TMP/mcp.out")"
mcp_ok legacy tools/call '{"name":"fake__check_outage","arguments":{"service":"email"}}'
[ "$(mcp_json .result.content[0].text)" = "check_outage: ok" ] || fail "legacy check_outage returned: $(cat "$TMP/mcp.out")"
ok "legacy: initialize, tools/list (2 tools, no resultType), tools/call echo and check_outage"

step "MCP through /mcp/${GW_SLUG}, modern era (MCP-Protocol-Version 2026-07-28)"
mcp_ok modern server/discover '{}'
[ "$(mcp_json '.result.supportedVersions | index("2026-07-28") != null')" = true ] || fail "server/discover does not list 2026-07-28: $(cat "$TMP/mcp.out")"
mcp_ok modern tools/list
[ "$(mcp_json .result.resultType)" = complete ] || fail "modern tools/list has no resultType complete: $(cat "$TMP/mcp.out")"
[ "$(mcp_json '[.result.tools[].name] | sort | join(",")')" = "fake__check_outage,fake__echo" ] || fail "modern tools/list is not the two selected tools: $(cat "$TMP/mcp.out")"
[ "$(mcp_json .result.cacheScope)" = private ] || fail "modern tools/list is not cacheScope private: $(cat "$TMP/mcp.out")"
mcp_ok modern tools/call '{"name":"fake__echo","arguments":{"text":"hello-modern"}}' fake__echo
[ "$(mcp_json .result.resultType)" = complete ] || fail "modern tools/call has no resultType complete: $(cat "$TMP/mcp.out")"
[ "$(mcp_json .result.content[0].text)" = hello-modern ] || fail "modern echo returned: $(cat "$TMP/mcp.out")"
mcp_ok modern tools/call '{"name":"fake__check_outage","arguments":{"service":"email"}}' fake__check_outage
[ "$(mcp_json .result.resultType)" = complete ] && [ "$(mcp_json .result.content[0].text)" = "check_outage: ok" ] || fail "modern check_outage returned: $(cat "$TMP/mcp.out")"
ok "modern: server/discover, tools/list and tools/call answer with resultType complete"
# A modern request without Mcp-Method is refused (HeaderMismatch -32020).
API_CODE="$(curl -sS --max-time 15 -o "$TMP/mcp.out" -w '%{http_code}' -X POST -H "Authorization: Bearer ${API_KEY}" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' -H 'MCP-Protocol-Version: 2026-07-28' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}' \
  "${APP_URL}/mcp/${GW_SLUG}")"
[ "$API_CODE" = 400 ] && [ "$(mcp_json .error.code)" = -32020 ] || fail "a modern request without Mcp-Method should be 400 -32020, got $API_CODE: $(cat "$TMP/mcp.out")"
ok "a modern request without Mcp-Method is refused (400, -32020)"
API_CODE="$(curl -sS --max-time 15 -o "$TMP/mcp.out" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H 'MCP-Protocol-Version: 2025-11-25' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' "${APP_URL}/mcp/${GW_SLUG}")"
[ "$API_CODE" = 401 ] || fail "/mcp without a key should be 401, got $API_CODE"
ok "/mcp without an API key is refused (401)"

# ---------------------------------------------------------------- rolling update
step "Rolling update under load (maxUnavailable 0)"
start_probe probe-roll
old_cm="$(kn get deploy open-mcp-portal -o jsonpath='{.spec.template.spec.containers[0].envFrom[0].configMapRef.name}')"
old_rs="$(kn get rs -l "$POD_SEL" -o jsonpath='{range .items[?(@.spec.replicas>0)]}{.metadata.name}{"\n"}{end}')"
log "changing a config literal (LOG_LEVEL=debug): the ConfigMap name carries a content hash, so the pods must roll"
render LOG_LEVEL=debug | k apply -f - >/dev/null
new_cm="$(kn get deploy open-mcp-portal -o jsonpath='{.spec.template.spec.containers[0].envFrom[0].configMapRef.name}')"
[ "$new_cm" != "$old_cm" ] || fail "the Deployment still references $old_cm after a config change: it would not roll"
kn rollout status deploy/open-mcp-portal --timeout=300s >/dev/null || fail "rolling update did not finish in 300s"
sleep 5 # a few more rounds of requests on the new pods
stop_probe probe-roll
[ "$PROBE_TOTAL" -ge 20 ] || fail "the probe made only $PROBE_TOTAL requests during the rollout; it did not run"
[ "$PROBE_FAILS" = 0 ] || fail "$PROBE_FAILS of $PROBE_TOTAL requests through the Service failed during the rolling update (maxUnavailable: 0)"
ok "rolling update: $PROBE_TOTAL requests through the Service (/healthz and tools/list), 0 failed; config $old_cm -> $new_cm"
if [ "$PROBE_READY503" != 0 ]; then log "note: $PROBE_READY503 /readyz request(s) through the Service got 503: a pod that already had SIGTERM answers it on purpose until kube-proxy drops it"; fi
new_rs="$(kn get rs -l "$POD_SEL" -o jsonpath='{range .items[?(@.spec.replicas>0)]}{.metadata.name}{"\n"}{end}')"
[ "$new_rs" != "$old_rs" ] || fail "no new ReplicaSet after the config change"
nodes="$(portal_nodes | wc -l | tr -d ' ')"
[ "$nodes" = 2 ] || fail "after the rollout the replicas run on $nodes node(s), want 2"
ok "after the rollout 2 replicas run on 2 different nodes"
pf_start
mcp_ok legacy tools/list
[ "$(mcp_json '.result.tools | length')" = 2 ] || fail "the API key stopped working after the rollout"
api_ok GET /v1/me
ok "the browser session and the API key (both in PostgreSQL) work on the new pods"

# ---------------------------------------------------------------- delete a pod
step "Delete one pod under load; it drains on SIGTERM"
victim="$(portal_pods | head -n 1)"
victim_ip="$(kn get pod "$victim" -o jsonpath='{.status.podIP}')"
start_probe probe-del
kn logs -f "$victim" -c portal >"$TMP/victim.log" 2>&1 &
LOG_PIDS="$LOG_PIDS $!"
sleep 1
kn delete pod "$victim" --wait=false >/dev/null
# During SHUTDOWN_DELAY (10s) the pod is out of the endpoints and /readyz
# says "draining" (503), while /healthz still answers: it has not stopped
# serving yet.
drained=""
for _ in 1 2 3 4 5 6 7 8; do
  if out="$(k -n "$NS_CLIENT" exec probe-del -- wget -q -T 2 -O - "http://${victim_ip}:8088/readyz" 2>&1)"; then
    sleep 1
  else
    drained="$out"
    break
  fi
done
echo "$drained" | grep -q 503 || fail "the terminating pod's /readyz did not turn 503 (draining): '$drained'"
k -n "$NS_CLIENT" exec probe-del -- wget -q -T 2 -O /dev/null "http://${victim_ip}:8088/healthz" >/dev/null 2>&1 ||
  fail "the terminating pod stopped answering /healthz while its drain delay (10s) had barely begun"
ok "the terminating pod failed /readyz (503 draining) but still answered /healthz: it keeps serving during SHUTDOWN_DELAY"
wait_until "pod $victim to be gone" 160 gone "$NS" "pod/$victim"
wait_until "the Deployment to have 2 ready replicas again" 120 has_value "$NS" deploy/open-mcp-portal '{.status.readyReplicas}' 2
sleep 3
stop_probe probe-del
[ "$PROBE_FAILS" = 0 ] || fail "$PROBE_FAILS of $PROBE_TOTAL requests failed while a pod was deleted"
ok "deleting a pod: $PROBE_TOTAL requests through the Service, 0 failed; a replacement is Ready"
# slog writes durations as nanoseconds: 10s is 10000000000.
t_down="$(jq -Rr 'fromjson? | select(.msg=="shutting down" and .drain_delay==10000000000 and .timeout==125000000000) | .time[0:19]' "$TMP/victim.log" | head -n 1)"
[ -n "$t_down" ] || fail "the deleted pod's log has no 'shutting down' with drain_delay 10s and timeout 125s: $(tail -n 5 "$TMP/victim.log")"
t_done="$(jq -Rr 'fromjson? | select(.msg=="shutdown complete") | .time[0:19]' "$TMP/victim.log" | head -n 1)"
[ -n "$t_done" ] || fail "the deleted pod did not log 'shutdown complete' (killed instead of drained?): $(tail -n 5 "$TMP/victim.log")"
drain="$(jq -rn --arg a "${t_down}Z" --arg b "${t_done}Z" '($b|fromdateiso8601) - ($a|fromdateiso8601)')"
{ [ "$drain" -ge 10 ] && [ "$drain" -lt 60 ]; } || fail "the pod took ${drain}s from 'shutting down' to 'shutdown complete'; SHUTDOWN_DELAY is 10s and nothing was in flight"
ok "SIGTERM: 'shutting down' (drain_delay 10s, timeout 125s), then 'shutdown complete' ${drain}s later: it kept serving for the delay, then stopped by itself"
nodes="$(portal_nodes | wc -l | tr -d ' ')"
[ "$nodes" = 2 ] || fail "after the replacement the replicas run on $nodes node(s), want 2"
ok "the replacement keeps the 2 replicas on 2 different nodes"

# ---------------------------------------------------------------- disruption budget
step "PodDisruptionBudget refuses a second concurrent eviction"
pods="$(portal_pods)"
p1="$(echo "$pods" | sed -n 1p)"
p2="$(echo "$pods" | sed -n 2p)"
evict() { # POD -> prints the HTTP outcome; the API server answers 429 when the budget forbids it
  jq -nc --arg n "$1" --arg ns "$NS" '{apiVersion:"policy/v1",kind:"Eviction",metadata:{name:$n,namespace:$ns}}' |
    k create --raw "/api/v1/namespaces/${NS}/pods/$1/eviction" -f - 2>&1
}
out1="$(evict "$p1")" || fail "the first eviction was refused though the budget allows one: $out1"
out2="$(evict "$p2" || true)"
echo "$out2" | grep -q -i "disruption budget" || fail "a second eviction right after the first was not refused by the budget: $out2"
ok "PDB: one eviction allowed, the second refused ('Cannot evict pod as it would violate the pod's disruption budget')"
# A terminating pod can still count as Ready while it drains.
wait_until "evicted pod $p1 to be gone" 160 gone "$NS" "pod/$p1"
kn rollout status deploy/open-mcp-portal --timeout=180s >/dev/null || fail "the Deployment did not recover after the eviction"
wait_until "the Deployment to have 2 ready replicas" 120 has_value "$NS" deploy/open-mcp-portal '{.status.readyReplicas}' 2
pf_start
[ "$(curl -sS --max-time 5 "${APP_URL}/readyz" | jq -r .data.status)" = ok ] || fail "/readyz not ok after the evictions"
ok "back to 2 ready replicas"

# ---------------------------------------------------------------- NetworkPolicy (calico)
if [ "$CNI" = calico ]; then
  step "NetworkPolicy enforcement (Calico): who may reach the portal, and what it may reach"
  [ "$(kn get netpol -o name | wc -l | tr -d ' ')" = 6 ] || fail "expected the base's 5 NetworkPolicies plus the overlay's: $(kn get netpol -o name | tr '\n' ' ')"

  # netpod NAMESPACE NAME COMMAND [EXTRA LABEL LINES] [EXTRA CONTAINER LINES]: a
  # restricted-profile pod from the probe image.
  netpod() {
    k -n "$1" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $2
  labels:
    app.kubernetes.io/part-of: omp-smoke-nettest
${4:-}
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
    - name: c
      image: ${PROBE_IMAGE}
      imagePullPolicy: IfNotPresent
      command: [sh, -c, "$3"]
${5:-}
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
EOF
  }
  # reach NAMESPACE POD URL: "blocked" when the connection times out (what a
  # policy that drops packets looks like), else "reachable" (an HTTP answer, a
  # refusal or a protocol error all prove the packets arrived).
  reach() {
    local out
    if out="$(k -n "$1" exec "$2" -- wget -q -T 3 -O /dev/null "$3" 2>&1)"; then
      echo reachable
      return 0
    fi
    case "$out" in
      *"timed out"*) echo blocked ;;
      *"bad address"*) echo "dns-failure: $out" ;;
      *) echo reachable ;;
    esac
  }

  sleeper="sleep 900"
  netpod "$NS_CLIENT" client "$sleeper"
  netpod "$NS_OTHER" outsider "$sleeper"
  netpod "$NS" neighbour "$sleeper"
  netpod "$NS_OTHER" listener 'while true; do echo ok | nc -l -p 8080; done'
  # Wears the portal's labels (so the same policies select it) but is never
  # Ready, so the Service and the PDB never send it traffic.
  netpod "$NS" portal-lookalike "$sleeper" \
    "    app.kubernetes.io/name: open-mcp-portal
    app.kubernetes.io/component: server" \
    "      readinessProbe:
        exec:
          command: [\"false\"]
        periodSeconds: 5"
  wait_until "the nettest pods to run" 120 nettest_pods_running
  portal_svc="http://open-mcp-portal.${NS}.svc.cluster.local/healthz"
  portal_ip="$(kn get pods -l "$POD_SEL" -o json | jq -r '[.items[] | select(.metadata.deletionTimestamp == null and (.status.conditions[]? | select(.type=="Ready" and .status=="True")))][0].status.podIP')"
  listener_ip="$(k -n "$NS_OTHER" get pod listener -o jsonpath='{.status.podIP}')"

  r="$(reach "$NS_CLIENT" client "$portal_svc")"
  [ "$r" = reachable ] || fail "a pod in the allowed namespace $NS_CLIENT cannot reach the portal Service ($r)"
  ok "ingress: a pod in the allowed namespace ($NS_CLIENT) reaches the portal Service"
  r="$(reach "$NS_OTHER" outsider "$portal_svc")"
  [ "$r" = blocked ] || fail "a pod in the namespace $NS_OTHER reached the portal Service (or failed another way): $r"
  r="$(reach "$NS_OTHER" outsider "http://${portal_ip}:8088/healthz")"
  [ "$r" = blocked ] || fail "a pod in the namespace $NS_OTHER reached a portal pod by IP: $r"
  ok "ingress: a pod in another namespace cannot reach the portal (Service or pod IP): timed out"
  r="$(reach "$NS" neighbour "$portal_svc")"
  [ "$r" = blocked ] || fail "a pod in the portal's own namespace reached the portal Service: $r"
  ok "ingress: a pod beside the portal, in its own namespace, cannot reach it either"

  # What the portal pods may reach, from a pod with the portal's labels.
  r="$(reach "$NS" portal-lookalike "http://postgres.${NS}.svc.cluster.local:5432/")"
  [ "$r" = reachable ] || fail "a pod with the portal's labels cannot reach PostgreSQL on 5432 ($r): the narrowed egress rule is wrong"
  r="$(reach "$NS" portal-lookalike "http://fakemcp.${NS}.svc.cluster.local:8091/mcp")"
  [ "$r" = reachable ] || fail "a pod with the portal's labels cannot reach the fake MCP server on 8091 ($r): the overlay's egress rule is wrong"
  ok "egress: PostgreSQL (5432) and the in-cluster MCP server (8091) are reachable, and DNS resolved their names"
  r="$(reach "$NS" portal-lookalike "http://${listener_ip}:8080/")"
  [ "$r" = blocked ] || fail "a pod with the portal's labels reached another namespace's pod on 8080 ($r): egress is not restricted"
  r="$(reach "$NS" portal-lookalike "http://postgres.${NS}.svc.cluster.local:8080/")"
  [ "$r" = blocked ] || fail "a pod with the portal's labels reached PostgreSQL's pod on 8080 ($r): only 5432 should be open"
  ok "egress: another namespace's pod on 8080, and PostgreSQL on a port other than 5432, are blocked"
  # The portal itself kept working under all of that.
  kn exec "$(portal_pods | head -n 1)" -c portal -- /open-mcp-portal doctor >"$TMP/doctor-calico.out" 2>&1 || fail "doctor failed under enforced policies:
$(cat "$TMP/doctor-calico.out")"
  ok "the portal pods reach PostgreSQL and the fake MCP server under enforced policies (doctor passes; the API flow above ran under them)"
else
  log "note: kindnet does not enforce NetworkPolicy: the base's policies were applied, not tested (SMOKE_CNI=calico tests them)"
fi

step "Done"
