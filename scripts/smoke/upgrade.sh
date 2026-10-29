#!/usr/bin/env bash
# shellcheck disable=SC2034 # globals shared with scripts/k8s-smoke.sh and the other sourced files
# Scenario "upgrade" (SMOKE_SCENARIO=upgrade): what an operator does between two
# releases, and the rule docs/deploy.md ("Upgrades") only promised: a release's
# migrations must work with the previous release's code.
#
#   1. install the previous release by digest (scripts/previous-release.sh)
#   2. create a team, a server, a gateway, an API key, a browser session and an
#      OAuth app grant on it
#   3. roll to the working-tree image while a request loop calls the Service:
#      not one request may fail; the key, the session and the grant must still
#      work; `doctor` must report the schema the new image carries
#   4. roll back to the old digest under the same loop: it still serves, with
#      the new schema in place (expand/contract), and writes still work
#
# Sourced by scripts/k8s-smoke.sh, which provides the helpers used here.

# node_pull IMAGE: pull an image on every node with containerd's own client
# and retry it: a registry hiccup is the one failure worth a second try. The
# pods then start from the node's copy.
node_pull() {
  local image=$1 node attempt
  for node in $(kind get nodes --name "$CLUSTER"); do
    attempt=1
    until docker exec "$node" crictl pull "$image" >"$TMP/pull-${node}.log" 2>&1; do
      [ "$attempt" -lt 3 ] || fail "pulling $image on node $node failed 3 times: $(tail -n 3 "$TMP/pull-${node}.log")"
      attempt=$((attempt + 1))
      log "pull of $image on $node failed; retrying ($attempt/3)"
      sleep 5
    done
  done
}

# portal_image_state: "IMAGE<TAB>IMAGEID" of the portal container of every pod that
# is not terminating, one per line.
portal_image_state() {
  kn get pods -l "$POD_SEL" -o json | jq -r '.items[] | select(.metadata.deletionTimestamp == null) |
    [(.spec.containers[] | select(.name=="portal") | .image),
     (.status.containerStatuses[]? | select(.name=="portal") | .imageID)] | @tsv'
}
# expect_image WHAT IMAGE_REF [DIGEST]: every running portal pod (two of them)
# runs IMAGE_REF; with a digest, the node's imageID names it too.
expect_image() {
  local what=$1 ref=$2 digest=${3-} n=0
  while IFS=$'\t' read -r image id; do
    [ -n "$image" ] || continue
    n=$((n + 1))
    [ "$image" = "$ref" ] || fail "$what: a pod runs image '$image', want '$ref'"
    if [ -n "$digest" ]; then
      check_contains "$what: the node's image ID of a pod" "$id" "$digest"
    fi
  done <<<"$(portal_image_state)"
  [ "$n" -ge 2 ] || fail "$what: only $n pod(s) found, want 2"
  ok "$what: both pods run $ref"
}

# doctor_of OUTFILE: runs doctor in a running portal pod; the exit status is not
# the assertion (during a rollback it notes a database newer than the binary),
# the printed lines are.
doctor_of() {
  local pod
  pod="$(portal_pods | head -n 1)"
  [ -n "$pod" ] || fail "no running portal pod to run doctor in"
  kn exec "$pod" -c portal -- /open-mcp-portal doctor >"$1" 2>&1 || true
  grep -q 'postgres migrations' "$1" || fail "doctor printed no migration line: $(head -c 600 "$1")"
}

scenario_upgrade() {
  local from_tag from_image from_name from_digest
  step "The release to upgrade from"
  if [ -n "${SMOKE_FROM_IMAGE:-}" ]; then
    from_image="$SMOKE_FROM_IMAGE"
    from_tag="(SMOKE_FROM_IMAGE)"
  else
    local resolved
    if [ -n "${SMOKE_FROM_TAG:-}" ]; then
      resolved="$("$ROOT/scripts/previous-release.sh" --tag "$SMOKE_FROM_TAG")" || fail "could not resolve $SMOKE_FROM_TAG: $resolved"
    else
      resolved="$("$ROOT/scripts/previous-release.sh")" || fail "could not resolve the previous release (a full clone with tags is needed): $resolved"
    fi
    from_tag="${resolved%% *}"
    from_image="${resolved#* }"
  fi
  [[ "$from_image" =~ ^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$ ]] || fail "the image to upgrade from must be a digest reference, got '$from_image'"
  from_name="${from_image%@*}"
  from_digest="${from_image#*@}"
  ok "upgrading from $from_tag = $from_image"
  local tree_latest
  tree_latest="$(tree_latest_migration "$BUILD_CONTEXT/migrations")"
  log "the working tree carries migrations up to $tree_latest"

  step "Install the previous release by digest"
  node_pull "$from_image"
  create_namespaces
  create_secrets
  PORTAL_NAME="$from_name"
  PORTAL_DIGEST="$from_digest"
  apply_overlay
  wait_for_stack
  expect_image "previous release" "$from_image" "${from_digest#sha256:}"
  doctor_of "$TMP/doctor-before.out"
  local before
  before="$(doctor_version "$TMP/doctor-before.out")"
  ok "the previous release's doctor reports schema version $before: $(head -n 1 "$TMP/doctor-before.out")"

  step "Create what an upgrade must not lose: team, server, gateway, API key, session, OAuth grant"
  pf_start
  dev_signin
  seed_data
  OLD_API_KEY="$API_KEY"
  mcp_tools_ok "the new API key" "" 2
  oauth_grant
  mcp_tools_ok "the OAuth access token" "$OAUTH_ACCESS" 2
  api_ok GET /v1/me
  api_ok GET /v1/me/oauth-grants
  [ "$(jq '.data | length' "$TMP/api.out")" -ge 1 ] || fail "the OAuth grant is not listed: $(head -c 300 "$TMP/api.out")"
  ok "session, API key and OAuth grant (access token) work on the previous release"
  OLD_ACCESS="$OAUTH_ACCESS"

  step "Roll to the working-tree image under load"
  start_probe probe-up
  PORTAL_NAME="omp-smoke/portal"
  PORTAL_DIGEST=""
  apply_overlay
  wait_portal_rollout 300
  sleep 5 # more requests on the new pods
  stop_probe probe-up
  check_probe "upgrade rollout" "$PROBE_TOTAL" "$PROBE_FAILS" 20
  ok "rolling to the new image: $PROBE_TOTAL requests through the Service (/healthz and tools/list with the old key), 0 failed"
  expect_image "upgraded" "${PORTAL_NAME}:${PORTAL_TAG}"

  step "After the upgrade: schema, key, session, grant"
  doctor_of "$TMP/doctor-after.out"
  local after
  after="$(doctor_version "$TMP/doctor-after.out")"
  check_schema_advanced "$before" "$after" "$tree_latest"
  ok "$SCHEMA_NOTE (doctor: $(grep 'postgres migrations' "$TMP/doctor-after.out" | sed 's/  */ /g'))"
  check_contains "the new image's doctor header" "$(head -n 1 "$TMP/doctor-after.out")" "smoke-"
  pf_start
  API_KEY="$OLD_API_KEY"
  mcp_tools_ok "the API key made before the upgrade" "" 2
  api_ok GET /v1/me # the session cookie of the old release, in the same jar
  mcp_tools_ok "the OAuth access token issued before the upgrade" "$OLD_ACCESS" 2
  oauth_refresh
  mcp_tools_ok "the access token from refreshing the old grant" "$OAUTH_ACCESS" 2
  ok "the old API key, the old browser session and the old OAuth grant (access and refresh) all work on the new image"
  api_ok POST /v1/me/api-keys '{"name":"after upgrade","expiresInDays":1}'
  NEW_KEY="$(data .data.secret)"
  mcp_tools_ok "a key created after the upgrade" "$NEW_KEY" 2
  ok "writes work on the new image: a new API key was created and used"

  step "Roll back to the previous digest under load (expand/contract)"
  start_probe probe-down
  PORTAL_NAME="$from_name"
  PORTAL_DIGEST="$from_digest"
  apply_overlay
  wait_portal_rollout 300
  sleep 5
  stop_probe probe-down
  check_probe "rollback" "$PROBE_TOTAL" "$PROBE_FAILS" 20
  ok "rolling back: $PROBE_TOTAL requests through the Service, 0 failed"
  expect_image "rolled back" "$from_image" "${from_digest#sha256:}"
  doctor_of "$TMP/doctor-rollback.out"
  log "the previous release's doctor on the (possibly newer) schema: $(grep 'postgres migrations' "$TMP/doctor-rollback.out" | sed 's/  */ /g')"
  if [ "$after" -gt "$before" ]; then
    check_contains "doctor of the previous release on the advanced schema" "$(cat "$TMP/doctor-rollback.out")" "newer than this binary"
  fi
  pf_start
  API_KEY="$OLD_API_KEY"
  mcp_tools_ok "the API key on the rolled-back release" "" 2
  mcp_tools_ok "the key created on the new image, on the rolled-back release" "$NEW_KEY" 2
  api_ok GET /v1/me
  mcp_tools_ok "the OAuth token from the new image, on the rolled-back release" "$OAUTH_ACCESS" 2
  oauth_refresh
  api_ok POST /v1/me/api-keys '{"name":"after rollback","expiresInDays":1}'
  mcp_tools_ok "a key created after the rollback" "$(data .data.secret)" 2
  ok "the rolled-back release serves every credential and can write to the schema the new image left"
}
