#!/usr/bin/env bash
# shellcheck disable=SC2034 # globals shared with scripts/k8s-smoke.sh and the other sourced files
# Scenario "restore" (SMOKE_SCENARIO=restore): the backup story docs/deploy.md
# ("Backups") tells, with plain PostgreSQL tools (pg_dump and pg_restore, as
# a trusted administrator would run them):
#
#   1. install, create two API keys, a team and a session
#   2. pg_dump the portal's database
#   3. change things: a new team and key, and revoke the second key
#   4. restore the dump into a second database and point the portal at it
#   5. what the dump held is back (including the key revoked after the dump:
#      docs/threat-model.md 7.12), what came after is gone, doctor passes
#
# A CloudNativePG variant is a later addition (issue #42). Sourced by
# scripts/k8s-smoke.sh.

# apply_db_secrets DATABASE: (re)creates the portal's two database Secrets for
# DATABASE, with the passwords and keys of this run. Secrets are not hashed
# into the pod template, so the caller restarts the pods.
apply_db_secrets() {
  local db=$1 old_umask
  old_umask="$(umask)"
  umask 077
  printf 'DATABASE_MIGRATE_URL=postgres://omp_owner:%s@postgres.%s.svc.cluster.local:5432/%s?sslmode=disable\n' "$OWNER_PASSWORD" "$NS" "$db" >"$TMP/migrate.env"
  {
    printf 'DATABASE_URL=postgres://omp_app:%s@postgres.%s.svc.cluster.local:5432/%s?sslmode=disable\n' "$RUNTIME_PASSWORD" "$NS" "$db"
    printf 'ENCRYPTION_KEY=%s\nAPI_KEY_PEPPER=%s\n' "$ENC_KEY" "$PEPPER"
    printf 'OIDC_CLIENT_SECRET=%s\n' "$OIDC_SECRET"
  } >"$TMP/runtime.env"
  kn create secret generic open-mcp-portal-runtime --from-env-file="$TMP/runtime.env" --dry-run=client -o yaml | k apply -f - >/dev/null
  kn create secret generic open-mcp-portal-migrate --from-env-file="$TMP/migrate.env" --dry-run=client -o yaml | k apply -f - >/dev/null
  rm -f "$TMP/runtime.env" "$TMP/migrate.env"
  umask "$old_umask"
}

# no_portal_connections DATABASE: true when no portal pod is connected to it.
no_portal_connections() {
  [ "$(pg_scalar postgres "SELECT count(*) FROM pg_stat_activity WHERE datname = '$1' AND application_name = 'open-mcp-portal'")" = 0 ]
}

scenario_restore() {
  local key_a key_b key_b_id key_c
  step "Install the working-tree image"
  create_namespaces
  create_secrets
  apply_overlay
  wait_for_stack
  pf_start

  step "Create what the dump will hold"
  dev_signin
  seed_data
  key_a="$API_KEY"
  api_ok POST /v1/me/api-keys '{"name":"revoked after the dump","expiresInDays":1}'
  key_b="$(data .data.secret)"
  key_b_id="$(data .data.key.id)"
  api_ok POST /v1/admin/teams '{"slug":"predump","name":"Before the dump","ownerEmail":"admin@localhost"}'
  mcp_tools_ok "key A" "$key_a" 2
  mcp_tools_ok "key B" "$key_b" 2
  api_ok GET /v1/me
  local teams_before audit_before
  teams_before="$(pg_scalar omp "SELECT count(*) FROM audit_log WHERE action = 'team.create'")"
  audit_before="$(pg_scalar omp "SELECT count(*) FROM audit_log")"
  check_eq "teams created before the dump (audit entries)" "$teams_before" 2
  ok "two API keys, teams smoke and predump, a gateway and a browser session exist ($audit_before audit entries)"

  step "pg_dump the database"
  kn exec postgres-0 -- pg_dump -U postgres -Fc -d omp >"$TMP/omp.dump" || fail "pg_dump failed"
  [ "$(wc -c <"$TMP/omp.dump" | tr -d ' ')" -gt 10000 ] || fail "the dump is suspiciously small: $(wc -c <"$TMP/omp.dump") bytes"
  ok "pg_dump -Fc of database omp: $(wc -c <"$TMP/omp.dump" | tr -d ' ') bytes"

  step "Change things after the dump"
  api_ok POST /v1/admin/teams '{"slug":"postdump","name":"After the dump","ownerEmail":"admin@localhost"}'
  api_ok POST /v1/me/api-keys '{"name":"created after the dump","expiresInDays":1}'
  key_c="$(data .data.secret)"
  api_ok DELETE "/v1/me/api-keys/${key_b_id}"
  MCP_BEARER="$key_b" mcp legacy tools/list
  check_eq "key B right after it was revoked (HTTP status)" "$API_CODE" 401
  mcp_tools_ok "key C" "$key_c" 2
  check_eq "teams now (audit entries)" "$(pg_scalar omp "SELECT count(*) FROM audit_log WHERE action = 'team.create'")" 3
  ok "a team and a key were added, and key B was revoked (401 now)"

  step "Restore the dump into a second database and point the portal at it"
  pg_sql postgres "CREATE DATABASE omp_restore OWNER omp_owner" >/dev/null
  kn exec -i postgres-0 -- pg_restore -U postgres -d omp_restore --exit-on-error <"$TMP/omp.dump" >"$TMP/pg_restore.log" 2>&1 ||
    fail "pg_restore failed: $(tail -n 5 "$TMP/pg_restore.log")"
  check_eq "teams in the restored database (audit entries)" "$(pg_scalar omp_restore "SELECT count(*) FROM audit_log WHERE action = 'team.create'")" 2
  ok "pg_restore into database omp_restore: it holds the dump's rows only"
  apply_db_secrets omp_restore
  kn rollout restart deploy/open-mcp-portal >/dev/null
  wait_portal_rollout 300
  wait_until "the old pods to be gone" 120 has_value "$NS" deploy/open-mcp-portal '{.status.readyReplicas}' 2
  pf_start
  local conns
  conns="$(pg_scalar postgres "SELECT count(*) FROM pg_stat_activity WHERE datname = 'omp_restore' AND application_name = 'open-mcp-portal'")"
  [ "$conns" -ge 1 ] || fail "no portal connection to omp_restore: the portal is not on the restored database"
  wait_until "the old database to have no portal connections" 60 no_portal_connections omp
  ok "the portal pods are connected to omp_restore ($conns connections) and to nothing else"

  step "What survived, what came back, what is gone"
  mcp_tools_ok "key A (made before the dump)" "$key_a" 2
  mcp_tools_ok "key B (revoked after the dump)" "$key_b" 2
  ok "key A works, and key B, revoked after the dump, works again: a restore revives it as it was (threat model 7.12)"
  MCP_BEARER="$key_c" mcp legacy tools/list
  check_eq "key C (made after the dump), HTTP status" "$API_CODE" 401
  api_ok GET /v1/me # the browser session made before the dump
  api_ok GET /v1/teams/smoke
  api_ok GET /v1/teams/predump
  api GET /v1/teams/postdump
  check_eq "the team created after the dump, HTTP status" "$API_CODE" 404
  ok "key C and the team created after the dump are gone; the teams and the browser session from before are back"
  kn exec "$(portal_pods | head -n 1)" -c portal -- /open-mcp-portal doctor >"$TMP/doctor-restore.out" 2>&1 || fail "doctor failed on the restored database:
$(cat "$TMP/doctor-restore.out")"
  ok "doctor passes on the restored database ($(grep 'postgres migrations' "$TMP/doctor-restore.out" | sed 's/  */ /g'))"
}
