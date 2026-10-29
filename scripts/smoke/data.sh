#!/usr/bin/env bash
# shellcheck disable=SC2034 # globals shared with scripts/k8s-smoke.sh and the other sourced files
# What the scenarios create through the real API, and the OAuth app sign-in
# that makes a grant. Sourced by the scenarios; uses api/api_ok/data/mcp_ok
# from scripts/k8s-smoke.sh.

# dev_signin: the development sign-in (loopback APP_URL only), then the CSRF
# token every later write needs.
dev_signin() {
  api POST /auth/dev '{"account":"admin"}'
  [ "$API_CODE" = 200 ] || fail "POST /auth/dev: HTTP $API_CODE: $(head -c 400 "$TMP/api.out") (DEV_AUTH on, APP_URL loopback?)"
  api_ok GET /v1/me
  CSRF="$(data .data.csrfToken)"
}

# seed_data [TOOL...]: team smoke, the in-cluster fake MCP server, a gateway
# (slug $GW_SLUG) selecting TOOL... (default echo and check_outage) and an API
# key (API_KEY). SERVER_ID, GW_ID and the key's ID (API_KEY_ID) are set.
seed_data() {
  local tools="${*:-echo check_outage}" want caps
  api_ok POST /v1/admin/teams "$(jq -nc --arg e "${SEED_OWNER_EMAIL:-admin@localhost}" '{slug:"smoke",name:"Smoke",ownerEmail:$e}')"
  ok "team smoke created"

  FAKE_URL="http://fakemcp.${NS}.svc.cluster.local:8091/mcp"
  api_ok POST /v1/teams/smoke/mcp-servers "$(jq -nc --arg u "$FAKE_URL" '{slug:"fake",name:"Fake",url:$u,description:"cmd/fakemcp in the cluster"}')"
  if jq -e '.data.refreshError // empty' "$TMP/api.out" >/dev/null; then
    fail "the portal could not read the in-cluster fake MCP server at $FAKE_URL: $(data .data.refreshError)"
  fi
  SERVER_ID="$(data .data.server.id)"
  ok "the in-cluster fake MCP server is registered ($FAKE_URL: $(jq -c '.data.server.counts' "$TMP/api.out"))"

  api_ok GET "/v1/teams/smoke/gateway-options?limit=500"
  want="$(echo "$tools" | wc -w | tr -d ' ')"
  caps="$(jq -c --arg s "$SERVER_ID" --arg names " $tools " \
    '[.data.items[] | select(.serverId==$s and .kind=="tool" and (. as $i | $names | contains(" " + $i.name + " "))) | {capabilityId}]' "$TMP/api.out")"
  [ "$(echo "$caps" | jq length)" = "$want" ] || fail "the fake server's tools ($tools) are not all offered: $(head -c 600 "$TMP/api.out")"
  api_ok POST /v1/teams/smoke/gateways "$(jq -nc --arg s "$GW_SLUG" --arg d "$tools" '{slug:$s,name:"Smoke",description:$d}')"
  GW_ID="$(data .data.id)"
  local rev
  rev="$(data .data.revision)"
  api_ok PUT "/v1/teams/smoke/gateways/${GW_ID}/capabilities" "$(jq -nc --argjson c "$caps" '{items:$c}')" "$rev"
  ok "gateway /mcp/${GW_SLUG} selects the fake's ${tools}"

  api_ok POST /v1/me/api-keys '{"name":"k8s smoke","expiresInDays":1}'
  API_KEY="$(data .data.secret)"
  [ -n "$API_KEY" ] || fail "no API key secret in the answer"
  API_KEY_ID="$(data .data.key.id 2>/dev/null || true)"
  ok "API key created"
}

# oauth_grant: signs an OAuth app in to gateway $GW_SLUG with the session in
# $COOKIES: registers a public client, authorizes with PKCE, allows it on the
# consent page and exchanges the code. Sets OAUTH_CLIENT_ID, OAUTH_ACCESS and
# OAUTH_REFRESH. Every step is the protocol a client such as Claude Code uses.
oauth_grant() {
  local redirect="http://127.0.0.1:18999/callback" verifier challenge q location code
  verifier="$(openssl rand -base64 48 | tr -d '=+/\n' | head -c 64)"
  challenge="$(pkce_challenge "$verifier")"
  http_do "$TMP/oauth-reg.out" -sS --max-time 30 -X POST -H 'Content-Type: application/json' \
    --data "$(jq -nc --arg r "$redirect" '{client_name:"omp-smoke-app",redirect_uris:[$r],grant_types:["authorization_code","refresh_token"],response_types:["code"],token_endpoint_auth_method:"none"}')" \
    "${APP_URL}/oauth/register" || fail "POST /oauth/register: curl failed"
  [ "$API_CODE" = 201 ] || fail "POST /oauth/register: HTTP $API_CODE: $(head -c 400 "$TMP/oauth-reg.out")"
  OAUTH_CLIENT_ID="$(jq -er .client_id "$TMP/oauth-reg.out")"
  q="response_type=code&client_id=${OAUTH_CLIENT_ID}&redirect_uri=$(jq -rn --arg u "$redirect" '$u|@uri')&code_challenge=${challenge}&code_challenge_method=S256&state=smoke-state&resource=$(jq -rn --arg u "${APP_URL}/mcp/${GW_SLUG}" '$u|@uri')"
  # The signed-in browser is sent to the consent page; the consent decision is
  # what the page posts.
  [ -n "$COOKIES" ] || COOKIES="$TMP/cookies"
  curl_run -sS --max-time 30 -o /dev/null -D - -b "$COOKIES" "${APP_URL}/oauth/authorize?${q}" >"$TMP/oauth-authz.h" || fail "GET /oauth/authorize: curl failed"
  location="$(header_value "$TMP/oauth-authz.h" location)"
  check_contains "the authorization endpoint sends a signed-in browser to the consent page" "$location" "/oauth/consent?"
  api_ok POST /v1/oauth/consent "$(jq -nc --arg q "$q" '{query:$q,decision:"allow"}')"
  location="$(data .data.redirectUrl)"
  code="$(query_param "$location" code)"
  [ -n "$code" ] || fail "the consent answer carries no code: $location"
  oauth_token authorization_code --data-urlencode "code=${code}" --data-urlencode "code_verifier=${verifier}" \
    --data-urlencode "redirect_uri=${redirect}" --data-urlencode "resource=${APP_URL}/mcp/${GW_SLUG}"
}
# oauth_token GRANT_TYPE CURL-ARGS...: POST /oauth/token; sets OAUTH_ACCESS and
# OAUTH_REFRESH from the answer, or fails.
oauth_token() {
  local grant=$1
  shift
  http_do "$TMP/oauth-token.out" -sS --max-time 30 -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=${grant}" --data-urlencode "client_id=${OAUTH_CLIENT_ID}" "$@" "${APP_URL}/oauth/token" ||
    fail "POST /oauth/token ($grant): curl failed"
  [ "$API_CODE" = 200 ] || fail "POST /oauth/token ($grant): HTTP $API_CODE: $(head -c 400 "$TMP/oauth-token.out")"
  OAUTH_ACCESS="$(jq -er .access_token "$TMP/oauth-token.out")"
  OAUTH_REFRESH="$(jq -er .refresh_token "$TMP/oauth-token.out")"
}
# oauth_refresh: exchanges the refresh token for new tokens (the old refresh
# token is replaced).
oauth_refresh() {
  oauth_token refresh_token --data-urlencode "refresh_token=${OAUTH_REFRESH}"
}

# mcp_tools_ok WHAT [BEARER]: tools/list with the API key (or BEARER) returns the
# gateway's tools, so the credential is valid.
mcp_tools_ok() {
  local what=$1 bearer=${2-} want="${3:-2}"
  MCP_BEARER="$bearer" mcp_ok legacy tools/list
  [ "$(mcp_json '.result.tools | length')" = "$want" ] || fail "$what: tools/list did not return $want tools: $(head -c 400 "$TMP/mcp.out")"
}
