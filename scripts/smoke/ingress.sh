#!/usr/bin/env bash
# shellcheck disable=SC2034 # globals shared with scripts/k8s-smoke.sh and the other sourced files
# Scenario "ingress" (SMOKE_SCENARIO=ingress): what sits in front of the portal
# in a real install, and the sign-in that only works there.
#
#   - Envoy Gateway (Gateway API) and cert-manager, installed from pinned,
#     checksum-verified release manifests; a cert-manager self-signed CA issues
#     the certificate of https://omp.smoke.test (overlays/smoke-ingress)
#   - a curl pod in the cluster resolves omp.smoke.test to the gateway's Service
#     (curl --resolve) and trusts the CA: requests take the path a client's do
#   - TLS: the certificate verifies for the host, is refused without the CA and
#     for another name, over TLS 1.3 (curl --resolve cannot reach a
#     port-forward on another port, so the client runs in the cluster)
#   - TRUSTED_PROXIES: empty, the audit entry of a sign-in names the proxy; set to
#     the proxy's address, it names the real caller, never the X-Forwarded-For
#     value the caller made up
#   - streaming: a tools/call with _meta.progressToken arrives as it is produced
#   - OIDC through Dex (pinned): authorization-code login scripted with curl, the
#     groups claim lands in users.groups, an unverified email is refused, an
#     auth.login audit entry is written, DEV_AUTH is refused for this APP_URL
#
# The ingress controller is Envoy Gateway, not ingress-nginx: the community
# ingress-nginx was retired in March 2026 (docs/deploy.md, "Ingress").
#
# Sourced by scripts/k8s-smoke.sh.

# Pinned controllers: the release manifests are checked against these SHA-256
# sums before they are applied, and every image in them gets its digest.
EG_VERSION="v1.9.3"
EG_MANIFEST_SHA256="ac89b0b564e52c97c97a3f8b4d82bb594a0fbc810431fb2e6ffd91702aabebfb"
CM_VERSION="v1.21.3"
CM_MANIFEST_SHA256="c04a51295adda2b1a775146751f973e787190778c7f35180861d9678876e5c74"
# "image-as-written-in-the-manifest digest": the index digests of the tags.
INGRESS_IMAGE_PINS="
envoyproxy/gateway:v1.9.3 sha256:192fc9bdadb6d2462e8cf7bd702ce3dd9648f3310c6038787448a1f509b7cd9f
quay.io/jetstack/cert-manager-controller:v1.21.3 sha256:9f4f96a33c7774cef24466fcd85031997531a03a8d117f151126baa8d1290dcc
quay.io/jetstack/cert-manager-cainjector:v1.21.3 sha256:083d0e906f8eb44e255fe4ff817ae54e49f9ed82e22f1011bb4e9e4f4b8a641f
quay.io/jetstack/cert-manager-webhook:v1.21.3 sha256:055ac8e9de6a0ba6763794838fe38944acc650f68ebe1b01dd8be079e580f458
"
# Pulled onto the nodes too (they are pinned in the overlay's manifests).
ENVOY_PROXY_IMAGE="docker.io/envoyproxy/envoy:distroless-v1.39.5@sha256:9d84a586119a27b50437dbb01eccd4722832741539b1ed53c8e9d6da6067a6e0"
DEX_IMAGE="ghcr.io/dexidp/dex:v2.46.1@sha256:65b72ca0f4b0bf6d4ada84ec21da8851782563404ac7b8f926923d27ceced9ab"
CURL_IMAGE="docker.io/curlimages/curl:8.17.0@sha256:935d9100e9ba842cdb060de42472c7ca90cfe9a7c96e4dacb55e79e560b3ff40"

EDGE_HOST="omp.smoke.test"
EDGE_NS="envoy-gateway-system"
DEX_BASE="http://dex.${NS}.svc.cluster.local:5556"
EDGE_IP=""
ENVOY_POD_IP=""
CLIENT_POD_IP=""
SPOOFED_IP="203.0.113.9"
ALICE_PASSWORD=""
MALLORY_PASSWORD=""
OVERLAY_EXTRA=()

# fetch_manifest NAME URL SHA256 OUTFILE: download and verify.
fetch_manifest() {
  local name=$1 url=$2 want=$3 out=$4 got attempt=1
  until curl -fsSL --max-time 180 -o "$out" "$url"; do
    [ "$attempt" -lt 3 ] || fail "could not download $name from $url"
    attempt=$((attempt + 1))
    sleep 3
  done
  if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$out" | cut -d' ' -f1)"; else got="$(shasum -a 256 "$out" | cut -d' ' -f1)"; fi
  [ "$got" = "$want" ] || fail "$name checksum mismatch: got $got, want $want"
}
# pin_images FILE...: appends @digest to every pinned image reference in the
# manifests. A reference no manifest has means the manifests are not the ones
# the pins were made for, and fails.
pin_images() {
  local ref digest file found
  while read -r ref digest; do
    [ -n "$ref" ] || continue
    found=0
    for file in "$@"; do
      grep -qE "image: \"?${ref}\"?\$" "$file" || continue
      sed -E "s#(image: \"?)${ref}(\"?)\$#\\1${ref}@${digest}\\2#" "$file" >"$file.pinned" && mv "$file.pinned" "$file"
      grep -qE "image: \"?${ref}@${digest}\"?\$" "$file" || fail "could not pin $ref in $file"
      found=1
    done
    [ "$found" = 1 ] || fail "no manifest has the image $ref to pin (the pinned release manifests changed?)"
  done <<<"$INGRESS_IMAGE_PINS"
}

# worker_pull IMAGE: node_pull on the worker nodes only (the control plane
# runs none of these).
worker_pull() {
  local image=$1 node attempt
  for node in $(kind get nodes --name "$CLUSTER" | grep -v control-plane); do
    attempt=1
    until docker exec "$node" crictl pull "$image" >"$TMP/pull-${node}.log" 2>&1; do
      [ "$attempt" -lt 3 ] || fail "pulling $image on node $node failed 3 times: $(tail -n 3 "$TMP/pull-${node}.log")"
      attempt=$((attempt + 1))
      log "pull of $image on $node failed; retrying ($attempt/3)"
      sleep 5
    done
  done
}

install_controllers() {
  step "Install cert-manager ${CM_VERSION} and Envoy Gateway ${EG_VERSION} (pinned manifests, checked against their SHA-256)"
  fetch_manifest "cert-manager ${CM_VERSION}" "https://github.com/cert-manager/cert-manager/releases/download/${CM_VERSION}/cert-manager.yaml" "$CM_MANIFEST_SHA256" "$TMP/cert-manager.yaml"
  fetch_manifest "Envoy Gateway ${EG_VERSION}" "https://github.com/envoyproxy/gateway/releases/download/${EG_VERSION}/install.yaml" "$EG_MANIFEST_SHA256" "$TMP/envoy-gateway.yaml"
  pin_images "$TMP/cert-manager.yaml" "$TMP/envoy-gateway.yaml"
  local image
  while read -r image _; do
    [ -n "$image" ] && worker_pull "$(grep -ohE "${image}@sha256:[0-9a-f]{64}" "$TMP/cert-manager.yaml" "$TMP/envoy-gateway.yaml" | head -n 1)"
  done <<<"$INGRESS_IMAGE_PINS"
  worker_pull "$ENVOY_PROXY_IMAGE"
  worker_pull "$DEX_IMAGE"
  worker_pull "$CURL_IMAGE"
  ok "manifests verified, every controller image pinned by digest and pulled on the workers"

  k apply --server-side -f "$TMP/cert-manager.yaml" >/dev/null
  for d in cert-manager cert-manager-cainjector cert-manager-webhook; do
    k -n cert-manager rollout status "deploy/$d" --timeout=240s >/dev/null || fail "$d not ready in 240s"
  done
  ok "cert-manager ${CM_VERSION} is running"
  k apply --server-side -f "$TMP/envoy-gateway.yaml" >/dev/null
  k -n "$EDGE_NS" rollout status deploy/envoy-gateway --timeout=240s >/dev/null || fail "envoy-gateway not ready in 240s"
  k wait --for=condition=Established crd/gateways.gateway.networking.k8s.io crd/httproutes.gateway.networking.k8s.io crd/envoyproxies.gateway.envoyproxy.io --timeout=60s >/dev/null || fail "Gateway API CRDs not established"
  k apply -k "$ROOT/deploy/kubernetes/overlays/smoke-ingress/controller" >/dev/null
  wait_until "the GatewayClass to be accepted" 90 has_cluster_value gatewayclass/omp-smoke-envoy '{.status.conditions[?(@.type=="Accepted")].status}' True
  ok "Envoy Gateway ${EG_VERSION} is running; GatewayClass omp-smoke-envoy is accepted"
}
has_cluster_value() { [ "$(k get "$1" -o "jsonpath=$2" 2>/dev/null)" = "$3" ]; }

# dex_subject USER_ID CONNECTOR_ID: the `sub` Dex puts in an ID token, a
# base64url protobuf of (user_id, connector_id). The script verifies it
# against the real sign-in, so a change in Dex fails loudly.
dex_subject() {
  local uid=$1 cid=$2
  # 0x0a <len> user_id 0x12 <len> connector_id, written with octal escapes.
  # shellcheck disable=SC2059 # the escapes are in the format on purpose
  printf "\\012\\$(printf %03o "${#uid}")%s\\022\\$(printf %03o "${#cid}")%s" "$uid" "$cid" | base64 | tr '+/' '-_' | tr -d '=\n'
}

# bcrypt_hash PASSWORD: through PostgreSQL's pgcrypto, which the throwaway
# server already has (Dex wants bcrypt, and nothing else on the runner is
# certain to make it).
bcrypt_hash() {
  pg_sql postgres "CREATE EXTENSION IF NOT EXISTS pgcrypto" >/dev/null
  pg_scalar postgres "SELECT crypt('$1', gen_salt('bf', 10))"
}

# edge_headers OUTFILE CURL-ARGS...: GET/POST with the response headers (and no
# body) in OUTFILE, whichever transport is in use.
edge_headers() {
  local out=$1
  shift
  curl_run -sS --max-time 30 -o /dev/null -D - "$@" >"$out" || fail "curl failed: $*"
}

# dex_login EMAIL PASSWORD: the authorization-code login of a browser, scripted:
# the portal's /auth/login sends it to Dex, the password form is posted, and the
# portal's callback is called with the code. Leaves the callback's answer in
# $TMP/callback.h (the status line and Set-Cookie) and its status in API_CODE.
# Extra curl arguments (CALLBACK_ARGS) go to the callback request only.
CALLBACK_ARGS=()
dex_login() {
  local email=$1 password=$2 loc url hops=0
  [ -n "$COOKIES" ] || COOKIES="/tmp/cookies"
  curl_run -sS -o /dev/null -c "$COOKIES" -b "$COOKIES" -D - "${APP_URL}/auth/login" >"$TMP/login.h" || fail "GET /auth/login failed"
  case "$(head -n 1 "$TMP/login.h")" in *302*) ;; *) fail "GET /auth/login did not redirect: $(head -n 3 "$TMP/login.h")" ;; esac
  url="$(header_value "$TMP/login.h" location)"
  check_contains "/auth/login redirects to Dex" "$url" "${DEX_BASE}/dex/auth"
  check_contains "the redirect asks for the groups scope" "$url" "groups"
  check_contains "the redirect carries a PKCE challenge" "$url" "code_challenge_method=S256"
  # Follow Dex's redirects (to its login form) with Dex's own cookie jar.
  while [ "$hops" -lt 6 ]; do
    hops=$((hops + 1))
    edge_headers "$TMP/dex.h" -c /tmp/dex-cookies -b /tmp/dex-cookies "$url"
    loc="$(header_value "$TMP/dex.h" location)"
    [ -n "$loc" ] || break
    case "$loc" in http*) url="$loc" ;; *) url="${DEX_BASE}${loc}" ;; esac
  done
  check_contains "Dex serves its login form" "$(head -n 1 "$TMP/dex.h")" 200
  # The form posts to the same URL.
  hops=0
  edge_headers "$TMP/dex.h" -c /tmp/dex-cookies -b /tmp/dex-cookies -X POST \
    --data-urlencode "login=${email}" --data-urlencode "password=${password}" "$url"
  loc="$(header_value "$TMP/dex.h" location)"
  [ -n "$loc" ] || fail "Dex's login did not redirect (wrong password?): $(head -n 3 "$TMP/dex.h")"
  while [ "$hops" -lt 6 ]; do
    hops=$((hops + 1))
    case "$loc" in
      "${APP_URL}/auth/callback"*) break ;;
      http*) url="$loc" ;;
      *) url="${DEX_BASE}${loc}" ;;
    esac
    edge_headers "$TMP/dex.h" -c /tmp/dex-cookies -b /tmp/dex-cookies "$url"
    loc="$(header_value "$TMP/dex.h" location)"
    [ -n "$loc" ] || fail "Dex's redirect chain ended before the portal's callback: $(head -n 3 "$TMP/dex.h")"
  done
  check_contains "Dex sends the browser back to the portal's callback" "$loc" "${APP_URL}/auth/callback?code="
  curl_run -sS --max-time 30 -o /dev/null -c "$COOKIES" -b "$COOKIES" -D - ${CALLBACK_ARGS[@]+"${CALLBACK_ARGS[@]}"} "$loc" >"$TMP/callback.h" || fail "GET /auth/callback failed"
  API_CODE="$(head -n 1 "$TMP/callback.h" | sed -n 's/^HTTP[^ ]* \([0-9]*\).*/\1/p')"
}

# user_field EMAIL COLUMN: a column of users, from the portal's database.
user_field() { pg_scalar omp "SELECT $2 FROM users WHERE email = '$1'"; }
# login_ips: the client_ip of every auth.login audit entry, oldest first.
login_ips() { pg_sql omp "SELECT client_ip FROM audit_log WHERE action = 'auth.login' ORDER BY id"; }

portal_warns_untrusted_xff() {
  local pod n=0
  for pod in $(portal_pods); do
    n=$((n + $(kn logs "$pod" -c portal 2>/dev/null | grep -c 'TRUSTED_PROXIES is empty' || true)))
  done
  echo "$n"
}

scenario_ingress() {
  EXTRA_NS="$EDGE_NS cert-manager"
  OVERLAY=smoke-ingress
  APP_URL="https://${EDGE_HOST}"
  OIDC_SECRET="$(openssl rand -hex 24)"
  install_controllers

  step "Namespaces, secrets, the ingress overlay"
  create_namespaces
  create_secrets
  ALICE_PASSWORD="$(openssl rand -hex 12)"
  MALLORY_PASSWORD="$(openssl rand -hex 12)"
  local alice_sub
  alice_sub="$(dex_subject 6a0f3c1e-2b4d-4c8a-9e7f-0d1a2b3c4d5e local)"
  OVERLAY_EXTRA=("BOOTSTRAP_ADMIN_SUBJECT=${alice_sub}")
  apply_overlay "${OVERLAY_EXTRA[@]}"
  kn rollout status sts/postgres --timeout=180s >/dev/null || fail "PostgreSQL not ready in 180s"
  # Dex's secret needs password hashes; PostgreSQL makes them. Dex waits for the secret.
  local alice_hash mallory_hash
  alice_hash="$(bcrypt_hash "$ALICE_PASSWORD")"
  mallory_hash="$(bcrypt_hash "$MALLORY_PASSWORD")"
  [[ "$alice_hash" =~ ^\$2[aby]\$10\$.{53}$ && "$mallory_hash" =~ ^\$2[aby]\$10\$.{53}$ ]] || fail "pgcrypto did not return bcrypt hashes"
  kn create secret generic omp-smoke-dex \
    --from-literal=OMP_CLIENT_SECRET="$OIDC_SECRET" \
    --from-literal=ALICE_PASSWORD_HASH="$alice_hash" \
    --from-literal=MALLORY_PASSWORD_HASH="$mallory_hash" >/dev/null
  kn rollout restart deploy/dex >/dev/null
  kn rollout status deploy/dex --timeout=120s >/dev/null || fail "Dex not ready in 120s"
  kn rollout status deploy/fakemcp --timeout=120s >/dev/null || fail "fake MCP server not ready in 120s"
  wait_portal_rollout 240
  ok "PostgreSQL, Dex, the fake MCP server and the portal run behind the gateway"

  step "The gateway, the certificate and a client pod that trusts it"
  k -n "$NS" wait --for=condition=Ready certificate/omp-smoke-tls --timeout=120s >/dev/null || fail "the certificate omp-smoke-tls is not Ready in 120s: $(kn get certificate,certificaterequest 2>&1 | tail -n 5)"
  k -n "$NS" wait --for=condition=Programmed gateway/omp-smoke --timeout=180s >/dev/null || fail "Gateway omp-smoke is not Programmed in 180s: $(kn describe gateway omp-smoke 2>&1 | tail -n 15)"
  local sel="gateway.envoyproxy.io/owning-gateway-name=omp-smoke,gateway.envoyproxy.io/owning-gateway-namespace=${NS}"
  k -n "$EDGE_NS" wait --for=condition=Ready pod -l "$sel" --timeout=180s >/dev/null || fail "the Envoy proxy pod is not Ready in 180s: $(k -n "$EDGE_NS" get pods 2>&1)"
  EDGE_IP="$(k -n "$EDGE_NS" get svc -l "$sel" -o jsonpath='{.items[0].spec.clusterIP}')"
  ENVOY_POD_IP="$(k -n "$EDGE_NS" get pod -l "$sel" -o jsonpath='{.items[0].status.podIP}')"
  [ -n "$EDGE_IP" ] && [ -n "$ENVOY_POD_IP" ] || fail "no Envoy Service/pod address (service '$EDGE_IP', pod '$ENVOY_POD_IP')"
  ok "Gateway omp-smoke is Programmed: Service ${EDGE_IP}, proxy pod ${ENVOY_POD_IP}, certificate Ready"
  start_edge_client
  CLIENT_POD_IP="$(k -n "$NS_CLIENT" get pod edge-curl -o jsonpath='{.status.podIP}')"
  TRANSPORT=pod
  POD_CURL_POD=edge-curl
  POD_CURL_ARGS=(--resolve "${EDGE_HOST}:443:${EDGE_IP}" --cacert /ca/ca.crt)
  COOKIES=/tmp/cookies

  tls_assertions

  step "OIDC through Dex, TRUSTED_PROXIES empty: the portal sees the proxy"
  # The browser the callback comes from lies about its address.
  CALLBACK_ARGS=(-H "X-Forwarded-For: ${SPOOFED_IP}")
  dex_login alice@smoke.test "$ALICE_PASSWORD"
  check_eq "the callback's HTTP status (303 to the app)" "$API_CODE" 303
  check_contains "the callback sets the session cookie" "$(cat "$TMP/callback.h")" "__Host-omp_session="
  check_eq "alice's OIDC subject is the one the overlay made platform admin" "$(user_field alice@smoke.test oidc_subject)" "$alice_sub"
  check_eq "alice's groups (OIDC_GROUPS_CLAIM=groups, from Dex) in users.groups" "$(user_field alice@smoke.test "groups::text")" "{omp-admins,smoke-team}"
  check_eq "alice's email is recorded as verified" "$(user_field alice@smoke.test email_verified)" t
  check_eq "alice is a platform admin (BOOTSTRAP_ADMIN_SUBJECT)" "$(user_field alice@smoke.test platform_role)" platform_admin
  check_eq "auth.login audit entries" "$(pg_scalar omp "SELECT count(*) FROM audit_log WHERE action = 'auth.login'")" 1
  check_eq "the auth.login entry's method" "$(pg_scalar omp "SELECT metadata->>'method' FROM audit_log WHERE action = 'auth.login'")" oidc
  ok "sign-in through Dex: alice exists with groups {omp-admins,smoke-team}, is platform admin, and an auth.login (oidc) audit entry was written"
  check_client_ip "TRUSTED_PROXIES empty" "$(login_ips | tail -n 1)" "$ENVOY_POD_IP" ""
  ok "TRUSTED_PROXIES empty: the audit client_ip is the proxy's address ${ENVOY_POD_IP}, whatever the caller sent"
  local warns
  warns="$(portal_warns_untrusted_xff)"
  [ "$warns" -ge 1 ] || fail "no portal pod warned that requests carry X-Forwarded-For with TRUSTED_PROXIES empty"
  ok "the portal warned about X-Forwarded-For with TRUSTED_PROXIES empty ($warns pod(s))"

  step "OIDC_REQUIRE_VERIFIED_EMAIL: an unverified email is refused"
  k -n "$NS_CLIENT" exec edge-curl -- rm -f /tmp/cookies /tmp/dex-cookies
  dex_login mallory@smoke.test "$MALLORY_PASSWORD"
  check_eq "the callback's HTTP status for an unverified email" "$API_CODE" 403
  check_not_contains "no session for the refused user" "$(cat "$TMP/callback.h")" "__Host-omp_session="
  check_eq "no users row for the refused email" "$(user_field mallory@smoke.test 'count(*)')" 0
  check_eq "auth.login entries are still only alice's" "$(pg_scalar omp "SELECT count(*) FROM audit_log WHERE action = 'auth.login'")" 1
  ok "mallory (email_verified false) is refused with 403, creates no user and no session"

  step "TRUSTED_PROXIES set to the proxy: the portal sees the caller"
  apply_overlay "${OVERLAY_EXTRA[@]}" "TRUSTED_PROXIES=${ENVOY_POD_IP}/32"
  wait_portal_rollout 300
  k -n "$NS_CLIENT" exec edge-curl -- rm -f /tmp/cookies /tmp/dex-cookies
  dex_login alice@smoke.test "$ALICE_PASSWORD"
  check_eq "the second sign-in's callback status" "$API_CODE" 303
  check_eq "auth.login audit entries" "$(pg_scalar omp "SELECT count(*) FROM audit_log WHERE action = 'auth.login'")" 2
  check_client_ip "TRUSTED_PROXIES=${ENVOY_POD_IP}/32" "$(login_ips | tail -n 1)" "$CLIENT_POD_IP" "$SPOOFED_IP"
  ok "TRUSTED_PROXIES=${ENVOY_POD_IP}/32: the audit client_ip is the caller's ${CLIENT_POD_IP}, not the proxy's and not the ${SPOOFED_IP} the caller put in its own X-Forwarded-For header"
  CALLBACK_ARGS=()

  step "Through the gateway: team, server, gateway and key as alice, then a streamed call"
  api_ok GET /v1/me
  CSRF="$(data .data.csrfToken)"
  check_eq "who is signed in" "$(data .data.user.email)" alice@smoke.test
  SEED_OWNER_EMAIL=alice@smoke.test seed_data echo check_outage progress
  mcp_ok legacy tools/call '{"name":"fake__echo","arguments":{"text":"through-the-gateway"}}'
  check_eq "echo through TLS" "$(mcp_json .result.content[0].text)" through-the-gateway
  sse_assertions

  step "DEV_AUTH is refused for this APP_URL"
  dev_auth_assertions

  if [ "$CNI" = calico ]; then
    step "NetworkPolicy (Calico): only the gateway's namespace reaches the portal"
    local rc=0
    k -n "$NS_CLIENT" exec edge-curl -- curl -sS --max-time 5 -o /dev/null "http://open-mcp-portal.${NS}.svc.cluster.local/healthz" >"$TMP/direct.out" 2>&1 || rc=$?
    check_eq "curl's exit code reaching the portal's Service directly from the client namespace (28 = timed out)" "$rc" 28
    ok "a pod outside the gateway's namespace cannot reach the portal Service directly; the gateway can"
  else
    log "note: kindnet does not enforce NetworkPolicy: the portal's ingress policy (envoy-gateway-system) and its Dex egress rule were applied, not tested"
  fi
}

# start_edge_client: the curl pod that plays the browser and the MCP client,
# with the CA certificate cert-manager issued.
start_edge_client() {
  kn get secret omp-smoke-tls -o jsonpath='{.data.ca\.crt}' | base64 -d >"$TMP/ca.crt"
  grep -q 'BEGIN CERTIFICATE' "$TMP/ca.crt" || fail "the serving secret has no ca.crt"
  k -n "$NS_CLIENT" create configmap smoke-ca --from-file=ca.crt="$TMP/ca.crt" >/dev/null
  k -n "$NS_CLIENT" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: edge-curl
  labels:
    app.kubernetes.io/name: omp-smoke-edge-curl
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  enableServiceLinks: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 100
    runAsGroup: 101
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: curl
      image: ${CURL_IMAGE}
      imagePullPolicy: IfNotPresent
      command: [sleep, "3600"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
      volumeMounts:
        - name: ca
          mountPath: /ca
          readOnly: true
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: ca
      configMap:
        name: smoke-ca
    - name: tmp
      emptyDir: {}
EOF
  wait_until "the client pod to run" 90 has_value "$NS_CLIENT" pod/edge-curl '{.status.phase}' Running
}

tls_assertions() {
  step "TLS"
  curl_run -sS -v --max-time 20 -o /dev/null "https://${EDGE_HOST}/healthz" >"$TMP/tls.out" 2>&1 || fail "https://${EDGE_HOST}/healthz failed with the CA trusted: $(tail -n 8 "$TMP/tls.out")"
  check_contains "the TLS version" "$(cat "$TMP/tls.out")" "TLSv1.3"
  check_contains "the certificate's issuer is the cert-manager CA" "$(cat "$TMP/tls.out")" "issuer: CN=omp-smoke-ca"
  check_contains "the certificate matches the host name" "$(cat "$TMP/tls.out")" "subjectAltName: \"${EDGE_HOST}\" matches cert"
  check_contains "the certificate verifies" "$(cat "$TMP/tls.out")" "SSL certificate verified via OpenSSL"
  ok "https://${EDGE_HOST}: TLS 1.3, issued by cert-manager's CA, subjectAltName matches, verification ok"
  local rc=0
  k -n "$NS_CLIENT" exec edge-curl -- curl --resolve "${EDGE_HOST}:443:${EDGE_IP}" -sS --max-time 10 -o /dev/null "https://${EDGE_HOST}/healthz" >"$TMP/tls-noca.out" 2>&1 || rc=$?
  check_eq "curl's exit code without the CA (60 = certificate not trusted)" "$rc" 60
  rc=0
  k -n "$NS_CLIENT" exec edge-curl -- curl --resolve "wrong.smoke.test:443:${EDGE_IP}" --cacert /ca/ca.crt -sS --max-time 10 -o /dev/null "https://wrong.smoke.test/healthz" >"$TMP/tls-name.out" 2>&1 || rc=$?
  # Envoy only serves the listener's host name: for another SNI it ends the
  # handshake (curl 35, no certificate at all); a certificate that did not
  # match would be curl 60. Either way the client gets no way in.
  case "$rc" in 35 | 60) ;; *) fail "curl's exit code for another host name: got '$rc', want 35 (handshake refused) or 60 (name mismatch)" ;; esac
  ok "the certificate is refused without the CA (curl 60), and a name the gateway does not host gets no TLS session (curl $rc)"
  http_do "$TMP/health.out" -sS --max-time 10 "${APP_URL}/healthz" || fail "healthz through the gateway failed"
  check_eq "/healthz through the gateway" "$API_CODE" 200
  http_do "$TMP/health.out" -sS --max-time 10 "${APP_URL}/v1/auth/config" || fail "auth/config through the gateway failed"
  check_eq "/v1/auth/config through the gateway" "$API_CODE" 200
  check_eq "the sign-in methods the portal offers (OIDC on, dev sign-in off)" "$(jq -c '[.data.oidcEnabled, .data.devAuthEnabled]' "$TMP/health.out")" "[true,false]"
}

sse_assertions() {
  local id=7
  step "Streaming: a tools/call with _meta.progressToken arrives as it is produced"
  local body
  body="$(jq -nc --argjson id "$id" '{jsonrpc:"2.0",id:$id,method:"tools/call",params:{name:"fake__progress",arguments:{count:4,delay_ms:2000},_meta:{progressToken:"smoke-sse"}}}')"
  : >"$TMP/sse.txt"
  curl_run -sS -N --max-time 60 -X POST -D /tmp/sse-headers.txt \
    -H "Authorization: Bearer ${API_KEY}" -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' -H 'MCP-Protocol-Version: 2025-11-25' \
    --data "$body" "${APP_URL}/mcp/${GW_SLUG}" |
    while IFS= read -r line; do printf '%s %s\n' "$(date +%s)" "$line"; done >"$TMP/sse.txt"
  k -n "$NS_CLIENT" exec edge-curl -- cat /tmp/sse-headers.txt | tr -d '\r' >"$TMP/sse-headers.txt"
  check_contains "the streamed call's status" "$(head -n 1 "$TMP/sse-headers.txt")" 200
  check_contains "the streamed call's content type" "$(cat "$TMP/sse-headers.txt")" "text/event-stream"
  check_not_contains "a streamed call is not compressed or length-framed" "$(tr '[:upper:]' '[:lower:]' <"$TMP/sse-headers.txt")" "content-length:"
  check_sse_stream "$TMP/sse.txt" 3 4 "$id"
  ok "the stream carried $(grep -c 'notifications/progress' "$TMP/sse.txt") progress events between $(grep 'notifications/progress' "$TMP/sse.txt" | head -n 1 | cut -d' ' -f1) and $(grep '"result"' "$TMP/sse.txt" | tail -n 1 | cut -d' ' -f1) (epoch seconds): delivered while the call ran, so the gateway does not buffer it"
}

dev_auth_assertions() {
  api POST /auth/dev '{"account":"admin"}'
  [ "$API_CODE" != 200 ] || fail "POST /auth/dev answered 200 on https://${EDGE_HOST}: dev sign-in is on"
  ok "POST /auth/dev through the gateway is refused (HTTP $API_CODE)"
  # The portal image refuses to start with DEV_AUTH on a non-loopback APP_URL:
  # the real binary, the real safety check, in a pod that cannot join the
  # Deployment (other labels).
  kn delete pod omp-devauth --ignore-not-found >/dev/null
  kn apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: omp-devauth
  labels:
    app.kubernetes.io/name: omp-smoke-devauth
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  enableServiceLinks: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: portal
      image: ${PORTAL_NAME}:${PORTAL_TAG}
      imagePullPolicy: IfNotPresent
      args: [serve]
      env:
        - {name: APP_URL, value: "https://${EDGE_HOST}"}
        - {name: DEV_AUTH, value: "true"}
        - {name: LISTEN_ADDR, value: ":8089"}
        - {name: DATABASE_URL, value: "postgres://nobody:nobody@127.0.0.1:1/none"}
        - {name: ENCRYPTION_KEY, value: "$(openssl rand -base64 32)"}
        - {name: API_KEY_PEPPER, value: "$(openssl rand -base64 32)"}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
EOF
  wait_until "the DEV_AUTH pod to stop" 90 has_value "$NS" pod/omp-devauth '{.status.phase}' Failed
  kn logs omp-devauth -c portal >"$TMP/devauth.log" 2>&1 || true
  check_contains "serve with DEV_AUTH=true on https://${EDGE_HOST}" "$(cat "$TMP/devauth.log")" "DEV_AUTH requires a loopback APP_URL"
  check_eq "the pod's exit code" "$(kn get pod omp-devauth -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}')" 1
  kn delete pod omp-devauth --wait=false >/dev/null
  ok "serve refuses DEV_AUTH=true with APP_URL https://${EDGE_HOST}: exit 1, \"DEV_AUTH requires a loopback APP_URL\""
}
