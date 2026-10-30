# Deploying Open MCP Portal

Open MCP Portal is one stateless binary in one container image. It needs
PostgreSQL, an OIDC provider and TLS in front of it. There is no worker, cache,
queue or object storage.

| Path | What |
|---|---|
| [`Dockerfile`](../Dockerfile) | Image: UI built with `npm ci`, Go built with `-trimpath` and version ldflags, distroless `nonroot` runtime; the base images are pinned by digest (tag kept), and Dependabot moves the digests. Default target is the portal; `--target fakemcp` is the demo's fake MCP server. |
| [`compose.demo.yaml`](../compose.demo.yaml) | Local demo: gateway, Postgres and the fake MCP server, with development sign-in. |
| [`deploy/kubernetes/base`](../deploy/kubernetes/base) | Kustomize base: Deployment (+ migrate init container), Service, PodDisruptionBudget, NetworkPolicies, ServiceAccount and a generated ConfigMap. |
| [`deploy/kubernetes/overlays/example`](../deploy/kubernetes/overlays/example) | Example overlay: namespace, pinned image, settings, NGINX Ingress (or Gateway API `httproute.yaml`), narrowed NetworkPolicies. |
| [`deploy/kubernetes/overlays/smoke`](../deploy/kubernetes/overlays/smoke) | Test overlay for `make k8s-smoke` ([Smoke test](#smoke-test)): a throwaway PostgreSQL, the fake MCP server, development sign-in. Not for real installs. |

## Image

Released images are `ghcr.io/ncecere/open-mcp-portal:vX.Y.Z` (and `latest` for final releases), multi-arch
(linux/amd64 and linux/arm64) with SBOM and provenance attestations, signed with cosign (keyless, GitHub Actions OIDC):

```sh
docker pull ghcr.io/ncecere/open-mcp-portal:v0.9.0
docker run --rm ghcr.io/ncecere/open-mcp-portal:v0.9.0 version     # open-mcp-portal 0.9.0 (<commit>)

# Pin the digest from the GitHub Release, and verify it first (cosign v3 or newer):
cosign verify ghcr.io/ncecere/open-mcp-portal@sha256:<digest> \
  --certificate-identity https://github.com/ncecere/open-mcp-portal/.github/workflows/image.yml@refs/tags/v0.9.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

To build it yourself:

```sh
make docker                     # open-mcp-portal:<git describe>
docker run --rm open-mcp-portal:<tag> version
```

- Commands: `serve` (default), `migrate`, `doctor`, `version`. The binary is `/open-mcp-portal`. The image has no shell.
- The image runs as UID/GID 65532, listens on 8088 (`LISTEN_ADDR`, default `:8088`) and needs no writable filesystem.
- There is no `HEALTHCHECK` because distroless has no shell or curl. Orchestrators probe `/healthz` and `/readyz`, as in [Health checks](#health-checks).
- Multi-arch: `docker buildx build --platform linux/amd64,linux/arm64 --build-arg VERSION=… --build-arg COMMIT=… .`.
  The UI and Go builds run on the build platform and cross-compile.

## Demo

```sh
make demo        # docker compose -f compose.demo.yaml up --build
```

Open <http://localhost:8090> and sign in as `admin`. Register the fake MCP server in a team as `http://127.0.0.1:8091/mcp`
(it shares the portal's network namespace, so the address is loopback to the portal), build a gateway and call it at
`http://localhost:8090/mcp/<slug>` with a personal API key. `OMP_DEMO_PORT` changes the port. `make demo-down` deletes the
data.

**Development only.** The demo uses development sign-in and the public example keys from `.env.example`. The portal
accepts them only because `APP_URL` is loopback.

## Required settings and secrets

Every setting is described in [`.env.example`](../.env.example). They come from environment variables or from a flat YAML
file named by `OMP_CONFIG_FILE`. Each secret can also be read from a file named by `<NAME>_FILE`, for example
`DATABASE_URL_FILE=/run/secrets/database-url`.

| Setting | Required | Notes |
|---|---|---|
| `APP_URL` | yes | Public **https** origin, for example `https://mcp.example.org`. It must match the Ingress host. |
| `DATABASE_URL` | serving (secret) | Runtime URL, `postgres://user:pass@host:5432/db?sslmode=require`. URL-encode the password. |
| `DATABASE_MIGRATE_URL` | no (secret) | Migration owner URL, only for `migrate` / `MIGRATE_ON_START`; falls back to `DATABASE_URL`. Supports `_FILE` and YAML. |
| `DB_RUNTIME_ROLE` | no | Existing role to reconcile grants to after every migrate; empty retains single-owner operation. |
| `DB_REQUIRE_SPLIT_ROLES` | no | `false` by default; `true` refuses unsafe serving privileges and requires a target role for migration. |
| `ENCRYPTION_KEY` | yes (secret) | 32 random bytes, base64. Encrypts MCP server header values, identity signing keys, auth provider client secrets, people's provider tokens and captured call payloads. |
| `ENCRYPTION_KEY_PREVIOUS` | while rotating (secret) | The old key, still accepted for decryption until `rotate-keys` re-encrypts everything. See [Key rotation](#key-rotation). |
| `API_KEY_PEPPER` | yes (secret) | 32 random bytes, base64. Keys the HMAC that stores API keys, service account keys and connected apps' tokens. Rotate it with `API_KEY_PEPPER_PREVIOUS`, never by just replacing it. |
| `API_KEY_PEPPER_PREVIOUS` | while rotating (secret) | The old pepper: keys and tokens made with it keep working, and keys are re-digested on use. |
| `METRICS_ADDR` | optional | Prometheus `/metrics` on its own listener, for example `:9090` (empty: off). See [Metrics](#metrics). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` and the other `OTEL_*` settings, `TRACE_LINK_TEMPLATE` | optional | OpenTelemetry tracing, off unless an endpoint is set. See [Tracing](#tracing). `OTEL_EXPORTER_OTLP_HEADERS` is a secret (`_FILE` works). |
| `RETENTION_INTERVAL`, `RETENTION_BATCH_SIZE` | optional | How often old data is deleted (default 15m) and rows per transaction (1000). Periods are set in Admin › Retention. |
| `TASKS_MAX_TTL`, `TASKS_MAX_OPEN_PER_PRINCIPAL` | optional | The MCP task relay's bounds ([docs/mcp-tasks.md](mcp-tasks.md)): the longest a task handle lives in the portal whatever the upstream says (default `24h`; `1m` to `24h`) and how many unfinished tasks one person or service account may hold across all its keys and gateways (default `100`; 1 to 1000). Invalid values stop startup; neither can mean unlimited. Expired task rows are deleted by the retention loop. |
| `OAUTH_MAX_REGISTERED_CLIENTS` | optional | Cap on live OAuth clients registered through the open `POST /oauth/register` (default `1000`; `0` = no cap; 0 to 1000000). Counts registrations used in the last 30 days; over it, registration answers `503 temporarily_unavailable` until one expires. Apps that identify themselves with a metadata document aren't counted. An admin can also turn open registration off (Admin › Trusted clients). |
| `OAUTH_MAX_UNUSED_CLIENTS_PER_ADDRESS` | optional | How many registrations that have not received tokens yet one source address can hold (default `20`; `0` = no cap). The answer past it is `429 slow_down`. Registrations that sign in stop counting; unused ones leave after 24 hours. Behind an ingress, set `TRUSTED_PROXIES`, or every caller shares one address. |
| `SESSION_TTL` | optional | Absolute browser-session lifetime, default `12h` (5m to 30 days). |
| `SESSION_IDLE_TIMEOUT` | optional | Browser inactivity limit, default `0` (off). When enabled, 5m through `SESSION_TTL`; `8h` is suggested with the default 12h absolute lifetime. Activity is recorded at most once a minute, so expiry can be up to a minute earlier than the last request plus this limit. Every browser entry point refuses either expiry immediately; cleanup removes idle rows too. Account › Sessions lists and revokes sign-ins; platform admins can list and revoke a person's sessions. Connected apps and keys are separate. |
| `OAUTH_REFRESH_ABSOLUTE_TTL` | optional | How long after a person last signed an app in its refresh tokens stop working, however often they are used (default `180d`; `0` turns it off; `180d`, or a duration such as `4320h`, 1 hour to 10 years). Past it the app signs in again. Headless agents should use service accounts or API keys. |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID` | yes | The only production sign-in method. The redirect URI to register is `${APP_URL}/auth/callback`. |
| `OIDC_CLIENT_SECRET` | yes (secret) | |
| `BOOTSTRAP_ADMIN_SUBJECT` | first install | The OIDC `sub` made platform admin on first sign-in. It takes effect once. |
| `TRUSTED_PROXIES` | recommended behind an ingress | Ingress controller CIDRs allowed to set `X-Forwarded-For`, used for logging, audit addresses and per-address rate limits. Left empty, the header is ignored (safe), but every request then appears to come from the ingress. See [Behind a proxy](#behind-a-proxy-trusted_proxies). |
| `UPSTREAM_ALLOWED_NETWORKS` | optional | Internal networks and hosts MCP servers may use, besides public addresses. See [Internal MCP servers](#internal-mcp-servers). |
| `SMTP_HOST`, `SMTP_FROM`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TLS` | optional | Notification email; off without `SMTP_HOST`. See [Notifications and automation tokens](#notifications-and-automation-tokens). `SMTP_PASSWORD` is a secret (`SMTP_PASSWORD_FILE` works). |
| `NOTIFICATION_INTERVAL` | optional | The notification dispatcher's tick (default `15s`, 5s to 10m). |
| `NOTIFY_WEBHOOK_ALLOWED_NETWORKS` | optional | Internal networks and hosts **webhook destinations** may use (default empty: public https only). Separate from `UPSTREAM_ALLOWED_NETWORKS`. |
| `OIDC_ALLOWED_EMAIL_DOMAINS`, `OIDC_GROUPS_CLAIM`, `INSTANCE_NAME`, `ORG_NAME`, `SUPPORT_URL`, … | optional | |

Generate keys. `ENCRYPTION_KEY`, `ENCRYPTION_KEY_PREVIOUS` and `API_KEY_PEPPER` must each decode to exactly 32 bytes:

```sh
openssl rand -base64 32     # ENCRYPTION_KEY
openssl rand -base64 32     # API_KEY_PEPPER (a different value)
```

### Internal MCP servers

Out of the box, MCP servers must be at **public** addresses over https. To let teams register servers on your internal
network, allow those networks and hosts:

- **Deployment entries**: `UPSTREAM_ALLOWED_NETWORKS`, comma-separated. Each entry is a network or address
  (`10.20.0.0/16`, `fd00:1234::/32`, `10.20.0.5`) or a host name (`mcp.corp.example.com`, or `*.corp.example.com` for
  its subdomains only). Prefix an entry with `http:` to also allow plain http for it:
  `UPSTREAM_ALLOWED_NETWORKS=10.20.0.0/16,http:*.svc.cluster.local,mcp.corp.example.com`. An invalid entry stops `serve`
  (and `doctor` reports it). Admins see these entries read-only.
- **Admin entries**: platform admins manage up to 100 more in **Admin › Internal networks** (stored in PostgreSQL,
  audited as `settings.network_update`). The replica that saves a change applies it at once; other replicas within 30
  seconds.

Loopback, link-local (including cloud metadata such as `169.254.169.254`), unspecified, multicast and broadcast
addresses stay blocked whatever the entries say. The rules are in [registry.md](registry.md#security).

**Private CAs and client certificates (mTLS).** An internal server behind a private CA, or one that requires a client
certificate, is set up per server (Settings › TLS to the server, or `tls` in the API: [registry.md](registry.md#tls-to-the-server)),
not in the deployment. There is nothing to mount into the pod: the portal never reads a CA file or a certificate from
disk for MCP servers, and **there is no setting that turns certificate verification off**. A server's CA replaces the
system roots for that server only. The address rule above still applies on top of it. Things for an operator to know:

- The **client key is stored in the database**, sealed with `ENCRYPTION_KEY` (the same protection as header values).
  Backups hold it sealed, and restoring one revives the key as it was then (threat model 7.12); keep the key a server
  presents scoped to what the portal needs and rotate it when someone who could read the database leaves.
- `rotate-keys` re-seals it with the other sealed columns (`mcp_server_tls.client_key_cipher`).
- The **expiry** is watched: 14 days ahead the server's health, the admin overview and the team's attention show it, and
  the hourly scan emails the team's owners, admins and editors (`key.expiring`, `keyKind` `server_certificate`; see
  [notifications.md](notifications.md)). Renew by uploading the new certificate (and, if the key changed, the key).
- A change of a server's CA or certificate reads the server again at once; a changed CA sends a published server back to
  review under `approval_required`.
- Not covered: a server in `oauth` mode behind a private CA (the sign-in discovery doesn't use the server's CA),
  certificate revocation (CRL, OCSP) and certificate issuance.

**The NetworkPolicies must allow the same networks and ports.** The base's egress allows TCP 443 to `0.0.0.0/0` and
`::/0`; add rules in your overlay for internal servers on other ports (plain http on 80 or 8080, `:8443`…). Many CNIs
don't match pod addresses with `ipBlock`, so in-cluster servers (`*.svc.cluster.local`) usually need a
`namespaceSelector`/`podSelector` egress rule for their namespace and port. If the portal can resolve and approve an
address but the policy drops it, the server's health shows `unavailable` (a timeout), not `not_allowed`.

**Safety checks.** Unless `APP_URL` is a loopback address, `serve` refuses to start in any of these cases:

- `ENCRYPTION_KEY` or `API_KEY_PEPPER` is the public example value from `.env.example`.
- `DEV_AUTH=true`.
- `APP_URL` is `http://`.

`serve` (on any address) also refuses an `ENCRYPTION_KEY` equal to the `API_KEY_PEPPER`: one value for both would tie
the sealed secrets to the digests of every key and token. Generate each with `openssl rand -base64 32`.

`serve` also requires a sign-in method. Without `DEV_AUTH`, that means OIDC. OIDC discovery runs on the first sign-in,
not at startup, so a misconfigured issuer shows up at sign-in and in the logs. `migrate` needs only `DATABASE_MIGRATE_URL`
(or its `DATABASE_URL` fallback), not runtime connectivity, and it
applies the safety checks only when `APP_URL` is set. `open-mcp-portal doctor` prints all of this and also checks
Postgres and the migration state:

```sh
kubectl -n open-mcp-portal exec deploy/open-mcp-portal -c portal -- /open-mcp-portal doctor
```

## Database roles

Use distinct non-superuser logins in production. See [database-roles.md](database-roles.md) for the security design,
including the 30-day audit and 1-day call age floors, rollup limitation and rollback compatibility.

### PostgreSQL setup

As a trusted PostgreSQL administrator (substitute generated passwords, URL-encoded in URLs):

```sql
CREATE ROLE omp_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '<owner-password>';
CREATE ROLE omp_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '<runtime-password>';
CREATE DATABASE omp OWNER omp_owner;
```

In that database, ensure `public` belongs to `pg_database_owner` (PostgreSQL 17's default) or `omp_owner`, and
`REVOKE CREATE ON SCHEMA public FROM PUBLIC` for a database upgraded from older PostgreSQL defaults. Never grant
`omp_app` membership in `omp_owner`, even with NOINHERIT. The application does not create roles or change passwords.
Run `open-mcp-portal migrate` with `DATABASE_MIGRATE_URL` set to the owner URL and `DB_RUNTIME_ROLE=omp_app`.
Then serve with only the runtime `DATABASE_URL`, `MIGRATE_ON_START=false`, and optionally
`DB_REQUIRE_SPLIT_ROLES=true`. Doctor uses the runtime URL and reports effective catalog privileges, including
PUBLIC/column/inherited grants, memberships and owner rights. Single-owner mode warns rather than failing by default.
The grants step runs on every migration invocation, even with no pending migrations, to cover new tables and repair
stale direct grants. Unsafe PUBLIC or inherited rights require an administrator's fix; direct REVOKE cannot remove them.

### CloudNativePG

A new CloudNativePG Cluster can provision the two identities without superuser application credentials:

```yaml
spec:
  bootstrap:
    initdb:
      database: omp
      owner: omp_owner
      secret:
        name: omp-owner-password
  managed:
    roles:
      - name: omp_app
        ensure: present
        login: true
        superuser: false
        createdb: false
        createrole: false
        inherit: false
        passwordSecret:
          name: omp-app-password
```

Create `omp-owner-password` and `omp-app-password` as `kubernetes.io/basic-auth` Secrets (`username` and `password`),
using different generated passwords. The owner created by initdb is non-superuser. Using your secrets operator
(for example External Secrets templating), assemble **two** URL Secrets against the cluster's read-write service,
`sslmode=require`: `open-mcp-portal-migrate.DATABASE_MIGRATE_URL` as owner, and
`open-mcp-portal-runtime.DATABASE_URL` as runtime. Retain the runtime encryption/pepper/IdP keys in its Secret.
Add `DB_RUNTIME_ROLE=omp_app` and `DB_REQUIRE_SPLIT_ROLES=true` to the portal's non-secret configuration.
The serving pod must not mount the owner basic-auth Secret or URL. Existing Cluster bootstrap settings do not
recreate roles: use managed roles or an administrator for an existing database, not re-bootstrap.

### Existing installation

1. Back up the database and encryption keys. Identify the current database, public schema, table and function owners.
   Keep the existing owner login for migration; do not migrate as a different superuser. Purge functions and the two
   protected tables must share that owner. Correct historical inconsistent ownership as a trusted administrator first.
2. Create a new non-superuser runtime login, without owner membership or administrative grants. Remove historical
   PUBLIC CREATE/write grants where necessary, scoped to this database; do not change unrelated deployments' roles.
3. Set the owner URL in the init-only migration Secret and `DB_RUNTIME_ROLE` in configuration; run the new binary's
   migration before switching serving credentials. It applies migration 00032 and reconciles least-privilege grants.
4. Update only the runtime Secret's `DATABASE_URL`, disable migrate-on-start, and roll serving pods. Run `doctor`
   from the portal container and check Admin › Retention for successful passes. Enable `DB_REQUIRE_SPLIT_ROLES=true`.
5. Verify raw SQL as runtime refuses UPDATE/DELETE on `audit_log` and `mcp_calls`, and TRUNCATE on all tables,
   even after setting purge flags. Reads, inserts and normal retention through the functions must still work.

The previous binary works with the new schema **as owner**, including its legacy retention flags; its retention
cannot run with restricted runtime credentials. If rolling back the binary, also restore the old owner credentials
(or accept retention failures temporarily). Never remove the additive migration to roll back.

## Kubernetes

### Secrets

The base references the secret `open-mcp-portal-runtime` by name and never contains values. Create it with your
secrets operator (an `ExternalSecret`, for example) or by hand:

```sh
kubectl create namespace open-mcp-portal   # or apply the overlay's namespace.yaml first
kubectl -n open-mcp-portal create secret generic open-mcp-portal-runtime \
  --from-literal=DATABASE_URL='postgres://omp_app:<password>@db.example.org:5432/omp?sslmode=require' \
  --from-literal=ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  --from-literal=API_KEY_PEPPER="$(openssl rand -base64 32)" \
  --from-literal=OIDC_CLIENT_SECRET='<from your IdP>'
kubectl -n open-mcp-portal create secret generic open-mcp-portal-migrate \
  --from-literal=DATABASE_MIGRATE_URL='postgres://omp_owner:<password>@db.example.org:5432/omp?sslmode=require'
```

| Key | Used by |
|---|---|
| `DATABASE_URL` (runtime Secret) | `portal` only |
| `DATABASE_MIGRATE_URL` (separate `open-mcp-portal-migrate` Secret) | `migrate` init container only |
| `ENCRYPTION_KEY`, `API_KEY_PEPPER`, `OIDC_CLIENT_SECRET` | `portal` (required: a missing key stops the pod with `CreateContainerConfigError`) |
| `ENCRYPTION_KEY_PREVIOUS`, `API_KEY_PEPPER_PREVIOUS` | `portal`, optional, only during a rotation |

Store `ENCRYPTION_KEY` and `API_KEY_PEPPER` in your secrets store as well. A database backup is useless without them:
see [Backups](#backups). Secrets are not hashed into the pod template, so after changing one, run
`kubectl -n open-mcp-portal rollout restart deploy/open-mcp-portal` (or use your operator's reloader).

The init container references only the separate migration Secret, not the runtime Secret. Its key reference is
optional so overlays can inject credentials another way; without either database URL, migration fails clearly.
For a legacy single-role install, copy the same owner URL into the separate migration Secret. Never put an owner
URL or its `_FILE` mount in the serving container or shared ConfigMap. The base forces `MIGRATE_ON_START=false`.

### Configuration

`open-mcp-portal-config` is generated from [`base/config.env`](../deploy/kubernetes/base/config.env), so its name carries
a content hash and **a configuration change rolls the pods**. Merge keys in an overlay:

```yaml
configMapGenerator:
  - name: open-mcp-portal-config
    behavior: merge
    literals:
      - APP_URL=https://mcp.example.org
      - OIDC_ISSUER=https://idp.example.org
```

The base sets `LISTEN_ADDR=:8088`, `LOG_FORMAT=json`, `DEV_AUTH=false`, `MIGRATE_ON_START=false` (the Deployment also
pins it), `SHUTDOWN_DELAY=10s`, `SHUTDOWN_TIMEOUT=125s`, and placeholders for `APP_URL`, `OIDC_ISSUER` and
`OIDC_CLIENT_ID`. Do not set `generatorOptions.disableNameSuffixHash`, because then pods keep running with stale settings.

### Image

The base references `ghcr.io/ncecere/open-mcp-portal` and sets its tag to `v0.9.0` through a Kustomize `images:` entry.
A tag can move, so pin the digest of the release you verified in your overlay (the digest wins over the tag):

```yaml
images:
  - name: ghcr.io/ncecere/open-mcp-portal
    newTag: v0.9.0
    digest: sha256:<digest from the GitHub Release>
```

### What the base deploys

- **Deployment `open-mcp-portal`**: 2 replicas, `maxUnavailable: 0` / `maxSurge: 1`, spread across nodes (and, best
  effort, zones), with a `migrate` init container. The pod runs as non-root UID 65532 with a read-only root filesystem, all
  capabilities dropped, no privilege escalation, seccomp `RuntimeDefault`, an `emptyDir` on `/tmp`, no service-account
  token and no service links. That meets the `restricted` Pod Security Standard, and the example namespace enforces it.
  Resources: requests 100m CPU / 128Mi, limits 1 CPU / 512Mi, with `GOMEMLIMIT` set from the memory limit.
- **Service `open-mcp-portal`**: port `http` 80 → 8088. No session affinity.
- **PodDisruptionBudget**: `maxUnavailable: 1`. Unhealthy pods never block a drain.
- **ServiceAccount** with `automountServiceAccountToken: false`. The portal never calls the Kubernetes API.
- **Metrics port**: none by default. With `METRICS_ADDR=:9090`, add the container port `metrics` (commented in the
  Deployment), a Service port and a NetworkPolicy from the monitoring namespace; the example overlay does all three and
  keeps an example `ServiceMonitor` beside it. See [Metrics](#metrics).
- **NetworkPolicies** select only the portal pods, so the base can share a namespace:
  - default deny;
  - ingress on TCP 8088 from the ingress controller's namespace (placeholder `ingress-controller`; patch it);
  - DNS to kube-dns in `kube-system`;
  - TCP 5432 to anywhere (narrow it to your database);
  - TCP 443 to anywhere, for upstream MCP servers, the OIDC provider and auth providers' token, revocation and
    userinfo endpoints (delegated credentials).

  **Upstream MCP servers on another port** (for example `https://mcp.example.com:8443`) need an extra egress rule in the
  overlay, as the example shows, and so do internal servers allowed by
  [`UPSTREAM_ALLOWED_NETWORKS`](#internal-mcp-servers) or Admin › Internal networks on ports other than 443. The
  gateway's SSRF guard applies whatever the policy allows. Outside development it connects to public addresses, and to
  internal ones only when an allowlist entry covers them; never to loopback or link-local addresses, and never through
  an HTTP(S) proxy. Auth providers' endpoints (Admin › Auth providers) go through the same guard, so an internal
  identity provider needs an allowlist entry too. Register `<APP_URL>/connect/callback` as the redirect URI of each
  provider's OAuth app; the ingress must route `/connect/` to the portal like every other path.

### Ingress

- The host must equal `APP_URL`'s host, and TLS terminates at the ingress or gateway.
- **ingress-nginx is retired.** Kubernetes retired the community Ingress NGINX controller in March 2026: best-effort
  maintenance ended then, its repository was archived on 24 March 2026, and there are no more releases or security fixes
  ([the Steering and Security Response Committees' statement](https://kubernetes.io/blog/2026/01/29/ingress-nginx-statement/),
  [the retirement announcement](https://www.kubernetes.dev/blog/2025/11/12/ingress-nginx-retirement/)). Existing installs
  keep working but should plan their move. This guide therefore treats **Gateway API** as the default: the `HTTPRoute` in
  `overlays/example` is the recommended route, and the smoke test's ingress scenario
  ([`overlays/smoke-ingress`](../deploy/kubernetes/overlays/smoke-ingress)) runs exactly that on **Envoy Gateway** with a
  cert-manager certificate. The portal needs nothing controller-specific, only the settings below, so any maintained
  Gateway API implementation or Ingress controller works. The ingress-nginx `Ingress` and its annotations stay in
  `overlays/example/ingress.yaml` for clusters that still run it.
- **Timeouts.** A `/mcp/{slug}` call waits up to 120s for its upstream server (the maximum per-server timeout). Allow
  reads of a few minutes: the example sets `timeouts.request: 300s` on the HTTPRoute (the smoke test runs it) and
  `proxy-read-timeout: 300` on the ingress-nginx Ingress. Requests are capped at 1 MiB.
- **Streaming (SSE).** A `tools/call` that carries `_meta.progressToken` from a client that accepts
  `text/event-stream` is answered as a Server-Sent Events stream (the server's progress, then the response), with an SSE
  comment (`: keep-alive`) every 15 s while it waits. The portal sends `X-Accel-Buffering: no` and sets no write timeout
  of its own, so the proxy in front must neither buffer the response nor cut a quiet one. These are the settings to
  check. **Tested here:** the Gateway API route on Envoy Gateway (the smoke test makes a streamed call through it and checks
  that the progress events arrive while the call is still running, not together at its end). The others are not tested
  here:
  - **Gateway API (`HTTPRoute`):** `timeouts.request` of at least 300s (the example), and the same or unset for
    `timeouts.backendRequest`. Envoy Gateway needed nothing else for streaming: it does not buffer responses.
  - **Traefik:** don't put the `buffering` middleware on the portal's route, leave the entrypoint's
    `respondingTimeouts.writeTimeout` at 0, keep `idleTimeout` above 120s, and, if a `ServersTransport` sets
    `forwardingTimeouts.responseHeaderTimeout`, make it at least 300s.
  - **ingress-nginx (retired):** `proxy-buffering: "off"` (the example sets it; the response header does the same) and a
    `proxy-read-timeout` above the longest server timeout, 120s (the example: 300). Don't compress `text/event-stream`.
  - **Cloud load balancers** have idle timeouts of their own (AWS ALB: 60s by default). The keep-alive comments count as
    traffic, but a total call time above the balancer's request limit still ends the stream.
  A client that closes the stream cancels the call to the upstream server, so a proxy that ends a response early also
  cancels the call. Calls without a progress token, or without `text/event-stream` in `Accept`, stay one buffered JSON
  response (at most 1 MiB); a streamed call relays at most 64 progress events and 4 MiB.
- **No sticky sessions.** `/mcp/{slug}` is stateless: no MCP session lives in a pod, and browser sessions and OIDC login
  state are in PostgreSQL. Any replica can serve any request.
- Set `TRUSTED_PROXIES` to the controller's pod network ([why](#behind-a-proxy-trusted_proxies)). The portal skips
  trusted addresses from the right of `X-Forwarded-For`, so name the proxy's pods, not a network callers can also be in:
  a caller inside the range would have its own `X-Forwarded-For` value believed. The smoke test sets it to the one
  proxy pod's address and checks that the audit entry names the real caller, not the proxy and not a spoofed header.

### Behind a proxy (`TRUSTED_PROXIES`)

The portal serves plain http and expects TLS to end at a proxy, so `APP_URL` is `https://` and every request arrives from
the proxy. The portal believes `X-Forwarded-For` only from peers inside `TRUSTED_PROXIES`. With it empty the header is
ignored: that is safe (nobody can spoof an address), but per-address rate limits (sign-in, client registration, failed
tokens), audit entries and access logs all name the proxy, so one noisy caller can use up everyone's allowance.

- **A warning tells you.** With `TRUSTED_PROXIES` empty and a non-loopback `APP_URL`, a request that carries
  `X-Forwarded-For` or `Forwarded` makes the portal log `requests carry X-Forwarded-For (or Forwarded) but
  TRUSTED_PROXIES is empty…` at WARN level: once for the first such request, then at most once a minute. Nothing about
  the request changes. Setting `TRUSTED_PROXIES` (to the proxy's network, such as `10.0.0.0/8`) stops it. The warning is
  not given when `TRUSTED_PROXIES` is set, even for a request from outside it.
- **`open-mcp-portal doctor`** prints an info line (`configuration / trusted proxies`) when `APP_URL` is https and
  `TRUSTED_PROXIES` is empty. It cannot see traffic, so ignore it when nothing sits in front of the portal.
- **Sign-in cookie.** On https the sign-in state cookie is `__Host-omp_oidc_state` (host-only, `Secure`, `Path=/`), like
  the session cookie `__Host-omp_session`; over the development http origin the names have no prefix. The old
  name `omp_oidc_state` was accepted on https for one release (v0.2.2) and is not read any more (v0.3.0): a person who
  started signing in just before the upgrade to v0.3.0 starts again.

### Health checks

| Endpoint | Meaning | Probe |
|---|---|---|
| `/healthz` | The process is up. It never checks dependencies, so a database outage does not restart pods. | liveness, startup |
| `/readyz` | Postgres answers within 2s and the pod is not draining; otherwise 503 with the failing check. | readiness |

The listener opens only after Postgres answers (the process waits up to 3 minutes) and the schema is current. The startup
probe allows 4 minutes.

**Graceful shutdown.** On SIGTERM the portal fails `/readyz` and waits `SHUTDOWN_DELAY` (10s) so endpoints and load
balancers stop sending traffic. It then gives in-flight requests `SHUTDOWN_TIMEOUT` (125s) to finish. The pod's
`terminationGracePeriodSeconds` (150s) must exceed the two together. Raise all three together.

## Smoke test

`make k8s-validate` (CI's `k8s` job) only renders the manifests and checks their schemas. `make k8s-smoke`
([`scripts/k8s-smoke.sh`](../scripts/k8s-smoke.sh)) applies them to a real cluster and uses what it deployed. Five
scenarios, each in a fresh kind cluster of its own (`SMOKE_SCENARIO`):

| Scenario | Command | Takes (warm, Linux) | Workflow |
|---|---|---|---|
| `base` (default): one fresh install, a rolling update, pod deletion, PDB, NetworkPolicy | `make k8s-smoke`, `SMOKE_CNI=calico make k8s-smoke` | 3 to 5 min | `k8s-smoke` (both CNIs) |
| `upgrade`: the previous release, then this tree, then back | `SMOKE_SCENARIO=upgrade make k8s-smoke` | 4 min | `k8s-upgrade` |
| `ingress`: Envoy Gateway, TLS, `TRUSTED_PROXIES`, streaming and OIDC through Dex | `SMOKE_SCENARIO=ingress make k8s-smoke` | 4 min (kindnet), 4 min (Calico) | `k8s-smoke` (both CNIs) |
| `restore`: `pg_dump`, more data, restore into a second database | `SMOKE_SCENARIO=restore make k8s-smoke` | 2 min | `k8s-smoke` |
| `load`: three replicas under a k6 ramp | `SMOKE_SCENARIO=load make k8s-smoke` | 6 to 7 min | `k8s-load` |

```sh
make k8s-smoke                    # needs docker, kind, kubectl, curl and jq (k6 for load)
SMOKE_CNI=calico make k8s-smoke   # Calico enforces the NetworkPolicies, which are then tested
make smoke-selftest               # the scripts' assertion helpers against stubs: no cluster, no Docker
make shellcheck                   # ShellCheck on every script
scripts/install-smoke-tools.sh DIR kind kubectl shellcheck k6   # the pinned, checksum-verified tools
```

Each scenario builds the portal and the fake MCP server images from the working tree, creates a kind cluster of one
control plane and two workers (node image pinned by tag and digest, its own kubeconfig in a temporary directory; it never
touches `~/.kube`), loads the images and applies the base through [`overlays/smoke`](../deploy/kubernetes/overlays/smoke)
(a throwaway PostgreSQL 17 StatefulSet on a PVC, the fake MCP server, and run-time random secrets, config merged into
`open-mcp-portal-config` and the local image tags). It stops at the first failed assertion with a message, then (always)
collects `kubectl get pods,events`, `describe` and every pod's logs into `bin/k8s-smoke-artifacts` (`SMOKE_ARTIFACTS`),
deletes the cluster, the images and the temporary directory. `SMOKE_KEEP=1` keeps them. Every wait has its own timeout,
and `SMOKE_TIMEOUT` bounds the run (900 s; 1500 s for `upgrade`, `ingress` and `load`). Only image pulls are retried, three
times; nothing else is, so a flaky assertion is a bug to fix, not to retry.

### `base`: what it proves

- The `migrate` init container completed in every pod, and `doctor` passes in the running pod.
- Both replicas are Ready on **different nodes** (the control plane, which they do not tolerate, is not used), the
  Service has two endpoints, and the PodDisruptionBudget exists and counts two healthy pods.
- `/healthz` and `/readyz` answer, and development sign-in (`POST /auth/dev`) works through `kubectl port-forward`.
- Through the real API: a team, the in-cluster fake MCP server registered at `http://fakemcp.omp-smoke.svc.cluster.local:8091/mcp`,
  a gateway selecting its `echo` and `check_outage` tools, and an API key. With that key, `initialize`, `tools/list` and
  `tools/call` work at `/mcp/{slug}` in both protocol eras: legacy (`MCP-Protocol-Version: 2025-11-25`) and modern
  (`2026-07-28` with `Mcp-Method`, `Mcp-Name` and the `_meta` fields; the answers carry `resultType`). A modern request
  without `Mcp-Method` is a 400 and a request without a key a 401.
- **A rolling update** (a config literal changes, so the hashed ConfigMap name changes and the pods roll) under a loop
  that calls the Service from inside the cluster (`/healthz` and a real `tools/list`): no request fails
  (`maxUnavailable: 0`). The same loop runs while a pod is **deleted**: no failures; the terminating pod answers
  `/readyz` with 503 while it still answers `/healthz`, logs `shutting down` and, 10 seconds later (`SHUTDOWN_DELAY`),
  `shutdown complete`; the replacement lands on a different node from the survivor. The API key and the browser session,
  both in PostgreSQL, work on the new pods.
- The PodDisruptionBudget: one eviction is allowed and a second one right after it is refused.
- With `SMOKE_CNI=calico`: a pod in the namespace the ingress policy allows reaches the portal; a pod in another
  namespace and a pod beside the portal in its own namespace do not (a timeout, by Service and by pod IP). From a pod
  that wears the portal's labels (so the same policies select it), PostgreSQL on 5432 and the in-cluster MCP server on
  8091 are reachable and DNS works, while another namespace's pod and PostgreSQL's pod on other ports are not. The portal
  keeps passing `doctor` and serving calls under those policies.

### `upgrade`: what it proves

The upgrade rule above ("a release's migrations must work with the previous release's code") was only a promise.
[`scripts/previous-release.sh`](../scripts/previous-release.sh) names the **previous release**: the newest `vX.Y.Z` tag
reachable from the checkout that does not point at it (a release tag tests the release before it; pre-releases are
skipped), and reads its image digest from GHCR. If the example overlay pins that tag with a digest, the two must agree,
so a moved tag fails the job. `SMOKE_FROM_TAG=v0.7.0` or `SMOKE_FROM_IMAGE=ghcr.io/...@sha256:...` start from another
release.

1. The previous release is installed **by digest** (pulled on the nodes, so a pull can be retried) and both pods are
   checked to run that image.
2. Through its API: a team, the fake MCP server, a gateway, an API key, a browser session (`POST /auth/dev`) and an OAuth app
   grant (dynamic client registration, authorization with PKCE, consent, code exchange: access and refresh token), each
   used once.
3. The Deployment rolls to the image built from the checkout, under the request loop (`/healthz` and a real `tools/list`
   with the old key through the Service): **not one request may fail**. Afterwards `doctor` must report the schema version
   the new image carries (the highest file in `migrations/`; it advances when the new image has newer migrations, and is
   reported as unchanged when it has none), and the old API key, the old browser session, the old OAuth access token and its
   refresh token must all work, and a new key can be created.
4. It rolls **back to the old digest** under the same loop: no failed request, the old image's `doctor` names the newer
   schema where there is one, and every credential, including the key made on the new image, works on the old image,
   which can still write (a new key).

The gate is proved to fail: [`scripts/k8s-upgrade-canary.sh`](../scripts/k8s-upgrade-canary.sh) builds the image from a
scratch copy of the tree with a throwaway migration that hides every API key from the previous release's connections
(row-level security keyed on `application_name`) while the copy's own code, which connects under another name, is
unaffected, which is what a release does when its migration breaks the previous release's code. The scenario must fail,
and at the rollout's request loop; the previous release's pods, still serving while the new pod migrates, answer 401. The
migration exists only in the scratch copy and its image, never in the repository (`k8s-upgrade` runs it weekly and on
request). Two things remain true of any run: when this tree's migrations are the previous release's own (the usual case on
a fresh release), the schema does not advance, which the run says; starting from the release before it (`SMOKE_FROM_TAG`)
exercises a real advance and rollback.

### `ingress`: what it proves

Overlay [`overlays/smoke-ingress`](../deploy/kubernetes/overlays/smoke-ingress) puts the portal behind **Envoy Gateway**
(Gateway API: a `Gateway` with an https listener and an `HTTPRoute`, request timeout 300 s) with a **cert-manager**
self-signed CA issuing the certificate of `https://omp.smoke.test`, and Dex as the OpenID Connect provider. APP_URL is
`https://omp.smoke.test`; the client is a `curl` pod in the cluster that resolves the name to the gateway's Service
(`curl --resolve`) and trusts the CA, so requests take the path a client's do and the portal sees that pod's address (a
`kubectl port-forward` cannot be used with `--resolve`, which maps the port 443 only). Envoy Gateway and cert-manager are
installed from the projects' release manifests, **pinned by version and checked against a SHA-256 before they are
applied**, and every image they start is pinned by digest. Why Envoy Gateway and not ingress-nginx: [Ingress](#ingress).

- **TLS.** The certificate cert-manager issued is the one served; the client verifies it (TLS 1.3, issuer
  `omp-smoke-ca`, `subjectAltName` matches `omp.smoke.test`), and refuses it without the CA and for another name
  (curl exit 60 both times).
- **OIDC through Dex** (the authorization-code login scripted with `curl`: `/auth/login`, Dex's password form, the portal's
  callback). `alice` has a verified email and the groups `omp-admins` and `smoke-team`: she gets a user whose
  `users.groups` is exactly those groups (`OIDC_GROUPS_CLAIM=groups`, asked for with the `groups` scope), a platform admin
  through `BOOTSTRAP_ADMIN_SUBJECT` (the subject is computed from Dex's user ID and checked against the real sign-in), and
  an `auth.login` audit entry with `method: oidc`. `mallory`'s email is not verified: with `OIDC_REQUIRE_VERIFIED_EMAIL=true`
  the callback answers 403, and no user, session or `auth.login` entry exists.
- **`DEV_AUTH` is refused**: `POST /auth/dev` through the gateway is not a sign-in (`/v1/auth/config` offers OIDC only),
  and the portal image itself exits 1 with "DEV_AUTH requires a loopback APP_URL" when started with `DEV_AUTH=true` and
  this APP_URL.
- **`TRUSTED_PROXIES`.** With it empty, the first sign-in's audit `client_ip` is the gateway proxy's pod address (and the portal
  logs its warning about `X-Forwarded-For`), whatever the caller sent. With `TRUSTED_PROXIES` set to that one pod's address,
  the next sign-in's `client_ip` is the curl pod's: the real caller, not the proxy and not the `203.0.113.9` the caller put
  in its own `X-Forwarded-For` header (the portal believes the right-most address it does not trust, which is the
  one the proxy added).
- **Streaming.** With the API key, a `tools/call` with `_meta.progressToken` and `Accept: text/event-stream` to the fake
  server's `progress` tool (four notifications two seconds apart) is answered as `text/event-stream` and the events
  arrive while the call is still running: the first progress event comes at least four seconds before the response, which
  a buffering proxy would deliver together at the end. Team, server, gateway and key were created through the same
  TLS path as alice, and registering the in-cluster server, with `DEV_AUTH` off, goes through
  `UPSTREAM_ALLOWED_NETWORKS`.
- With `SMOKE_CNI=calico`, the same run proves the ingress policy admits the gateway's namespace (and the Dex egress rule),
  and that a pod elsewhere cannot reach the portal's Service directly (a timeout).

### `restore`: what it proves

The backup procedure is plain PostgreSQL: `pg_dump -Fc` of the portal's database, run as the administrator.

1. Two API keys, two teams, a gateway and a browser session exist; the dump is taken.
2. After the dump: a third team and a third key are created, and **the second key is revoked** (it answers 401).
3. The dump is restored (`pg_restore --exit-on-error`) into a second database owned by the migration role, the portal's
   two database Secrets are pointed at it, and the pods are restarted. The portal's connections are checked to be on
   the second database and on no other.
4. The first key and the browser session from before the dump work and the teams from before are back; **the key revoked
   after the dump works again** (a restore revives a key as it was: [threat model](threat-model.md) 7.12); the third team
   and third key are gone; `doctor` passes on the restored database.

A CloudNativePG variant belongs to #42 (it ships that overlay) and is not part of this scenario.

### `load`: what it proves

Three replicas with `METRICS_ADDR=:9090`, driven by **k6** (a pinned, checksum-verified binary copied into a pod next to
the Service, so the requests spread over every replica) against the fake MCP server. These are regression gates with loose
bounds, **not a benchmark**.

- **Shared rate limits.** A gateway limit of 60 a minute, in a fresh minute window, and 120 `tools/call` requests sent with a
  new connection each (so kube-proxy spreads them): exactly 60 pass and 60 are refused with 429, the
  `rate_limit_counters` row of the gateway's bucket holds all 120, and every replica's own request counter shows it
  served part of them. Counters kept per replica would admit up to 60 on each.
- **A ramp** of `tools/call echo` to 24 virtual users for about 100 seconds (the person and API-key limits are raised first;
  they are 600 and 300 a minute by default): **no failed request, no failed check** (every answer must be a 200 carrying
  the echoed text, which also catches a JSON-RPC error inside a 200) and a **p95 under 3 s** (`SMOKE_LOAD_P95_MS`; runs on a 4-CPU machine measured 320 to 390 ms).
- **Loops.** Every background loop (`omp_loop_leader`, summed over the replicas' own `/metrics`: notifications, retention,
  usage rollup) has a leader. The gauge is 1 on a replica whose latest run held the loop's advisory lock, and runs are
  short, so it can be 1 on several replicas at once; the lock only keeps runs from overlapping. The test therefore also
  holds the notification and retention locks from outside (a `psql` session): no replica leads either loop meanwhile, and
  both are led again after the release.
- **Connections.** The database's connections at the peak of the ramp, and the replicas' pools afterwards, stay below
  `max_connections`.
- A JSON summary (`SMOKE_SUMMARY`, default `bin/k8s-load-summary.json`) holds the k6 numbers, the shared-limit run, the
  leaders and the connection counts; `k8s-load` uploads it. The fake MCP server records every request it receives, so the
  scenario raises its memory limit to 1 GiB (at the smoke overlay's 128 MiB it is OOM-killed after about 6000 calls).

### What it does not prove

- **NetworkPolicy under kindnet.** kind's default CNI does not enforce NetworkPolicy: the base's policies are applied and
  the manifests are valid, nothing more. Only `SMOKE_CNI=calico` tests the ingress policy (with the example overlay's
  patch: the ingress namespace), the DNS and PostgreSQL rules and an overlay's rule for an in-cluster MCP server or Dex. The
  `open-mcp-portal-egress-https` rule (TCP 443 to anywhere) is not exercised: nothing in the tests dials a public https
  address.
- **The internal-network allowlist, negatively.** The `base`, `upgrade`, `restore` and `load` scenarios use `DEV_AUTH` on a
  loopback `APP_URL`, where the portal allows private and plain-http MCP server addresses whatever
  `UPSTREAM_ALLOWED_NETWORKS` says. Only `ingress` registers the fake server with development sign-in off, so the allowlist
  entry `http:*.svc.cluster.local` is needed there; no test shows a server outside the list being refused.
- **Other ingress controllers, real certificates, real load balancers.** One controller (Envoy Gateway v1.9.3, on a
  Kubernetes version newer than its published compatibility matrix lists), one self-signed CA, no ACME, no cloud load
  balancer, no Traefik, no ingress-nginx; streaming is proved through that one proxy and for a 8 s call, not for the
  idle timeouts of other proxies or calls near the 120 s upstream maximum. The example overlay's `Ingress`,
  ServiceMonitor and metrics `NetworkPolicy` are only validated, never applied. The client is a pod in the cluster, not an
  address outside it.
- **A real identity provider.** Dex with static password users proves authorization code with PKCE, the `groups` claim, `email_verified`, the
  bootstrap admin and the audit entry. Not covered: another provider's claim shapes (Entra, Okta, Google), refresh,
  logout and session expiry, `OIDC_ALLOWED_EMAIL_DOMAINS`, an issuer behind TLS with a private CA, the delegated-credential auth
  providers (`/connect/`).
- **Upgrade depth.** Only from the previous release (or a tag you name), on a database with a handful of rows: migration
  time and locks on large tables, and the previous release's other endpoints after the schema change, are not covered
  (the loop exercises API-key authentication and `tools/list`; the checks afterwards add the browser session, the OAuth
  grant and a write). When the tree has no migration beyond the previous release's, the schema does not advance (the run
  says so). Nothing here upgrades across more than one release.
- **Restore depth.** A custom-format dump of a small database restored in the same cluster: no point-in-time recovery or WAL
  archive, no managed or CloudNativePG database (#42), no loss of the encryption key or pepper, no cross-version restore.
- **Production sizing, storage and Postgres.** One throwaway PostgreSQL with no backup, TLS or failover; a three-node
  cluster in one Docker VM; no zones (kind's nodes carry no `topology.kubernetes.io/zone`, so the second spread
  constraint has nothing to spread over); a pod eviction through the API but no real `kubectl drain`. The load test is a
  loose gate on a small cluster and says nothing about capacity, or about a slow real MCP server.
- **Client-visible `/readyz`.** A pod that has had SIGTERM answers `/readyz` with 503 on purpose, for 10 seconds, and
  for a second or so after the signal kube-proxy can still route a request to it. A loop of `/readyz` requests through
  the Service therefore sees a few 503s during a rollout (the test notes them); real traffic (`/healthz`, `/mcp`) does not.
  Use `/readyz` for health checks that remove a pod from a pool, not as a probe of what clients experience.
- **GitHub runners.** The jobs ([`k8s-smoke.yml`](../.github/workflows/k8s-smoke.yml),
  [`k8s-upgrade.yml`](../.github/workflows/k8s-upgrade.yml), [`k8s-load.yml`](../.github/workflows/k8s-load.yml)) are
  written for `ubuntu-latest`, pin every action by commit SHA and every binary by version and SHA-256, and have the
  limits above, but **the upgrade, ingress, restore and load jobs have not run on GitHub-hosted runners yet**: they were
  run on a Linux amd64 machine with Docker and the same pinned kind and kubectl. Their timeouts are not measured there.

### Pinned versions and decisions

The kind node image (Kubernetes 1.37), Calico, the PostgreSQL image, kind, kubectl, k6, ShellCheck, Envoy Gateway,
cert-manager, Dex, the `curl` image and Envoy are pinned: versions and digests are in
[`scripts/install-smoke-tools.sh`](../scripts/install-smoke-tools.sh), [`scripts/smoke/ingress.sh`](../scripts/smoke/ingress.sh)
and the overlays, and each download is checked against a SHA-256 before it runs. Other settings: `SMOKE_CLUSTER` (name,
must start with `omp-smoke`), `SMOKE_NODE_IMAGE`.

- **Dex, not Keycloak**, for OIDC: one small pinned image with static users, groups and `email_verified` set per user, no
  database; Keycloak is heavier and closer to a production provider but slower to start and to pin. A change to Keycloak
  would be a new decision.
- **Plain PostgreSQL `pg_dump` for the restore check**, per run. CloudNativePG comes with #42's overlay, as a later nightly
  entry.
- **Previous release = the newest `vX.Y.Z` tag reachable from `HEAD`** (not the one at `HEAD`).
- **Envoy Gateway (Gateway API), not ingress-nginx**, because ingress-nginx is retired ([Ingress](#ingress)). Traefik
  needs Helm to render and has no single release manifest to checksum; Envoy Gateway ships `install.yaml` per release.
- **k6, not `hey`**: ramping stages, thresholds, a JSON summary and per-request checks in one static binary.

## Migrations

- In Kubernetes, the `migrate` init container runs `open-mcp-portal migrate` in every new pod. A PostgreSQL advisory
  lock serialises concurrent runs, so only the first pod does any work.
- Elsewhere, run `open-mcp-portal migrate` before `serve`, or set `MIGRATE_ON_START=true` on a single instance.
- `serve` refuses to start while migrations are pending. The message names the current and required versions.

## Scaling

- The portal is stateless, so scale the Deployment horizontally. All shared state is in PostgreSQL.
- Background loops:
  - The MCP server health checks (`HEALTH_CHECK_INTERVAL`, default 5m), the signing-key rotation, the retention loop
    (`RETENTION_INTERVAL`, default 15m), the usage rollup (every 5 minutes), the server governance loop (advisory lock `omp.governance`, every 5 minutes, `omp_loop_leader{loop="governance"}`; decision 88) and the optional background refresh of
    connected accounts' tokens (`PROVIDER_REFRESH_INTERVAL`, default `0`: off) take a PostgreSQL advisory lock, so one
    replica runs each at a time (`omp_loop_leader` is 1 on a replica whose latest run held the lock; runs are short,
    so it can be 1 on several replicas at once, and 0 on all of them only when nothing is running the loop).
  - Session cleanup and the deletion of old rate limit windows run on every replica. Their deletes are idempotent.
- Each replica holds a pgx connection pool. Size Postgres `max_connections` (or a pooler) for replicas × pool size.
- **Rate limits are shared by every replica.** The limits on `/mcp/{slug}` (Admin › Limits), the OAuth endpoints,
  connect start, sign-in (`LOGIN_ATTEMPTS_PER_MINUTE`) and `/v1` (`REQUESTS_PER_MINUTE`) are counted in one PostgreSQL
  table (`rate_limit_counters`, UNLOGGED: counters may be lost on a crash or failover) in fixed one-minute windows. One
  statement per `/mcp` request; a single gateway's counter row is fine to a few thousand requests per second. Client
  addresses are stored only as SHA-256 digests. Front unauthenticated traffic with the ingress's own limits.

## Upgrades

1. Pin the new release's image digest in the overlay (verify its signature first, [Image](#image)).
2. **Migrate, then roll.** The new pods' `migrate` init container applies the schema before any new pod serves. Old pods
   keep serving during the rollout (`maxUnavailable: 0`), so a release's migrations must work with the previous release's
   code. Outside Kubernetes, run `migrate` with the new image first, then restart `serve`.
3. To roll back, pin the previous digest. Migrations are never rolled back automatically.

The [`k8s-upgrade` workflow](../.github/workflows/k8s-upgrade.yml) rehearses exactly this on a kind cluster for every
release tag and weekly: the previous release by digest, data and credentials created on it, the roll to the new image
under a request loop with no failed request, `doctor` on the new schema, then the roll back
([Smoke test](#upgrade-what-it-proves)).

**v0.2.2 (migration `00018`, expand only).** Every OAuth app (Claude Code, VS Code, pi, ...) has to sign in again about
every **180 days** from now: grants that exist at the upgrade get one whole window from the migration, however old they
are, so nobody is signed out by the upgrade itself. Set `OAUTH_REFRESH_ABSOLUTE_TTL` to another value, or `0` for no
limit, before upgrading if that doesn't suit you. Clients that refresh twice at once now get the same new tokens
instead of two sets. A trusted client (Claude Code) shows a one-time notice the first time a person signs it in to a
gateway from a computer; people who already connected it are not asked. Registrations that never received tokens
disappear after 24 hours, and one address can hold 20 of them. An anonymous request to `/oauth/authorize` is sent to
sign in before the client is looked at, so a bad client is reported after sign-in.

## Backups

PostgreSQL is the only state. Back it up with your usual tooling (managed snapshots, `pg_dump`, or WAL archiving). Also
keep `ENCRYPTION_KEY` (and any `ENCRYPTION_KEY_PREVIOUS`) and `API_KEY_PEPPER` somewhere safe and separate from the
backups:

- Without `ENCRYPTION_KEY`, restored MCP server header values and identity signing keys cannot be decrypted.
- Without `API_KEY_PEPPER`, every API key stops working.

A restore brings the database back **as it was at the dump**: keys, sessions and grants revoked or created since then
are as they were, so a key revoked after the dump works again until it is revoked again ([threat
model](threat-model.md) 7.12). Revoke such keys again after a restore, or rotate `API_KEY_PEPPER`. The smoke test's
[`restore` scenario](#restore-what-it-proves) rehearses it with `pg_dump` and `pg_restore`: the data of the dump back, the
data after it gone, a key revoked after the dump valid again, `doctor` passing.

## Metrics

Set `METRICS_ADDR` (for example `:9090`) to serve Prometheus metrics at `/metrics` on a listener of its own. It has no
authentication: allow only your monitoring namespace (the example overlay's `networkpolicy-metrics.yaml`). Labels never
carry user, key, service account, team or request IDs; gateway, server and provider slugs are limited to existing
objects (at most `METRICS_MAX_OBJECTS`, default 200 each, then `other`) and dropped when the object is deleted.

| Metric | Labels |
|---|---|
| `omp_build_info` | `version`, `commit` |
| `omp_mcp_requests_total`, `omp_mcp_request_duration_seconds` | `method` (MCP methods, `notification`, else `other`), `outcome` |
| `omp_mcp_call_duration_seconds` | `gateway`, `server` |
| `omp_mcp_rate_limited_total` | `limit` |
| `omp_payload_captures_total`, `omp_payload_capture_errors_total`, `omp_payload_redactions_total` | `rule` (redactions) |
| `omp_provider_token_refresh_total` | `provider`, `result` (`ok`, `refused`, `unavailable`) |
| `omp_machine_token_requests_total` | `result` (`ok`, `refused`, `unavailable`): token requests of `machine_oauth` servers, not cache hits |
| `omp_server_health_checks_total`, `omp_mcp_servers` | `result` / `state` (`healthy`, `failing`, `unknown`) |
| `omp_http_requests_total`, `omp_http_request_duration_seconds` | `route` (pattern), `method`, `code` (`2xx`…) |
| `omp_retention_deleted_total`, `omp_retention_last_success_timestamp_seconds` | `kind` |
| `omp_usage_rollup_last_success_timestamp_seconds`, `omp_loop_leader` | `loop` |
| `omp_db_pool_*` | |

Plus the Go and process collectors.

### Dashboards and alerts

Five Grafana dashboards are committed under [`deploy/grafana/dashboards/`](../deploy/grafana/dashboards) (MCP traffic,
MCP servers, providers and tokens, notifications, platform). Import each JSON file in Grafana (Dashboards › New ›
Import), or provision the directory with a file provider; each asks for a Prometheus data source through its
`datasource` variable. Alert rules are in [`deploy/prometheus/omp-alerts.yaml`](../deploy/prometheus/omp-alerts.yaml)
(load it with `rule_files:`) and, for the Prometheus Operator, as a `PrometheusRule` in
`deploy/kubernetes/overlays/example/prometheusrule.yaml` beside the `ServiceMonitor` (neither is in the overlay's
resources: they need the operator's CRDs, so add them when the cluster has them). The alerts are: the portal or a
replica down, server errors, a saturated database pool, tool calls failing at the servers, slow calls, sustained rate
limiting, failing MCP servers, a provider refusing refreshes, payload capture errors, stale retention or usage rollup, no
loop leader and failed notifications. Each links to its entry in the
[alert runbook](phase6-operations.md#alert-runbook). The two "down" alerts match `job="open-mcp-portal"`, the name the
example `ServiceMonitor` gives; change it if your scrape configuration names the job otherwise.

Every metric and label the dashboards and rules use is checked against the registry by a test, so a renamed metric
fails CI instead of leaving an empty panel. `make prom-check` runs `promtool check rules` and the rules' unit tests
(`omp-alerts.test.yaml`) with a local `promtool` or the pinned `prom/prometheus` image through Docker.

## Tracing

Tracing shows where a slow call spent its time: in the portal, in the database, in a provider's token refresh or at the
MCP server. It is **off** unless you configure an exporter, and then costs only the spans of the requests that are
sampled. Off, the portal creates no spans, reads no trace headers and sends nothing; a client's `traceparent`,
`tracestate` and `baggage` in `_meta` pass through to the server exactly as they always did
([MCP protocol](mcp-protocol.md#trace-context)).

### Enabling it

Set the standard OpenTelemetry variables (the YAML file takes the lower-case names; `OTEL_EXPORTER_OTLP_HEADERS` may be
read from `OTEL_EXPORTER_OTLP_HEADERS_FILE`):

| Setting | Default | Notes |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | empty (off) | The collector's OTLP/HTTP base URL, for example `http://otel-collector.observability:4318`; `/v1/traces` is added. Tracing is on when this (or the next) is set. No credentials, query or fragment in the URL. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | empty | The full traces URL, used as it is, for backends that give one. Wins over the base URL. |
| `OTEL_TRACES_EXPORTER` | empty | `otlp` turns tracing on with the OpenTelemetry default endpoint `http://localhost:4318` when none is set; `none` turns it off whatever else is set. Nothing else is supported. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | The only protocol spoken; another value is refused at start-up (no gRPC exporter is built in). |
| `OTEL_EXPORTER_OTLP_HEADERS` | empty (secret) | `key=value,key=value` sent with every export, for a collector or SaaS backend that needs a token. Never logged or reported by `doctor`. |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | `parentbased_traceidratio`, `0.1` | See [Sampling](#sampling). |
| `OTEL_SERVICE_NAME` | `open-mcp-portal` | The `service.name` of the spans. |
| `TRACE_LINK_TEMPLATE` | empty | A URL containing `{trace_id}` once, for example `https://grafana.example.com/explore?left=%7B%22datasource%22:%22tempo%22,%22queries%22:%5B%7B%22query%22:%22{trace_id}%22%7D%5D%7D` (your Grafana's own Explore link for a Tempo trace). A call's page shows its trace ID as a link to it. |

The SDK also reads the standard `OTEL_EXPORTER_OTLP_CERTIFICATE`, `_TIMEOUT`, `_COMPRESSION` and the matching
`_TRACES_` variables from the process environment (not from the YAML file). `OTEL_RESOURCE_ATTRIBUTES` is not read.
`open-mcp-portal doctor` reports whether tracing is on, the collector's host and the sampler (never the path or the
headers); it does not contact the collector. Spans are exported in the background in batches: a collector that is down
or slow loses spans (the queue is bounded and drops the excess), never requests. On shutdown the portal flushes what is
queued within `SHUTDOWN_TIMEOUT`.

On Kubernetes the base's default-deny egress also blocks the collector: add
`overlays/example/networkpolicy-otlp.yaml` (patch the namespace and pod labels to your collector) and, in the overlay's
`configMapGenerator`, `OTEL_EXPORTER_OTLP_ENDPOINT=http://<collector>.<namespace>:4318`. Use a collector (the
OpenTelemetry Collector, Grafana Alloy, a vendor agent) and let it forward to Tempo, Jaeger or a SaaS backend; the portal
speaks OTLP/HTTP only. Prefer `https://` to a collector outside the cluster: spans are not secret, but they name your
gateways and servers.

### What a trace holds

One trace per sampled request. For `/mcp/{slug}` the root is `MCP <method>` (server span) with these children:
`mcp.authenticate`, `mcp.resolve_gateway`, `mcp.rate_limit`, `mcp.authorize` (what the caller may use),
`mcp.provider_credential` (a provider token refresh happens inside it) and `mcp.upstream.forward` (a client span around
the call to the server; one per attempt). Every other request to the management API is one server span named by its
route pattern (`GET /v1/teams/{team}/gateways`). The registry's probes (the scheduled health check, **Test** and
**Refresh**) are `registry.probe` spans with the server's slug and the result. Health probes of the scheduled loop start
their own traces. Database queries are not spans.

**Attributes are limited to a fixed list**: the MCP method, the gateway, server and provider slugs (the same objects the
metrics label), the outcome, the principal kind (`api_key`, `oauth`, `service_account`), the protocol era, an error or
rate-limit class, the HTTP method, the route pattern and the status code. The code drops any other key. Spans never
carry a person, an email, a key or its name, a tool, prompt or resource name, arguments, results, headers, paths,
client addresses or tokens, have no events, and a failure is a class (`timeout`, `auth`, ...), not the error's text; a
test makes a call with sentinel secrets and scans every span. See the [threat model](threat-model.md#69-telemetry-decision-71).

### Trace context and the MCP servers

The parent of the portal's span is the request's HTTP `traceparent` header, else the `traceparent` in `params._meta`
(validated as before). With the portal's span sampled, the call to the MCP server carries a `traceparent` whose parent
is the portal's `mcp.upstream.forward` span, **to every server, third-party ones included** (a trace ID is not
sensitive), with the client's `tracestate`. `baggage` is passed exactly as the client sent it; the portal never adds
any. If the trace is not sampled, or tracing is off, the client's own context is passed on unchanged.

Logs of a sampled request carry `trace_id` and `span_id` beside `request_id`, and the call record keeps the trace ID
(Calls shows it, as a link when `TRACE_LINK_TEMPLATE` is set; the API's `McpCall.traceId` and `traceUrl`). Calls recorded
before v0.3.1, calls of requests the sampler dropped, and any call with tracing off have none.

### Sampling

The default, `parentbased_traceidratio` at `0.1`, follows a sampled or unsampled parent (a client that traces its own
requests decides) and samples one request in ten of the rest. Raise `OTEL_TRACES_SAMPLER_ARG` while you investigate and
lower it afterwards; `always_on` traces every request and `always_off` none (`always_on`, `always_off`, `traceidratio`
and the `parentbased_` forms are accepted). A parent-based sampler also means **anyone who can send a request can ask
for it to be sampled** with a `traceparent` whose flag is `01`: the cost is bounded (about ten small spans a request,
a bounded export queue that drops the excess, and rate limits apply as always), but if the portal is reachable by
untrusted clients use `traceidratio`, which ignores the parent, and accept that a client's sampled trace is then
recorded in part.

## Notifications and automation tokens

**Email** is off until `SMTP_HOST` is set. `SMTP_FROM` is required with it (`portal@example.org` or `Open MCP Portal
<portal@example.org>`), `SMTP_USERNAME` and `SMTP_PASSWORD` are set together or not at all, and a half configuration (any
`SMTP_*` without a host) is an error rather than "off". `SMTP_TLS` is `starttls` (the default, port 587: a server that
doesn't offer STARTTLS fails, never a downgrade), `tls` (implicit, port 465) or `none` (port 25). Certificates are always
verified: there is no insecure switch. `none` **with** credentials is refused unless `APP_URL` or `SMTP_HOST` is loopback;
`none` without credentials is accepted (an in-cluster relay) and `doctor` says "unencrypted". `doctor` connects, greets,
upgrades, authenticates and quits within 5 s without sending anything (group `notifications`, check `email`). Mail goes
only to people's **verified** addresses (the identity provider's `email_verified`, recorded at each sign-in), one message
per person, at most 30 per person per hour, plain text and a simple HTML alternative with no images or remote content.
The Kubernetes egress policies must allow the SMTP port (the base allows 443 only; add it in your overlay).

**Webhook destinations** are set by team owners and admins (team destinations) and platform admins. They reach **public
https addresses only**: the URL is checked when saved and again, with the resolved addresses pinned, on every delivery;
redirects are never followed; loopback, link-local and cloud-metadata addresses are never allowed, nor IPv6 forms of them
(mapped, NAT64, compatible). They deliberately do **not** use the internal-network allowlist of MCP servers (Admin ›
Internal networks, `UPSTREAM_ALLOWED_NETWORKS`): otherwise any team owner could make the portal POST into your network.
If a destination must be internal (a self-hosted receiver), the operator lists it in `NOTIFY_WEBHOOK_ALLOWED_NETWORKS`
(comma-separated CIDRs and hosts, `http:` before an entry also allows plain http; loopback and metadata can't be listed)
and opens the egress port. Only the status and a short error class of a delivery are kept, never the response. The URLs
and signing secrets are sealed with `ENCRYPTION_KEY` (`rotate-keys` re-encrypts them). See
[notifications.md](notifications.md) for the signature and payloads.

**Automation tokens** (`ompadm_…` platform-admin tokens, `omppub_…` team publisher tokens) authenticate `/v1/*` with
`Authorization: Bearer`, never `/mcp`. They are digested with `API_KEY_PEPPER` like personal keys and rotate with
`API_KEY_PEPPER_PREVIOUS` (re-digested on use). Create no token until **every replica runs this release**: the previous
release can't list audit entries written by tokens. Revoked and expired tokens are deleted after 30 days. Metrics:
`omp_automation_token_auth_total{result}`, `omp_notifications_emitted_total{event}`,
`omp_notification_deliveries_total{channel,event,outcome}`, `omp_notification_emit_errors_total`.
See [automation-tokens.md](automation-tokens.md).

## External-platform retirement

Migration `00034` permanently retires external-platform trust and relay accounts, revokes their keys and fences older replicas. It preserves original schema and history; Down never restores authority. Arrange explicit new ordinary credentials before rollout. Inbound `MCP-Gateway-Identity` is refused, including on ordinary credentials; outbound signing and JWKS remain supported. Read [platform-retirement.md](platform-retirement.md) before upgrading or configuring nested portals.

## Key rotation

**`ENCRYPTION_KEY`** seals MCP server header values and credential parts, MCP servers' TLS client keys, signing keys' private keys, auth provider client secrets,
provider connection tokens, PKCE verifiers, consent request IDs, captured payloads and webhook destinations' URLs and signing secrets.

1. **Set previous.** Put the current value in `ENCRYPTION_KEY_PREVIOUS` and a new one (`openssl rand -base64 32`) in
   `ENCRYPTION_KEY`, in the runtime secret.
2. **Roll** every pod (`kubectl rollout restart`), and wait until no pod runs with the old configuration: new values are
   sealed with the new key, old ones still open.
3. **Dry run.** `kubectl exec deploy/open-mcp-portal -- /open-mcp-portal rotate-keys --dry-run` checks that every
   sealed value opens with one of the two keys and counts them per column. If any doesn't, it stops and names the table
   and row: find the key it was sealed with, or re-enter or delete that value.
4. **Rotate.** `… rotate-keys` re-seals values still on the previous key in batches (`--batch-size`, default 100) with
   row locks; safe while serving and safe to run again. It audits `platform.secrets_reencrypt` per batch and
   `platform.key_rotation` (counts only).
5. **Verify.** `… doctor` reports `keys encryption: … ENCRYPTION_KEY_PREVIOUS can be removed`.
6. **Remove `ENCRYPTION_KEY_PREVIOUS`** and roll again. Keep the old key with your backups made before the rotation.

**`API_KEY_PEPPER`** keys the digests of API keys, service account keys, automation tokens and connected apps' tokens. Digests can't be
recomputed without the key, so rotation happens on use:

1. Put the current value in `API_KEY_PEPPER_PREVIOUS` and a new one in `API_KEY_PEPPER`; roll the pods.
2. Keys used from then on are re-digested with the new pepper (audited `api_key.pepper_rehash` /
   `service_account_key.pepper_rehash`). Connected apps' access tokens expire within an hour and their refresh tokens are
   replaced when used.
3. `rotate-keys` (or `rotate-keys --dry-run`) lists usable keys still on the previous pepper (kind, ID, name, owner or
   team, last use); `doctor` counts them.
4. After 2-4 weeks, remove `API_KEY_PEPPER_PREVIOUS`. Keys never used meanwhile stop working; their owners create new
   ones. Connected apps that weren't used sign in again.

## Not covered yet

- No OTLP export of logs or metrics, no exemplars, no database spans and no trace viewer (tracing: [Tracing](#tracing); metrics, dashboards and alerts: [Metrics](#metrics)). Logs are JSON on stdout.
- No in-cluster PostgreSQL component or backup CronJob. Bring your own Postgres and backups; a `pg_dump` and `pg_restore` round trip is rehearsed by the smoke test ([Backups](#backups)).
- The kind smoke test ([Smoke test](#smoke-test)) covers one ingress controller (Envoy Gateway), a self-signed CA, one OIDC provider (Dex), the upgrade from the previous release, a plain `pg_dump` restore and a loose load gate. It does not cover other controllers or providers, the default CNI's (kindnet) NetworkPolicy enforcement, zones, a real node drain, CloudNativePG or production sizing; see [What it does not prove](#what-it-does-not-prove).
- Images are published only for releases (`v*` tags), not for every commit on `main`. The example overlay pins the digest of the release it names: use the digest from the release you install.
- No Helm chart and no HorizontalPodAutoscaler.
