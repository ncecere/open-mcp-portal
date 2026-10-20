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
docker pull ghcr.io/ncecere/open-mcp-portal:v0.2.2
docker run --rm ghcr.io/ncecere/open-mcp-portal:v0.2.2 version     # open-mcp-portal 0.2.2 (<commit>)

# Pin the digest from the GitHub Release, and verify it first (cosign v3 or newer):
cosign verify ghcr.io/ncecere/open-mcp-portal@sha256:<digest> \
  --certificate-identity https://github.com/ncecere/open-mcp-portal/.github/workflows/image.yml@refs/tags/v0.2.2 \
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
| `DATABASE_URL` | yes (secret) | `postgres://user:pass@host:5432/db?sslmode=require`. URL-encode the password. |
| `ENCRYPTION_KEY` | yes (secret) | 32 random bytes, base64. Encrypts MCP server header values, identity signing keys, auth provider client secrets, people's provider tokens and captured call payloads. |
| `ENCRYPTION_KEY_PREVIOUS` | while rotating (secret) | The old key, still accepted for decryption until `rotate-keys` re-encrypts everything. See [Key rotation](#key-rotation). |
| `API_KEY_PEPPER` | yes (secret) | 32 random bytes, base64. Keys the HMAC that stores API keys, service account keys and connected apps' tokens. Rotate it with `API_KEY_PEPPER_PREVIOUS`, never by just replacing it. |
| `API_KEY_PEPPER_PREVIOUS` | while rotating (secret) | The old pepper: keys and tokens made with it keep working, and keys are re-digested on use. |
| `METRICS_ADDR` | optional | Prometheus `/metrics` on its own listener, for example `:9090` (empty: off). See [Metrics](#metrics). |
| `RETENTION_INTERVAL`, `RETENTION_BATCH_SIZE` | optional | How often old data is deleted (default 15m) and rows per transaction (1000). Periods are set in Admin › Retention. |
| `OAUTH_MAX_REGISTERED_CLIENTS` | optional | Cap on live OAuth clients registered through the open `POST /oauth/register` (default `1000`; `0` = no cap; 0 to 1000000). Counts registrations used in the last 30 days; over it, registration answers `503 temporarily_unavailable` until one expires. Apps that identify themselves with a metadata document aren't counted. An admin can also turn open registration off (Admin › Trusted clients). |
| `OAUTH_MAX_UNUSED_CLIENTS_PER_ADDRESS` | optional | How many registrations that have not received tokens yet one source address can hold (default `20`; `0` = no cap). The answer past it is `429 slow_down`. Registrations that sign in stop counting; unused ones leave after 24 hours. Behind an ingress, set `TRUSTED_PROXIES`, or every caller shares one address. |
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
not at startup, so a misconfigured issuer shows up at sign-in and in the logs. `migrate` needs only `DATABASE_URL`, and it
applies the safety checks only when `APP_URL` is set. `open-mcp-portal doctor` prints all of this and also checks
Postgres and the migration state:

```sh
kubectl -n open-mcp-portal exec deploy/open-mcp-portal -c portal -- /open-mcp-portal doctor
```

## Kubernetes

### Secrets

The base references the secret `open-mcp-portal-runtime` by name and never contains values. Create it with your
secrets operator (an `ExternalSecret`, for example) or by hand:

```sh
kubectl create namespace open-mcp-portal   # or apply the overlay's namespace.yaml first
kubectl -n open-mcp-portal create secret generic open-mcp-portal-runtime \
  --from-literal=DATABASE_URL='postgres://omp:<password>@db.example.org:5432/omp?sslmode=require' \
  --from-literal=ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  --from-literal=API_KEY_PEPPER="$(openssl rand -base64 32)" \
  --from-literal=OIDC_CLIENT_SECRET='<from your IdP>'
```

| Key | Used by |
|---|---|
| `DATABASE_URL` | `migrate` init container and `portal` |
| `ENCRYPTION_KEY`, `API_KEY_PEPPER`, `OIDC_CLIENT_SECRET` | `portal` (required: a missing key stops the pod with `CreateContainerConfigError`) |
| `ENCRYPTION_KEY_PREVIOUS`, `API_KEY_PEPPER_PREVIOUS` | `portal`, optional, only during a rotation |

Store `ENCRYPTION_KEY` and `API_KEY_PEPPER` in your secrets store as well. A database backup is useless without them:
see [Backups](#backups). Secrets are not hashed into the pod template, so after changing one, run
`kubectl -n open-mcp-portal rollout restart deploy/open-mcp-portal` (or use your operator's reloader).

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

The base references `ghcr.io/ncecere/open-mcp-portal` and sets its tag to `v0.2.2` through a Kustomize `images:` entry.
A tag can move, so pin the digest of the release you verified in your overlay (the digest wins over the tag):

```yaml
images:
  - name: ghcr.io/ncecere/open-mcp-portal
    newTag: v0.2.2
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

- The host must equal `APP_URL`'s host, and TLS terminates at the ingress.
- **Timeouts.** A `/mcp/{slug}` call waits up to 120s for its upstream server (the maximum per-server timeout). Allow
  reads of a few minutes: the example sets `proxy-read-timeout: 300` for ingress-nginx and `timeouts.request: 300s` on the
  HTTPRoute. Requests are capped at 1 MiB.
- **Streaming (SSE).** A `tools/call` that carries `_meta.progressToken` from a client that accepts
  `text/event-stream` is answered as a Server-Sent Events stream (the server's progress, then the response), with an SSE
  comment (`: keep-alive`) every 15 s while it waits. The portal sends `X-Accel-Buffering: no` and sets no write timeout
  of its own, so the proxy in front must neither buffer the response nor cut a quiet one. These are the settings to
  check (the nginx example is in `deploy/kubernetes/overlays/example`; the others are not tested here):
  - **ingress-nginx:** `proxy-buffering: "off"` (the example sets it; the response header does the same) and a
    `proxy-read-timeout` above the longest server timeout, 120s (the example: 300). Don't compress `text/event-stream`.
  - **Traefik:** don't put the `buffering` middleware on the portal's route, leave the entrypoint's
    `respondingTimeouts.writeTimeout` at 0, keep `idleTimeout` above 120s, and, if a `ServersTransport` sets
    `forwardingTimeouts.responseHeaderTimeout`, make it at least 300s.
  - **Gateway API (`HTTPRoute`):** `timeouts.request` of at least 300s (the example), and the same or unset for
    `timeouts.backendRequest`.
  - **Cloud load balancers** have idle timeouts of their own (AWS ALB: 60s by default). The keep-alive comments count as
    traffic, but a total call time above the balancer's request limit still ends the stream.
  A client that closes the stream cancels the call to the upstream server, so a proxy that ends a response early also
  cancels the call. Calls without a progress token, or without `text/event-stream` in `Accept`, stay one buffered JSON
  response (at most 1 MiB); a streamed call relays at most 64 progress events and 4 MiB.
- **No sticky sessions.** `/mcp/{slug}` is stateless: no MCP session lives in a pod, and browser sessions and OIDC login
  state are in PostgreSQL. Any replica can serve any request.
- Set `TRUSTED_PROXIES` to the controller's pod network ([why](#behind-a-proxy-trusted_proxies)).

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
  the session cookie `__Host-omp_session`; over the development http origin the names have no prefix. For one release
  (v0.2.2) the old name `omp_oidc_state` is still accepted, so a person who started signing in just before an upgrade is
  not sent back to the start.

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
([`scripts/k8s-smoke.sh`](../scripts/k8s-smoke.sh)) applies them to a real cluster and uses what it deployed:

```sh
make k8s-smoke                    # about 2 minutes warm; needs docker, kind, kubectl, curl and jq
SMOKE_CNI=calico make k8s-smoke   # about 3 minutes; Calico enforces the NetworkPolicies, which are then tested
```

It builds the portal and the fake MCP server images from the working tree, creates a kind cluster of one control plane
and two workers (node image pinned by tag and digest, its own kubeconfig in a temporary directory; it never touches
`~/.kube`), loads the images and applies the base through [`overlays/smoke`](../deploy/kubernetes/overlays/smoke) (a
throwaway PostgreSQL 17 StatefulSet on a PVC, the fake MCP server, and run-time random secrets, config merged into
`open-mcp-portal-config` and the local image tags). It stops at the first failed assertion with a message, then (always)
collects `kubectl get pods,events`, `describe` and every pod's logs into `bin/k8s-smoke-artifacts` (`SMOKE_ARTIFACTS`),
deletes the cluster, the images and the temporary directory. `SMOKE_KEEP=1` keeps them. Every wait has its own timeout,
and `SMOKE_TIMEOUT` (900s) bounds the run.

**What it proves**

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

**What it does not prove**

- **NetworkPolicy under the default run.** kind's default CNI (kindnet) does not enforce NetworkPolicy: the base's
  policies are applied and the manifests are valid, nothing more. Only `SMOKE_CNI=calico` tests the ingress policy
  (with the example overlay's patch: the ingress namespace), the DNS and PostgreSQL rules (the Postgres rule narrowed
  to PostgreSQL's pods, as an overlay would) and an overlay's rule for an in-cluster MCP server. The `open-mcp-portal-egress-https` rule
  (TCP 443 to anywhere) is not exercised: nothing in the test dials a public https address.
- **The internal-network allowlist.** With `DEV_AUTH` on a loopback `APP_URL`, which the test needs, the portal allows private and plain-http MCP
  server addresses whatever `UPSTREAM_ALLOWED_NETWORKS` says. The test sets `http:*.svc.cluster.local` as the docs say
  (the portal parses it and `doctor` validates it), but registering the fake server would work without it.
- **Ingress and TLS.** No ingress controller, Gateway API implementation, certificate or `TRUSTED_PROXIES`; the
  "ingress controller" is a pod in a namespace named in the policy. The example overlay's Ingress, HTTPRoute,
  ServiceMonitor and metrics port are only validated, never applied.
- **OIDC.** Sign-in is the development sign-in; `OIDC_ISSUER` and `OIDC_CLIENT_SECRET` are placeholders.
- **Production sizing, storage and Postgres.** One throwaway PostgreSQL with no backup, TLS or failover; a three-node
  cluster in one Docker VM; no zones (kind's nodes carry no `topology.kubernetes.io/zone`, so the second spread
  constraint has nothing to spread over); no node drain, upgrade between releases or restore.
- **Client-visible `/readyz`.** A pod that has had SIGTERM answers `/readyz` with 503 on purpose, for 10 seconds, and
  for a second or so after the signal kube-proxy can still route a request to it. A loop of `/readyz` requests through
  the Service therefore sees a few 503s during a rollout (the test notes them); real traffic (`/healthz`, `/mcp`) does not.
  Use `/readyz` for health checks that remove a pod from a pool, not as a probe of what clients experience.
- **GitHub runners.** [`k8s-smoke.yml`](../.github/workflows/k8s-smoke.yml) runs the script on demand, weekly and on pushes to `main` that
  change `deploy/**`, the `Dockerfile`, the script or the workflow (both CNIs). It has not run on GitHub yet; the script was
  run on macOS (Docker Desktop, arm64).

The node image (Kubernetes 1.37), Calico, the PostgreSQL image and the kind and kubectl binaries are pinned (the workflow
also checks their checksums). Other settings: `SMOKE_CLUSTER` (name, must start with `omp-smoke`), `SMOKE_NODE_IMAGE`.

## Migrations

- In Kubernetes, the `migrate` init container runs `open-mcp-portal migrate` in every new pod. A PostgreSQL advisory
  lock serialises concurrent runs, so only the first pod does any work.
- Elsewhere, run `open-mcp-portal migrate` before `serve`, or set `MIGRATE_ON_START=true` on a single instance.
- `serve` refuses to start while migrations are pending. The message names the current and required versions.

## Scaling

- The portal is stateless, so scale the Deployment horizontally. All shared state is in PostgreSQL.
- Background loops:
  - The MCP server health checks (`HEALTH_CHECK_INTERVAL`, default 5m), the signing-key rotation, the retention loop
    (`RETENTION_INTERVAL`, default 15m) and the usage rollup (every 5 minutes) take a PostgreSQL advisory lock, so one
    replica runs each at a time (`omp_loop_leader` says which).
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
| `omp_server_health_checks_total`, `omp_mcp_servers` | `result` / `state` (`healthy`, `failing`, `unknown`) |
| `omp_http_requests_total`, `omp_http_request_duration_seconds` | `route` (pattern), `method`, `code` (`2xx`…) |
| `omp_retention_deleted_total`, `omp_retention_last_success_timestamp_seconds` | `kind` |
| `omp_usage_rollup_last_success_timestamp_seconds`, `omp_loop_leader` | `loop` |
| `omp_db_pool_*` | |

Plus the Go and process collectors. Useful alerts: `omp_payload_capture_errors_total` increasing; no replica with
`omp_loop_leader{loop="retention"} == 1` for an hour; `omp_mcp_servers{state="failing"} > 0`; a high rate of
`omp_mcp_rate_limited_total`.

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

## Key rotation

**`ENCRYPTION_KEY`** seals MCP server header values, signing keys' private keys, auth provider client secrets,
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

- No dashboards, alert rules or tracing (metrics: [Metrics](#metrics)). Logs are JSON on stdout.
- No in-cluster PostgreSQL component, backup CronJob or restore procedure. Bring your own Postgres and backups.
- The kind smoke test ([Smoke test](#smoke-test)) does not cover ingress, TLS, OIDC, the default CNI's (kindnet) NetworkPolicy enforcement, zones, upgrades between releases or restores.
- Images are published only for releases (`v*` tags), not for every commit on `main`. The example overlay pins the digest of the release it names: use the digest from the release you install.
- No Helm chart and no HorizontalPodAutoscaler.
