# Changelog

Notable changes to Open MCP Portal, one entry per release. Design notes for each phase are in [`docs/`](docs/), and
[`docs/status.md`](docs/status.md) records what was verified.

The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor releases may include
breaking changes; the entry says how to adapt.

## [0.3.0] - 2026-10-20

Calls from agents as the person's calls (roadmap #55 to #58 and #60, [decisions](docs/decisions.md) 65 to 68). Migration `00020` (expand-only).

- **Trusted agent platforms** (#55, [agent-platforms.md](docs/agent-platforms.md)). Platform admins trust an external agent platform (Pi Durable Platform) as an issuer of agent identity tokens: Admin › Trusted agent platforms (name, issuer, keys address, audience, on or off, the result of the last key fetch and its key IDs, and a **Test** that fetches the keys). A strict verifier accepts only ES256 tokens in the format of the platform's design note: no `none`, HS\* or RS\*, the key from the platform's JWKS only (fetched through the same address guard as MCP servers, no redirects, 5 s, 64 KiB, cached for at most 5 minutes, refetched at most twice a minute for an unknown `kid`, kept for 15 minutes past expiry while the platform is down), `iss`, `aud`, `principal_type: agent`, the claims and time limits, and a `jti` accepted once across replicas. A named person's `person.iss` must equal `OIDC_ISSUER`. API `/v1/admin/agent-platforms…`, session-only (no automation token can change or read them), audited as `agent_platform.*`.
- **Relay service accounts** (#56). A platform admin marks a team service account as a relay for a platform (`PUT /v1/admin/agent-platforms/{id}/relays/{serviceAccountId}`; audited `service_account.relay_set` and `relay_clear`). A call with that account's key may carry the platform's `MCP-Gateway-Identity` token. A token naming a person makes the call **the person's, limited to what the relay account could reach** (the gateways both can use, the lower of the two roles for minimum roles); the person is read on every call, so suspending them or removing them from a team applies to their agents at once; an unknown or suspended person is a tool error, never the account's own call. A token that fails any check on a relay's request refuses the request (HTTP 403); a token with any other credential is ignored, counted (`omp_agent_token_total`) and logged. A service account key alone behaves as before. The call log shows the person, the agent, the relay account and the platform (`McpCall.agent`).
- **No consent links in agent calls; require a present person** (#57). A relayed person call never gets `-32042`, a consent link or an `input_required` result: a missing connection, a server the person hasn't allowed, too few scopes and an upstream sign-in are tool errors naming the provider and saying to connect under Account › My connections (recorded `needs_authorization`, class `needs_connection`). New switch **Require a present person for calls from agents** on a server and an override on each capability (`PUT …/capabilities/{id}/present-person`; editors; default off): relayed calls whose token says `person_present: false` are refused (class `person_not_present`; calls that name nobody are refused too, see the review below). Turning it on needs no review; relaxing it sends a published server back to review under `approval_required`.
- **Allow a server from My connections** (#60, decision 68, [agent-platforms.md](docs/agent-platforms.md#delegated-credentials-and-agents-that-have-no-browser)). On Account › My connections, **Allow servers…** on a connection lists the servers that require that provider and that the person may use through a gateway now, each with its team, address, the scopes it asks for and **Allow**; allowing records the same grant as a consent link's confirm step, for the server's current address and the scopes it requires, with no call and no link, and **Take back** removes one server's allowance without disconnecting. A server that moved or now asks for more since the list loaded is refused (`409 server_changed`); an account without the scopes is sent to the provider (`409 connect_required`). An agent's `server_not_allowed` tool error now says to allow the server there (still link-free). API: `GET …/allowable-servers`, `POST …/allow-server`, `DELETE …/allowed-servers/{serverId}` under `/v1/me/connections/{id}`, browser session only, 20 a minute per person; audited `provider_connection.server_allow` (`viaRequest` false) and `provider_connection.server_revoke`. No migration.
- **`act` claim and the administrator's guide** (#58). The identity token for the MCP server behind the gateway keeps the person's `principal_type: user`, `sub`, `email` and `teams` on a relayed person call, sets `client` to the relay account's name and adds `act` (`sub`, `name`, `iss`, `principal_type: agent`, `person_present`), exactly on those calls ([upstream-identity.md](docs/upstream-identity.md#calls-from-agents)). `cmd/fakemcp`'s `whoami` shows it. [agent-platforms.md](docs/agent-platforms.md) walks through the setup and a manual end-to-end check; the [threat model](docs/threat-model.md#68-the-agent-platform-relay-decisions-65-to-67) has the relay trust boundary. **Not run:** a running Pi Durable Platform instance (see the contract fixtures below for what was checked against its real code).
- **Security review of the agent platform work, applied** ([agent-platforms.md](docs/agent-platforms.md#limits-you-should-know), [threat model](docs/threat-model.md#68-the-agent-platform-relay-decisions-65-to-67) AG-2, AG-3, AG-9, AG-10; decisions 65 to 67 edited with dated notes). Changes to behaviour that was never released:
  - **A token's `tool` claim is bound to the request** (M-1). On a `tools/call` the claim must be present and equal `params.name` (the name the portal exposes); on every other method it must be absent. A mismatch refuses the request like any bad relay token (`403`, nothing runs, `omp_agent_token_total{result="rejected_tool_mismatch"}`). PDP's recorded tokens fit the rule (tokens for a tool carry `tool`, the handshake token has none); what PDP's gateway puts in `tool` for a real call was not checked against a running PDP. **Accepted residual, documented:** the token is still bound only to the platform's audience, not to a relay or a gateway, so a token another PDP server received can be used with any relay key of that platform for a call of the same tool name; run PDP so that only platform admins set `identityAudience` and a team server never gets a token whose `aud` is a trusted portal audience. A per-gateway audience mode is not built.
  - **Require a present person also covers calls that name nobody** (M-2). On a relay service account, a capability that requires a present person now refuses a valid token that names no person (a team agent's shared thread or background run) and a relay key with no token, as `person_not_present`, as well as a person who isn't present. Calls not on a relay account are never affected. The UI text for the switch and the override says so.
  - **The keys address of a trusted platform is https, always** (L-1). An Internal networks entry that allows plain http for a host no longer applies to it; `http://` is refused when saved (`422 url_not_allowed`) and again before every fetch.
  - **Migration `00020` takes no long lock on `mcp_calls`** (L-2; edited in place, it was never released). The three new text columns are added without a `CHECK`, the length checks are added `NOT VALID` and then validated (they don't block recording calls), the index on `via_platform_id` is dropped (no query filters on it, and building it blocks writes), and the migration runs without goose's wrapping transaction (`NO TRANSACTION`) with every statement safe to run again. Tested up, down and up again, and with the Up run a second time.
  - **The review digest covers each capability's effective present-person requirement** (L-4), only when on, so relaxing it (or adding it) after a reviewer read the server makes the approval stale (`409 changed_since_review`), also for a pending server.
  - **Names from the token lose Unicode format characters** (I-8): right-to-left overrides, zero-width spaces and joiners, the byte order mark and the soft hyphen are removed from the agent's name and the other texts shown to people, as control characters already were; the agent, team and token IDs may contain none. The stale-keys warning is logged at most once a minute per platform (I-3). The unused `request.intersect` is removed (I-5).
  - **Documented, no code:** a server with Send identity off receives the person's provider token on a relayed call and no `act` claim; leave Send identity on for servers that must tell agents from people (L-3, [upstream-identity.md](docs/upstream-identity.md#calls-from-agents)). Accepted limits I-1, I-2, I-4, I-6 and I-7 are one line each in the threat model.
- **Contract fixtures from Pi Durable Platform v0.4.0** ([agent-platforms.md](docs/agent-platforms.md#what-is-not-covered)). `internal/agentidentity/testdata/pdp/` holds 8 tokens and 5 key sets produced on 2026-10-20 by PDP's real signer and JWKS handler, with fixed timestamps and a README (no private key: public JWK members only), and `contract_pdp_test.go` checks that the verifier accepts or refuses each exactly as recorded, including key rotation (prepublish, overlap, drop), clock-skew edges, replay and tampering. The docs now say that a team agent's shared thread or background work names nobody, a personal workspace names its owner even with no thread (`person_present` false), and that a PDP server without `identityAudience` gets tokens whose `aud` is the server's own URL, which the portal refuses unless the platform's audience is set to it. Not checked: PDP's gateway and runtime end to end, and a live deployment.
- **The old sign-in state cookie name is no longer read** (as announced in v0.2.2). On https only `__Host-omp_oidc_state` is accepted; a person who started signing in just before the upgrade starts again.
- **Tests:** `TestIdentitySentMigrationKeepsWhatExists` named "the newest migration" and failed once `00020` existed; it now goes down to migration 18 and up to 19 explicitly. The relay tests use TLS issuers (the test app trusts the test certificate) and mint tokens whose `tool` is the tool called.

Documentation: the [roadmap](docs/roadmap.md) is rewritten around what v0.2.1 shipped and what is still open, with an [issue](https://github.com/ncecere/open-mcp-portal/issues?q=is%3Aissue+is%3Aopen+label%3Aroadmap) and implementation plan for each item; the threat model's hardening table links its issues and no longer lists Trivy as open.

## [0.2.2] - 2026-10-20

Documentation: the [roadmap](docs/roadmap.md) is rewritten around what v0.2.1 shipped and what is still open, with an [issue](https://github.com/ncecere/open-mcp-portal/issues?q=is%3Aissue+is%3Aopen+label%3Aroadmap) and implementation plan for each item; the threat model's hardening table links its issues and no longer lists Trivy as open.

OAuth hardening, migration `00018` (expand only; [decisions 62 and 63](docs/decisions.md), threat model H-1, H-3, H-4 and H-8, [phase4-client-auth.md](docs/phase4-client-auth.md#as-built-v022-hardening-h-1-h-3-h-4-h-8)).

- **The client is looked at only after sign-in** (H-3). `GET /oauth/authorize` without a session now sends the browser to sign in before anything else: the client's metadata document is not fetched and no reason is given, so an anonymous caller can neither make the portal fetch a URL nor learn why a request would fail (a query that is too long or repeats a parameter gets one generic page). Uncached metadata document fetches are limited to 20 a minute per source address. People see no difference except that a bad client is reported after signing in.
- **Controls for open client registration** (H-4; [deploy.md](docs/deploy.md)). Admin › Trusted clients has a switch **Allow open client registration** (on by default; session-only, platform tokens can't change it): off, the authorization server metadata leaves out `registration_endpoint` and `POST /oauth/register` answers `403`. A registration that never received tokens is deleted after **24 hours** (one that did keeps its 30 days unused). `OAUTH_MAX_UNUSED_CLIENTS_PER_ADDRESS` (default `20`, `0` = no cap) limits the registrations one address holds that nobody has used yet (`429 slow_down`); the address is kept on the row. `doctor` prints the registration state and the live count against the cap. `PUT /v1/admin/settings/oauth-clients` takes an optional `openRegistration`, and its answer has it.
- **A trusted client asks once when it signs in from this computer** (H-1). The first time a person signs a trusted client (such as Claude Code) in to a gateway with a loopback redirect (`http://localhost:<port>/…`), the consent page shows a short notice, **Continue** or **Cancel**, instead of the client receiving a code silently. Audited `oauth.grant_confirmed`. Asked once per person, client and gateway (again after the app is disconnected); never for `https` redirects, and not for people who already connected the client. The consent API gets `notice`.
- **Refresh tokens have an absolute lifetime** (H-8). `OAUTH_REFRESH_ABSOLUTE_TTL` (default **180 days**, `0` = no limit, `180d` or `4320h`) counted from the person's last sign-in of the app; after it the next refresh answers `invalid_grant`, the grant is revoked (`expired_absolute`) and the app signs in again. Connected apps shows **Sign-in expires** (`OAuthGrant.expiresAt`). A refresh token presented again within the 30-second grace now gets the **same** new tokens instead of a second set; outside the grace it still revokes the grant.
- **Upgrade note.** Every OAuth app has to sign in again about every 180 days (service accounts and API keys don't: use them for agents that run without a person). Grants that exist when `00018` runs get one whole window from the migration, however old they are, so the upgrade signs nobody out; set `OAUTH_REFRESH_ABSOLUTE_TTL=0` to keep today's unlimited life. Registrations that already had a grant keep working; ones nobody ever used disappear. An anonymous `/oauth/authorize` request is sent to sign in first. Roll back by pinning the previous image (the old release ignores the new columns).

- **Send identity token starts off for a public server with no sign-in** ([#5](https://github.com/ncecere/open-mcp-portal/issues/5), [registry.md](docs/registry.md), [upstream-identity.md](docs/upstream-identity.md), decision 64, threat model H-2). Found with DeepWiki's public server, which refuses any `Authorization` header when a tool runs, after registration and Test passed. When a server is registered with `authMode` none and no explicit `sendIdentity`, a **public** host (or a name that can't be resolved) now defaults to off; an **internal** host (an allowlist entry or a private address) and the static-header and OAuth modes default to on; an explicit value is always kept. The add form shows the default for the address and says why. **Existing servers are unchanged.** If a public server you register expects the token, turn the switch on. Call records gain `identity_sent` (migration `00019`, nullable; shown on the call's page as Identity token, in the call list's optional column, and filterable with `?identitySent=true|false`; empty for calls that weren't forwarded and for older calls). New endpoint `POST /v1/teams/{team}/mcp-servers/identity-default` (session only, 30 a minute). Still not caught by Test: a server that accepts the request and refuses only when a tool runs; the call record now shows whether the token was sent.
- **Triage and support policy** ([#21](https://github.com/ncecere/open-mcp-portal/issues/21), [CONTRIBUTING.md](CONTRIBUTING.md#how-issues-are-handled)). Documentation: what each label and milestone means, the best-effort reply goal for one maintainer (about a week; security reports follow [SECURITY.md](SECURITY.md)), supported versions (the latest minor), release cadence, how decisions are made and what a good pull request holds. It is linked from the README and the issue chooser, and the Releasing section now uses `scripts/bump-version.py`.
- **Dockerfile base images are pinned by digest** ([#11](https://github.com/ncecere/open-mcp-portal/issues/11), threat model H-9). `node:22-alpine`, `golang:1.26` and `gcr.io/distroless/static-debian12:nonroot` keep their tag and carry the digest of their multi-arch index, so the same commit builds on the same bases. Dependabot's `docker` entry now ignores only the version of `golang` and `node` (a toolchain change stays deliberate), so their digest updates arrive in its weekly pull request.
- **The sign-in state cookie is `__Host-omp_oidc_state` on https, and a missing `TRUSTED_PROXIES` is reported** ([#10](https://github.com/ncecere/open-mcp-portal/issues/10), [deploy.md](docs/deploy.md#behind-a-proxy-trusted_proxies), threat model H-7). The cookie that ties a sign-in to its browser had no `__Host-` prefix, so a sibling subdomain could set or shadow it; now it is host-only, `Secure`, `Path=/` on https (the development http origin keeps `omp_oidc_state`). The old name is still accepted for this release, so a person who is mid sign-in during the upgrade is not sent back; it will be removed in v0.3. Behind a proxy with `TRUSTED_PROXIES` empty, every request appears to come from the proxy, which makes per-address rate limits and audit addresses useless without saying so: when a request carries `X-Forwarded-For` or `Forwarded` and `TRUSTED_PROXIES` is empty (non-loopback `APP_URL`), the portal logs one warning, at most once a minute, and `doctor` prints an info check. No change for installs that set `TRUSTED_PROXIES`.
- **End-to-end test that an echoed token is redacted** ([#12](https://github.com/ncecere/open-mcp-portal/issues/12), threat model DC-4, MCP-7). A server that returns a token it was given must not get it into recorded payloads, audit, call records or logs. `TestEchoedProviderTokenIsRedactedEverywhere` and `TestEchoedUpstreamOAuthTokenIsRedactedEverywhere` run a platform provider's token and an oauth-mode server's own token through the fake server's new `echo_tokens` tool and check the payload as the team owner and as platform staff, both call lists, both audit logs and the logs. No behaviour change: an oauth server's token is scrubbed from the answer the client receives, a platform provider's token still is not (it is the caller's own), and recordings redact both.

## [0.2.1] - 2026-10-18

Small changes since v0.2.0 ([release notes](docs/releases/v0.2.1.md)). No migration.

- **Test connection sends the identity token** ([registry.md](docs/registry.md#health), [upstream-identity.md](docs/upstream-identity.md#what-a-test-sends), decision 61). Found with DeepWiki's public server, which refuses any `Authorization` header on a call while registration, Test, refresh and health checks all passed. A manual Test of a server with **Send identity token** on now sends the identity token of the editor who pressed it (`gateway` `omp:test`, no `tool`, `client` `Test connection`). If the server answers `401` or `403` to that and accepts the same request without the token, the Test fails (class `auth`, the server's HTTP status) with "Turn off Send identity token for this server, or have the server accept the token." Refresh and scheduled checks still send no token, and an automation token's Test (no person) sends none. **Not caught:** a server that accepts the request and refuses only when a tool runs (HTTP 200 with `isError`, which is what DeepWiki does) still passes Test. The help text of the switch says what is sent and that some public servers refuse it. No API contract change.
- **Cap on dynamically registered OAuth clients** ([deploy.md](docs/deploy.md), threat model H-4). `OAUTH_MAX_REGISTERED_CLIENTS` (default `1000`, `0` = no cap) bounds the clients registered through the open `POST /oauth/register` that were used in the last 30 days; over it the endpoint answers `503 temporarily_unavailable`. Clients that use a metadata document aren't counted. **Upgrade note:** an installation with more than 1000 live registrations stops accepting new ones until some expire; set the variable higher (or `0`) first if that matters. The per-address limit (10 a minute) is unchanged.
- Kubernetes smoke test: `make k8s-smoke` ([`scripts/k8s-smoke.sh`](scripts/k8s-smoke.sh), [docs/deploy.md](docs/deploy.md#smoke-test)) applies the Kustomize base, through the new test overlay `deploy/kubernetes/overlays/smoke`, to a three-node kind cluster with a throwaway PostgreSQL and the fake MCP server, and checks the migrate init container, `doctor`, spreading over nodes, the PodDisruptionBudget, the API and `/mcp/{slug}` in both protocol eras, a rolling update and a pod deletion with no failed request, and the SIGTERM drain; `SMOKE_CNI=calico` enforces and tests the NetworkPolicies. `.github/workflows/k8s-smoke.yml` runs it on demand, weekly and on pushes to `main` that touch `deploy/**`, the `Dockerfile` or the script (not yet run on GitHub). It does not cover ingress, TLS, OIDC, kindnet's missing NetworkPolicy enforcement, zones or upgrades.
- Dependencies: Go `kin-openapi` 0.149.0 to 0.151.0, `go-jose` 4.1.5 to 4.1.6, `goose` 3.28.0 to 3.29.0; the web group (React 19.3.1, TanStack Query and Router, lucide-react, Vitest). `govulncheck` and `npm audit` report nothing.
- Documentation: a public server that refuses any `Authorization` header (found with DeepWiki's `https://mcp.deepwiki.com/mcp`) fails on its first call while **Send identity token** is on, because the token travels as `Authorization: Bearer`; documented in [registry.md](docs/registry.md) and the docs site's troubleshooting page. Claude Code 2.1.280 was run against the 2026-07-28 revision, over an API key and over OAuth on a real deployment ([status.md](docs/status.md)).
- The example Kubernetes overlay pins v0.2.0's digest.
- Repository: `web/node_modules`, a local symlink committed by mistake in v0.2.0, is no longer tracked, and `.gitignore` ignores it whatever its type.

## [0.2.0] - 2026-10-18

Support for the MCP 2026-07-28 revision, pilot readiness (admin overview, notifications, automation tokens) and fixes from
a security review ([release notes](docs/releases/v0.2.0.md)). Migrations `00014` to `00017`.

**MCP 2026-07-28, server side** ([docs/mcp-protocol.md](docs/mcp-protocol.md), decision 51). Gateways at `/mcp/{slug}`
now speak the new protocol era next to 2024-11-05 to 2025-11-25, chosen per request; legacy clients see no change.

- `server/discover` (supported versions, capabilities, identity); required `_meta`, `MCP-Protocol-Version`,
  `Mcp-Method` and `Mcp-Name` validated against the body (`400`, `HeaderMismatch` `-32020`; unsupported version
  `-32022` with the supported list; unknown methods `404` `-32601`); `Mcp-Param-*` headers validated for tools with
  `x-mcp-header`.
- Results carry `resultType` and `_meta` `serverInfo`; lists, discovery and reads carry `ttlMs` and
  `cacheScope: "private"` (lists differ per person, never public); lists sorted by exposed name.
- Any JSON Schema `outputSchema` and any JSON `structuredContent` pass through to modern clients (legacy clients
  still get object schemas only); resource not found is `-32602` (legacy `-32002`); `ping` and `logging/setLevel`
  are method not found; the rate-limit code is `429` instead of `-32029` for modern requests.
- "Connect your account" as a multi round-trip request: modern clients that declare URL elicitation get an
  `input_required` result with the existing connect link and a sealed `requestState` (AES-GCM, key derived from
  `ENCRYPTION_KEY`; bound to the person, gateway, request and parameters; 10 minutes) and retry; declines return
  "authorization declined". A modern client that did not declare URL elicitation gets no `-32042` (the revision forbids it): a tool call answers a tool error and a prompt or resource read `-32010`, with the same link in the message. Legacy clients keep `-32042`.
- Dynamic client registration accepts and echoes `application_type` (`web` or `native`); documented as deprecated.
- `cmd/fakemcp -schema-tools`; `secrets.Box.Derive`. The MCP conformance suite was run against a gateway
  (results in docs/mcp-protocol.md).

**MCP 2026-07-28, client side** ([docs/mcp-protocol.md](docs/mcp-protocol.md#the-portal-as-a-client-of-your-servers),
decisions 51 and 54). How the portal talks to your servers. Migration `00016` (three nullable columns on `mcp_servers`).

- **Era negotiation per server.** Discovery, refresh, test, health checks and forwarded calls try the modern era first
  (`server/discover`) and fall back to `initialize` only by the specification's rule (a `400` whose body is not a
  recognized modern error; `404` and `405` from an HTTP+SSE-only server stay errors). The newest mutually supported
  version is used. The era is cached in memory per server ID and URL for 5 minutes. The last negotiated `protocol`
  (`era`, `version`, `negotiatedAt`) is stored on the server by refresh, test and health checks and returned by the API
  (`McpServer.protocol`; cleared when the URL changes).
- **Elicitation is relayed.** An upstream `input_required` result reaches a modern client that declared elicitation as
  `inputRequests` (validated, bounded, https URLs only) with a sealed `requestState` bound to the person, gateway, call
  and upstream server; the retry goes back to the server with the original parameters, the answers and the server's own
  state. The portal declares to the server exactly the elicitation modes the client declared, per request. Sampling and
  roots are refused with a tool error. Legacy clients keep getting no relay. Recorded `ok` with error class
  `input_required`.
- **Streaming.** A `tools/call` with `_meta.progressToken` from a client that accepts `text/event-stream` is answered
  as SSE: the server's progress (at most 64 events, 4 MiB), then the response; `X-Accel-Buffering: no`, a keep-alive
  comment every 15 s; closing the connection cancels the upstream call. [deploy.md](docs/deploy.md#ingress) has the
  ingress settings.
- `traceparent`, `tracestate` and `baggage` pass from the client's `_meta` to the server's (validated).
- Upstream OAuth: dynamic registration says `application_type: "web"` (SEP-837); a client registered by dynamic
  registration is registered again, and chosen afresh (a Client ID Metadata Document is preferred), when the resource
  metadata names another authorization server (SEP-2352).
- A request id of its own for every modern request, a retry included (found by the conformance suite, which passes its
  client scenarios for this revision except the interactive `auth/*` ones: `cmd/upstream-conformance`).
- `cmd/fakemcp -protocol legacy|modern|both`, `-mrtr-tools`, `-stream-tools`.

### Security

Fixes from the [threat model](docs/threat-model.md) review (section 8). Two additive API changes need a client update:
approving now names what was reviewed. People re-consent once per server for provider tokens (F-3).

- **Another origin never keeps a server's stored header value (F-1).** A URL edit that changes scheme, host or port is
  refused with `422 auth_value_required` unless the same request sends a new `authValue` or removes the header; in `oauth`
  mode it erases the connections and sends the server back to the setup sign-in. The audit entry names `oldOrigin` and
  `newOrigin`. Path, trailing-slash and case edits are unchanged.
- **Approvals are bound to what the reviewer saw (F-2).** `McpServer.reviewDigest` is new and read-only. Approving a
  server (`adminReviewMcpServer`) must send it as `expectedDigest`, approving a capability (`adminApproveMcpCapability`,
  `approveTeamMcpCapability`) must send `expectedFingerprint`: `400 expected_digest_required` or
  `expected_fingerprint_required` without it, `409 changed_since_review` when the server or capability changed in
  between. Publishing accepts an optional `expectedDigest`. The web UI sends them; scripts that approve (such as
  `scripts/dev-seed.py`) read the digest first.
- **Provider tokens are bound to a server and its origin (F-3, decision 60).** A platform provider's token (GitHub,
  Google, ...) used to go to whichever server required the provider, at whatever URL it had, so an editor could make a
  server "require" GitHub, or re-point one, and receive teammates' tokens with no prompt. Now the token is sent only to
  a server the person **allowed**, at the origin (scheme, host, port) it had when they allowed it, for the scopes they
  were shown. A call without that gets consent with the new reason `server_not_allowed` (the same three answer shapes
  as before: `-32042`, the modern URL-elicitation request, or a tool error with the link), and nothing is forwarded.
  **After upgrading, every person consents once per server** the first time they call it (no backfill, on purpose: it
  would grandfather any malicious server). When the person's account already has the scopes, the consent page just
  asks "Allow <server> (<team>)" and records the grant without going to the provider. A server's grants end when its
  URL moves to another origin, it requires another provider, or it is deleted (a path-only edit keeps them);
  disconnecting deletes the account's. Migration `00017` (table `provider_server_grants`; two nullable columns on
  `provider_connect_requests`; a consent link made before the upgrade is refused as expired, run the tool again).
  API (additive): `POST /v1/connect/requests/{id}/confirm`, `ConnectRequest.server` and reason `server_not_allowed`,
  `ProviderConnection.allowedServers`; Account › My connections lists the allowed servers. **Not changed:** the token
  still holds the union of every scope the person granted, a server they allowed receives all of them, and there is no
  per-provider allow-list of teams or servers (H-5).
- **Sign-in `next` refuses control characters (F-4).** `/auth/login?next=/%09/evil.example` ended in a redirect to
  `//evil.example`; sign-in and the connect flow now share one path rule (`internal/safepath`).
- `serve` refuses an `ENCRYPTION_KEY` equal to the `API_KEY_PEPPER`; the main listener's `ReadHeaderTimeout` (10 s) and
  `IdleTimeout` are pinned by a test; CI runs `govulncheck` and `npm audit --audit-level=high` (none reported).

**v0.2 pilot readiness, web UI.** Admin Overview (replaces the redirect to Users) and a team attention card; a bell and inbox in the header, notification preferences per event and channel, team and platform webhook destinations (shown as a host, the signing secret shown once), a test email; Automation tokens pages (platform and team); the protocol a server last negotiated on its overview; the consent page names the server and team and allows it without a round trip (F-3); the review dialogs send what the reviewer saw (F-2).

**v0.2 pilot readiness, backend** (migrations `00014`, `00015`; designs: [admin overview](docs/admin-overview.md), [notifications](docs/notifications.md), [automation tokens](docs/automation-tokens.md)).

- Admin overview and team attention: `GET /v1/admin/overview` and `GET /v1/teams/{team}/attention` (failing and changed servers, lapsed sign-ins, pending reviews, expiring keys and tokens, connections, gateways, rate limits, notification failures), computed per request with exact totals.
- Notifications: in-app inbox, email through `SMTP_*` (off without `SMTP_HOST`; STARTTLS required, certificates always verified, verified addresses only), signed (HMAC-SHA256) and Slack-compatible webhooks. Eight events, per-person preferences, team and platform destinations, delivery log, retries with backoff, `doctor` check. Webhooks reach public https addresses only; internal ones only through the new `NOTIFY_WEBHOOK_ALLOWED_NETWORKS`, never the MCP servers' allowlist.
- Automation tokens: platform-admin (`ompadm_`) and team publisher (`omppub_`) tokens for `/v1`, scoped by `x-omp-token-scopes`, expiring, revocable, audited as the token; never valid for `/mcp`. Create no token until every replica runs this release.
- Upgrade notes: users must sign in once for their email to count as verified; `API_KEY_PEPPER_PREVIOUS` also covers tokens; the new `go.mod` entries are indirect.

## [0.1.0] - 2026-10-17

The first release ([release notes](docs/releases/v0.1.0.md)): a self-hosted portal where teams register MCP servers, publish them to a company catalog, curate
gateways and give people and agents governed access. Migrations `00001` to `00013`.

**Foundations** (Phase 1). Configuration from environment variables or a YAML file (`OMP_CONFIG_FILE`, `<NAME>_FILE`
secrets), PostgreSQL 17 with forward-only expand/contract migrations, OIDC sign-in plus a loopback-only development
sign-in, sessions with CSRF and Origin checks, users, teams, members and invites, platform admins and auditors, an
append-only audit log, and the web UI shell (workspace and admin modes, team switcher, command palette). The OpenAPI
contract (`api/openapi.yaml`) is enforced by a route test and an authorization matrix over every operation.

**Registry and catalog** (Phase 2). Team-owned remote MCP servers with discovery of tools, resources, resource
templates and prompts, change detection and review, scheduled health checks, encrypted static header values
(`ENCRYPTION_KEY`), a company catalog with approval or self-publishing policies, and an SSRF guard. Platform admins
allow internal networks and hosts (decision 20, `UPSTREAM_ALLOWED_NETWORKS`).

**Gateways** (Phase 3). Curated sets of capabilities served at `/mcp/{slug}` (Streamable HTTP, stateless), granted to
teams, people or SSO groups; tools and prompts exposed as `{server}__{name}`, resources as `omp://{server}/{uri}`.
Every upstream call carries a short-lived ES256 identity JWT (JWKS at `/.well-known/jwks.json`, rotating and
pre-published keys). Personal API keys (`omp_`, HMAC digests with `API_KEY_PEPPER`), optionally limited to some
gateways. A call log without arguments or results.

**Sign-in for MCP clients and service accounts** (Phase 4). An OAuth 2.1 authorization server for `/mcp/{slug}`:
PKCE S256, Client ID Metadata Documents and dynamic registration, one gateway per connection, per-person consent,
trusted clients, rotating refresh tokens (`ompat_`, `omprt_`, `ompac_`, `ompcl_`). Team service accounts with
expiring keys (`omp_sa_`, two active for rotation).

**Delegated credentials** (Phase 5). Auth providers (presets for GitHub, Google, Microsoft Entra ID, Atlassian, Slack
and GitLab), server requirements and capability overrides, consent links (JSON-RPC `-32042`), each person's tokens
sealed, refreshed under a row lock and revocable, sent to servers in `MCP-Gateway-Provider-Token`. The Gmail example
server in `examples/mail-mcp`.

**Operations** (Phase 6). Rate limits shared by every replica (per person, credential, service account and gateway),
opt-in payload capture (redacted, truncated, sealed, audited views), retention, hourly usage rollups and reports,
Prometheus metrics (`omp_*`, `METRICS_ADDR`), pepper and encryption key rotation (`open-mcp-portal rotate-keys`),
`doctor`, a distroless image, a demo Compose file, a Kustomize base and overlay, and CI.

**Per-person OAuth to upstream servers** (Phase 7). Servers in `oauth` mode (such as GitHub's hosted MCP server):
sign-in discovery (RFC 9728, RFC 8414, OIDC), DCR, CIMD, a manual client or a linked platform provider, a setup
sign-in that reads capabilities, each caller's own token with refresh and step-up, and a per-server `sendIdentity`
switch.

**Fixes since Phase 7**, found by running Claude Code, pi and GitHub's hosted MCP server end to end. An empty token scope from a provider (GitHub Apps) counts as no scope information; tool lists
drop `outputSchema` values that aren't objects and relayed results drop `structuredContent` that isn't an object (MCP
schema); client cancellations aren't recorded as errors; failed exchanges with a server include the server's own
reason (redacted, bounded); forwarded tool calls send SEP-2243 `Mcp-Param-*` headers built from the approved
definition (GitHub's server needs them).

**Renamed to Open MCP Portal** (decision 46), formerly Open MCP Gateway, so it no longer clashes with Open Model
Gateway. Module `github.com/ncecere/open-mcp-portal`, binary `open-mcp-portal`, `OMP_*` environment variables, `omp_*`
metrics, `open-mcp-portal` Kubernetes names. Keys and tokens now start with `omp_`, `omp_sa_`, `ompat_`, `omprt_`,
`ompac_` and `ompcl_` (were `omcp_`, `omcp_sa_`, `omat_`, `omrt_`, `omac_`, `omcl_`), and exposed resources with
`omp://` (was `omcp://`): keys and tokens made before no longer authenticate; create new keys and sign MCP clients in
again. Payload capture still redacts the old prefixes. Migration `00013_open_mcp_portal`. The `MCP-Gateway-*` headers
MCP servers receive keep their names. A development database of the old Compose project moves with
`scripts/migrate-dev-db.sh`.

**Release** (v0.1.0). A `v*` tag runs `.github/workflows/image.yml`: it builds `ghcr.io/ncecere/open-mcp-portal` for
linux/amd64 and linux/arm64 on native runners with SBOM and provenance attestations, checks that the image reports the
tag's version and scans it, signs the multi-arch index with cosign (keyless) and tags it `vX.Y.Z` (and `latest` for a
final release). `scripts/github-release.sh` then creates the GitHub Release from `docs/releases/vX.Y.Z.md` with each
platform's SBOM, the digest and `checksums.txt`. `open-mcp-portal version` prints `open-mcp-portal 0.1.0 (<commit>)`. The
Kustomize base points at `ghcr.io/ncecere/open-mcp-portal:v0.1.0`.

[0.1.0]: https://github.com/ncecere/open-mcp-portal/releases/tag/v0.1.0
