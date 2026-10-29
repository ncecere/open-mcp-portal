# Roadmap

Status: **2026-10-29.** v0.6.0 is published and verified; #32 is closed. This is an order of work, not a schedule, for one maintainer. Every item below is an
issue with its implementation plan (data model, API, packages to change, tests, acceptance criteria, open questions):
[all roadmap issues](https://github.com/ncecere/open-mcp-portal/issues?q=is%3Aissue+is%3Aopen+label%3Aroadmap), grouped by
[milestone](https://github.com/ncecere/open-mcp-portal/milestones). Sizes are relative effort: **S** a few days, **M** a week or two, **L** several weeks. Each item that needs a
design gets one in `docs/` before code, as the earlier phases did. The decisions behind the work are in [decisions.md](decisions.md).

## What the portal is, and isn't

Open MCP Portal is a portal for MCP servers: teams register them, a catalog lists them, gateways curate them, and
people and agents get governed access. It is **not** an LLM gateway, an agent runtime, a workflow engine or a RAG
system, and the roadmap adds none of those. The owner has also withdrawn external agent-platform trust and
person impersonation ([decision 81](decisions.md)); #68 retired that integration safely in v0.4.0. Ordinary MCP clients,
including coding assistants, still use the portal's standard credentials.

Decided out of scope:

- **Hosting stdio servers: never** (decision 47). Servers are remote and speak Streamable HTTP. A team with a stdio
  server runs a bridge next to it and registers the bridge.
- **Sampling, roots and logging.** The 2026-07-28 revision deprecates them; new work doesn't add them.
- **The old HTTP+SSE transport** for upstream servers: deprecated by the same revision.
- **Content scanning** (prompt-injection and data-loss checks): wanted, **not scheduled** (decision 50); a design comes first (#52).

## Where things stand

| Release | Date | What it delivered |
| --- | --- | --- |
| [v0.1.0](releases/v0.1.0.md) | 2026-10-17 | Phases 1 to 7: registry and catalog, gateways, OAuth for MCP clients, service accounts, delegated credentials, per-person OAuth to upstream servers, operations. |
| [v0.2.0](releases/v0.2.0.md) | 2026-10-18 | MCP 2026-07-28 next to every earlier revision (toward clients and toward upstream servers); an admin overview, notifications, automation tokens; fixes F-1 to F-4 from the [threat model](threat-model.md), including per-server consent for provider tokens. |
| [v0.2.1](releases/v0.2.1.md) | 2026-10-18 | Test connection exercises the identity token; a cap on open client registration; a Kubernetes smoke test (`make k8s-smoke`, in CI on kindnet and Calico). |
| [v0.2.2](releases/v0.2.2.md) | 2026-10-20 | Hardening: Send identity token off by default for public no-auth servers, OAuth sign-in looked at only after login, a one-time notice for trusted loopback clients, an absolute refresh-token lifetime, registration controls, a `__Host-` state cookie, base images pinned by digest. |
| [v0.3.0](releases/v0.3.0.md) | 2026-10-20 | Trust for an external agent platform (Pi Durable Platform): trusted platforms, relay service accounts, calls as the person (access intersected with the relay's), no consent links for agents, a present-person policy, the `act` claim, allowing a server from My connections; an independent security review applied. |
| [v0.3.1](releases/v0.3.1.md) | 2026-10-20 | A per-provider access list and narrower tokens per call (closes the F-3 residual), a server's own credential as several parts (headers, bearer, Basic, a query key), OpenTelemetry tracing, Grafana dashboards and Prometheus alert rules. |
| [v0.3.2](releases/v0.3.2.md) | 2026-10-20 | Three more ways to authenticate to a server: each person's own key, the portal's own OAuth client (client credentials), and mTLS with a private CA; found and fixed a migration interplay before release. |
| [v0.3.3](releases/v0.3.3.md) | 2026-10-28 | Owner-set tool classification and review binding; browser-session inventory/revocation and optional idle expiry; patched dependencies and deterministic smoke-helper lifecycle tests. |
| [v0.4.0](releases/v0.4.0.md) | 2026-10-28 | Credential tool scopes, per-selection tool curation, team-owned service connections, migration/runtime database roles and safe retirement of external-platform impersonation. |
| [v0.5.0](releases/v0.5.0.md) | 2026-10-28 | Sensitive-call approval rules, private human review, exact merged-argument binding and single-use dispatch; private notices/attention, sealed preview and binding-key rotation. |
| [v0.5.1](releases/v0.5.1.md) | 2026-10-28 | Provider-refresh reliability under constrained runtime pools; scoped dependency reads, fail-closed address-policy checks and bounded cancellation/drain. No schema/API change. |
| [v0.6.0](releases/v0.6.0.md) | 2026-10-29 | Opt-in gateway access requests, narrowly delegated human stewardship, private queues/notices, atomic user/team grants and optional expiry. |

Proven on a real deployment (one Talos cluster, Authentik sign-in, CloudNativePG with continuous archiving and daily backups, a restore tested twice):
Claude Code over OAuth and an API key on the 2026-07-28 revision; per-person OAuth to GitHub's hosted MCP server; DeepWiki through a gateway.
What is **not** proven yet is tracked below as verification issues (#14 to #18, #19) and
the pilot (#20). [status.md](status.md) records what each release verified.

## How the next work is ordered

The [implementation order](implementation-order.md) reconciles the open GitHub issues with what has already
shipped. **#28 classification** and **#37 session hardening** shipped in v0.3.3. **v0.4.0 shipped and closed
#29 scopes, #30 curation, #26 service connections, #44 database roles and #68 external-platform retirement**,
with independent review corrections, full-tree tests, browser checks and CI/deployment/artifact verification.
#62/#63 are withdrawn as not planned, not completed verification. Historical milestone headings below are
planning buckets, not a promise of release numbering. #31 approvals shipped in v0.5.0 under decision 82.
The v0.5.1 reliability follow-up is published and verified. Development resumed after the machine transfer;
#32 shipped in verified v0.6.0 and is closed. #33 upstream protection is next. The owner authorized ready pre-1.0 releases but reserves the
v1.0.0 decision. A new agent should read [agent-handoff.md](agent-handoff.md) and current [status](status.md).

1. **Verify and pilot alongside implementation.** Decisions #5, #6 and #7 shipped in v0.2.2. The
   real-client checks (#14–#17), provider/channel checks (#18–#19), independent review (#13) and
   team pilot (#20) still need evidence, not more fake-server tests.
2. **Credentials foundations shipped.** Waves 1 and 2 below are complete, including #26 shared service
   connections. External-platform impersonation was retired in #68, not extended or verified.
3. **Governance foundations shipped.** #31 exact-call approvals shipped in v0.5.0,
   with defaults recorded in decision 82; #32 access requests shipped in v0.6.0 under decision83.
   Next is #33 upstream protection; its read retries also need classification and must never replay spent approvals.
4. **Operations before scale.** #44 database roles shipped; next prove upgrades, ingress and restores (#43)
   before releasing the Helm chart (#42). See the implementation order for staged lifecycle/audit dependencies.

## Owner decisions needed

Each links to an issue that lays out the options and a recommendation. The shipped #28 implementation takes
the fail-closed recommendation and keeps classification with team owners/admins ([decision 75](decisions.md)).

| Issue | Decision | Recommended |
| --- | --- | --- |
| [#36](https://github.com/ncecere/open-mcp-portal/issues/36) | How a SCIM user links to a login, and whether `active: false` suspends or destroys. | Link by a configurable claim (default `sub`), never bare email; `active: false` suspends, `DELETE` destroys. |
| [#51](https://github.com/ncecere/open-mcp-portal/issues/51) / [#39](https://github.com/ncecere/open-mcp-portal/issues/39) | How usage is attributed to a calling team; whether erasure leaves audit snapshots. | The team of the grant that admitted the call (a billing team for user and group grants); erasure leaves audit snapshots, bounded by audit retention, documented. |

## v0.2.x: pilot follow-ups

Patch releases. Decisions, hardening leftovers from the [threat model](threat-model.md#9-hardening-ideas-not-findings), real-world verification
and the pilot. Milestone: [v0.2.x](https://github.com/ncecere/open-mcp-portal/milestone/1).

| Issue | Item | Size | What it does, and why | Depends on |
| --- | --- | --- | --- | --- |
| [#5](https://github.com/ncecere/open-mcp-portal/issues/5) | ~~Decide the default of "Send identity token" for public servers~~ **done in v0.2.2** | S | A public server that refuses any Authorization header (DeepWiki) fails on its first call because the portal sends its identity token as `Authorization: Bearer` by default. v0.2.1 diagnoses the HTTP-level case; the owner decides whether the default should change. | – |
| [#6](https://github.com/ncecere/open-mcp-portal/issues/6) | ~~Decide whether trusted clients with loopback redirects need a first-use notice~~ **done in v0.2.2** | S | A trusted OAuth client skips consent and may redirect to `http://localhost:<any port>`; a local process could start the flow and receive a code for the signed-in person. A first-use confirmation would close it at a small UX cost. | – |
| [#7](https://github.com/ncecere/open-mcp-portal/issues/7) | ~~Decide an absolute lifetime for OAuth refresh tokens~~ **done in v0.2.2** | S | Refresh tokens roll for 30 days from their last use, so a client that keeps refreshing never has to sign in again. Threat-model idea H-8 proposes an absolute lifetime and stricter handling of a token presented again inside the reuse grace. | – |
| [#8](https://github.com/ncecere/open-mcp-portal/issues/8) | ~~Fetch a client's metadata document only after sign-in (H-3)~~ **done in v0.2.2** | S | `GET /oauth/authorize` resolves the client (fetching its metadata-document URL) before the person is signed in, so an anonymous caller can trigger fetches and learn distinct failure reasons. | – |
| [#9](https://github.com/ncecere/open-mcp-portal/issues/9) | ~~Add controls for open client registration beyond the cap (H-4)~~ **done in v0.2.2** | S | v0.2.1 caps live dynamic registrations (default 1000). What remains: one caller behind a shared ingress can fill the cap, and an install that only wants metadata-document clients cannot turn registration off. | – |
| [#10](https://github.com/ncecere/open-mcp-portal/issues/10) | ~~Use a __Host- OIDC state cookie and warn when TRUSTED_PROXIES is unset (H-7)~~ **done in v0.2.2** | S | The session cookie is already `__Host-`prefixed on https; the OIDC state cookie is not. And a deployment behind a proxy with `TRUSTED_PROXIES` unset silently rate-limits and audits the proxy's address instead of the client's. | – |
| [#11](https://github.com/ncecere/open-mcp-portal/issues/11) | ~~Pin the Dockerfile base images by digest (H-9)~~ **done in v0.2.2** | S | The Dockerfile's base images use tags (`node:22-alpine`, `golang:1.26`, distroless). Pinning them by digest makes builds reproducible; Dependabot's Docker ecosystem keeps the digests current. Trivy already fails the release on fixable HIGH/CRITICAL findings. | – |
| [#12](https://github.com/ncecere/open-mcp-portal/issues/12) | ~~Add an end-to-end test that a provider token echoed by a server is redacted~~ **done in v0.2.2** | S | The redactor's exact-value rule has unit tests, but nothing proves that a delegated provider token echoed back by a provider-backed server is redacted from a recorded payload, the audit log and the logs. | – |
| [#13](https://github.com/ncecere/open-mcp-portal/issues/13) | Commission an independent security review of the portal **needs real-world testing** | M | The threat model was written for reviewers and every finding so far came from the maintainers' own review. An outside review (or a structured community audit) is the next step before broader use. | – |
| [#14](https://github.com/ncecere/open-mcp-portal/issues/14) | Test VS Code against a gateway and report the result **needs real-world testing** | S | VS Code's connect snippet is generated by the portal but no one has run VS Code against a gateway. A ten-minute check with the compatibility checklist closes that. | – |
| [#15](https://github.com/ncecere/open-mcp-portal/issues/15) | Test Cursor against a gateway and report the result **needs real-world testing** | S | Same as VS Code: the portal generates a Cursor snippet, but Cursor has never been run against a gateway. | – |
| [#16](https://github.com/ncecere/open-mcp-portal/issues/16) | Find and test a real client that declares URL elicitation **needs real-world testing** | S | The `input_required` consent result (for clients that declare URL elicitation) is covered by an SDK-based test, but no shipping product has been seen using it. Claude Code declares form-mode elicitation only. | – |
| [#17](https://github.com/ncecere/open-mcp-portal/issues/17) | Verify that real clients refresh their access token after an hour **needs real-world testing** | S | Access tokens last an hour and refresh tokens 30 days; the portal's side is tested but no one has watched Claude Code or pi refresh against a real deployment. | – |
| [#18](https://github.com/ncecere/open-mcp-portal/issues/18) | Verify delegated credentials with real Google and Microsoft Entra ID providers **needs real-world testing** | M | Auth providers for Google and Microsoft exist as presets and run against a fake OAuth provider, but only GitHub (per-person OAuth to its hosted MCP server) has run end to end against a real provider. | – |
| [#19](https://github.com/ncecere/open-mcp-portal/issues/19) | Verify notifications with a real Slack webhook and a real SMTP provider over TLS **needs real-world testing** | S | Notifications were tested against a local SMTP sink and local webhook receivers. A real Slack incoming webhook and a real SMTP server with STARTTLS/TLS have not been run. | – |
| [#20](https://github.com/ncecere/open-mcp-portal/issues/20) | Run a pilot with a real team and define when the portal is ready for wider use **needs real-world testing** | M | Everything so far was built and tested by the maintainers. A pilot with one real team (3 to 5 people, a few real servers) is the next evidence, with success criteria written down first. | – |
| [#21](https://github.com/ncecere/open-mcp-portal/issues/21) | ~~Write the triage and support policy (labels, expectations, supported versions)~~ **done in v0.2.2** | S | The repo has issue forms and Discussions now. People need to know how issues are labelled and triaged, what response to expect from a single maintainer, and which versions are supported. | – |

## v0.3: credentials and tool policy

Making "all MCP servers" true, then governing what runs. Milestone: [v0.3](https://github.com/ncecere/open-mcp-portal/milestone/2).

**Order** (each wave can ship as it is ready):

- **Wave 1, shipped in v0.3.1:** #27 (provider access and narrower tokens), #34 (tracing/observability), and #23 (credential parts and multi-secret redaction).
- **Wave 2, shipped:** #22, #24 and #25 in v0.3.2; #26 in v0.4.0.
- **Wave 3, tool policy shipped:** #28 in v0.3.3; #29/#30 in v0.4.0; #31 exact-call approvals in v0.5.0. Independent #32 access requests shipped in v0.6.0; #33 is next.
- **Wave 4:** #33 (retries of reads need classification; failover is the contentious part and may become its own issue) and #35 last, once its shape is confirmed against the specification and approvals exist.
- **Historical additive/expand-only candidates** (not a current open-issue list): #34, #27, #23, #25, #32, #28.

| Issue | Item | Size | What it does, and why | Depends on |
| --- | --- | --- | --- | --- |
| [#55–#58](https://github.com/ncecere/open-mcp-portal/issues/55) | External-platform trust and impersonation **historically shipped v0.3.0; retired v0.4.0** | – | Owner decision 81 retires these features in #68. Historical release/audit records remain; this is no longer a supported direction for new work. | #68 |
| [#60](https://github.com/ncecere/open-mcp-portal/issues/60) | ~~Let a person allow a server from My connections~~ **done in v0.3.0; retained** | S | Self-service per-server origin/scope consent remains useful for ordinary MCP connections independently of the retired integration. | decision 60 |
| [#68](https://github.com/ncecere/open-mcp-portal/issues/68) | ~~Retire external agent-platform trust and impersonation~~ **done in v0.4.0** | M | Remove active integration and fence obsolete relay credentials without erasing history or weakening normal MCP authentication. Replaces withdrawn #62/#63. | decision 81 |
| [#22](https://github.com/ncecere/open-mcp-portal/issues/22) | ~~Add per-person secrets as an upstream auth mode for MCP servers~~ **done in v0.3.2** | L | Add an upstream auth mode `person_secret` where each person pastes their own API key or token for a server once. The portal seals it, binds it to the server's origin, and sends it as a header, bearer token or query parameter on that person's calls. It makes servers that want a personal key usable without a shared static header that erases who is calling. | #23, decision 19, decision 59, decision 60 |
| [#23](https://github.com/ncecere/open-mcp-portal/issues/23) | ~~Support several headers, query keys and Basic auth for a server's own credential~~ **done in v0.3.1** | M | Let a server's own static credential be a list of parts instead of one header: several headers, a query-string key, Basic auth, or a bearer token. Values stay sealed, bound to the origin they were entered for, and redacted everywhere. It also introduces the shared credential list on the upstream target that per-person secrets and machine OAuth reuse. | decision 39, decision 44 |
| [#24](https://github.com/ncecere/open-mcp-portal/issues/24) | ~~Add OAuth client credentials for servers that authenticate the portal itself~~ **done in v0.3.2** | M | Add an upstream auth mode where the portal itself is an OAuth client: it fetches a token with the client-credentials grant and sends it as the bearer on every call, discovery and health check. It covers servers that trust the portal, not a person, and works for service accounts because no person is needed. | #23, decision 39, decision 40 |
| [#25](https://github.com/ncecere/open-mcp-portal/issues/25) | ~~Add mTLS client certificates and a per-server CA for upstream connections~~ **done in v0.3.2** | M | Let a server present a client certificate to its upstream and trust a private CA for that server only. The SSRF guard and the internal-network allow-list stay in force, certificate verification is never turned off, and the private key is sealed and never returned. | decision 20, decision 45 |
| [#26](https://github.com/ncecere/open-mcp-portal/issues/26) | ~~Add team service connections so service accounts can call credentialed tools~~ **done in v0.4.0** | L | Let a team own a shared connection (a platform-provider token or an upstream sign-in) that its service accounts can use. Agents and CI can then call tools that today answer `-32010` `service_account`. The team consents per server and origin, exactly as a person does after F-3. | #27, decision 22, decision 23, decision 29, decision 60 |
| [#27](https://github.com/ncecere/open-mcp-portal/issues/27) | ~~Add a per-provider allow-list and narrower delegated tokens (H-5)~~ **done in v0.3.1** | M | Close the residual of finding F-3 (threat model H-5a): platform admins decide which teams or servers may require a provider, and a call gets a token narrowed to the scopes it needs where the provider supports that. Background refresh falls out naturally; several accounts per provider does not. | decision 60, decision 26 |
| [#28](https://github.com/ncecere/open-mcp-portal/issues/28) | ~~Let server owners classify each tool as read, write or destructive~~ **done in v0.3.3** | M | Add a tool class (read, write, destructive) set by the server's team owners and admins. The server's own annotations are shown as a suggestion and never trusted. The class is the input for scoped credentials, approval rules and read-only retries, and the gateway can publish it back to clients as trustworthy annotations. | decision 48, decision 49 |
| [#29](https://github.com/ncecere/open-mcp-portal/issues/29) | ~~Limit keys, OAuth grants, service accounts and grants by tool class or name~~ **done in v0.4.0** | L | Let a credential or grant be limited to tool classes or named tools (a read-only key). Scopes only narrow what the owner may already use. The OAuth consent screen shows the scope, the `scope` parameter maps to classes, and tools outside the scope are hidden and refused like unknown tools. | #28, decision 49, decision 24 |
| [#30](https://github.com/ncecere/open-mcp-portal/issues/30) | ~~Constrain, rename and re-describe tools per gateway~~ **done in v0.4.0** | L | Per gateway tool, let owners fix or restrict argument values (pin GitHub's `owner`), show the model a narrowed schema, rename the tool and rewrite its description. Curation is stored beside the approved definition, never replaces it, and fails closed when the upstream definition changes. | decision 49 |
| [#31](https://github.com/ncecere/open-mcp-portal/issues/31) | ~~Require approval before sensitive tool calls~~ **done in v0.5.0** | L | Add rules (for example 'destructive tools need approval') that stop a call and return a multi-round-trip result with an approval link. Named approvers approve in the portal; the person retries. Approvals are bound to the arguments and the definition, expire, are single use and audited, and the requester can never approve their own call. | #28, decision 48, decision 52, decision 59 |
| [#32](https://github.com/ncecere/open-mcp-portal/issues/32) | ~~Let people request access to a gateway and owners approve it~~ **done in v0.6.0** | M | Let a signed-in person ask for access to a platform gateway that its owner has made requestable, with a reason. Approvers decide in the portal and approval creates the normal gateway grant, optionally with an expiry. Gateways stay invisible to people who cannot use them unless an owner opts in. | decision 17, decision 23 |
| [#33](https://github.com/ncecere/open-mcp-portal/issues/33) | Add per-server quotas, concurrency caps, retries, a circuit breaker and failover | L | Protect upstream servers and callers: a quota and a concurrency cap per server, retries only for reads that cannot have run, a circuit breaker, and several upstream URLs per server with failover. Failover is limited to auth modes where a second origin cannot receive a credential nobody entered for it. | #28, decision 31 |
| [#34](https://github.com/ncecere/open-mcp-portal/issues/34) | ~~Add OpenTelemetry tracing, Grafana dashboards and Prometheus alert rules~~ **done in v0.3.1** | M | Trace each `/mcp/{slug}` request through authentication, credential lookup and the upstream call, join traces with the `traceparent` passthrough that exists, and ship Grafana dashboards and Prometheus alert rules for the existing `omp_*` metrics, validated in CI. | decision 35 |
| [#35](https://github.com/ncecere/open-mcp-portal/issues/35) | Support the io.modelcontextprotocol/tasks extension for long-running tools | L | Relay the 2026-07-28 tasks extension through gateways: when an upstream returns a task handle, the portal gives the client its own handle bound to the person who started it, and `tasks/get`, `tasks/update` and `tasks/cancel` re-run every access check before reaching the upstream. The extension's exact shape must be confirmed against its specification before design. | decision 51 |

## v0.4: identity lifecycle and scale

Leavers lose access automatically, the audit trail leaves the database, and operating it at scale is tested. Milestone: [v0.4](https://github.com/ncecere/open-mcp-portal/milestone/3).

**Order:** #37 and #44 are expand-only and off by default, so they can ship early as patch releases, as can the export parts of #38. Make the gates trustworthy next: the upgrade, ingress, OIDC and restore parts of #43, then #42, which should not be released until that CI proves it. #40 and #41 are independent and can run in parallel. Then #36; audit sinks come before #39, because erasure reuses the deprovision path and holds need the audit tail. #45 goes last, and only once a real client sends it.

| Issue | Item | Size | What it does, and why | Depends on |
| --- | --- | --- | --- | --- |
| [#36](https://github.com/ncecere/open-mcp-portal/issues/36) | Add SCIM 2.0 provisioning and SSO-group to team-role mapping | L | Let the identity provider create, update and remove people in the portal over SCIM 2.0, and map IdP groups to team roles. Deprovisioning ends sessions and revokes API keys, connected apps and provider connections, closing threat-model gap TN-5, where a leaver's keys and refresh tokens keep working. | #37, #40, decision 38, decision 53, #22, #26 |
| [#37](https://github.com/ncecere/open-mcp-portal/issues/37) | ~~Add session list, sign out everywhere and an idle timeout~~ **done in v0.3.3** | S | Let people see and end their own browser sessions, let platform admins end anyone's, and sign out sessions that have been idle too long (threat-model H-12). The refresh-token absolute lifetime (H-8) is a different credential and gets its own issue. | decision 53 |
| [#38](https://github.com/ncecere/open-mcp-portal/issues/38) | Stream the audit log to a SIEM with gap detection and tamper evidence | M | Send every audit entry to a SIEM by signed webhook, syslog over TLS or OTLP, with sequence numbers and a hash chain so a missing or altered entry is detectable. Also add server-side exports of the audit and call logs and a minimum audit retention an admin cannot lower (threat-model H-10). | #44, #39, decision 33 |
| [#39](https://github.com/ncecere/open-mcp-portal/issues/39) | Add legal holds and per-person data export and erasure | M | Let platform admins place legal holds that suspend retention deletion for a scope, and give each person a data export and an erasure that anonymises them in place. Decision 33 and the `retention` package header currently say legal holds are out of scope. | #38, #36, #44, decision 33 |
| [#40](https://github.com/ncecere/open-mcp-portal/issues/40) | Add server owner, on-call contact, sensitivity label, re-review and sunset | M | Give every registered server an accountable owner and on-call contact, a data-sensitivity label that caps where it can be exposed, a re-review date, a deprecation and sunset lifecycle and an owner-transfer flow. This turns the catalog from a list into something an operator can govern over time. | #31, #28, #36, decision 26, decision 52 |
| [#41](https://github.com/ncecere/open-mcp-portal/issues/41) | Wrap stored secrets with OpenBao, Vault or a cloud KMS using envelope encryption | M | Stop requiring the master key to sit in an environment variable: let a Vault, OpenBao or cloud KMS hold the key-encryption key and wrap per-epoch data keys stored in PostgreSQL. A rewrap then rotates the master without re-sealing every column. | #44, decision 36 |
| [#42](https://github.com/ncecere/open-mcp-portal/issues/42) | Publish a Helm chart with autoscaling, backup job and restore runbook | L | Ship a Helm chart that deploys the same hardened workload as the Kustomize base, with an optional HorizontalPodAutoscaler, guidance for highly available PostgreSQL (CloudNativePG), a backup job and a tested restore runbook. Keep one source of truth by testing the two renderings against each other. | #43, #44, #41 |
| [#43](https://github.com/ncecere/open-mcp-portal/issues/43) | Extend the kind smoke test with upgrade, ingress, OIDC, restore and load | L | Grow the kind-based smoke test into the release gate: install the previous release and upgrade it, route through a real ingress with TLS, sign in through a real OIDC provider, prove a restore, and run a multi-replica load test. | #44 |
| [#44](https://github.com/ncecere/open-mcp-portal/issues/44) | ~~Split migration-owner and runtime database roles~~ **done in v0.4.0** | M | Run migrations as an owner role and the portal as a runtime role that cannot change or delete the append-only audit and call tables. A stolen runtime credential or a SQL-capable bug can then no longer rewrite history (threat-model H-11). | decision 11 |
| [#45](https://github.com/ncecere/open-mcp-portal/issues/45) | Implement subscriptions/listen for list-changed notifications | M | Let modern-era clients keep one long-lived stream open to a gateway and be told when its tools or prompts change, instead of polling lists every 30 seconds. Gateways are stateless today, so the design centres on fan-out across replicas and on closing streams when access is revoked. | decision 51 |

## v0.5: developer experience and catalog

Milestone: [v0.5](https://github.com/ncecere/open-mcp-portal/milestone/4). **Order:** #46 first, because it creates the public client package and the configuration schema, then #47; #49 and #51 are independent (chargeback could ship as a patch); #48 and #50 wait for v0.3's classification and approvals.

| Issue | Item | Size | What it does, and why | Depends on |
| --- | --- | --- | --- | --- |
| [#46](https://github.com/ncecere/open-mcp-portal/issues/46) | Add an omp command line for connect snippets, keys and CI publishing | M | Add `omp`, a user-facing command line: print connect snippets, manage keys, register, refresh and publish servers from CI, and export or import configuration. It is separate from the operator binary `open-mcp-portal`, and it needs a decision on how a person signs in. | decision 55, decision 58, #29 |
| [#47](https://github.com/ncecere/open-mcp-portal/issues/47) | Add a GitHub Action and a Terraform provider for server and gateway config | M | Let teams register or refresh a server on every deploy with a GitHub Action, and manage servers, platform gateways and grants with a Terraform provider, both built on automation tokens. Deletes and team gateways need new scopes, which is an owner decision. | #46, decision 55, decision 58 |
| [#48](https://github.com/ncecere/open-mcp-portal/issues/48) | Add a try-a-tool console that shows the exact request and response | M | Let a server's authors call one of its tools from the browser, as themselves, and see exactly what the portal sent and what came back. It must obey the same credential and policy rules as a real call, or it becomes a bypass. | #28, #31, #22, decision 60, decision 61 |
| [#49](https://github.com/ncecere/open-mcp-portal/issues/49) | Improve the catalog: categories, icons, README, verified badge, search | M | Make the catalog findable and trustworthy: categories and tags, uploaded icons, a Markdown README per server, a verified badge that cannot outlive a change, search across tools, and popularity from usage. Search today matches only a server's name, slug and description. | #40, decision 9 |
| [#50](https://github.com/ncecere/open-mcp-portal/issues/50) | Add a gateway tool-search mode with find and call tools | M | For gateways with hundreds of tools, let an owner switch to a mode that lists just `find_tools` and `call_tool`, so the model's context holds two definitions instead of hundreds. Every existing check still applies because `call_tool` runs the normal call path. | #28, #30, #49 |
| [#51](https://github.com/ncecere/open-mcp-portal/issues/51) | Add exportable usage and chargeback reports per team and gateway | M | Export monthly usage per team and per gateway as CSV or JSON for finance. The existing rollups group by the gateway's team, which lumps every platform gateway into one 'Platform' bucket, so real chargeback needs a billing-team attribution recorded at call time. | #38, decision 34 |

## Later

Not scheduled. Milestone: [Later](https://github.com/ncecere/open-mcp-portal/milestone/5).

| Issue | Item | Size | What it does, and why | Depends on |
| --- | --- | --- | --- | --- |
| [#52](https://github.com/ncecere/open-mcp-portal/issues/52) | Write the design for content scanning of tool definitions, results and arguments | M | Design, before any code, how the portal could detect prompt injection in tool descriptions and results and data loss in arguments and results. The deliverable is `docs/content-scanning.md` and a decision record, with go or no-go and a list of follow-up build issues. | #31, #28, decision 50 |
| [#53](https://github.com/ncecere/open-mcp-portal/issues/53) | Explore multiple IdPs, client mTLS and DPoP-bound tokens | S | Find out whether contractors on a second identity provider, mTLS-bound clients and DPoP-bound tokens are worth building, before building any of them. The issue ends in written go or no-go decisions. | #36, #37 |

## Resolved questions (2026-10-17)

1. **Suspension blocks** and does not disconnect (decision 53).
2. **Tool scoping** means limiting which tools a credential can use and constraining arguments (decision 49, confirmed).
3. **Who approves:** the server's team owners and admins by default, named approvers per rule, never the requester,
   platform admins as the fallback (decision 52).
4. **Oldest protocol:** keep every revision accepted today and add 2026-07-28; negotiation prefers the newest
   (decision 54).
5. **Automation tokens:** two kinds, platform-admin and team publisher (decision 55).
