# Agent platforms: calls from agents as the person's calls

An agent platform such as [Pi Durable Platform](https://github.com/ncecere/pi-durable-platform) (PDP) runs agents for people and for teams. When an agent calls a tool through a gateway of Open MCP Portal, the portal can treat the call as **the person's own**: their gateway access, their minimum roles, their own connections (their GitHub, their mail), recorded under their name, with the agent named as the actor. This page is the administrator's guide to setting that up and to what the portal does with it. It implements roadmap items #55 to #58 ([decisions](decisions.md) 65, 66 and 67).

Without this, a PDP agent reaches the portal as a team service account, and everything it does is the service account's. Nothing here changes that for a service account key used on its own.

## How it works

1. **A team service account** (the *relay*) holds a key. PDP stores the key as the `Authorization` header of the portal's gateway, as it does for any server.
2. **A platform admin trusts PDP** in the portal (Admin › Trusted agent platforms): its issuer, where it publishes its keys, and the audience the portal expects. **Only a platform admin** can do this, and can mark the service account as PDP's relay.
3. On every request PDP forwards, it adds `MCP-Gateway-Identity`: a short-lived token (ES256, five minutes) that says which agent is calling and, **when PDP's own records say so**, which person the agent acts for (`person.iss` and `person.sub`: the person's sign-in at your identity provider) and whether they are present (`person_present`). The format is the one in PDP's design note, `docs/mcp-identity.md`.
4. The portal verifies the token, finds the person by their sign-in, and runs the call **as that person, limited to what the relay could reach itself**.

The portal trusts PDP for one thing: naming a person from PDP's own records. See the [threat model](threat-model.md#68-the-agent-platform-relay-decisions-65-to-67) for what that means if PDP, or the relay's key, is compromised.

## Set it up

You need: the portal and PDP signed in with **the same identity provider** (the person's `iss` and `sub` must be the ones the portal stored when they signed in; `person.iss` must equal the portal's `OIDC_ISSUER` exactly, with or without a trailing slash as the provider writes it), PDP v0.4 or later in proxy mode, and a platform admin.

1. **A service account and a key.** In the team that will own the connection, Team › Service accounts › Create service account (role `member`, or `editor` if agents need capabilities that ask for editors), then Keys › Create key. Copy the key (it is shown once). The account decides which gateways agents can reach at all: the team's own gateways, and platform gateways granted to the team. A key can be limited to some gateways.
2. **Register the portal's gateway in PDP** as an MCP server (a platform server, or a team's own server in PDP): URL `<APP_URL>/mcp/<gateway slug>`, header `Authorization: Bearer omp_sa_…` (the key), **Send identity** on, and `identityAudience` = the portal's `APP_URL` exactly (for example `https://mcp.example.com`). Leave `identityEmail` off unless you want PDP to send people's email: the portal never uses the email to find anyone.
3. **Trust PDP in the portal.** Admin › Trusted agent platforms › Trust a platform:
   - **Issuer:** PDP's `APP_URL`, exactly as PDP writes it in a token's `iss` (an https address).
   - **Keys address:** leave empty for `<issuer>/.well-known/mcp-identity-jwks.json`. It follows the address rule of MCP servers: https, and an internal address only if a platform admin allowed it under Admin › Internal networks (add PDP there first if it runs inside your network). Loopback, link-local and metadata addresses are never allowed.
   - **Audience:** leave empty for this portal's `APP_URL`.
4. **Test the keys** (the row's menu): the portal fetches PDP's key set the way a verification does and shows the key IDs, or says why it couldn't (not allowed, redirect, timeout, status, content type, too large, not a key set, no usable keys). The result stays on the page as the *last fetch*.
5. **Mark the relay.** On the platform's row, Relay accounts… › search the service account › Mark as relay (or on the service account's own page). Only a platform admin can; the team's owners and admins see the mark and can't change it. An account is a relay for one platform; marking it again for another moves it.
6. **People connect their accounts.** A person needs a portal account (they signed in once) and, for capabilities that act as them on another service, their own connection under Account › My connections (and, for each server, to have allowed it; see "When a person hasn't connected an account"). Agents can't ask: a call that needs a connection that isn't there fails with a message saying where to connect.
7. **Try it** (below), then look at the call log.

## What the portal checks

For a request whose credential is a relay account's key and that carries `MCP-Gateway-Identity`:

| Check | Rule |
|---|---|
| Shape | One header, at most 8 KiB, a compact JWS. The header is exactly `alg` `ES256`, a `kid`, `typ` `JWT`, and none of `crit`, `jwk`, `jku`, `x5u`, `x5c`. `none`, HS256 (whatever its key), RS256 and every other algorithm are refused. The key is never taken from the token |
| Issuer | `iss` equals a platform an admin added **and turned on**, exactly. An unknown or disabled issuer is refused before any key is fetched |
| Signature | By the key the platform's key set publishes for that `kid` (public P-256 keys with a key ID only) |
| Audience | `aud` (a string or a list) contains the platform's audience |
| Claims | `principal_type` is `agent`; `sub`, `team.id` and `jti` are present; a `person` has `iss` and `sub`, and its `iss` equals the portal's `OIDC_ISSUER` |
| Time | `exp`, `nbf`, `iat` are plain numbers; 30 seconds of skew either way; `exp - iat` at most 10 minutes (PDP's is 5) |
| Replay | A `jti` is accepted once, by any replica (a table in PostgreSQL, kept until `exp` plus the skew plus a minute, then deleted by the retention loop) |
| The credential | The key's account is a relay **for this platform** |

The token's `name`, `team.slug`, `thread_visibility` and `tool` are informational (shown in the call log, clipped and cleaned of control characters). The portal decides on the person's sign-in and the team's own rules, never on a claim's name or email.

### What a failed check does

| Case | Result |
|---|---|
| A token with any credential that isn't a relay account's key (a personal API key, a connected app, a service account that is not a relay) | **Ignored**: the call is that credential's own. Counted (`omp_agent_token_total{result="ignored_not_relay"}`) and logged (a warning, at most once a minute per credential). A key alone is never changed by a token it can't use |
| A token on a relay account's request that fails a check, or is another platform's | **The request is refused**: HTTP 403, JSON-RPC code `-32001`, "The agent identity token was refused (reason). The request was not run." Counted as `rejected_<reason>` (`malformed`, `algorithm`, `key_id`, `type`, `untrusted_issuer`, `disabled_issuer`, `unknown_kid`, `jwks_unavailable`, `signature`, `audience`, `principal_type`, `claims`, `person_issuer`, `expired`, `not_yet_valid`, `lifetime`, `replay`, `other_platform`) and logged with the reason, never the token. Nothing runs: the portal doesn't fall back to the account's own call, because that would turn a person's call into the team's |
| A relay account's request with no token | The account's own call, as before |
| A valid token that names nobody (a team agent's shared thread, or a team agent's work with no thread; in a personal workspace PDP names the owner even then, with `person_present` false for work with no thread) | The account's own call; the agent and platform are recorded, and the downstream token has no `act` |
| A valid token naming a person the portal doesn't know, or who is suspended | A tool error ("This agent acts for a person who has no active Open MCP Portal account…" or "…whose account is suspended"); other methods answer `-32010`; recorded as denied (`person_no_account`, `person_suspended`). **Never** the account's own call |

The person is read from the database on **every** call. Suspending them, or removing them from a team, takes effect on their agents' next call; there is no cache of who a person is. In-flight calls aren't cancelled.

## What a call may do: person ∩ relay

The call is authorised as the person **and** the relay account:

- **Gateways.** A gateway is usable only if the person may use it (their team membership, or a grant to them, their team or their SSO group) **and** the relay account may (its team's own gateways, or a platform gateway granted to its team). A person outside the relay's team can't use the team's gateways through it; a gateway granted only to the person isn't reachable through the relay.
- **Minimum roles.** A capability with a minimum role on a team gateway needs both the person's role in the team and the account's role (`member` or `editor`) to meet it: the lower of the two decides. An owner reaches no more through an `editor` relay than the relay itself could.
- **The key's own limits** (a key limited to some gateways) apply as for any key.
- **Rate limits.** The relay account's limit counts the call, and so does the person's own per-person limit.

So the relay's team decides which gateways its agents can ever use, and a person never gets more through an agent than they have themselves.

## Delegated credentials, and agents that have no browser

A relayed person call uses the person's own connections (`MCP-Gateway-Provider-Token`), as their own call would, within the per-server permission they gave (F-3).

An agent has nobody to open a link. For a relayed person call the portal **never** answers `-32042`, a consent link, or an `input_required` result, whatever the client declared, and stores no consent request. A capability that needs a connection the person hasn't made returns a **tool error** (for a prompt or resource read: `-32010` with the same text) that names the provider and says where to connect, for example:

> `github__create_issue needs your Github account (repo). Connect your Github account under Account › My connections in Open MCP Portal, then try again.`

This covers a missing, lapsed or too narrow connection, an MCP server's own sign-in (in `oauth` mode, including an upstream `401` that can't be refreshed and a `403 insufficient_scope`), and a server the person hasn't allowed to use their account (F-3 `server_not_allowed`). The call record is `needs_authorization` with error class `needs_connection`. If a server asks for input (an elicitation) while serving a relayed call, the call fails with a tool error: an agent can't answer it.

**Allowing a server without a call (decision 68, #60).** A person allows a *server* to use a connection in Account › My connections: on the connection, **Allow servers…** lists the servers that require that provider and that they may use through a gateway now (their team's servers on gateways they can use, and published servers on gateways they have access to), each with its team, address and the scopes it asks for, and **Allow**. No call of their own and no link is needed. When an agent's call fails with "allow STATUS (tools) to use your Github account", the person does exactly that; the message is link-free:

> `github__create_issue needs you to allow STATUS (tools) to use your Github account (repo), which you haven't. Allow STATUS under Account › My connections in Open MCP Portal, then try again.`

Allowing records the same grant as a consent link's confirm step (the server's address now, the scopes it requires), is the person's own act in a browser session (an API key, automation token, service account or agent can't), and is audited. A server that is not on a gateway the person can use is not listed and can't be allowed. If the account doesn't have the scopes yet, the dialog offers **Grant more access** (the normal provider round trip). **Take back** deletes one server's allowance without disconnecting.

## Calls that need the person there

Some tools shouldn't run while nobody is watching (send mail, post, spend). PDP's token says whether the person is **present** (`person_present`): true for a thread of their own conversation, false for scheduled work, webhooks and other runs. A server's team (editors and above) can turn on **Require a present person for calls from agents** on the server's Settings, and override it on each capability (Capabilities › Present person…): *same as the server*, *needs a present person* or *doesn't*. Off by default. A relayed person call whose token says the person isn't present is refused with a tool error, recorded as denied with error class `person_not_present`. Calls that aren't relayed for a person (a person's own key, a relay's own call, a token naming nobody) are never affected.

**Review.** Requiring a present person narrows what agents can do, so turning it on needs no review. Relaxing it (the server's switch off while capabilities followed it, or a capability set to *doesn't need*) sends a published server back to review under `approval_required`, with reason `requirement_changed`, because what was approved relied on it; the editor is told before saving. The server's switch is part of the review digest (a reviewer who read it with the switch off can't approve after it was turned on). A capability's override is shown on the Capabilities tab and in the audit log (`mcp_capability.presence_set`) but is not part of the digest. Recommend the switch for capabilities that send, post or spend.

An automation token (a team publisher token) can't change the switch (`403 token_not_allowed`, field `requiresPresentPerson`).

## What the server behind the gateway sees

The identity token the portal signs for your MCP server (`aud` = its URL) is the usual one, with the **person** as the principal, and `act` naming the agent:

```json
{"iss": "https://mcp.example.com", "aud": "https://mail.example.com/mcp", "principal_type": "user",
 "sub": "10101010-1010-4101-8101-101010101010", "email": "ada@example.com", "name": "Ada Lovelace", "teams": ["platform-tools"],
 "gateway": "support", "tool": "mail__search", "client": "pdp-relay",
 "act": {"sub": "0e6a3d4c-5f1b-4f0e-9b8e-2d7c1a9f3b21", "name": "Mail assistant", "iss": "https://agents.example.com",
         "principal_type": "agent", "person_present": true},
 "jti": "…", "iat": 1792500000, "nbf": 1792499970, "exp": 1792500300}
```

`client` is the relay service account's name. `act` appears **exactly** on relayed person calls and never otherwise; a server that wants to refuse agent calls, or to require `person_present`, checks it ([upstream-identity.md](upstream-identity.md#calls-from-agents)). A call by the relay account with no person (or a token naming nobody) is the usual service account token, with no `act`.

## What the call log and audit show

- **Calls** (team: owners and admins; platform: admins and auditors): the principal is the relay service account (it owns the key), and the row says "Mail assistant via Pi Durable Platform · for Ada Lovelace" (and "(not present)"), or "no person named". The call's page lists the agent, the person, whether they were present, and the outcome and error class: `needs_authorization` / `needs_connection`, `denied` / `person_not_present`, `person_no_account`, `person_suspended`, and the usual `no_access` / `role` when the intersection leaves nothing. The relay team's admins see the people their agents acted for; that is the point of an audit, and it follows from the relay account being the team's.
- **A person's calls.** The call list's person filter (`user`) includes the calls their agents made for them, because the record names the person.
- **Audit log:** `agent_platform.create`, `agent_platform.update`, `agent_platform.delete` (with how many relays it had), `service_account.relay_set`, `service_account.relay_clear` (on the account's team), `mcp_server.update` (the switch) and `mcp_capability.presence_set`. A token, a key or a person's claim is never in them.
- **Metrics and logs:** `omp_agent_token_total{result}` (see above). Tokens, keys and the `MCP-Gateway-Identity` header are never logged, recorded or returned.

## Keys, rotation and outages

- **Cache.** Each replica caches a platform's keys for `min(Cache-Control max-age, 5 minutes)`: 60 seconds when the answer has no `max-age`, never less than 10 seconds. PDP publishes `max-age=300`.
- **Rotation.** PDP publishes a new key ahead of using it and keeps the old one for an hour. A token with a `kid` the portal hasn't seen makes the portal fetch the set again (at most twice a minute per platform per replica, so a flood of unknown key IDs can't make a fetch per request). While both keys are published, both are accepted. A key PDP withdraws (for example a leaked one, `--drop-previous`) is refused once the replica's cache expires: at most 5 minutes later.
- **Outage (stale while error).** If the portal can't refresh a platform's keys (the platform is down), the keys it already has keep verifying for **15 minutes past their expiry**; after that every token fails (`jwks_unavailable`) and agent calls with a person are refused until the keys can be fetched again. A failed fetch isn't retried for 10 seconds. Calls by relay accounts with no token are unaffected. A platform that has never been reached verifies nothing.
- **Time.** Replicas and PDP need reasonably synchronised clocks (30 seconds of skew are allowed).

## Try it

With the fake MCP server (`make fake-mcp`, [upstream-identity.md](upstream-identity.md#try-it-locally)): register it in a team, select its `whoami` tool in a gateway, make a service account and key, trust a platform and mark the account. Without a PDP, mint a token with any ES256 key whose public half you serve as a JWKS (the test helpers in `internal/httpapi/agent_relay_helpers_test.go` do exactly this) and send it with the key:

```sh
curl -s http://localhost:8088/mcp/<gateway> -H "Authorization: Bearer omp_sa_..." \
  -H "MCP-Gateway-Identity: <token>" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"<server>__whoami","arguments":{}}}'
```

`whoami` shows `principal_type: user`, the person, `client`, and the `act` claim (also as `act` and the sentence `actedBy` in its output).

## Manual end-to-end check with a real PDP

**This has not been run.** The tests below use a fake issuer (a loopback server that serves a JWKS and signs with locally generated P-256 keys); no real Pi Durable Platform was available. Before relying on it, do this once on a real deployment:

1. In the portal: a team, a service account `pdp-relay` (role editor) and a key; a gateway with a harmless tool (`whoami` of the fake server, or any tool that echoes who called) and a tool that needs a provider connection (for example GitHub's `get_me`, with the person's connection and server permission).
2. In PDP: register `<APP_URL>/mcp/<slug>` with the key as `Authorization`, **Send identity** on and `identityAudience` = `APP_URL`. Create a personal workspace agent for a person who has signed in to both.
3. In the portal: trust PDP (issuer = PDP's `APP_URL`), **Test the keys** (expect PDP's key ID), mark `pdp-relay` as its relay.
4. In a private thread of that person, ask the agent to call `whoami`. Expect: `principal_type: user`, the person's ID and email, `client: pdp-relay`, `act` with the agent's ID, name and PDP's issuer and `person_present: true`; the call log shows the agent, PDP and the person.
5. Ask for the provider tool before the person has connected: expect a tool error naming the provider and Account › My connections, no link. Connect (and allow the server from your own client), ask again: it works as them.
6. In a shared thread, or from a schedule: the call is the relay's own (no `act`), or `person_present: false`; with **Require a present person** on the capability the scheduled call is refused (`person_not_present`).
7. Suspend the person in the portal: the next agent call is refused ("account is suspended"); remove them from the team: the gateway is gone for them at once. Reactivate: it works again.
8. Turn the platform off (Admin › Trusted agent platforms › Turn off): the next call is refused (`disabled_issuer`). Rotate PDP's key with `rotate-mcp-identity-key --now` and check that calls keep working after one unknown-key fetch.

## What is not covered

- **A running PDP instance** (above). On 2026-10-20 the verifier was checked against tokens signed by PDP v0.4.0's real signer and key sets served by its real JWKS handler: `internal/agentidentity/testdata/pdp/` holds them (with a README on how they were made, and no private key) and `contract_pdp_test.go` checks them, including key rotation and tampering. **Not checked:** PDP's gateway and runtime end to end (which token it attaches to which request, and what it puts in `tool`), and a live deployment (real DNS and TLS, your identity provider's `iss` spelling, clock skew). The portal's side after the verifier (relay marks, person lookup, the call) is covered by the fake issuer's tests only.
- **Several replicas** are tested as separate service instances sharing one database (a jti is accepted by exactly one of four racing instances), not as separate processes behind a balancer.
- **Clock skew between the portal and PDP** is tested with a controllable clock, not with a real skewed host.
- **A browser:** the admin pages are tested with the component test harness, not in a real browser.
- **Per-server permission from the portal** (the gap above) and **notifying a person to connect later** are not built.
- **Several identity providers for people** (roadmap #53): `person.iss` must equal `OIDC_ISSUER`.

## Troubleshooting

| You see | Likely cause |
|---|---|
| Calls through the relay work but ignore the person (no `act`) | The token isn't sent (PDP's Send identity is off), names nobody (a shared thread), or the key's account isn't marked as a relay (look for `ignored_not_relay` in the metrics and a warning in the logs) |
| `403 … (untrusted_issuer)` | The issuer isn't added, or differs from PDP's `iss` by a character (a trailing slash) |
| `(audience)` | PDP's `identityAudience` isn't the platform's audience (default `APP_URL`). A PDP server **without** an `identityAudience` gets tokens whose `aud` is that server's own URL (for the portal's gateway: `<APP_URL>/mcp/<slug>`); the portal refuses them unless the platform's audience is set to exactly that URL. Set `identityAudience` to `APP_URL` in PDP instead |
| `(person_issuer)` | The person's `iss` isn't `OIDC_ISSUER`: PDP and the portal sign people in with different providers, or issuer spellings |
| `(unknown_kid)` or `(signature)` | The key set the portal sees isn't the one PDP signs with: Test the keys; check PDP's rotation |
| `(jwks_unavailable)` | The platform's keys can't be fetched and the cached ones are older than 15 minutes past expiry: Test the keys; the address may need an entry in Admin › Internal networks |
| `(replay)` | PDP re-sent a token (a transport retry): its tokens are one request each |
| `(expired)` / `(not_yet_valid)` | Clocks differ by more than 30 seconds |
| A tool error "has no active Open MCP Portal account" | The person never signed in to the portal (or signs in with another issuer): ask them to sign in once |
| A tool error "Connect your … account" | The person hasn't connected the provider (or allowed the server): Account › My connections |
