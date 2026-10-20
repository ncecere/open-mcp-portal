# Each person's own key (`person_secret`)

*(Decision 72; roadmap #22; migration `00024`.)* Many servers want a **personal API key or token**, not OAuth. A static header
(decision 70) would make every caller act as the key's owner. In `person_secret` mode the server's team says **how a secret
travels**, and **each person pastes their own** once. It is sealed, bound to the person, the server and the server's origin,
shown only as its last four characters, and sent on that person's calls only.

This page is for the team that registers such a server and for the person who enters a key. Server authors: your server
gets the key exactly as the team configured it, plus the portal's identity token
([upstream-identity.md](upstream-identity.md#where-the-token-arrives)).

## For a server's team

Add the server with **Authentication › Each person's own key** (or `authMode: "person_secret"` and `personSecret` in the API).

| Field | Meaning |
|---|---|
| `placement` | `header`: `Name: prefix + key`. `bearer`: `Authorization: Bearer key`. `query`: `?name=prefix+key`, added to each request and never to the saved URL |
| `name` | The header (any valid name the portal doesn't own; `Authorization` is allowed) or the query parameter (`^[A-Za-z0-9_.-]{1,64}$`, never `mcp-*`). Absent for `bearer` |
| `prefix` | Sent before the key, for example `Token ` (at most 64 characters, one line). Not for `bearer` |
| `label` | What the key is called on the page where people enter it ("Acme API key") |
| `help` | Plain text on that page: where to find the key |

Prefer `header` or `bearer`. A query value is part of the address: servers and proxies often log addresses, so the form warns,
and the paste page warns each person. The portal itself never logs the key.

**What it excludes.** A user authorization requirement (one credential per call, as `oauth`); a static part that sets the same
header or query parameter; and, for `bearer` or an `Authorization` header, a static part that sets `Authorization` (`422
auth_conflict`, `details.reason` `requirement`, `static_duplicate` or `static_authorization`, `details.mode` `person_secret`).
Other static parts (a tenant header) may stay: they are sent with everyone's calls. When the key occupies `Authorization`, the
caller's identity token arrives in `MCP-Gateway-Identity`.

**Capabilities are read with an editor's key.** Nobody's key exists when the server is added, so it is created without reading
its capabilities (`setupRequired`). An editor, admin or owner of the team enters their own key under **Account › My
connections › Keys for servers** and chooses *Use my key to read this server's capabilities*. The portal reads the server with
that key (Test and Refresh use it too), and the server's Overview names whose key it is. An editor can do this before any
gateway offers the server (everyone else needs a gateway that offers it). **Scheduled health checks send nobody's key**: a
`401` or `403` answer counts as healthy, shown as "Reachable — requires sign-in" (a robot must not use anyone's key). Review
and the origin rule bound a malicious URL: the paste page names the server, its team and the address.

**What changes people's keys.** Everyone's keys for the server are **deleted** (audited `mcp_server.person_secrets_reset`, a
count) when its URL moves to another **origin** (scheme, host, port), when its mode changes, when it is deleted, or when the
placement changes (a header to a query parameter puts keys in places they were not meant for). A path-only edit, another
name, prefix, label or help keeps them. A published server goes back to review under `approval_required` when it switches to
this mode or the placement, name or prefix changes (`upstream_auth_changed`); the review digest covers them.
An automation token can't switch a server to this mode or send `personSecret` (`403 token_not_allowed`).

## For a person

The first time a call needs your key, your AI client shows a link to a page (`/connect/secret/<id>`; 10 minutes, once, only for you)
that names the server, its team, the address the key goes to and how it is sent. Paste the key in the password field and save.
You can also do it ahead of time, replace it or remove it under **Account › My connections › Keys for servers**.

* **Nobody can read it back**, you included: the API and the pages show its last four characters (when it has at least
  eight). Keys are 8 to 4096 characters on one line.
* **Agents.** An agent acting for you (decisions 65 to 68) uses your key only when you switch on *Let my agents use this key*
  for that server (off by default; it is the counterpart of allowing a server for a connected account, decision 68), and it
  **never gets a link**: a tool error says to enter or allow the key under Account › My connections.
* **Suspension** (decision 53) blocks your calls and keeps your keys; reactivating restores them. Deleting you deletes them.
  Platform admins can remove anyone's key (Admin › Users › person).
* **A server that refuses your key** (HTTP 401 or 403 on a call) marks it **rejected**: it is not sent again, nothing is
  retried, and you are asked to enter it again. A 403 that is only a permission problem on one tool also does this; enter the
  key again once it is fixed.

## What a call does

After the usual checks and the provider credential step (a server in this mode has no requirement), a call to such a server:

1. from a **service account** is refused: `-32010`, `data.reason` `service_account`, recorded `denied` (shared team secrets
   are roadmap #26);
2. from a **person with no usable key** gets the consent answer in the three shapes of decision 59: `-32042` with the link for
   a legacy client; an `input_required` result with the link for a 2026-07-28 client that declared URL elicitation; a tool
   error (or `-32010` for a prompt or a read) with the link in its text otherwise. Recorded `needs_authorization`, class
   `secret_missing` (never entered, or entered for another origin) or `secret_rejected`. **Nothing is forwarded and there is no
   fallback to any other credential.**
3. **relayed for a person** is the person's call: their key if they allowed agents (class `agents_not_allowed` and a tool
   error otherwise); no link, no stored request, whatever the client declared. An agent-only call (no person) is a service
   account's call: refused.
4. is forwarded with the key in the chosen placement, and the identity token where
   [upstream-identity.md](upstream-identity.md) says;
5. answered 401 or 403 marks the key rejected (compare-and-set on the value that was sent: a key entered meanwhile is not
   touched), and asks again as in 2 (class `secret_rejected`).

A suspended person's key is never used (the call is refused before it).

## Where the key is, and where it is not

* Table `person_secrets` (`secret_cipher`, sealed with `ENCRYPTION_KEY`, AAD `person_secret:<id>`, so a ciphertext moved to
  another row doesn't open), unique per (person, server), with the **origin** it was entered for, a hint, `status`
  (`active`/`rejected`), `allow_agents`, `last_used_at` (once a minute). Links are `secret_requests` (ID sealed like
  `provider_connect_requests`, AAD `secret_request:<digest>`). `rotate-keys` re-seals both columns.
* **Never**: returned by any API response, in a log line, an audit entry (`person_secret.create`, `rotate`, `revoke`,
  `agents_update` and `mcp_server.person_secrets_reset` name the person, server and origin only), a call record, a captured
  payload, a health message, an error, a trace attribute (the tracing allow-list of decision 71 is unchanged), or the answer
  to the client (a server that echoes the key back gets it redacted: the bare value, the value with its prefix and their
  URL-encoded forms; the same redaction as decision 70's parts). The query value is added to a copy of the request, never to a
  stored URL, so no error built from a URL shows it.
* A key is bound to the origin it was entered for: the call refuses one whose origin is not the server's now (even if a row
  says otherwise), and the entry request names the origin the person was shown (`409 server_changed` when it moved).

## API

All six operations are browser-session only and have no `x-omp-token-scopes` (decision 58): no automation token, API key,
service account or agent can enter, read or remove a key.

| Operation | |
|---|---|
| `listMyServerSecrets` `GET /v1/me/server-secrets` | the servers the caller may use through a gateway (and, for an editor, their team's), with their entry (never the key), and every key they have |
| `setMyServerSecret` `PUT /v1/me/server-secrets/{serverId}` | `{origin, value?, allowAgents?, useForSetup?}`; 20 changes a minute per person |
| `revokeMyServerSecret` `DELETE …` | |
| `getSecretRequest` `GET /v1/connect/secret-requests/{requestId}` | what a link is for; `404` for another person's, `410` expired or used or the server moved |
| `adminListUserServerSecrets`, `adminRevokeUserServerSecret` `/v1/admin/users/{userId}/server-secrets` | platform admins and auditors read, admins remove |

`McpServer` gains `personSecret` (settings, how many people entered a key, the setup person's state) and
`McpServerCreate`/`Update` gain `personSecret`.

## With TLS to the server (decision 74)

A person-secret server can also have a private CA and a client certificate ([registry.md](registry.md#tls-to-the-server)). Every
exchange with it uses them: the editor's setup read, Test and Refresh with their own key, and every person's call, so the key
travels only over the server's own trust. Another origin deletes everyone's keys and, separately, needs the TLS key entered again
or cleared (`422 tls_key_required`); a changed CA sends a published server back to review like a changed placement does. An
automation token can't send `tls` or `personSecret`, on create or update.

## What was not tested

Against a real third-party server that wants a personal key (the fake MCP server in the tests checks headers, bearer and
query values, and a server that answers 401 or 403); in a browser by hand (the pages are covered by Vitest and the API by
the integration tests); with more than one replica (nothing here is cached per replica, but the rate limit and the key
rotation are the shared ones). Not built: shared team secrets and service-account use (#26), several keys per person and
server, testing a key when it is pasted, per-tool keys.
