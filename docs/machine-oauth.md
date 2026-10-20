# The portal's own OAuth client (machine OAuth)

`authMode: machine_oauth` (roadmap #24, [decision 73](decisions.md)). For a server that authenticates **the calling system**,
not the person: an internal API behind an IdP, a vendor server with a machine client. The portal is an OAuth client of
the server's authorization server. It asks for a token with the **client credentials grant** (RFC 6749 section 4.4),
keeps it in memory, and sends it as `Authorization: Bearer` to the server's stored URL on **every** request to it:
discovery, Refresh, Test, scheduled health checks and forwarded calls, from every caller alike (a person, a service
account, an agent platform's relay). Before this, the answer was a long-lived static header rotated by hand.

It is the portal's credential, not a person's. Everyone who can call the server shares one token; the call log and the
identity token ([upstream-identity.md](upstream-identity.md)) are the only record of who called. Use
[oauth mode](phase7-upstream-oauth.md) when the server must know the person.

## Setting it up

Add MCP server (or Settings › Authentication) › **The portal's own OAuth client**. It needs no detection, but **Detect
sign-in** helps: when the server publishes protected-resource metadata and its authorization server's metadata lists
`client_credentials` in `grant_types_supported`, it offers the token endpoint and the resource to fill in (`machineOAuth`
in the detect-auth answer: `tokenEndpoint`, `clientCredentials`, `grantTypesListed`, `tokenAuthMethods`, `resource`). A
server with no OAuth metadata at all (an IdP-fronted API that only documents its token URL) is set up by hand.

| Field | |
| --- | --- |
| Token endpoint (`tokenUrl`) | Required. https (plain http only where the address rules allow it, as for a server's URL); no userinfo, query or fragment. Checked against the address rules **when saved and at every token request**. |
| Client ID, client secret | Required the first time. The secret is sealed with `ENCRYPTION_KEY` (AAD `machine_oauth:<server id>`) and **never shown again**: the API and the page show only whether one is stored and its last four characters (when it has eight or more) and the last six of the client ID. |
| Token method (`tokenAuthMethod`) | `client_secret_basic` (default: the form-encoded ID and secret in an HTTP Basic header, RFC 6749 section 2.3.1) or `client_secret_post` (in the body). `private_key_jwt` and mTLS are not supported. |
| Scopes | Optional, space-joined in the `scope` parameter. |
| Resource (`resource`), audience (`audience`) | Optional. `resource` (RFC 8707, an absolute URI) binds the token to this server where the authorization server honours it; `audience` is what Auth0 and some others want instead. An authorization server that ignores both leaves the token usable at other servers that trust it: set what it supports. |

The mode excludes a static `Authorization` header (a header part named so, a bearer or a Basic part) and a user
authorization requirement, as oauth mode does (`422 auth_conflict`, `details.reason` `static_authorization` or
`requirement`; also a database CHECK for the header columns). Other static parts (a tenant header, a query key) stay and
are sent next to the bearer. **Who may set it up:** a team **editor**, as for oauth setup (the owner delegated the
question; the review gate covers other teams). A platform automation token may **not** (see below).

## At run time

- **Token source** (`internal/upstream/machineauth.go`). The request is `POST` to `tokenUrl` with
  `grant_type=client_credentials` (and `scope`, `audience`, `resource`), through the address guard (guarded dialer: every
  resolved address checked and the connection pinned to it, **no proxy, no redirects**, 10 s, an answer of at most 64 KiB).
  The answer must be JSON with an `access_token` of at most 8 KiB without whitespace or control characters; a
  `token_type` other than Bearer (DPoP, MAC) is refused.
- **Cache.** One token per server, **in memory on each replica**, never in the database. It is used until 60 seconds before
  its `expires_in` (a token that lives less than two minutes is used for the first half of its life; none given: five
  minutes; at most 24 hours). Concurrent callers share **one** token request (single flight; a caller that gives up
  does not cancel it). The cache key includes the token endpoint, client ID, secret, method, scopes, audience and
  resource, so a changed configuration **never reuses a token**, and any change, a mode change or a delete also drops the
  entry at once.
- **A 401 from the server** means the call did not run, so the portal drops that token, gets another (one request however
  many calls were refused together; a call that finds a newer token already cached uses it) and retries **once**. A
  second 401 is class `auth`. Discovery, Test and health checks do the same.
- **Identity.** The bearer occupies `Authorization`, so the identity token travels as `MCP-Gateway-Identity` (as in oauth
  mode and when a static part sets `Authorization`), on calls, on a manual Test, and on calls an agent platform relays.
  Scheduled health checks and Refresh send no identity token, as before.
- **Service accounts and agents.** The credential belongs to the server, so a service account (and a relayed agent call)
  can call a tool on such a server like any caller; the identity token's `principal_type` stays what it was.

## Failures

| What happened | Call | Test, Refresh, health |
| --- | --- | --- |
| The token endpoint is unreachable, times out, answers 5xx or 429 or nonsense, or its address is no longer allowed | `-32010`, `data.reason` `machine_auth_unavailable`; recorded `upstream_error` with the class (`unavailable`, `timeout`, `not_allowed`); **the server is not contacted** | the same class; message "The portal could not get a token for this server: its authorization server is unavailable (code)." |
| The authorization server refuses the client (`invalid_client`, `invalid_scope`, `unauthorized_client`, `unsupported_grant_type`, an HTTP 4xx) | class `auth`, `-32603` with "The authorization server refused the portal's client (code). Check the server's client ID, secret and scopes." | class `auth`, the same message |
| The stored secret can't be decrypted (a different `ENCRYPTION_KEY`) | class `config`: enter the secret again | class `config` |
| The server refuses a fresh token | one renewal and retry, then class `auth` (HTTP 401) | the same |

Only an **OAuth error code** (or one of ours) is ever kept from the authorization server (`safeMachineCode`: letters,
digits, `_ . -`, at most 64, else `error`): its `error_description` and body are never shown, logged or stored, and a
token or the secret is in no message. The token is also added to `Target.Secrets()`, so a server that echoes it back
is redacted from the call result, the captured payload and stored errors.

## Changing it (F-1 and review)

- **The secret goes to one place.** A changed `tokenUrl`, a changed `clientId`, or a server URL on another **origin** needs
  `clientSecret` in the **same request** (`422 client_secret_required`, `details.reason` `new`, `token_url_changed`,
  `client_id_changed` or `origin_changed`, `details.field` `machineOAuth.clientSecret`). Nothing is stored and **nothing is
  sent to the new endpoint or host**. Without the mode's row (switching in), the three fields and the secret are required
  (`400 invalid_machine_oauth` when the object is missing); `machineOAuth` with any other mode is refused, not ignored,
  because it carries a secret. A path-only change of the URL or a change of scopes, method, audience or resource keeps
  the secret.
- **Review.** Under `approval_required` a published server goes back to `pending` (`upstream_auth_changed`, as decision
  40) when it switches to the mode, its token endpoint, client ID, audience or resource changes, or a scope is added;
  a **new secret** or fewer scopes does not. A new URL goes back as before (`url_changed`). The review digest
  (`reviewDigest`) covers the token endpoint, client ID, method, scopes, audience and resource (never the secret), so an
  approval made on an earlier look is refused with `409 changed_since_review` (F-2). Reviewers see the token endpoint
  (with a badge when it is on another host than the server), the scopes and the hints in the publish and review dialogs.
- **Audit.** `mcp_server.auth_update` with the mode, token endpoint, method, scopes, audience, resource, `sendIdentity`
  before and after, and `clientSecretChanged`, `clientIdChanged`, `tokenUrlChanged`: **never** the secret, its hint, the
  client ID or a token.
- **Automation tokens.** `machineOAuth`, and a switch to `machine_oauth`, are **session only**: a platform or team
  automation token gets `403 token_not_allowed` (`details.field` `machineOAuth` or `authMode`), on create and on update,
  even for a server with no credentials, and a token can't change the URL, mode, sendIdentity or credentials of a server
  already in the mode. No new operation was added (the existing create and update operations carry the field).
- **Leaving the mode** (or deleting the server) deletes the client and the secret.

## Operations

- **Metric** `omp_machine_token_requests_total{result}`: `ok`, `refused`, `unavailable`. Requests to a token endpoint,
  not cache hits (alert on a rising `refused`: the secret was rotated at the IdP). **Spans:** `upstream.machine_token`
  with only the existing allow-listed attributes (result, error class), never a URL, token or client.
- **`ENCRYPTION_KEY` rotation.** `rotate-keys` re-seals `mcp_server_machine_oauth.client_secret_cipher` (it is in
  `keyrotation.Columns`; a test fails if the column is missing).
- **Migration `00025`** (expand-only): `auth_mode` accepts `machine_oauth`, and the table `mcp_server_machine_oauth`
  (one row per server, cascading) holds the client. It depends on no other migration. The previous release ignores the
  table and reads such a server as one without authentication, so servers are only put in this mode after every replica
  runs this release; `Down` turns them into servers without authentication.

## Developing and testing with the fakes

`cmd/fakeoauth` serves the client credentials grant (Basic or form client authentication, the scope asked for unless
`-machine-scopes` limits it, no refresh token, `-ttl` as the lifetime, `-enforce-expiry` to make a token inactive after
it, `resource` and `audience` recorded, `-no-client-credentials` to refuse and unlist it), and `cmd/fakemcp -protect <issuer>`
requires a bearer the authorization server says is active and bound to its URL:

```
go run ./cmd/fakeoauth -ttl 2m -enforce-expiry          # http://127.0.0.1:8092 (client fake-client / fake-secret-0123456789)
go run ./cmd/fakemcp -addr 127.0.0.1:8094 -protect http://127.0.0.1:8092
# token endpoint http://127.0.0.1:8092/token, resource http://127.0.0.1:8094/mcp (DEV_AUTH on a loopback APP_URL)
```

## With TLS to the server (decision 74)

A `machine_oauth` server can also have a private CA and a client certificate ([registry.md](registry.md#tls-to-the-server)). They
apply to the exchange with **the MCP server**: discovery, Test, health checks and calls reach it over the CA and, when it asks, the
client certificate, carrying the portal's token. **The token request is not covered**: the token endpoint is reached with the system
roots and no client certificate, so an authorization server behind a private CA is not supported (a token request to it fails with
`machine_auth_unavailable`, never with a wider trust), and the resource-metadata discovery in Detect sign-in is likewise unaffected.
Moving the URL to another origin needs the client secret *and* the TLS key entered again in the same request (`422 client_secret_required`
and `422 tls_key_required`, each on its own); a changed CA sends a published server back to review like a changed token endpoint does.

## Not built, and not tested

- `private_key_jwt` and mTLS client authentication at the token endpoint, token exchange (RFC 8693), a platform-wide
  client library, per-person tokens (all out of scope in the issue).
- **No real authorization server was used**: Entra ID, Okta, Keycloak, Auth0 and the like were not tried, so their quirks
  (a required `audience`, `scope` spelled as `.default`, a different `token_type` case, a secret that expires) are untested.
  The grant, the two client authentication methods and the answer shapes are tested against `FakeOAuth` and the
  protected `FakeMCP`; DNS answers that change, blocked and private addresses and redirects are unit-tested in
  `internal/upstream` (the integration tests run with the development allowance).
- Not browser-checked: the web form is covered by component tests only.
- A token is cached until it expires: a token the authorization server revokes is used until the server answers 401
  (then renewed once). There is no cross-replica cache, so each replica asks for its own token.
