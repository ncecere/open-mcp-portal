# Verifying Open MCP Portal's identity token

When someone calls a tool, gets a prompt or reads a resource through a gateway, Open MCP Portal forwards the request to your MCP server with a short-lived **identity token**: a JWT signed by the portal that says who is calling, through which gateway and for which tool ([decisions](decisions.md) 7 and 19). Verify it before you trust it. The token is the only credential from the caller that reaches your server. The portal never forwards the client's own API key, service account key or OAuth token.

The caller is either a **person** (with a personal API key, or through an MCP client they connected with OAuth sign-in) or a team **service account** (a headless agent, CI job or script; decisions 22 and 23). The `principal_type` claim says which. A call made by an **agent for a person** through a trusted agent platform is the person's call with an `act` claim naming the agent ([Calls from agents](#calls-from-agents)).

Lists (`tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`) are served from the definitions approved in the portal, so your server only receives calls (`tools/call`, `prompts/get`, `resources/read`), plus the handshake and lists of an editor's **Test connection** (below). A read arrives with your own URI (the portal strips its `omp://{server-slug}/` prefix). Each call also performs the MCP handshake again, because the portal is stateless.

## Where the token arrives

| Your server's upstream auth (set when it was registered) | The token arrives as |
|---|---|
| `none`, or a static credential none of whose parts sets `Authorization` (headers such as `X-API-Key`, a query key) | `Authorization: Bearer <jwt>` |
| a static credential with a part that sets `Authorization`: a header named `Authorization`, a bearer token or Basic ([registry.md](registry.md#a-servers-own-credential-parts)) | `MCP-Gateway-Identity: <jwt>` (the bare token). Your static `Authorization` value is sent unchanged |
| `oauth` (each person signs in to your server's own authorization server, [phase7-upstream-oauth.md](phase7-upstream-oauth.md)) | `MCP-Gateway-Identity: <jwt>`. `Authorization: Bearer` carries the person's own token for your server, issued for your server's URL (RFC 8707 `resource`) |
| `person_secret` (each person's own key, [person-secrets.md](person-secrets.md)) with the key as a header other than `Authorization` or as a query parameter | `Authorization: Bearer <jwt>`; the person's key arrives in that header or parameter |
| `person_secret` with the key as `bearer` or in a header named `Authorization` | `MCP-Gateway-Identity: <jwt>`. The person's own key is in `Authorization` (`Bearer <key>`, or the team's header value with its prefix) |
| `machine_oauth` (the portal is an OAuth client of your server's authorization server, [machine-oauth.md](machine-oauth.md)) | `MCP-Gateway-Identity: <jwt>`. `Authorization: Bearer` carries the portal's own token, obtained with the client credentials grant, the same for every caller (people, service accounts, health checks); the JWT says who is calling |
| any mode with **Send identity** off (`sendIdentity: false`) | not sent at all: no identity header |

A static credential's other parts (more headers, a query parameter) arrive on every request as the team entered them, next to the identity token; they are the portal's secret for your server, so don't log the query string. A call an agent platform relays for a person (decisions 65 to 68) gets its identity token in the same place as the person's own call. With no static credential, your server can act as an ordinary OAuth resource server that accepts bearer tokens from the portal's JWKS. Servers can't register a static header named `MCP-Gateway-Identity`, `MCP-Gateway-Provider` or `MCP-Gateway-Provider-Token`.

The header names keep `Gateway` although the product is now called Open MCP Portal (it was Open MCP Gateway): they are a contract with the authors of MCP servers, and they describe what reaches your server, a call relayed through a gateway (`/mcp/{slug}`). They won't change.

**Send identity (decisions 45 and 64).** Every server has a `sendIdentity` switch. When you register a server without
saying, it is **off** if the server has no authentication and its host is public (or can't be resolved), and **on** if the
host is internal (an internal-allowlist entry or a private address) or the server uses a static header or OAuth. Servers saved
before decision 64 keep their value (on, unless a team turned it off). Turn it off for servers run outside the company, such
as GitHub's hosted MCP server, so people's names, emails and teams aren't sent to a third party; the server then gets no
identity token on any call. Turn it **on** for a public server that expects the token. It isn't a review trigger (it sends
less).

Each call record says whether the token was sent (`identitySent` in the API, **Identity token** on the call's page, and
`?identitySent=true|false` on the call lists): `true` when it was attached to the request, `false` when the switch was off,
and absent when the call was not forwarded (refused, rate limited, a list the portal answered) or was recorded before the
field existed. If a server rejects calls only when a tool runs, look at this value first: a failure on calls that sent the
token, with the same server working without it, points at the switch.

**OAuth servers.** In `oauth` mode the portal is an ordinary MCP client of your server (MCP authorization 2025-11-25):
it reads your protected-resource metadata and your authorization server's metadata, and sends each person's token
only to your server's URL, which must equal the metadata's `resource`. There is never an `MCP-Gateway-Provider` header
or a `provider` claim. Answer `401` with a `Bearer` challenge when a token isn't valid (the portal refreshes once and
retries, then asks the person to sign in again) and `403` with `error="insufficient_scope", scope="…"` when a call needs
more access (the portal asks for it if your team's reviewed scopes or your `scopes_supported` include it). Scheduled
health checks send an unauthenticated `initialize`; your `401` challenge counts as healthy ("requires sign-in").

## What a Test sends

An editor's **Test connection** (decision 61) behaves like a call for a server whose Send identity is on: it does the handshake (`initialize` or `server/discover`) and the lists with an identity token for **the person who pressed the button**, in the same header a call uses (table above). It calls no tool. The token is the same kind as a call's, with these values where a call names a gateway and a tool:

| Claim | In a Test |
|---|---|
| `principal_type`, `sub`, `email`, `name`, `teams` | The editor, as for a call from them |
| `aud` | Your server's URL, as registered |
| `gateway` | `omp:test`. No gateway slug can look like this (slugs are lowercase letters, digits and hyphens), so a server that decides by gateway can't mistake a test for traffic |
| `tool`, `prompt`, `resource` | **None of them is set** (a call sets exactly one) |
| `client` | `Test connection` (no `client_verified`) |

If your server answers a Test's request with `401` or `403` but accepts the same request without the token, the portal reports that the server refuses the identity token (and to turn Send identity token off, or to accept it). A public server that refuses any `Authorization` header is the usual case. This catches only a server that refuses at the HTTP level: one that accepts the request and rejects the token when a tool runs still passes a Test. Since decision 64 a new server with no authentication on a public host starts with the switch off, which avoids this; the call record's `identitySent` shows the remaining cases. Refresh, discovery and the scheduled health checks send **no** identity token, and an automation token's Test has no person to name, so it sends none either.

## What to check

| Item | Value |
|---|---|
| Algorithm | `ES256` only (header `alg`), and the header `kid` names the key |
| Keys | `GET <APP_URL>/.well-known/jwks.json`, a JWK Set of the key that signs now, the next key (published at least a day before it signs, `SIGNING_KEY_PREPUBLISH`) and any key retired in the last day. Cache it for up to 5 minutes (`Cache-Control: max-age=300`). Keys rotate every 30 days; a cached set normally already holds the next key, but still fetch the set again when a token has a `kid` you haven't seen (the very first key signs as soon as it exists, and so does a new key if the portal ever finds no key to sign with) |
| `iss` | The portal's URL (its `APP_URL`, for example `https://mcp.example.com`) |
| `aud` | **Your server's URL exactly as registered** (for example `https://status.example.com/mcp`). A token minted for another server must be rejected |
| `exp`, `nbf`, `iat` | `exp` is 5 minutes after `iat`, and `nbf` is 30 seconds before it. Allow a little clock skew |

The claims:

| Claim | Meaning |
|---|---|
| `principal_type` | `user` for a person, `service_account` for a team service account. Always present. It is `user` for an agent's call for a person too: look for `act` |
| `sub` | A person's user ID, or the service account's ID (UUIDs, stable). Check `principal_type` before treating `sub` as a person |
| `email` | A person's email at the time of the call. **Absent for service accounts** |
| `name` | A person's display name, or the service account's name (such as `ci-release-bot`) |
| `teams` | Slugs of the teams the person belongs to; for a service account, its own team only |
| `gateway` | The gateway's slug |
| `tool` / `prompt` | The exposed name of the tool (`tools/call`) or prompt (`prompts/get`), `{server-slug}__{name}` |
| `tool_class` | Optional owner-set class (`read`, `write`, `destructive`) on a forwarded tool call. Absent for unclassified tools, prompts, resources and Tests. This is the team's assertion, not a verified account of the tool's effects; upstream hints never set it. See [tool-classification.md](tool-classification.md). |
| `resource` | The exposed URI read (`resources/read`): `omp://{server-slug}/{your-uri}`, for example `omp://status/status://services/email`. Exactly one of `tool`, `prompt` and `resource` is set on a call (none in a [Test](#what-a-test-sends)) |
| `client` | For a client connected with OAuth, the client's name as it signed in (such as `Claude Code`), with `client_verified`. Otherwise the MCP client's `clientInfo.name` when the request carried it, else the name of the API key or service account key |
| `client_verified` | Present whenever `client` comes from an OAuth client. `true`: the client is identified by a Client ID Metadata Document, so its name is vouched for by the host that publishes it. `false`: the client registered itself (Dynamic Client Registration) and its name is **self-asserted**: anyone can register any name, so don't trust `client` for decisions in that case. Absent for API keys and service account keys (then `client` is the MCP client's or the key's own label, never verified) |
| `provider` | The slug of the auth provider whose user token came with this call in `MCP-Gateway-Provider-Token` (see [Provider tokens](#provider-tokens)). **Absent** when the call carries no provider token |
| `act` | Present **only** on a call an agent made for a person through a trusted agent platform: `{"sub", "name", "iss", "principal_type": "agent", "person_present"}` ([Calls from agents](#calls-from-agents)). **Absent** on every other call |
| `jti` | A unique ID for the token (useful in your logs) |

`client` is informational: decide on `principal_type`, `sub`, `email` and `teams`, which the portal checked. Treat `client` as a hint, and as plain self-asserted text unless `client_verified` is `true`.

The portal has already checked that the caller may use this tool (for a service account: its team's own gateways, with its team role `member` or `editor` for minimum roles, and platform gateways granted to its team). Your server decides what they may do with it, for example by reading `principal_type`, `sub`, `email` or `teams`.

A service account's token, for example:

```json
{"iss": "https://mcp.example.com", "aud": "https://status.example.com/mcp", "principal_type": "service_account",
 "sub": "2f2e1390-9eca-4c8e-ac70-701505d92272", "name": "ci-bot", "teams": ["platform-tools"],
 "gateway": "support", "tool": "status__check_outage", "client": "deploy", "jti": "…", "iat": 1760650000, "nbf": 1760649970, "exp": 1760650300}
```

## Calls from agents

An agent platform the portal trusts (Admin › Trusted agent platforms, [agent-platforms.md](agent-platforms.md); decisions 65 to 67) can relay its agents' calls through a team service account and name the person each agent acts for. When it does, the portal runs the call as that person and the token it signs for your server says so:

```json
{"iss": "https://mcp.example.com", "aud": "https://mail.example.com/mcp", "principal_type": "user",
 "sub": "10101010-1010-4101-8101-101010101010", "email": "ada@example.com", "name": "Ada Lovelace", "teams": ["platform-tools"],
 "gateway": "support", "tool": "mail__search", "client": "pdp-relay",
 "act": {"sub": "0e6a3d4c-5f1b-4f0e-9b8e-2d7c1a9f3b21", "name": "Mail assistant", "iss": "https://agents.example.com",
         "principal_type": "agent", "person_present": true},
 "jti": "…", "iat": 1792500000, "nbf": 1792499970, "exp": 1792500300}
```

- `principal_type`, `sub`, `email`, `name` and `teams` are **the person's**, exactly as for a call from them with their own key. The portal has checked that they may use this tool, **and** that the relay service account may (the call can reach no more than either could alone).
- `client` is the name of the relay service account.
- `act` is the actor (RFC 8693 style): `sub` and `name` are the agent's ID and name **at the platform** (`name` is chosen by the agent's team: informational), `iss` is the platform's issuer, `principal_type` is always `agent`, and `person_present` is the platform's statement that the call belongs to a conversation the person is in. `false` means scheduled or background work that nobody watches.
- **`act` appears exactly on relayed person calls, in the identity token.** A call with the person's own key or app never has it; a call by a service account (including the relay account itself, when the platform names no person) has `principal_type` `service_account` and no `act`. **If the server's Send identity switch is off, there is no identity token at all, so no `act` either, but a relayed call still carries the person's provider token** (`MCP-Gateway-Provider-Token`, or the bearer token of an `oauth` server) when the capability needs one: that server can't tell an agent's call from the person at the keyboard. Leave **Send identity** on for a server that must tell agents from people (or that must refuse unattended calls itself).
- Provider tokens work as for the person (`MCP-Gateway-Provider-Token` is *their* token). An agent has no browser, so the portal never sends an agent's caller a consent link: a person who hasn't connected the provider gets an error naming where to connect, and your server isn't called.

**Telling "Ada" from "Ada's agent".** Check `act` before treating the call as a person at the keyboard:

- refuse agent calls for a tool that must never run unattended: `if claims.act: refuse`;
- require the person for actions that need them there (sending mail, spending): `if claims.act and not claims.act.person_present: refuse`. A server's team can also make the portal refuse such calls before they reach you (**Require a present person for calls from agents**, per server or per capability): use that for a rule that is the same for every caller, and check `act` yourself for a rule that depends on the call;
- log `act.sub` and `act.name` next to `sub` so an audit says which agent did what. Don't base decisions on `act.name`, and treat `act.iss` as the platform the portal trusts, not as a login.

The token you receive is the portal's own, signed with its keys: the platform's token stops at the portal and is never forwarded.

## Provider tokens

A server can need to act **as the person** on a third-party service, for example to create a GitHub issue as them
(decisions 25–30, [phase5-delegated-credentials.md](phase5-delegated-credentials.md)). Your team sets a **user
authorization requirement** on the server (an auth provider a platform admin configured, and scopes), optionally
overridden per capability. The first call asks the person to connect their account in a browser; after that, every call
of a capability that requires the provider arrives with:

| Header | Value |
|---|---|
| `MCP-Gateway-Provider` | The provider's slug, for example `github` |
| `MCP-Gateway-Provider-Token` | The person's access token for that provider, **bare** (no `Bearer`). The portal refreshes it before it expires |

and the identity token gains `"provider": "github"`. Calls without a requirement (or with the override "none") never get
these headers or the claim, and neither do discovery, tests or health checks. Service accounts can't call such
capabilities. The client and the model never see the token.

The person has to **allow your server** first: the consent page says "Allow <your server> (<your team>) to use your
GitHub account", and the token is sent only while the server's URL keeps the **origin** (scheme, host and port) it had
when they allowed it. Moving the server to another host, or requiring another provider, ends everyone's permission and
asks again; changing only the path doesn't. The token is the person's whole connection to that provider, so it holds
every scope they ever granted for it, not only the ones you require (F-3, decision 60).

1. **Verify the identity token first** (above).
2. **Check that its `provider` claim equals `MCP-Gateway-Provider`.** A request with the headers but without the claim (or
   with another value) did not come from the portal for this provider: reject it.
3. **Use the token only with that provider's API**, as the person, and never log or store it.

The portal doesn't check that the provider account belongs to the person (for example by email); if that matters, ask
the provider who the token belongs to and compare it with the identity token's `email` or `sub`. If the provider answers
`401` the token was revoked: return a tool error; the person reconnects under Account › My connections.

**Worked example.** [`examples/mail-mcp`](../examples/mail-mcp/README.md) is a Gmail MCP server (search, read, create
draft) that used to need its own Google OAuth and now relies on the portal's provider token: it verifies the identity
token on every request (JWKS cache with a refetch for unknown kids, `iss`, `aud`, expiry), checks the `provider` claim
against `MCP-Gateway-Provider`, and returns a clear tool error when no token comes because the requirement isn't set.
`make example-mail-fake` runs it against `make fake-oauth`; `make example-mail` against real Google.

**Recorded call contents.** When your team (or a gateway's) turns on "Record call contents"
([phase6-operations.md](phase6-operations.md), "Payload capture"), the portal stores each call's arguments and your
result, redacted. Headers are never stored, and the identity token, the provider token and your server's static header
value are replaced by `[REDACTED]` wherever they appear in a result, but don't echo credentials: other secrets in your
results are only caught by the redaction rules.

## Go (go-jose)

```go
import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const gatewayURL = "https://mcp.example.com"
const myURL = "https://status.example.com/mcp" // as registered in the portal

type Identity struct {
	PrincipalType string `json:"principal_type"` // "user" or "service_account"
	Email   string   `json:"email"`
	Name    string   `json:"name"`
	Teams   []string `json:"teams"`
	Gateway string   `json:"gateway"`
	Tool    string   `json:"tool"`
	Client  string   `json:"client"`
	// ClientVerified is set only for OAuth clients; nil otherwise.
	ClientVerified *bool `json:"client_verified"`
	// Act is set only on a call an agent made for a person (nil otherwise).
	Act *struct {
		Sub           string `json:"sub"`
		Name          string `json:"name"`
		Iss           string `json:"iss"`
		PersonPresent bool   `json:"person_present"`
	} `json:"act"`
}

// Fetch the JWKS (cache it for up to 5 minutes, and fetch again for an
// unknown kid).
func fetchKeys() (jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	res, err := http.Get(gatewayURL + "/.well-known/jwks.json")
	if err != nil {
		return set, err
	}
	defer res.Body.Close()
	return set, json.NewDecoder(res.Body).Decode(&set)
}

func verify(r *http.Request, keys jose.JSONWebKeySet) (jwt.Claims, Identity, error) {
	raw := r.Header.Get("MCP-Gateway-Identity")
	if raw == "" {
		raw = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	var std jwt.Claims
	var id Identity
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(tok.Headers) != 1 {
		return std, id, err
	}
	matches := keys.Key(tok.Headers[0].KeyID)
	if len(matches) == 0 {
		return std, id, errUnknownKey // fetch the JWKS again and retry once
	}
	if err := tok.Claims(matches[0].Key, &std, &id); err != nil {
		return std, id, err
	}
	err = std.ValidateWithLeeway(jwt.Expected{Issuer: gatewayURL, AnyAudience: jwt.Audience{myURL}, Time: time.Now()}, 30*time.Second)
	return std, id, err // std.Subject is the person's user ID; id.Act != nil: an agent called for them
}
```

`cmd/fakemcp` has a working version of this check (`testutil.VerifyIdentity`), and its `whoami` tool reports the token it received, including the `act` claim of a call an agent made for a person (as `act`, and in words as `actedBy`). Its `provider_token` tool reports the provider header, a SHA-256 prefix of the provider token (never the token) and whether the identity token's `provider` claim matches (`testutil.ProviderTokenReport`).

## Python (PyJWT)

```python
import jwt  # pip install "pyjwt[crypto]"

GATEWAY = "https://mcp.example.com"
MY_URL = "https://status.example.com/mcp"  # as registered in the portal

# Caches keys; fetches the set again when it meets an unknown kid.
jwks = jwt.PyJWKClient(f"{GATEWAY}/.well-known/jwks.json", cache_jwk_set=True, lifespan=300)

def identity(headers) -> dict:
    token = headers.get("MCP-Gateway-Identity") or headers.get("Authorization", "").removeprefix("Bearer ")
    key = jwks.get_signing_key_from_jwt(token)
    return jwt.decode(
        token, key.key, algorithms=["ES256"], issuer=GATEWAY, audience=MY_URL, leeway=30,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )  # claims["principal_type"], claims["sub"], claims.get("email"), claims["teams"], claims["tool"]; claims.get("act") is set only when an agent called for the person
```

## TypeScript (jose)

```ts
import { createRemoteJWKSet, jwtVerify } from "jose";

const GATEWAY = "https://mcp.example.com";
const MY_URL = "https://status.example.com/mcp"; // as registered in the portal

// Caches keys and fetches the set again for an unknown kid.
const jwks = createRemoteJWKSet(new URL(`${GATEWAY}/.well-known/jwks.json`), { cacheMaxAge: 300_000 });

export async function identity(headers: Headers) {
  const token = headers.get("mcp-gateway-identity") ?? headers.get("authorization")?.replace(/^Bearer /, "") ?? "";
  const { payload } = await jwtVerify(token, jwks, {
    algorithms: ["ES256"], issuer: GATEWAY, audience: MY_URL, clockTolerance: 30,
  });
  return payload; // payload.principal_type, payload.sub, payload.email (people only), payload.teams, payload.tool, payload.act (an agent called for the person)
}
```

## Try it locally

```sh
make fake-mcp   # go run ./cmd/fakemcp -jwks http://localhost:8088/.well-known/jwks.json
```

Register `http://127.0.0.1:8091/mcp` in a team, select its `whoami` tool in a gateway, create an API key under Account › API keys (or a key of a team service account), and call it:

```sh
curl -s http://localhost:8088/mcp/<gateway> -H "Authorization: Bearer omp_..." \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"<server>__whoami","arguments":{}}}'
```

The result shows the header the token arrived in, its claims (including `principal_type`) and `"verified": true` (with `-jwks`; without it, the claims are only decoded). The fake server also logs each call's identity.

To try provider tokens, run `make fake-oauth` (a fake OAuth provider on `http://127.0.0.1:8092`), add it under Admin ›
Auth providers (authorization `http://127.0.0.1:8092/authorize`, token `/token`, revocation `/revoke`, userinfo
`/userinfo`, client `fake-client`, secret `fake-secret-0123456789`, and register nothing: the fake accepts any redirect
URI), set it as the fake server's requirement, select `provider_token` in a gateway and call it: the first call answers
`-32042` with a link; open it, connect, and call again. (The link allows that one server; a second server that requires
the same provider gets its own link, which skips the provider when the account already has the scopes.)
