# Gmail MCP server behind Open MCP Portal

This is a reference MCP server with three Gmail tools. It shows how to adapt a server that used to run its own Google
OAuth so that it relies on the portal's **delegated credentials**
([phase5-delegated-credentials.md](../../docs/phase5-delegated-credentials.md)). The portal signs the person in,
asks for their consent at Google once, keeps and refreshes their token, and forwards it with each call that needs it.
The server stores no tokens, sessions or client secret.

| Tool | Annotations | Gmail API | Scope |
|---|---|---|---|
| `search_messages` `{query, max ≤ 25}` | `readOnlyHint` | `GET users/me/messages?q=` and `messages/{id}?format=metadata` | `gmail.readonly` |
| `read_message` `{id}` | `readOnlyHint` | `GET users/me/messages/{id}?format=full` | `gmail.readonly` |
| `create_draft` `{to, subject, body}` | `destructiveHint: false` (it writes, but only adds a draft and never sends) | `POST users/me/drafts` | `gmail.compose` |

`search_messages` returns ID, sender, subject, date and snippet for each message. `read_message` returns the main
headers, attachment names and the plain-text body (else the HTML part with its tags removed), cut to
`-max-body-chars` (20,000 by default).

Files: `main.go` (flags and wiring), `identity.go` (identity token verification and the HTTP guard), `tools.go`
(the MCP tools and provider checks), `gmail.go` (the Gmail REST client), `fakegmail.go` (an in-memory Gmail for local
runs and tests), `smoke.py` (an end-to-end check against a dev portal).

## What changed compared with a server that runs its own OAuth

| | Before: the server runs its own OAuth | After: behind Open MCP Portal |
|---|---|---|
| Sign-in | The server is an OAuth client of Google, with its own `/login` and `/callback`, a client secret and a session store | None. The portal signs the person in and runs the Google consent (`<APP_URL>/connect/callback`) |
| Tokens | Stored, encrypted and refreshed by the server | None stored. Every call brings a fresh access token in `MCP-Gateway-Provider-Token`, and the portal refreshes it |
| Who is calling | Google's userinfo, or the server's own session | The portal's signed **identity token** (`sub`, `email`, `teams`, `tool`, `provider`) |
| First use | The server sends the person to its login page | The portal answers the client with `-32042` and a consent link. The person connects, then runs the tool again |
| Revocation | A disconnect page in the server | Account › My connections in the portal |
| Access control | Your own rules | The portal decides who may call which tool. The server can still check `email`, `teams` or `sub` |

Code-wise, the change is small:

```go
// Before: look up the person's stored token, refresh it, maybe redirect to /login.
tok, err := tokenStore.Get(session.UserID) // + oauth2.Config.TokenSource(...) + refresh + persistence

// After: verify the portal's identity token (Guard, once per HTTP request) and take the token it forwarded.
id := IdentityFrom(r.Context())               // verified: iss, aud, exp, ES256 signature from the portal's JWKS
if id.Provider != "google" || r.Header.Get("MCP-Gateway-Provider") != "google" { /* refuse */ }
token := r.Header.Get("MCP-Gateway-Provider-Token") // bare access token, never logged or stored
```

Delete the OAuth client, the callback route, the token table and the refresh job.

## What a forwarded call carries

A `tools/call` that the portal forwards carries these headers (when the server registered no static `Authorization`
header):

```http
POST /mcp HTTP/1.1
Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6Ii4uLiJ9...   # the identity token (MCP-Gateway-Identity if your static header is Authorization)
MCP-Gateway-Provider: google                                    # the auth provider's slug
MCP-Gateway-Provider-Token: ya29.a0Af...                        # the person's Google access token, bare
Content-Type: application/json
```

The identity token's claims include
`{"iss":"https://mcp.example.com","aud":"https://mail.example.com/mcp","principal_type":"user","sub":"…","email":"pat@example.com","teams":["support"],"gateway":"mail","tool":"mail__search_messages","provider":"google","jti":"…","iat":…,"nbf":…,"exp":…}`.
The full list is in [upstream-identity.md](../../docs/upstream-identity.md).

The portal doesn't send an identity token with discovery (refresh), tests or health checks, and it never sends the
provider headers with them.

## How the server checks a request

`identity.go`, in order:

1. **Find the token:** `MCP-Gateway-Identity`, else `Authorization: Bearer`.
2. **No token:** only discovery may proceed (`server/discover`, `initialize`, `notifications/initialized`, `ping` and the
   `*/list` methods). Anything else, including `tools/call`, gets **401**. So do provider headers without an identity
   token. To lock discovery down as well, start the server with `-discovery-key <secret>` and register
   `X-Discovery-Key: <secret>` as the server's static header in the portal. The portal then sends the header on every
   request, discovery included.
3. **Verify the JWT:** `alg` must be `ES256` and `kid` must name a key in the portal's JWKS (`-jwks`). The key set is
   cached for 5 minutes and fetched again for an unknown `kid`, at most once every 10 seconds. If the JWKS can't be
   fetched, keys already cached keep working. The token must also have `iss` = `-issuer` (the portal's `APP_URL`),
   `aud` = `-audience` (this server's URL **exactly as registered**), and current `exp`/`nbf`/`iat` (30 s leeway).
   `exp`, `iat`, `sub` and `principal_type` are required, and the token may live at most 15 minutes. Any failure gets
   **401**.
4. **Provider headers:** if `MCP-Gateway-Provider` or `MCP-Gateway-Provider-Token` is present, the header must equal
   the token's `provider` claim, else **401** (the headers didn't come from the portal).
5. **In each tool (`tools.go`):**
   - A `service_account` principal gets a tool error.
   - No provider token gets the tool error *"no Google account token came with this call … set the requirement to
     the "google" auth provider with the Gmail scopes"*. This means the server's requirement isn't configured.
   - A `provider` other than `-provider` gets a tool error naming the wrong provider.
   - If Google answers `401`, the tool error tells the person to reconnect under Account › My connections.

The server logs one line per call (tool, `sub`, `jti`, provider, outcome) and one line per refused request. It never
logs tokens, search queries or message contents. Tool errors never include the token.

## Run it locally (fake Google)

You need the dev gateway (`make deps-up run dev-seed`, with `DEV_AUTH=true` and `APP_URL=http://localhost:8088`) and
`make fake-oauth`, a fake OAuth provider on `:8092` that stands in for Google. Then:

```sh
make example-mail-fake      # this server on http://127.0.0.1:8093/mcp, provider slug google-dev, fake Gmail at /fake-gmail
make example-mail-smoke     # python3 examples/mail-mcp/smoke.py
```

The smoke script creates the following, if missing, and **keeps** them:

- the auth provider `google-dev`, pointing at the fake provider (client `fake-client`, secret
  `fake-secret-0123456789`)
- the server `mail` in team `demo`, requiring `google-dev` with `gmail.readonly`, with `create_draft` overridden to
  `gmail.compose`
- the team gateway `mail` with the three tools

As `admin@localhost`, it then checks:

- the `-32042` consent link, and consent through the fake provider
- search, read and the second consent for `gmail.compose`, then the draft
- the tool error from a server registered without a requirement
- 401 for direct calls with no token, with only provider headers, or with a forged JWT

Finally it deletes its `qa-mail-*` objects and disconnects the admin from `google-dev`, so you can go through the
consent yourself:

```sh
claude mcp add --transport http mail http://localhost:8088/mcp/mail   # then /mcp to sign in (admin@localhost)
```

Ask Claude to "search my mail for messages from alice". It shows the consent link. Open it, choose Continue, then
Approve on the fake provider's page, and ask again.

The fake Gmail accepts any bearer token. Its search understands plain words, `from:`, `to:`, `subject:` and
`is:unread`.

## Set it up with real Google

1. **Google Cloud project.** Under *APIs & Services › Library*, enable the **Gmail API**.
2. **OAuth consent screen.** Use user type *Internal* for a Google Workspace organisation. Otherwise use *External*
   and add test users: `gmail.readonly` and `gmail.compose` are restricted scopes, so a public External app needs
   Google's verification. Add the scopes `openid`, `.../auth/userinfo.email`,
   `https://www.googleapis.com/auth/gmail.readonly` and `https://www.googleapis.com/auth/gmail.compose`.
3. **OAuth client.** Under *Credentials › Create credentials › OAuth client ID*, choose *Web application* and add the
   authorized redirect URI **`<APP_URL>/connect/callback`**, for example `https://mcp.example.com/connect/callback`.
   The portal shows this URI on the provider record and on the preset. Keep the client ID and secret.
4. **Add the provider in the portal** (platform admin). Go to Admin › Auth providers › New, choose the **Google**
   preset (it fills in the endpoints, `access_type=offline`, `prompt=consent` and `include_granted_scopes=true`), set
   the slug to `google` (or pass your slug with `-provider`), and paste the client ID and secret. A new provider
   starts **restricted**: open its **Access** tab and list the team that registers the server (or open it to every
   team) before the team sets the requirement.
5. **Run the server** where the portal can reach it, over https in production (a private address must be on the
   gateway's internal-network allowlist; see [registry.md](../../docs/registry.md#security)):

   ```sh
   go run ./examples/mail-mcp -addr 0.0.0.0:8093 -gateway https://mcp.example.com \
     -audience https://mail.example.com/mcp -provider google
   ```

   `-audience` must be exactly the URL you register in the next step. `make example-mail` runs it against the local
   dev gateway with real Gmail (`MAIL_PROVIDER`, `MAIL_AUDIENCE`).
6. **Register the server** (team editor or above). Under Team › Servers › New, enter the URL from step 5. In
   Settings › User authorization, choose the **Google** provider with the scope
   `https://www.googleapis.com/auth/gmail.readonly`. On the Capabilities tab, override `create_draft` to scopes
   `https://www.googleapis.com/auth/gmail.compose`. Gmail's compose scope also covers drafts, so people who only read
   never grant it. Under `approval_required`, publishing (or widening the requirement) needs a platform admin's
   review.
7. **Add the tools to a gateway.** In Team › Gateways (or a platform gateway, once the server is published), select
   `mail__search_messages`, `mail__read_message` and `mail__create_draft`.
8. **Connect from Claude Code:** run `claude mcp add --transport http mail https://mcp.example.com/mcp/mail`, then
   `/mcp` to sign in. The first mail tool call answers with a consent link. After you connect, run the tool again.
   Account › My connections shows the Google account and lets you disconnect it.

Use full scope URLs. They are the names Google's token response returns, so the portal can tell that they were granted.

## Adapting it to Microsoft Graph (Outlook)

Only the Gmail client and the scope names change:

- **Provider:** use the *Microsoft Entra ID* preset. Register an app in Entra ID with the redirect URI
  `<APP_URL>/connect/callback`, and add the delegated Graph permissions `Mail.Read` (for search and read) and
  `Mail.ReadWrite` (for drafts) plus `offline_access`, so the portal gets a refresh token. Set the requirement to
  `Mail.Read offline_access`, and override `create_draft` to `Mail.ReadWrite offline_access`.
- **API:** the base is `https://graph.microsoft.com/v1.0/me/messages`:
  - search: `GET /me/messages?$search="from:alice"&$top=25&$select=id,from,subject,receivedDateTime,bodyPreview`
    (needs `ConsistencyLevel: eventual` for some filters)
  - read: `GET /me/messages/{id}` with `Prefer: outlook.body-content-type="text"` for a plain-text body
  - draft: `POST /me/messages` with `{"subject", "body": {"contentType": "Text", "content"}, "toRecipients": [...]}`,
    which creates a draft without sending it
- **Server flags:** pass `-provider microsoft` (the provider's slug). Send the token as `Authorization: Bearer <token>`
  to Graph, as this example does to Gmail. Graph answers `401` for a revoked token, which maps to the same "reconnect"
  tool error.

## Tests

```sh
go test ./examples/mail-mcp/
```

- `identity_test.go`: a valid token, then bad `aud` and `iss`, expired, not yet valid, no `exp`, too long-lived, no
  `principal_type`, HS256, an unknown kid, a tampered payload, key rotation with the refetch limit, a JWKS outage, and
  the guard's 401 cases (anonymous call, provider headers without or not matching the claim, the discovery key)
- `tools_test.go`: the tools against the fake Gmail over Streamable HTTP. It covers annotations, the search limits,
  HTML and truncated bodies, attachments, the draft's MIME (including header injection), no token, the wrong provider,
  service accounts, a revoked token, and logs that contain no token, query or contents
- `integration_test.go`: the real gateway in process over a fresh database (skipped without Postgres, like the other
  integration tests; `make deps-up`), the fake OAuth provider and this server. It creates the provider, the server with
  its requirement, the gateway and an API key. The first call answers `-32042`; after consent, the retry returns
  messages, the server saw a verified identity token with `provider`, and Gmail got the token the provider issued.
