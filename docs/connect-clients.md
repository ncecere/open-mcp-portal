# Connecting MCP clients to a gateway

Every gateway has one MCP endpoint, `<gateway URL>/mcp/<gateway>`, for example `https://mcp.example.com/mcp/support`. You find it, with ready-made snippets, under **My gateways** (or the gateway's **Overview › Connect**). There are three ways to connect:

| Who connects | Use | Credential |
|---|---|---|
| You, in an interactive client (Claude Code, Claude, VS Code, Cursor) | **OAuth sign-in** (the default) | None to copy: you sign in in the browser, the client keeps short-lived tokens |
| You, from a script or a client that can't sign in | A **personal API key** (`omp_…`) | Account › API keys |
| A pipeline, agent or job that must not depend on one person | A **service account key** (`omp_sa_…`) | Team › Service accounts |

All three see only what the caller may use on that gateway, checked again on every request. Credentials and
platform gateway grants can further limit tools by owner-set class or exact exposed name (OAuth: classes only).
Matching grants are alternatives; independent ceilings all apply. A read-only ceiling hides write, destructive
and unclassified tools unless a name is explicitly included. Hidden tools are refused as unknown before any
upstream sign-in or consent prompt. Prompts and resources are unchanged. See [credential scopes](credential-scopes.md). The portal never passes your credential on to MCP servers; it sends them a signed identity instead ([upstream-identity.md](upstream-identity.md)).

> Which of these clients have actually been run against a gateway, and how to test and report one: [client compatibility](https://docs.omp.bitop.dev/docs/use/client-compatibility).

## Tools that need your account on another service

Some tools act as you on a third-party service (GitHub, Google, …). The first time you call one, the call fails with a
link instead. Clients of the 2026-07-28 protocol that support URL elicitation get it as an `input_required` result and
retry the call themselves once you have connected; every other client gets the JSON-RPC error `-32042` (clients that
support URL elicitation show it as a prompt, others show the error message, which contains the link)
([mcp-protocol.md](mcp-protocol.md#consent-as-a-multi-round-trip-request)). Open it in your browser while signed in to the portal: it shows the tool, the
gateway, the service and each permission (scope) asked for. Choose **Continue**, approve at the service, then run the tool
again. The link works only for you, only once and for 10 minutes. Your connected accounts, and **Disconnect**, are under
Account › My connections; **My gateways** shows which tools are connected. Service accounts can't use these tools.

**MCP servers that need you to sign in to them.** Some servers, such as GitHub's hosted MCP server, are OAuth-protected
themselves: each person signs in to the server's own service (decisions 39–45, [phase7-upstream-oauth.md](phase7-upstream-oauth.md)).
It works the same way: the first call answers `-32042` with a link ("github__get_me needs you to sign in to GitHub MCP
(repo …)"), the confirm page names the server, its sign-in host (for example github.com) and each scope, and the
connection appears under Account › My connections with an "MCP server" badge and its team. If the server later asks for
more access (a 403 `insufficient_scope` within the scopes its team had reviewed) or stops accepting your token (401),
the next call answers `-32042` again; otherwise it is refused with `-32010`. You can also sign in ahead of time from
**My gateways**. The client never sees your token for that server.

Building such a server? [`examples/mail-mcp`](../examples/mail-mcp/README.md) shows a Gmail server adapted from running
its own OAuth to using the portal's delegated Google token.

## OAuth sign-in (Claude Code, VS Code, Cursor, Claude)

Add the gateway's URL **without any header**. The first time the client talks to the gateway, it gets `401` with a pointer to the gateway's sign-in metadata, opens your browser, and:

1. You sign in with your company account, if you aren't signed in already.
2. The consent page names the app, the host that vouches for it, the gateway it wants, and where your browser goes back to. Choose **Allow** (or **Deny**).
3. The browser returns to the app, which now has tokens and refreshes them by itself.

Consent is remembered **per app and gateway**: connecting the same app to another gateway asks again (decision 21). Apps your platform admins trust (Claude, Claude Code and VS Code out of the box) skip the consent page, but you still sign in.

**Claude Code**

```sh
claude mcp add --transport http support https://mcp.example.com/mcp/support
```

Then run `/mcp` in Claude Code and choose the server to sign in.

**VS Code** (`.vscode/mcp.json`, or your user configuration)

```json
{
  "servers": {
    "support": { "type": "http", "url": "https://mcp.example.com/mcp/support" }
  }
}
```

VS Code asks to sign in when it starts the server.

**Cursor** (`~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "support": { "url": "https://mcp.example.com/mcp/support" }
  }
}
```

Cursor shows a sign-in prompt for the server in its MCP settings.

**Claude (claude.ai and Claude Desktop):** add a custom connector with the gateway's URL. The portal must be reachable from the internet for claude.ai.

### What a connected app can do

- It acts as **you**, on **that gateway only**: its token is refused by every other gateway and by the management API.
- Every request checks your account (suspended people are refused), your current access to the gateway (removing you from the team or the grant stops it at the next request) and that the connection still exists.
- Access tokens last an hour; the app refreshes them for up to 30 days of inactivity, and in any case it has to sign in again about every 180 days (`OAUTH_REFRESH_ABSOLUTE_TTL`; your administrator can change it or turn it off). Connected apps shows when each app's sign-in expires. If a refresh token is ever used twice (a sign of theft), the connection is revoked and you sign in again. Scripts and agents that run without a person should use a service account or an API key instead: they don't expire the same way and don't depend on someone signing in twice a year.
- The first time you sign in an app that your administrators trust (such as Claude Code) to a gateway from this computer, the portal shows a short notice ("Your administrators trust Claude Code ... it receives the result on this computer") with **Continue** and **Cancel**. Continue it only if you just started that sign-in yourself; Cancel if you didn't. It asks once per gateway; after that the app signs in without a page, until you disconnect it. Increasing the tool ceiling asks again, even for a trusted app; changing it invalidates the old tokens and pending sign-in codes.
- **Account › Connected apps** lists your connections per gateway, with their last use, and **Disconnect** stops one at once and forgets the consent. Platform admins can disconnect anyone's apps from the person's page.

### Apps without a metadata document

Clients identify themselves either with a *Client ID Metadata Document* (an https URL their maker publishes; the consent page shows "From <host>") or, for older clients, by registering themselves (Dynamic Client Registration, which the 2026-07-28 revision deprecates but the portal keeps; it accepts `application_type` `web` or `native`). Self-registered apps are marked **Unverified** on the consent page, with "It registered itself" (and the website it claims, if any): anyone can register any name, so allow one only if you just connected it yourself, and check the host the page says your answer goes to. They are never on the trusted list, a registration that was never used expires after 24 hours and one unused for 30 days expires (the app registers again), an administrator can turn open registration off (then an app that wants to register is refused, and only apps with a metadata document, or ones registered earlier, can connect), one network address can hold only so many unused registrations (`OAUTH_MAX_UNUSED_CLIENTS_PER_ADDRESS`, default 20), the portal accepts only so many of them at once (`OAUTH_MAX_REGISTERED_CLIENTS`, default 1000; past it an app that registers itself gets a "limit of registered apps" error, so ask your administrator; apps that use a metadata document are not counted), and call logs show their calls as "via <name> (unverified)". MCP servers see `client_verified: false` with such an app's name ([upstream-identity.md](upstream-identity.md)).

If the browser shows **"Can't connect this app"**, the app's request was refused before anything was shared (if you weren't signed in, you first sign in, and the page appears afterwards), for example an unknown app, a redirect address the app never registered, or a metadata document the portal can't fetch. Nothing is sent to the app in that case. Errors after that (no PKCE, a URL that isn't one of your gateways, a gateway you can't use) go back to the app, which usually shows them.

## Personal API keys

For scripts, curl, and clients that can't open a browser. Create one under **Account › API keys** (it is shown once), optionally limited to some gateways, with an expiry of up to 365 days. Send it as a bearer token:

```sh
claude mcp add --transport http support https://mcp.example.com/mcp/support \
  --header "Authorization: Bearer omp_..."
```

```json
{
  "inputs": [{ "type": "promptString", "id": "omp-key", "description": "Open MCP Portal API key", "password": true }],
  "servers": {
    "support": { "type": "http", "url": "https://mcp.example.com/mcp/support",
                 "headers": { "Authorization": "Bearer ${input:omp-key}" } }
  }
}
```

```sh
curl -X POST https://mcp.example.com/mcp/support \
  -H "Authorization: Bearer omp_..." -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

A personal key stops working when you leave the team or are suspended, like everything that acts as you.

## Service accounts

For CI, agents and jobs owned by a **team** rather than a person. Team owners and admins manage them under **Team › Service accounts**:

- An account has a name (unique in the team), a description, a **role** of `member` or `editor` (used for tools that require a minimum team role), and can be turned off.
- It can use the **team's own gateways**, and **platform gateways granted to the team**. Grants to people or SSO groups don't cover it. The account's **Overview** lists the gateways it can use now and how many capabilities it reaches on each with its role.
- Its keys (`omp_sa_…`) are shown once, always expire (at most 365 days), and can be limited to some of the gateways it can use (platform gateways granted to the team included). An account has at most **two active keys**, so you can rotate: create the new key, deploy it, then revoke the old one.
- Turning the account off, deleting it, archiving the team, or revoking or expiring a key refuses the next request. The account doesn't depend on the person who created it.

Use its key exactly like a personal key (`Authorization: Bearer omp_sa_...`). MCP servers see `principal_type: service_account` with the account's ID and name and its team, and no email. Calls are recorded under the account's name and the key used. The team's call log (owners and admins) includes every call of the team's service accounts, through any gateway, and can be filtered by service account; platform staff can filter Admin › Calls by any team's service account.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `401` with `error="invalid_token"` | The key or token was revoked or expired, the person is suspended, the service account is off or its team archived, or an OAuth token was used on another gateway. Sign in again or use a valid key |
| `404 Gateway not found` | The gateway doesn't exist or is off, you (or the account) can't use it, or the key is limited to other gateways |
| A tool you expect is missing | It isn't selected in this gateway, its server is unavailable, or your (or the account's) team role is below the tool's minimum |
| The browser keeps asking for consent | The app isn't trusted and you disconnected it, or it connects to a different gateway (one consent per gateway) |
