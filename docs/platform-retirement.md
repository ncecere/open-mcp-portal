# External agent-platform retirement (#68)

Open MCP Portal is an MCP portal, not an external agent-platform impersonation service. The owner withdrew Pi Durable Platform integration. This breaking retirement replaces #62 and #63, which were closed **NOTPLANNED**, not completed fixes. Older releases retain their previously documented exposure until upgraded; no external signer agreement or live platform verification is needed to retire the feature.

The **pi coding client remains supported** as an ordinary MCP client. It is not Pi Durable Platform.

## What changes

Removed: trusted-platform administration and JWKS fetching, external JWT verification and replay acceptance, relay assignments and person impersonation, platform-attested presence settings, `allowAgents` person-secret behavior, and `omp_agent_token_total`. The platform administration and capability `present-person` API operations and UI controls no longer exist. Removed request fields are rejected rather than silently accepted.

Kept: MCP OAuth, personal API keys, ordinary service accounts and key/tool scopes; provider consent and My connections' allow-server APIs; team/shared service connections; person-secret mode; machine OAuth and TLS; tool classification and publishing/security-review gates. Ordinary MCP clients can still request normal browser consent. Service accounts do not become people or use anyone's personal secrets.

## Upgrade safely

1. Identify callers using marked relay accounts. They will stop working, including requests with **no identity header**. Arrange explicit replacements: a person connects through normal MCP OAuth or uses their personal key; a machine gets a **new ordinary service account and new key**, with deliberately reviewed grants and scopes. Never clear a legacy mark to reuse its authority.
2. Apply migration `00034_retire_agent_platforms.sql` with the trusted migration owner. It disables enabled external issuers, disables every marked relay account, and revokes all of their still-unrevoked keys. Marks, original schema, rows, call attribution and audit history remain. A system audit entry records affected counts and IDs, never tokens or digests.
3. Roll out the new application to every replica. Database fences prevent old replicas from enabling issuer trust, assigning new relays, changing or clearing existing marks, enabling retired accounts, or issuing/unrevoking active keys for them. Ordinary null-mark accounts continue operating. In-flight work authorized before migration can finish; drain old replicas for a clean cutover. The new authenticator independently refuses a marked account even if its enabled flag says otherwise.
4. Confirm ordinary MCP sign-in, ordinary service accounts, provider connections and required outbound identity still work. Legacy accounts display **Retired**, read-only; create-key and enable/update operations refuse them with `service_account_retired`. Existing keys may be viewed or revoked; historical Calls and Audit remain readable.

The migration is **forward-only**: its Down does not restore trust or credentials. Do not roll back to code that accepts external identity. Restoring a pre-retirement backup also restores the old exposure. Database owners remain trusted and can remove database protections; ordinary application replicas cannot.

## Inbound and outbound identity are different

A supplied inbound `MCP-Gateway-Identity` header at `/mcp/{slug}` is explicitly refused with HTTP 403 **before authentication, protocol parsing or upstream transport**, in both MCP eras and for every HTTP/RPC method. Empty, malformed or formerly valid tokens all fail. The header value is never echoed. Removing the header is not enough for a retired relay key: that key is also refused.

The portal's **outbound** signed identity remains supported, with its normal JWKS, rotation, `sendIdentity` and `tool_class`. When an upstream owns `Authorization`, identity still travels in `MCP-Gateway-Identity`; otherwise it uses `Authorization: Bearer`. New tokens have no `act` claim. Historical attribution is not new authority.

For nested portals, disable **Send identity** (`sendIdentity: false`) on the upstream portal's server registration for the downstream portal when it would send `MCP-Gateway-Identity`. The downstream portal does not consume another portal's signed identity as delegation. Configure a normal downstream MCP credential explicitly instead.

## Verification boundary

Retirement tests exercise pre-upgrade rows, key revocation, old-replica SQL fences, ordinary authentication, removed contracts and fields, inbound rejection and outbound signing. Historical migrations are unchanged. Old-schema downgrade tests remove fences only through privileged setup inside disposable test databases; production retirement policy is not weakened for those fixtures. Legacy and authenticated split-role tests must run on disposable PostgreSQL, never by changing development-cluster roles or data.
