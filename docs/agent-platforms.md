# External agent platforms: retired

Pi Durable Platform trust and person impersonation have been removed by the owner's decision in #68. This is not the pi coding client: ordinary MCP clients, including pi, remain supported through normal MCP OAuth or API keys.

See [Platform retirement and upgrade](platform-retirement.md) for the breaking migration, permanently retired relay accounts, old-replica database fences, inbound identity rejection and explicit replacement credentials. The portal's own outbound signed identity and JWKS remain supported; new tokens have no `act` claim.

Issues #62 and #63 were closed NOTPLANNED and replaced by #68, not fixed in older releases. Historical release notes and call/audit attribution describe the previous behavior and remain readable. Do not follow old setup instructions or clear a relay mark to turn it into an ordinary account.
