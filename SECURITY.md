# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately**. Don't open a public issue, pull request or discussion.

Use GitHub's private vulnerability reporting: **[Report a vulnerability](https://github.com/ncecere/open-mcp-portal/security/advisories/new)** on the repository's Security tab. Only the maintainers see the report, and we work on the fix with you in a private advisory.

Include:
- the affected version or commit;
- what an attacker can do, and what they need first (an account, a team or platform role, an API key, service account key or OAuth client, control of an MCP server, network position);
- steps or a proof of concept to reproduce it;
- any suggested fix.

Open MCP Portal has one maintainer. We aim to reply within 5 business days and to agree a disclosure date with you once we understand the problem. We credit reporters in the fix's release notes unless you'd rather we didn't. Please give us reasonable time to fix the problem before you disclose it. Don't access or change data that isn't yours while testing, and don't send traffic to MCP servers or third-party services through an installation you don't operate.

## Supported versions

Open MCP Portal is pre-1.0 development software. Security fixes are made on `main` and released as a patch of the latest minor release only.

| Version | Supported |
|---|---|
| `main` and the latest release (v0.8.0) | Yes |

## Scope

In scope: the code in this repository, including
- the `open-mcp-portal` binary (management API, MCP endpoint `/mcp/{slug}`, OAuth authorization server, background loops, migrations and CLI) and its default configuration;
- the web UI in `web/`;
- the container image built from the `Dockerfile`;
- the Kubernetes base and example overlay in `deploy/kubernetes/`.

Areas we care most about:
- **gateway access:** calling a capability that isn't selected in a gateway, a gateway the caller isn't granted, or one of an archived team or a disabled server; a key limited to some gateways reaching others;
- **credentials:** API keys, service account keys, OAuth tokens or codes that keep working after revocation or expiry, are stored in plain text, or reach an MCP server, the logs, the audit log, the call log or captured payloads;
- **the OAuth authorization server:** PKCE, redirect URI and resource checks, consent, client metadata documents and dynamic registration, refresh token rotation;
- **the identity token:** forging or replaying the JWT sent to MCP servers, or a server receiving another person's identity;
- **delegated credentials and upstream OAuth:** one person's provider token sent for another person, to a server that doesn't require it, or to the client; consent links used by someone else;
- **SSRF:** reaching loopback, link-local, metadata or internal addresses that aren't allowed, through server URLs, auth provider endpoints, client metadata documents or redirects;
- **team isolation and roles:** a team member reading or changing another team's servers, gateways, service accounts, calls or settings, or gaining a platform role;
- **audit and payload capture:** changing append-only records, captured payloads without redaction, or reading them without the role and audit entry;
- browser sessions, CSRF and Origin checks.

Out of scope:
- a specific installation's infrastructure, identity provider, MCP servers or configuration choices (report those to the installation's operator);
- the development sign-in, the demo (`compose.demo.yaml`), the fake servers in `cmd/` and the development credentials in `compose.yaml` and `.env.example`, all refused off a loopback `APP_URL`;
- what an MCP server does with a call it was allowed to receive, and prompt injection through tool results;
- denial of service by volume alone, and findings that need a compromised host, database owner role or `ENCRYPTION_KEY`;
- vulnerabilities in dependencies with no demonstrated impact on this project (report them upstream).

Operators: see [deploying](docs/deploy.md) for configuration, secrets, network policies and key rotation, and [verifying the identity token](docs/upstream-identity.md) for what MCP servers should check.
