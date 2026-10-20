/* Phase 7 fixtures (OAuth to MCP servers: detection, server sign-in, server-bound connections), typed from the generated contract. */
import type { Schemas } from "../api/client";
import { mcpServer, serverId, team, user } from "./fixtures";
import { connection, providerRef, requires } from "./fixtures-providers";

export const githubUrl = "https://api.githubcopilot.com/mcp/";
export const serverProviderId = "21212121-2121-4212-8212-212121212121";
const githubScopes = ["repo", "read:org", "read:user", "user:email", "gist", "notifications", "project", "workflow", "admin:org", "codespace"];

/** What GitHub's remote server answers: OAuth at github.com/login/oauth, no automatic registration. */
export const detectResult = (extra: Partial<Schemas["DetectAuthResult"]> = {}): Schemas["DetectAuthResult"] => ({
  url: githubUrl,
  outcome: "oauth",
  httpStatus: 401,
  challenge: { scheme: "Bearer", resourceMetadataUrl: "https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/", scope: [], error: null },
  resourceMetadata: {
    url: "https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/",
    resource: githubUrl,
    resourceName: "GitHub MCP Server",
    authorizationServers: ["https://github.com/login/oauth"],
    scopesSupported: githubScopes,
    bearerMethodsSupported: ["header"],
  },
  suggestedUrl: null,
  authorizationServer: {
    issuer: "https://github.com/login/oauth",
    metadataUrl: "https://github.com/.well-known/oauth-authorization-server/login/oauth",
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    revocationEndpoint: null,
    registrationEndpoint: null,
    scopesSupported: githubScopes,
    codeChallengeMethodsSupported: ["S256"],
    tokenEndpointAuthMethodsSupported: ["client_secret_post", "client_secret_basic"],
    grantTypesSupported: ["authorization_code", "refresh_token"],
    issParameterSupported: true,
    clientIdMetadataDocumentSupported: false,
  },
  registration: {
    options: ["manual"],
    recommended: "manual",
    cimdUnavailableReason: "not_supported",
    matchingProviders: [],
    redirectUri: "https://mcp.example.com/connect/callback",
    clientMetadataUrl: "https://mcp.example.com/oauth/upstream-client-metadata.json",
  },
  suggestedScopes: githubScopes,
  problems: [{ code: "no_registration", blocking: false, message: "The authorization server offers no automatic registration: enter a client." }],
  steps: [
    { purpose: "mcp", url: githubUrl, httpStatus: 401, result: "challenge", latencyMs: 80 },
    { purpose: "resource_metadata", url: "https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/", httpStatus: 200, result: "ok", latencyMs: 40 },
    { purpose: "authorization_server_metadata", url: "https://github.com/.well-known/oauth-authorization-server/login/oauth", httpStatus: 200, result: "ok", latencyMs: 60 },
  ],
  ...extra,
});

/** An internal server with dynamic client registration. */
export const detectDcr = (): Schemas["DetectAuthResult"] => {
  const base = detectResult();
  return detectResult({
    url: "https://wiki.example.com/mcp",
    resourceMetadata: { ...base.resourceMetadata!, resource: "https://wiki.example.com/mcp", authorizationServers: ["https://sso.example.com"], scopesSupported: ["wiki.read", "wiki.write"] },
    authorizationServer: { ...base.authorizationServer!, issuer: "https://sso.example.com", registrationEndpoint: "https://sso.example.com/register", scopesSupported: ["wiki.read", "wiki.write"] },
    challenge: { ...base.challenge!, scope: ["wiki.read"] },
    registration: { ...base.registration!, options: ["dcr", "manual"], recommended: "dcr" },
    suggestedScopes: ["wiki.read"],
    problems: [],
  });
};

export const setupConnection = (extra: Partial<Schemas["McpServerOAuthSetupConnection"]> = {}): Schemas["McpServerOAuthSetupConnection"] => ({
  status: "active",
  personId: user().id,
  personName: "Ana Editor",
  authorizedAt: "2026-10-16T07:00:00Z",
  ...extra,
});

export const oauthConfig = (extra: Partial<Schemas["McpServerOAuth"]> = {}): Schemas["McpServerOAuth"] => ({
  providerId: serverProviderId,
  providerSlug: "mcp-0a1b2c3d4e5f",
  resource: githubUrl,
  resourceMetadataUrl: "https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/",
  authorizationServer: "https://github.com/login/oauth",
  issuer: "https://github.com/login/oauth",
  authorizationEndpoint: "https://github.com/login/oauth/authorize",
  tokenEndpoint: "https://github.com/login/oauth/access_token",
  revocationEndpoint: null,
  scopes: ["repo", "read:org", "read:user"],
  scopesSupported: githubScopes,
  registration: "manual",
  clientIdHint: "c0ffee",
  hasClientSecret: true,
  clientSecretExpiresAt: null,
  tokenAuthMethod: "client_secret_post",
  sendResource: true,
  issParameterSupported: true,
  platformProvider: null,
  setupConnection: setupConnection(),
  connectionCount: 12,
  discoveredAt: "2026-10-16T06:55:00Z",
  ...extra,
});

/** GitHub's remote MCP server, registered in oauth mode. */
export const oauthServer = (extra: Partial<Schemas["McpServer"]> = {}, oauth: Partial<Schemas["McpServerOAuth"]> = {}): Schemas["McpServer"] =>
  mcpServer({
    slug: "github",
    name: "GitHub MCP",
    description: "GitHub's hosted MCP server.",
    url: githubUrl,
    authHeaderName: undefined,
    hasAuth: false,
    authValueHint: "",
    credentials: [],
    authMode: "oauth",
    oauth: oauthConfig(oauth),
    sendIdentity: false,
    health: { status: "healthy", checkedAt: "2026-10-16T07:55:00Z", statusSince: "2026-10-15T08:00:00Z", latencyMs: 90, signInRequired: true },
    ...extra,
  });

/** A person's sign-in to an MCP server (server-bound provider, named after the server). */
export const serverConnection = (extra: Partial<Schemas["ProviderConnection"]> = {}): Schemas["ProviderConnection"] =>
  connection({
    id: "c-server",
    provider: providerRef({ id: serverProviderId, slug: "mcp-0a1b2c3d4e5f", name: "GitHub MCP", preset: null, kind: "mcp_server", server: { id: serverId, slug: "github", name: "GitHub MCP", teamSlug: team.slug } }),
    accountLabel: null,
    scopes: ["repo", "read:org", "read:user"],
    ...extra,
  });

/** What a capability of an oauth server needs: a sign-in to the server itself. */
export const serverRequires = (extra: Partial<Schemas["CapabilityRequirement"]> = {}): Schemas["CapabilityRequirement"] =>
  requires({ providerId: serverProviderId, providerSlug: "mcp-0a1b2c3d4e5f", providerName: "GitHub MCP", scopes: ["repo", "read:org", "read:user"], providerKind: "mcp_server", ...extra });
