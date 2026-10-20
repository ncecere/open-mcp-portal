/* Phase 5 fixtures (auth providers, requirements, connections, connect requests), typed from the generated contract. */
import type { Schemas } from "../api/client";
import { gatewayId } from "./fixtures";

export const providerId = "18181818-1818-4181-8181-181818181818";
export const googleId = "19191919-1919-4191-8191-191919191919";
export const connectionId = "20202020-2020-4202-8202-202020202020";
/** A consent link's opaque request ID (43 base64url characters). */
export const requestId = "Zk3aB9cD0eF1gH2iJ3kL4mN5oP6qR7sT8uV9wX0yZ1a";

export const providerSummary = (extra: Partial<Schemas["AuthProviderSummary"]> = {}): Schemas["AuthProviderSummary"] => ({
  id: providerId,
  slug: "github",
  name: "GitHub",
  kind: "oauth2",
  preset: "github",
  defaultScopes: ["repo"],
  logoUrl: null,
  ...extra,
});

export const providerSummaries: Schemas["AuthProviderSummary"][] = [
  providerSummary(),
  providerSummary({ id: googleId, slug: "google", name: "Google", preset: "google", defaultScopes: ["openid", "email"] }),
];

export const authProvider = (extra: Partial<Schemas["AuthProvider"]> = {}): Schemas["AuthProvider"] => ({
  id: providerId,
  slug: "github",
  name: "GitHub",
  kind: "oauth2",
  preset: "github",
  enabled: true,
  clientId: "Iv1.abc123",
  hasClientSecret: true,
  clientSecretHint: "9f2e",
  tokenAuthMethod: "client_secret_post",
  pkce: true,
  authorizationUrl: "https://github.com/login/oauth/authorize",
  tokenUrl: "https://github.com/login/oauth/access_token",
  revocationUrl: null,
  userinfoUrl: "https://api.github.com/user",
  defaultScopes: ["repo"],
  scopeParam: "scope",
  scopeSeparator: " ",
  tokenResponseFormat: "standard",
  extraAuthorizeParams: {},
  logoUrl: null,
  redirectUri: "https://mcp.example.com/connect/callback",
  serverCount: 1,
  connectionCount: 3,
  accessMode: "open",
  narrowOnRefresh: false,
  revision: 2,
  createdAt: "2026-10-14T10:00:00Z",
  updatedAt: "2026-10-15T10:00:00Z",
  createdByName: "Ada Admin",
  ...extra,
});

export const preset = (extra: Partial<Schemas["AuthProviderPreset"]> = {}): Schemas["AuthProviderPreset"] => ({
  preset: "github",
  name: "GitHub",
  authorizationUrl: "https://github.com/login/oauth/authorize",
  tokenUrl: "https://github.com/login/oauth/access_token",
  revocationUrl: null,
  userinfoUrl: "https://api.github.com/user",
  defaultScopes: ["repo"],
  tokenAuthMethod: "client_secret_post",
  pkce: true,
  scopeParam: "scope",
  scopeSeparator: " ",
  tokenResponseFormat: "standard",
  extraAuthorizeParams: {},
  urlParameters: [],
  docsUrl: "https://github.com/settings/developers",
  notes: "OAuth-app tokens don't expire.",
  narrowOnRefresh: false,
  ...extra,
});

export const presets: Schemas["AuthProviderPreset"][] = [
  preset(),
  preset({
    preset: "microsoft",
    name: "Microsoft Entra ID",
    authorizationUrl: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
    tokenUrl: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    userinfoUrl: "https://graph.microsoft.com/oidc/userinfo",
    defaultScopes: ["openid", "offline_access", "User.Read"],
    urlParameters: [{ name: "tenant", label: "Directory (tenant) ID, or organizations", default: "organizations" }],
    docsUrl: "https://entra.microsoft.com",
    notes: "Add offline_access for refresh tokens.",
  }),
  preset({
    preset: "slack",
    name: "Slack",
    authorizationUrl: "https://slack.com/oauth/v2/authorize",
    tokenUrl: "https://slack.com/api/oauth.v2.access",
    userinfoUrl: null,
    defaultScopes: ["chat:write"],
    pkce: false,
    scopeParam: "user_scope",
    scopeSeparator: ",",
    tokenResponseFormat: "slack_authed_user",
    docsUrl: "https://api.slack.com/apps",
    notes: "User tokens use user_scope.",
  }),
];

export const serverRequirement = (extra: Partial<Schemas["McpServerRequirement"]> = {}): Schemas["McpServerRequirement"] => ({
  providerId,
  providerSlug: "github",
  providerName: "GitHub",
  providerEnabled: true,
  scopes: ["repo"],
  ...extra,
});

export const requires = (extra: Partial<Schemas["CapabilityRequirement"]> = {}): Schemas["CapabilityRequirement"] => ({
  providerId,
  providerSlug: "github",
  providerName: "GitHub",
  scopes: ["repo"],
  ...extra,
});

export const providerRef = (extra: Partial<Schemas["ProviderRef"]> = {}): Schemas["ProviderRef"] => ({ id: providerId, slug: "github", name: "GitHub", preset: "github", logoUrl: null, ...extra });

export const connectServer = (extra: Partial<Schemas["ConnectServer"]> = {}): Schemas["ConnectServer"] => ({
  id: "30303030-3030-4303-8303-303030303030",
  slug: "github-tools",
  name: "GitHub tools",
  teamSlug: "platform",
  teamName: "Platform tools",
  ...extra,
});

export const connection = (extra: Partial<Schemas["ProviderConnection"]> = {}): Schemas["ProviderConnection"] => ({
  id: connectionId,
  provider: providerRef(),
  accountLabel: "octocat",
  scopes: ["repo", "read:org"],
  status: "active",
  connectedAt: "2026-10-15T09:00:00Z",
  refreshedAt: null,
  lastUsedAt: "2026-10-16T07:00:00Z",
  expiresAt: null,
  refreshable: false,
  narrowsScopes: false,
  allowedServers: [],
  ...extra,
});

/** A provider's access list (decision 69): restricted to one team and one server, one server blocked. */
export const providerAccess = (extra: Partial<Schemas["AuthProviderAccess"]> = {}): Schemas["AuthProviderAccess"] => ({
  accessMode: "restricted",
  teams: [{ id: "40404040-4040-4404-8404-404040404040", slug: "platform", name: "Platform tools" }],
  servers: [connectServer({ id: "50505050-5050-4505-8505-505050505050", slug: "wiki", name: "Wiki", teamSlug: "docs", teamName: "Docs" })],
  blocked: [],
  blockedCount: 0,
  revision: 2,
  ...extra,
});

export const connectRequest = (extra: Partial<Schemas["ConnectRequest"]> = {}): Schemas["ConnectRequest"] => ({
  id: requestId,
  provider: providerRef(),
  reason: "missing_scopes",
  requiredScopes: ["repo"],
  requestScopes: ["read:org", "repo"],
  grantedScopes: ["read:org"],
  accountLabel: "octocat",
  gateway: { id: gatewayId, slug: "support-tools", name: "Support tools", exists: true },
  capability: { kind: "tool", exposedName: "github-tools__create_issue", title: "Create issue" },
  server: connectServer(),
  createdAt: "2026-10-16T07:55:00Z",
  expiresAt: "2026-10-16T08:05:00Z",
  ...extra,
});
