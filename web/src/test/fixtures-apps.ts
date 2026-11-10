/* Fixtures for OAuth sign-in (consent, connected apps, trusted clients) and service accounts. */
import type { Schemas } from "../api/client";
import { team } from "./fixtures-core";
import { gatewayId, myGateway } from "./fixtures-gateways";

export const oauthClient = (extra: Partial<Schemas["OAuthClientInfo"]> = {}): Schemas["OAuthClientInfo"] => ({
  id: "https://claude.ai/oauth/claude-code-client-metadata",
  kind: "metadata",
  name: "Claude Code",
  host: "claude.ai",
  uri: "https://claude.ai",
  logoUrl: null,
  trusted: false,
  ...extra,
});

/** A client that registered itself (dynamic registration): its name is its own claim. */
export const registeredClient = (extra: Partial<Schemas["OAuthClientInfo"]> = {}): Schemas["OAuthClientInfo"] =>
  oauthClient({ id: "ompcl_3f9a1c", kind: "registered", name: "Handy MCP Helper", host: "helper.example.net", uri: "https://helper.example.net", ...extra });

export const oauthConsent = (extra: Partial<Schemas["OAuthConsent"]> = {}): Schemas["OAuthConsent"] => ({
  client: oauthClient(),
  gateway: myGateway({ capabilityCount: 3 }),
  redirectUri: "http://127.0.0.1:53211/callback",
  redirectHost: "127.0.0.1:53211",
  remembered: false,
  notice: false,
  ...extra,
});

export const oauthGrant = (extra: Partial<Schemas["OAuthGrant"]> = {}): Schemas["OAuthGrant"] => ({
  id: "14141414-1414-4141-8141-141414141414",
  client: oauthClient(),
  gateway: { id: gatewayId, slug: "support-tools", name: "Support tools", exists: true },
  createdAt: "2026-10-10T10:00:00Z",
  lastUsedAt: "2026-10-16T07:00:00Z",
  expiresAt: "2027-04-08T10:00:00Z",
  ...extra,
});

export const trustedClients = (extra: Partial<Schemas["TrustedClients"]> = {}): Schemas["TrustedClients"] => ({
  clients: [
    { clientId: "https://claude.ai/oauth/claude-code-client-metadata", label: "Claude Code" },
    { clientId: "https://vscode.dev/oauth/client-metadata.json", label: "VS Code" },
  ],
  openRegistration: true,
  revision: 2,
  updatedAt: "2026-10-15T10:00:00Z",
  ...extra,
});

export const serviceAccountId = "15151515-1515-4151-8151-151515151515";

export const serviceAccount = (extra: Partial<Schemas["ServiceAccount"]> = {}): Schemas["ServiceAccount"] => ({
  id: serviceAccountId,
  teamId: team.id,
  teamSlug: team.slug,
  name: "ci-release-bot",
  description: "Runs the release workflow's smoke checks.",
  role: "member",
  enabled: true,
  activeKeyCount: 1,
  lastUsedAt: "2026-10-16T06:00:00Z",
  createdByName: "Una User",
  revision: 5,
  createdAt: "2026-10-01T10:00:00Z",
  updatedAt: "2026-10-12T10:00:00Z",
  ...extra,
});

export const serviceAccountKey = (extra: Partial<Schemas["ServiceAccountKey"]> = {}): Schemas["ServiceAccountKey"] => ({
  id: "16161616-1616-4161-8161-161616161616",
  name: "GitHub Actions",
  prefix: "omp_sa_ab12cd34",
  status: "active",
  createdAt: "2026-10-01T10:00:00Z",
  createdByName: "Una User",
  expiresAt: "2026-12-30T10:00:00Z",
  lastUsedAt: "2026-10-16T06:00:00Z",
  revokedAt: null,
  gateways: [],
  ...extra,
});
