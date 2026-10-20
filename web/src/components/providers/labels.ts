/*
 * Delegated credentials' words and helpers (docs/phase5-delegated-credentials.md,
 * decisions 25-30): auth providers that platform admins configure, the
 * requirements a server's team sets on its capabilities ("Needs GitHub
 * (repo)"), and the accounts a person connects. The portal sends the
 * person's token to the server; the client and the model never see it, and
 * neither does this app: tokens and client secrets are never returned.
 */
import type { Schemas } from "../../api/client";

export type AuthProvider = Schemas["AuthProvider"];
export type AuthProviderSummary = Schemas["AuthProviderSummary"];
export type AuthProviderPreset = Schemas["AuthProviderPreset"];
export type PresetName = Schemas["AuthProviderPresetName"];
export type TokenAuthMethod = Schemas["AuthProviderTokenAuthMethod"];
export type TokenResponseFormat = Schemas["AuthProviderTokenResponseFormat"];
export type ProviderConnection = Schemas["ProviderConnection"];
export type ConnectionStatus = Schemas["ProviderConnectionStatus"];
export type CapabilityRequirement = Schemas["CapabilityRequirement"];
export type ServerRequirement = Schemas["McpServerRequirement"];
export type RequirementOverride = Schemas["CapabilityRequirementOverride"];
export type ConnectRequest = Schemas["ConnectRequest"];
export type ProviderRef = Schemas["ProviderRef"];
export type ConnectServer = Schemas["ConnectServer"];
export type ProviderServerGrant = Schemas["ProviderServerGrant"];
export type AuthProviderAccess = Schemas["AuthProviderAccess"];
export type AccessMode = Schemas["AuthProviderAccessMode"];

export const accessModeLabels: Record<AccessMode, string> = { open: "Open to every team", restricted: "Restricted" };

/** What a provider's access list says in one line (the list and the overview). */
export const accessSummary = (p: Pick<AuthProvider, "accessMode">) =>
  p.accessMode === "open" ? "Any team's server may require it" : "Only the listed teams and servers may require it";

/** Said wherever a connection's token is described: whether a server gets only what its call needs (decision 69). */
export const narrowingText = (c: Pick<ProviderConnection, "narrowsScopes">) =>
  c.narrowsScopes ? "Each call gets a token for only the scopes it needs" : "Servers get a token with every scope granted";

/** "Status (Platform tools)": the server a person is asked to allow, with its team (F-3, decision 60). */
export const serverWithTeam = (s: Pick<ConnectServer, "name" | "teamName">) => `${s.name} (${s.teamName})`;

/** Where connecting from Account › My connections comes back to: the page, saying which provider was connected. */
export const connectedReturnTo = (providerSlug: string) => `/settings/connections?connected=${encodeURIComponent(providerSlug)}`;

/** An MCP server's own sign-in (docs/phase7-upstream-oauth.md): a server-bound provider, named after its server. */
export const isServerSignIn = (p: Pick<ProviderRef, "kind">) => p.kind === "mcp_server";

/** What a connection is to: the server's name for a server sign-in, else the provider's. */
export const connectionName = (p: Pick<ProviderRef, "kind" | "name" | "server">) => (isServerSignIn(p) ? (p.server?.name ?? p.name) : p.name);

export const presetLabels: Record<PresetName, string> = {
  github: "GitHub",
  google: "Google",
  microsoft: "Microsoft Entra ID",
  atlassian: "Atlassian",
  slack: "Slack",
  gitlab: "GitLab",
};

export const tokenAuthMethodLabels: Record<TokenAuthMethod, string> = {
  client_secret_post: "Client secret in the request body (client_secret_post)",
  client_secret_basic: "Client secret in a Basic header (client_secret_basic)",
  none: "None: a public client (needs PKCE)",
};

export const tokenResponseFormatLabels: Record<TokenResponseFormat, string> = {
  standard: "Standard OAuth 2.0",
  slack_authed_user: "Slack user token (authed_user)",
};

export const connectionStatusLabels: Record<ConnectionStatus, string> = { active: "Active", needs_reconsent: "Needs reconnecting" };
export const connectionStatusTone = { active: "success", needs_reconsent: "warning" } as const;

/** "repo, read:org", or the fallback when there are none. */
export const scopesText = (scopes: string[], none = "None") => (scopes.length ? scopes.join(", ") : none);

/** "Needs GitHub (repo)": the account a capability needs, with its scopes; "Needs sign-in to GitHub MCP" for a server's own sign-in. */
export function needsText(r: Pick<CapabilityRequirement, "providerName" | "scopes" | "providerKind">) {
  if (r.providerKind === "mcp_server") return `Needs sign-in to ${r.providerName}`;
  return r.scopes.length ? `Needs ${r.providerName} (${r.scopes.join(", ")})` : `Needs ${r.providerName}`;
}

/** What requiring a connection means, said the same way in a server's Settings and its Capabilities tab. */
export const requirementHelp =
  "Each person who calls these capabilities connects their own account with the provider once, in their browser. The portal then sends their token to this server with each call that needs it, and refreshes it. Clients, models and service accounts never get it.";

/** Service accounts can't call capabilities that need a person's account (decision 29). */
export const serviceAccountsCant = "Service accounts can't use capabilities that need a person's account.";

/** A scope list typed by a person: trimmed, spaces split, no duplicates (scopes keep their case). */
export const normalizeScope = (tag: string) => tag.trim();

/** The contract's scope characters: RFC 6749 (printable ASCII, no space, quote or backslash). */
const scopePattern = /^[!#-\[\]-~]+$/;

/** What's wrong with a scope list, before it's sent (the server answers 400 invalid_scope otherwise). */
export function scopesProblem(scopes: string[]): string | undefined {
  const bad = scopes.find((s) => !scopePattern.test(s) || s.length > 200);
  if (bad) return `“${bad}” isn't a scope the portal accepts: use the provider's scope names, without spaces or quotes.`;
  if (scopes.length > 50) return "Use at most 50 scopes.";
  return undefined;
}

/** The server's refusal of a scope (400 invalid_scope, details.scope), in words. */
export function invalidScopeText(details: Record<string, unknown> | undefined) {
  const scope = typeof details?.scope === "string" ? details.scope : "";
  return scope ? `“${scope}” isn't a scope the portal accepts: use the provider's scope names, without spaces or quotes.` : "One of the scopes isn't accepted: use the provider's scope names, without spaces or quotes.";
}

/** Leaves the app for the provider (a seam for tests). */
export const redirectTo = { go: (url: string) => window.location.assign(url) };

/** Only an http(s) address the browser can be sent to (the server builds it from stored settings; anything else is refused here too). */
export function safeAuthorizeUrl(url: string): string | undefined {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.href : undefined;
  } catch {
    return undefined;
  }
}

/** The redirect URI every provider's OAuth app registers (the callback is a server route). */
export const callbackPath = "/connect/callback";
