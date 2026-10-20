/*
 * How the portal authenticates to an MCP server (decisions 39-45,
 * docs/phase7-upstream-oauth.md): none, one static header, or each person's
 * own OAuth sign-in to the server. The words, the form as edited (Add and
 * Settings), what a save sends, and when a save sends a published server
 * back to review or signs everyone out. The rules mirror the server's
 * (api/openapi.yaml); the server still decides, and it runs the discovery
 * again itself on every save.
 */
import type { Schemas } from "../../api/client";
import { scopesProblem, type TokenAuthMethod } from "../providers/labels";
import { type McpServer, urlHost } from "./labels";

export type AuthMode = Schemas["McpServerAuthMode"];
export type DetectResult = Schemas["DetectAuthResult"];
export type DetectProblem = Schemas["DetectAuthProblem"];
export type Registration = Schemas["McpServerOAuthRegistration"];
export type OAuthConfig = Schemas["McpServerOAuth"];
export type SetupConnection = Schemas["McpServerOAuthSetupConnection"];

export const authModeLabels: Record<AuthMode, string> = {
  none: "None",
  static_header: "Static header",
  oauth: "Sign-in with OAuth, per person",
};

export const authModeHelp: Record<AuthMode, string> = {
  none: "No credential of its own: calls carry the portal's signed identity token, unless you turn that off below.",
  static_header: "One header with a fixed value, such as an API key, sent with every request.",
  oauth: "Each person signs in to the server's own service once; every call carries their own token. Clients and models never see it.",
};

export const registrationLabels: Record<Registration, string> = {
  cimd: "Automatic (Client ID Metadata Document)",
  dcr: "Automatic (dynamic client registration)",
  manual: "A client ID and secret the team entered",
  platform_provider: "A platform auth provider's client",
};

/** The server's mode; servers saved before Phase 7 have none, so it follows the header. */
export const authModeOf = (s: Pick<McpServer, "authMode" | "hasAuth">): AuthMode => s.authMode ?? (s.hasAuth ? "static_header" : "none");

/** Whether the server receives the signed identity token (decision 45; absent before Phase 7: on). */
export const sendsIdentity = (s: Pick<McpServer, "sendIdentity">) => s.sendIdentity ?? true;

/** "Ana", "Ana · needs sign-in again", or "Nobody yet". */
export function readAsText(c: SetupConnection) {
  const who = c.personName ?? "Someone no longer here";
  if (c.status === "active") return who;
  if (c.status === "needs_reconsent") return `${who} · needs sign-in again`;
  return "Nobody yet";
}

/** The authorization server's host when it differs from the server's (shown to reviewers), else undefined. */
export function otherHost(authorizationServer: string, serverUrl: string) {
  const as = urlHost(authorizationServer).toLowerCase();
  return as && as !== urlHost(serverUrl).toLowerCase() ? as : undefined;
}

/** The scopes the server says it supports: the resource metadata's, else the authorization server's. */
export function supportedScopes(r: DetectResult | undefined): string[] {
  if (!r) return [];
  const own = r.resourceMetadata?.scopesSupported ?? [];
  return own.length ? own : (r.authorizationServer?.scopesSupported ?? []);
}

/** GitHub's own sign-in (its remote MCP server): the spec's default would ask for every scope it lists. */
const isGitHub = (r: DetectResult) => urlHost(r.authorizationServer?.issuer ?? "").toLowerCase() === "github.com";
export const gitHubScopes = ["repo", "read:org", "read:user"];

/** The scopes ticked after a detection: GitHub's usual three, else the challenge's, else what the server suggests. */
export function preselectScopes(r: DetectResult): string[] {
  const supported = supportedScopes(r);
  if (isGitHub(r)) return supported.length ? gitHubScopes.filter((s) => supported.includes(s)) : gitHubScopes;
  return r.challenge?.scope.length ? r.challenge.scope : r.suggestedScopes;
}

/** The detection can't be used for OAuth sign-in: not an OAuth challenge, or a blocking problem. */
export const blockingProblems = (r: DetectResult) => r.problems.filter((p) => p.blocking);
export const oauthUsable = (r: DetectResult | undefined) => Boolean(r && r.outcome === "oauth" && r.registration && blockingProblems(r).length === 0);

/** A registration as chosen in the form: a kind, or a platform provider ("platform_provider:<id>"). */
export type RegistrationChoice = Exclude<Registration, "platform_provider"> | `platform_provider:${string}`;

export const choiceOf = (registration: Registration, providerId?: string | null): RegistrationChoice =>
  registration === "platform_provider" ? `platform_provider:${providerId ?? ""}` : registration;

export function splitChoice(c: RegistrationChoice): { registration: Registration; platformProviderId?: string } {
  return c.startsWith("platform_provider:") ? { registration: "platform_provider", platformProviderId: c.slice("platform_provider:".length) } : { registration: c as Registration };
}

/** The OAuth settings as edited. clientId empty keeps the stored one (edits); the secret is kept apart (replace-only). */
export type OAuthForm = { registration: RegistrationChoice; clientId: string; tokenAuthMethod: TokenAuthMethod; scopes: string[]; sendResource: boolean; authorizationServer: string };

/** How the portal authenticates, as edited: the mode, the OAuth settings and the identity switch. */
export type UpstreamForm = { mode: AuthMode; oauth: OAuthForm; sendIdentity: boolean };

const blankOAuth: OAuthForm = { registration: "manual", clientId: "", tokenAuthMethod: "client_secret_post", scopes: [], sendResource: true, authorizationServer: "" };

export function upstreamFormOf(s?: McpServer): UpstreamForm {
  const o = s?.oauth;
  return {
    mode: s ? authModeOf(s) : "none",
    oauth: o
      ? { registration: choiceOf(o.registration, o.platformProvider?.id), clientId: "", tokenAuthMethod: o.tokenAuthMethod, scopes: o.scopes, sendResource: o.sendResource, authorizationServer: o.authorizationServer }
      : blankOAuth,
    sendIdentity: s ? sendsIdentity(s) : true,
  };
}

/** The token method a manual client starts with: client_secret_post when listed (or nothing is), else the first listed. */
function manualMethod(r: DetectResult): TokenAuthMethod {
  const listed = (r.authorizationServer?.tokenEndpointAuthMethodsSupported ?? []).filter((m): m is TokenAuthMethod => ["client_secret_post", "client_secret_basic", "none"].includes(m));
  return listed.includes("client_secret_post") ? "client_secret_post" : (listed[0] ?? "client_secret_post");
}

/**
 * The OAuth settings after a detection: the recommended registration (a matching platform provider rather than a
 * client typed by hand), the preselected scopes, the resource parameter on, and the first authorization server.
 */
export function oauthFromDetection(r: DetectResult, before: OAuthForm): OAuthForm {
  const reg = r.registration;
  const provider = reg?.matchingProviders[0];
  const registration: RegistrationChoice = !reg ? "manual" : reg.recommended === "manual" && provider ? choiceOf("platform_provider", provider.id) : choiceOf(reg.recommended, provider?.id);
  return { ...before, registration, tokenAuthMethod: manualMethod(r), scopes: preselectScopes(r), sendResource: true, authorizationServer: r.resourceMetadata?.authorizationServers[0] ?? "" };
}

/** The mode a detection suggests. */
export function modeFromDetection(r: DetectResult, current: AuthMode): AuthMode {
  if (oauthUsable(r)) return "oauth";
  if (r.outcome === "no_auth") return "none";
  if (r.outcome === "other_auth") return "static_header";
  return current === "oauth" ? "none" : current;
}

/**
 * The form after a detection: the suggested mode and, for OAuth, the suggested settings. A server that's in oauth
 * mode already keeps its settings (a detection only shows what the server offers now).
 */
export function applyDetection(u: UpstreamForm, r: DetectResult, stored?: OAuthConfig | null): UpstreamForm {
  if (stored && u.mode === "oauth" && oauthUsable(r)) return u;
  const mode = modeFromDetection(r, u.mode);
  return { ...u, mode, oauth: mode === "oauth" ? oauthFromDetection(r, u.oauth) : u.oauth };
}

export type OAuthErrors = Partial<Record<"mode" | "registration" | "clientId" | "clientSecret" | "scopes", string>>;

type ProblemContext = {
  /** The server as saved (edits): a stored client ID and secret can be kept. */
  server?: McpServer;
  detected?: DetectResult;
  secret: string;
};

/** What's wrong with the OAuth settings before they're sent. */
export function oauthProblems(f: UpstreamForm, { server, detected, secret }: ProblemContext): OAuthErrors {
  if (f.mode !== "oauth") return {};
  const out: OAuthErrors = {};
  const stored = server?.oauth;
  if (!stored && !oauthUsable(detected)) out.mode = "Detect sign-in first: OAuth sign-in needs what the server says about it.";
  const { registration, platformProviderId } = splitChoice(f.oauth.registration);
  if (registration === "platform_provider" && !platformProviderId) out.registration = "Choose the platform provider whose client to use.";
  const keepsManual = stored?.registration === "manual" && registration === "manual";
  if (registration === "manual") {
    if (!f.oauth.clientId.trim() && !keepsManual) out.clientId = "Enter the client ID of the OAuth app you created at the authorization server.";
    const hasSecret = Boolean(secret) || (keepsManual && Boolean(stored?.hasClientSecret));
    if (f.oauth.tokenAuthMethod !== "none" && !hasSecret) out.clientSecret = "Enter the client secret, or choose None as the token method for a public client.";
  }
  const scopes = scopesProblem(f.oauth.scopes);
  if (scopes) out.scopes = scopes;
  return out;
}

/** The oauth input for a new configuration (Add, or switching a server to oauth). */
export function oauthInput(f: OAuthForm, secret: string, detected?: DetectResult): Schemas["McpServerOAuthInput"] {
  const { registration, platformProviderId } = splitChoice(f.registration);
  const first = detected?.resourceMetadata?.authorizationServers[0];
  return {
    registration,
    ...(registration === "platform_provider" ? { platformProviderId } : {}),
    ...(registration === "manual" ? { clientId: f.clientId.trim(), tokenAuthMethod: f.tokenAuthMethod, ...(secret ? { clientSecret: secret } : {}) } : {}),
    scopes: f.scopes,
    sendResource: f.sendResource,
    ...(f.authorizationServer && first && f.authorizationServer !== first ? { authorizationServer: f.authorizationServer } : {}),
  };
}

/**
 * The oauth input for a server that's in oauth mode already: only what changed (a client ID or secret typed,
 * another registration or provider, scopes, the token method, the resource switch). registration and sendResource
 * are always sent (the contract requires them); undefined when nothing changed.
 */
export function oauthChanges(f: OAuthForm, secret: string, stored: OAuthConfig): Schemas["McpServerOAuthInput"] | undefined {
  const { registration, platformProviderId } = splitChoice(f.registration);
  const regChanged = f.registration !== choiceOf(stored.registration, stored.platformProvider?.id);
  const manual = registration === "manual";
  const changes = {
    ...(regChanged && registration === "platform_provider" ? { platformProviderId } : {}),
    ...(manual && f.clientId.trim() ? { clientId: f.clientId.trim() } : {}),
    ...(manual && secret ? { clientSecret: secret } : {}),
    ...(manual && (regChanged || f.tokenAuthMethod !== stored.tokenAuthMethod) ? { tokenAuthMethod: f.tokenAuthMethod } : {}),
    ...(JSON.stringify(f.scopes) !== JSON.stringify(stored.scopes) ? { scopes: f.scopes } : {}),
    ...(f.authorizationServer && f.authorizationServer !== stored.authorizationServer ? { authorizationServer: f.authorizationServer } : {}),
  };
  if (!regChanged && Object.keys(changes).length === 0 && f.sendResource === stored.sendResource) return undefined;
  return { registration, sendResource: f.sendResource, ...changes };
}

/** The authorization server a save would use: the one chosen, else the detection's, else the stored one. */
const authServerAfter = (f: OAuthForm, stored?: OAuthConfig, detected?: DetectResult) =>
  f.authorizationServer || detected?.resourceMetadata?.authorizationServers[0] || stored?.authorizationServer || "";

export type AuthChange = {
  /** Under approval_required a published server goes back to review: a switch to oauth, another authorization server, or a new scope. */
  review?: "switch" | "server" | "scopes";
  /** What happens to people's sign-ins to the server: erased (sign in again) or deleted (leaving oauth). */
  connections?: "reset" | "deleted";
};

/** What saving `f` does to the server's review and to the people signed in to it. */
export function authChange(server: McpServer, f: UpstreamForm, opts: { urlChanged: boolean; detected?: DetectResult }): AuthChange {
  const before = authModeOf(server);
  const stored = server.oauth;
  const signedIn = (stored?.connectionCount ?? 0) > 0;
  if (f.mode !== "oauth") return before === "oauth" && signedIn ? { connections: "deleted" } : {};
  if (before !== "oauth" || !stored) return { review: "switch" };
  const otherServer = authServerAfter(f.oauth, stored, opts.detected) !== stored.authorizationServer;
  const review = otherServer ? "server" : f.oauth.scopes.some((s) => !stored.scopes.includes(s)) ? "scopes" : undefined;
  const otherClient = Boolean(f.oauth.clientId.trim()) || f.oauth.registration !== choiceOf(stored.registration, stored.platformProvider?.id);
  return { review, connections: signedIn && (opts.urlChanged || otherServer || otherClient) ? "reset" : undefined };
}
