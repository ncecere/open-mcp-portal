/*
 * An auth provider's form (decision 25), shared by Create and Settings: the
 * fields as edited, the checks that catch mistakes before the server does
 * (it has the last word), the request bodies, and the server's refusals as
 * field errors. The client secret is not part of the form: it's
 * replace-only, sent only when typed, and never shown.
 */
import { ApiError, type Schemas } from "@/api/client";
import { type AuthProvider, type AuthProviderPreset, invalidScopeText, type PresetName, scopesProblem, type TokenAuthMethod, type TokenResponseFormat } from "@/components/providers/labels";

export type ProviderForm = {
  name: string;
  slug: string;
  preset: PresetName | "";
  enabled: boolean;
  clientId: string;
  tokenAuthMethod: TokenAuthMethod;
  pkce: boolean;
  authorizationUrl: string;
  tokenUrl: string;
  revocationUrl: string;
  userinfoUrl: string;
  defaultScopes: string[];
  scopeParam: string;
  scopeSeparator: " " | ",";
  tokenResponseFormat: TokenResponseFormat;
  /** extraAuthorizeParams as text: one key=value per line. */
  extraParams: string;
  logoUrl: string;
  /** A call carries a token refreshed with only the scopes it needs (decision 69). */
  narrowOnRefresh: boolean;
};

export type FieldKey = keyof ProviderForm | "clientSecret";
export type ProviderProblems = Partial<Record<FieldKey, string>>;

export const labels: Partial<Record<keyof ProviderForm, string>> = {
  name: "Name",
  enabled: "Enabled",
  clientId: "Client ID",
  tokenAuthMethod: "Token endpoint authentication",
  pkce: "PKCE",
  authorizationUrl: "Authorization URL",
  tokenUrl: "Token URL",
  revocationUrl: "Revocation URL",
  userinfoUrl: "Userinfo URL",
  defaultScopes: "Default scopes",
  scopeParam: "Scope parameter",
  scopeSeparator: "Scope separator",
  tokenResponseFormat: "Token response format",
  extraParams: "Extra authorization parameters",
  logoUrl: "Logo URL",
  preset: "Preset",
  narrowOnRefresh: "Narrow tokens per call",
};

export const emptyForm: ProviderForm = {
  name: "",
  slug: "",
  preset: "",
  enabled: true,
  clientId: "",
  tokenAuthMethod: "client_secret_post",
  pkce: true,
  authorizationUrl: "",
  tokenUrl: "",
  revocationUrl: "",
  userinfoUrl: "",
  defaultScopes: [],
  scopeParam: "scope",
  scopeSeparator: " ",
  tokenResponseFormat: "standard",
  extraParams: "",
  logoUrl: "",
  narrowOnRefresh: false,
};

/** extraAuthorizeParams as editable text. */
export const paramsText = (params: Record<string, string>) =>
  Object.entries(params)
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

/** A preset's {placeholders} filled in ({tenant} → organizations). */
export const fillUrl = (url: string | null, values: Record<string, string>) =>
  (url ?? "").replace(/\{([A-Za-z0-9_]+)\}/g, (whole, name: string) => values[name]?.trim() || whole);

/** The form a preset starts from, with its URL parameters filled in. */
export function formFromPreset(p: AuthProviderPreset, values: Record<string, string>): ProviderForm {
  return {
    ...emptyForm,
    name: p.name,
    slug: p.preset,
    preset: p.preset,
    tokenAuthMethod: p.tokenAuthMethod,
    pkce: p.pkce,
    authorizationUrl: fillUrl(p.authorizationUrl, values),
    tokenUrl: fillUrl(p.tokenUrl, values),
    revocationUrl: fillUrl(p.revocationUrl, values),
    userinfoUrl: fillUrl(p.userinfoUrl, values),
    defaultScopes: p.defaultScopes,
    scopeParam: p.scopeParam,
    scopeSeparator: p.scopeSeparator,
    tokenResponseFormat: p.tokenResponseFormat,
    extraParams: paramsText(p.extraAuthorizeParams),
    narrowOnRefresh: p.narrowOnRefresh,
  };
}

/** The saved provider as the form. */
export function formOf(p: AuthProvider): ProviderForm {
  return {
    name: p.name,
    slug: p.slug,
    preset: p.preset ?? "",
    enabled: p.enabled,
    clientId: p.clientId,
    tokenAuthMethod: p.tokenAuthMethod,
    pkce: p.pkce,
    authorizationUrl: p.authorizationUrl,
    tokenUrl: p.tokenUrl,
    revocationUrl: p.revocationUrl ?? "",
    userinfoUrl: p.userinfoUrl ?? "",
    defaultScopes: p.defaultScopes,
    scopeParam: p.scopeParam,
    scopeSeparator: p.scopeSeparator,
    tokenResponseFormat: p.tokenResponseFormat,
    extraParams: paramsText(p.extraAuthorizeParams),
    logoUrl: p.logoUrl ?? "",
    narrowOnRefresh: p.narrowOnRefresh,
  };
}

/** The keys a provider can't take as extra parameters (the portal sets them). */
export const reservedParams = ["response_type", "client_id", "redirect_uri", "state", "scope", "code_challenge", "code_challenge_method"];
const paramKey = /^[A-Za-z0-9_.-]{1,64}$/;

/** The extra parameters' text as an object, or what's wrong with it. */
export function parseParams(text: string, scopeParam: string): { params: Record<string, string>; problem?: string } {
  const params: Record<string, string> = {};
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const at = line.indexOf("=");
    if (at <= 0) return { params, problem: `Write each parameter as key=value on its own line (“${line}”).` };
    const key = line.slice(0, at).trim();
    const value = line.slice(at + 1).trim();
    if (!paramKey.test(key)) return { params, problem: `“${key}” isn't a parameter name: use letters, digits, dots, dashes and underscores.` };
    if (reservedParams.includes(key) || key === scopeParam.trim()) return { params, problem: `The portal sets “${key}” itself; remove it.` };
    if (key in params) return { params, problem: `“${key}” is listed twice.` };
    if (value.length > 500) return { params, problem: `“${key}”'s value is too long (at most 500 characters).` };
    params[key] = value;
  }
  if (Object.keys(params).length > 10) return { params, problem: "Use at most 10 extra parameters." };
  return { params };
}

const isLoopback = (host: string) => host === "localhost" || host.endsWith(".localhost") || /^127\.\d+\.\d+\.\d+$/.test(host) || host === "[::1]";

/** What's wrong with an endpoint address (the server checks it against the address guard too). */
export function endpointProblem(value: string, required: boolean, dev: boolean): string | undefined {
  const v = value.trim();
  if (!v) return required ? "Enter the address, as the provider's documentation gives it." : undefined;
  if (/\{[A-Za-z0-9_]+\}/.test(v)) return "Fill in the part in braces, such as your tenant or host.";
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return "Enter a full https address, such as https://github.com/login/oauth/authorize.";
  }
  if (u.protocol !== "https:" && !(u.protocol === "http:" && (dev || !isLoopback(u.hostname)))) return "Use an https address.";
  if (u.username || u.password) return "Remove the user name and password from the address.";
  if (u.hash || v.includes("#")) return "Remove the #fragment.";
  return undefined;
}

export const slugPattern = /^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/;

/** The form's field errors. `secret` is the typed secret; `hasSecret` says one is stored (Settings). */
export function providerProblems(f: ProviderForm, opts: { creating: boolean; secret: string; hasSecret: boolean; dev: boolean }): ProviderProblems {
  const out: ProviderProblems = {};
  if (!f.name.trim()) out.name = "Enter a name, such as GitHub.";
  else if (f.name.trim().length > 100) out.name = "Use at most 100 characters.";
  if (opts.creating && !slugPattern.test(f.slug)) out.slug = "Use 1 to 48 lower-case letters, digits and dashes, starting and ending with a letter or digit.";
  // /connect/done and /connect/callback are the connect pages' own addresses, not providers'.
  else if (opts.creating && (f.slug === "done" || f.slug === "callback")) out.slug = "The connect pages use this name. Choose another slug.";
  if (!f.clientId.trim()) out.clientId = "Enter the client ID of the OAuth app you registered with the provider.";
  if (f.tokenAuthMethod !== "none" && !opts.secret && !opts.hasSecret) out.clientSecret = "Enter the OAuth app's client secret, or choose None for a public client.";
  if (f.tokenAuthMethod === "none" && !f.pkce) out.pkce = "A public client (no secret) needs PKCE.";
  for (const [key, required] of [
    ["authorizationUrl", true],
    ["tokenUrl", true],
    ["revocationUrl", false],
    ["userinfoUrl", false],
  ] as const) {
    const p = endpointProblem(f[key], required, opts.dev);
    if (p) out[key] = p;
  }
  const scopes = scopesProblem(f.defaultScopes);
  if (scopes) out.defaultScopes = scopes;
  if (!paramKey.test(f.scopeParam.trim())) out.scopeParam = "Use the parameter's name, such as scope or user_scope.";
  const params = parseParams(f.extraParams, f.scopeParam);
  if (params.problem) out.extraParams = params.problem;
  const logo = f.logoUrl.trim();
  if (logo && !logo.startsWith("/") && !logo.startsWith("https://")) out.logoUrl = "Use an https address or a path on this site.";
  return out;
}

const blank = (v: string) => v.trim() || undefined;

/** The create request. */
export function createBody(f: ProviderForm, secret: string): Schemas["AuthProviderCreate"] {
  return {
    slug: f.slug,
    name: f.name.trim(),
    ...(f.preset ? { preset: f.preset } : {}),
    enabled: f.enabled,
    clientId: f.clientId.trim(),
    ...(secret && f.tokenAuthMethod !== "none" ? { clientSecret: secret } : {}),
    tokenAuthMethod: f.tokenAuthMethod,
    pkce: f.pkce,
    authorizationUrl: f.authorizationUrl.trim(),
    tokenUrl: f.tokenUrl.trim(),
    revocationUrl: blank(f.revocationUrl),
    userinfoUrl: blank(f.userinfoUrl),
    defaultScopes: f.defaultScopes,
    scopeParam: f.scopeParam.trim(),
    scopeSeparator: f.scopeSeparator,
    tokenResponseFormat: f.tokenResponseFormat,
    extraAuthorizeParams: parseParams(f.extraParams, f.scopeParam).params,
    logoUrl: blank(f.logoUrl),
    narrowOnRefresh: f.narrowOnRefresh,
  };
}

/** The update request: the whole form (the slug never changes), and the secret only when a new one was typed. */
export function updateBody(f: ProviderForm, secret: string): Schemas["AuthProviderUpdate"] {
  const { slug: _slug, preset, revocationUrl, userinfoUrl, logoUrl, ...rest } = createBody(f, secret);
  return { ...rest, preset: preset ?? null, revocationUrl: revocationUrl ?? null, userinfoUrl: userinfoUrl ?? null, logoUrl: logoUrl ?? null };
}

/** Why the server refused an endpoint (422 url_not_allowed, details.reason). */
const urlReasons: Record<string, string> = {
  invalid: "This isn't an address the portal can use.",
  too_long: "This address is too long.",
  userinfo: "Remove the user name and password from the address.",
  query: "Remove the query (the part from ?). Add parameters under Extra authorization parameters instead.",
  fragment: "Remove the fragment (the part from #).",
  scheme: "Use an https address. Plain http works only for internal hosts a platform admin has allowed it for.",
  private_address: "The portal won't connect to this internal (private) address until its network is allowed in Internal networks.",
  blocked_address: "The portal never connects to loopback, link-local (such as cloud metadata), multicast or broadcast addresses.",
};

const paramReasons: Record<string, string> = {
  reserved: "The portal sets this parameter itself; remove it.",
  invalid: "This parameter isn't accepted: check its name and value.",
  too_many: "Use at most 10 extra parameters.",
};

/** A server refusal as field errors (the rest show on the save bar or the form). */
export function serverProblems(err: unknown): ProviderProblems {
  if (!(err instanceof ApiError)) return {};
  const d = err.details ?? {};
  switch (err.code) {
    case "slug_taken":
      return { slug: "Another provider uses this slug. Choose another." };
    case "url_not_allowed": {
      const field = typeof d.field === "string" && d.field in labels ? (d.field as keyof ProviderForm) : "tokenUrl";
      const reason = typeof d.reason === "string" ? d.reason : "";
      return { [field]: urlReasons[reason] ?? err.message };
    }
    case "invalid_param": {
      const reason = typeof d.reason === "string" ? d.reason : "";
      const key = typeof d.key === "string" ? `“${d.key}”: ` : "";
      return { extraParams: `${key}${paramReasons[reason] ?? err.message}` };
    }
    case "invalid_scope":
      return { defaultScopes: invalidScopeText(d) };
    case "pkce_required":
      return { pkce: "A public client (no secret) needs PKCE." };
    case "client_secret_required":
      return { clientSecret: "Enter the OAuth app's client secret, or choose None for a public client." };
    default:
      return {};
  }
}
