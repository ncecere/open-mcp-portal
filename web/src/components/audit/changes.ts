/*
 * An audit entry's before and after, in words people use: roles and statuses
 * by their labels, internal ids left out, and no value as a missing key (the
 * diff says "Not set" for it, the one word for no value). Entries without a
 * known shape are shown as recorded.
 */
import type { Schemas } from "@/api/client";
import { eventLabel } from "@/components/notifications/events";
import { roleLabels } from "@/components/roles";

type AuditEntry = Schemas["AuditEntry"];
type Format = (value: unknown) => unknown;
/** A field's label and formatting; null leaves the field out. */
type Fields = Record<string, [label: string, format?: Format] | null>;

/** A switch's value in words: "On", "Off". */
export const onOff = (v: unknown) => (typeof v === "boolean" ? (v ? "On" : "Off") : v);
const label =
  (labels: Record<string, string>): Format =>
  (v) =>
    typeof v === "string" ? (labels[v] ?? v) : v;
const userStatusLabels: Record<string, string> = { active: "Active", suspended: "Suspended" };
const teamStatusLabels: Record<string, string> = { active: "Active", archived: "Archived" };
const platformRoleLabels: Record<string, string> = { none: "None", platform_admin: "Platform admin", platform_auditor: "Platform auditor" };

/** Internal network entries as words: "10.20.0.0/16", "*.corp.example.com (http) · Build farm". */
const networkEntries: Format = (v) =>
  Array.isArray(v)
    ? v.map((e: { value?: string; allowHttp?: boolean; note?: string }) => `${e.value ?? ""}${e.allowHttp ? " (http)" : ""}${e.note ? ` · ${e.note}` : ""}`)
    : v;

/** Trusted clients as words: "Claude Code (https://claude.ai/oauth/claude-code-client-metadata)". */
const trustedClients: Format = (v) =>
  Array.isArray(v) ? v.map((c: { clientId?: string; label?: string }) => (c.label ? `${c.label} (${c.clientId ?? ""})` : (c.clientId ?? ""))) : v;

const clientKindLabels: Record<string, string> = { metadata: "Yes (metadata document)", registered: "No (registered itself)" };

/** Extra authorization parameters as words: "access_type=offline". */
const params: Format = (v) => (v && typeof v === "object" && !Array.isArray(v) ? Object.entries(v as Record<string, unknown>).map(([k, x]) => `${k}=${String(x)}`) : v);

const accessModeWords: Record<string, string> = { open: "Open to every team", restricted: "Restricted to the listed teams and servers" };
/** A provider's listed teams or servers as words: "Platform tools (platform)", "Wiki (docs)". */
const listed: Format = (v) => (Array.isArray(v) ? v.map((e: { name?: string; slug?: string; teamSlug?: string }) => `${e.name ?? e.slug ?? ""} (${e.teamSlug ?? e.slug ?? ""})`) : v);

/** Whether a disconnected account was revoked at the provider too. */
const revoked: Format = (v) => (v === true ? "Yes" : v === false ? "No (failed)" : v === "not_supported" ? "Not supported by the provider" : v);

const presenceWords: Record<string, string> = { inherit: "Same as the server", required: "Needs a present person", not_required: "Doesn't need a present person" };
/** A server's credential parts as words (never a value): "Header X-Tenant", "Query parameter sig", "Basic". */
const credentialParts: Format = (v) =>
  Array.isArray(v)
    ? v.map((c: { kind?: string; name?: string }) => (c.kind === "bearer" ? "Bearer token" : c.kind === "basic" ? "Basic (user and password)" : `${c.kind === "query" ? "Query parameter" : "Header"} ${c.name ?? ""}`.trim()))
    : v;
const authModeWords: Record<string, string> = { none: "None", static_header: "Static header", oauth: "OAuth sign-in per person", person_secret: "Each person's own key" };
/** How people's own keys are sent (never a key): "Header X-Api-Key", "Bearer token", "Query parameter k". */
const ownKeySettings: Format = (v) => {
  if (!v || typeof v !== "object") return v;
  const c = v as { placement?: string; name?: string };
  return c.placement === "bearer" ? "Bearer token" : `${c.placement === "query" ? "Query parameter" : "Header"} ${c.name ?? ""}`.trim();
};
const registrationWords: Record<string, string> = {
  dcr: "Automatic (dynamic registration)",
  cimd: "Automatic (client metadata document)",
  manual: "Client entered by the team",
  platform_provider: "Platform provider's client",
};
const yesNo: Format = (v) => (typeof v === "boolean" ? (v ? "Yes" : "No") : v);
/** A person recorded as an object ({ id, name }) or a name. */
const personName: Format = (v) => (v && typeof v === "object" && "name" in v && typeof v.name === "string" ? v.name : v);

const overrideModeLabels: Record<string, string> = { inherit: "Same as the server", none: "No account", scopes: "Other scopes" };

const limitKeyLabels: Record<string, string> = {
  person_per_minute: "Per person",
  credential_per_minute: "Per API key or connected app",
  service_account_per_minute: "Per service account",
  gateway_per_minute: "Per gateway",
};
const perMinute = (v: unknown) => (typeof v === "number" ? `${v.toLocaleString()}/min` : "unlimited");

/** Platform limits as words: "Per person: 600/min (ceiling none)". */
const limitItems: Format = (v) =>
  Array.isArray(v)
    ? v.map((i: { key?: string; default?: unknown; ceiling?: unknown; value?: unknown }) =>
        "value" in i
          ? `${limitKeyLabels[i.key ?? ""] ?? i.key}: ${i.value === null ? "inherit" : perMinute(i.value)}`
          : `${limitKeyLabels[i.key ?? ""] ?? i.key}: ${perMinute(i.default)}${i.ceiling === null || i.ceiling === undefined ? "" : `, ceiling ${perMinute(i.ceiling)}`}`,
      )
    : v;

const retentionKindLabels: Record<string, string> = { call_metadata: "Call records", captured_payloads: "Recorded call contents", audit_log: "Audit log", usage_rollups: "Usage totals" };

/** Retention periods as words: "Call records: 90 days". */
const periodItems: Format = (v) =>
  Array.isArray(v)
    ? v.map((p: { kind?: string; days?: unknown }) => `${retentionKindLabels[p.kind ?? ""] ?? p.kind}: ${typeof p.days === "number" ? `${p.days} days` : "inherit"}`)
    : v;

/** Redaction patterns as words: "EMP-[0-9]{6} · Employee numbers". */
const patternItems: Format = (v) => (Array.isArray(v) ? v.map((p: { pattern?: string; note?: string }) => `${p.pattern ?? ""}${p.note ? ` · ${p.note}` : ""}`) : v);

const payloadViewWords: Record<string, string> = { team: "On the team's page", admin: "In Admin (platform staff)" };
const capturedByLabels: Record<string, string> = { gateway: "The gateway", server: "The server" };

const tokenKindWords: Record<string, string> = { platform_admin: "Platform admin token", team_publisher: "Team publisher token" };
/** A list of event names (server.unhealthy…) as the words the app uses for them. */
const eventNames: Format = (v) => (Array.isArray(v) ? v.map((e) => eventLabel(String(e))) : v);

const serviceAccountRoleLabels: Record<string, string> = { member: roleLabels.member, editor: roleLabels.editor };

function fieldsFor(action: string): Fields | undefined {
  switch (action) {
    case "settings.network_update":
      return { entries: ["Allowed networks and hosts", networkEntries] };
    case "settings.oauth_clients_update":
      return { clients: ["Trusted clients", trustedClients], openRegistration: ["Open client registration", onOff] };
    case "settings.limits_update":
    case "team.limits_update":
      return { items: ["Rate limits", limitItems] };
    case "settings.retention_update":
    case "team.retention_update":
      return { periods: ["Retention periods", periodItems] };
    case "settings.capture_update":
      return { patterns: ["Redaction patterns", patternItems] };
    case "mcp_call.payload_view":
      return { via: ["Viewed", label(payloadViewWords)], capturedBy: ["Recorded by", (v) => (Array.isArray(v) ? v.map((b) => capturedByLabels[String(b)] ?? b) : v)] };
    case "gateway.create":
    case "gateway.update":
      return { capturePayloads: ["Record call contents", onOff], rateLimitPerMinute: ["Rate limit per minute"] };
    case "mcp_server.create":
    case "mcp_server.update":
      return {
        capturePayloads: ["Record call contents", onOff],
        sendIdentity: ["Send identity token", onOff],
        requiresPresentPerson: ["Require a present person", onOff],
        authMode: ["Authentication", label(authModeWords)],
        credentials: ["Credential parts", credentialParts],
        personSecret: ["Each person's key is sent as", ownKeySettings],
      };
    case "person_secret.create":
    case "person_secret.rotate":
    case "person_secret.revoke":
    case "person_secret.agents_update":
      return { allowAgents: ["Agents may use it", onOff], userId: null, serverId: null, origin: ["Entered for"], server: ["Server"] };
    case "mcp_server.auth_update":
      return {
        mode: ["Authentication", label(authModeWords)],
        authMode: ["Authentication", label(authModeWords)],
        authorizationServer: ["Authorization server"],
        registration: ["Registration", label(registrationWords)],
        scopes: ["Scopes"],
        sendResource: ["Resource indicator", onOff],
        clientIdChanged: ["New client ID", yesNo],
        clientSecretChanged: ["New client secret", yesNo],
        registered: ["Registered a client", yesNo],
        connectionsReset: ["Sign-ins reset", (v) => (typeof v === "number" ? v.toLocaleString() : yesNo(v))],
        setupBy: ["Capabilities read as", personName],
        providerId: null,
      };
    case "service_account.create":
    case "service_account.update":
    case "service_account.delete":
      return { role: ["Role", label(serviceAccountRoleLabels)], enabled: ["Enabled", onOff], teamId: null };
    case "service_account.relay_set":
    case "service_account.relay_clear":
      return { platform: ["Agent platform"], platformId: null };
    case "agent_platform.create":
    case "agent_platform.update":
    case "agent_platform.delete":
      return { name: ["Name"], issuer: ["Issuer"], jwksUrl: ["Keys address"], audience: ["Audience"], enabled: ["Enabled", onOff] };
    case "mcp_capability.presence_set":
      return { mode: ["Present person", label(presenceWords)], effective: ["Needs a present person", yesNo] };
    case "service_account_key.create":
    case "service_account_key.revoke":
      return { serviceAccount: ["Service account"], expiresAt: ["Expires"], gatewayIds: null, serviceAccountId: null };
    case "notification_destination.create":
    case "notification_destination.update":
    case "notification_destination.delete":
    case "notification_destination.disable":
      return { events: ["Events", eventNames], enabled: ["Enabled", onOff], teamEvents: ["Also every team's events", onOff], urlDisplay: ["URL (host only)"], id: null };
    case "automation_token.create":
    case "automation_token.revoke":
      return { kind: ["Kind", label(tokenKindWords)], scopes: ["Can"], expiresAt: ["Expires"], id: null };
    case "oauth.consent":
    case "oauth.grant_confirmed":
    case "oauth.revoke":
    case "oauth.token_issue":
      return {
        clientName: ["App"],
        clientKind: ["Verified", label(clientKindLabels)],
        clientId: ["Client ID"],
        clientUri: ["App website"],
        gatewaySlug: ["Gateway"],
        gatewayId: null,
        userId: null,
      };
    case "auth_provider.access_update":
      return { accessMode: ["Access", label(accessModeWords)], teams: ["Teams", (v) => (Array.isArray(v) ? v.map((t: { name?: string; slug?: string }) => `${t.name ?? ""} (${t.slug ?? ""})`) : v)], servers: ["Servers", listed] };
    case "auth_provider.create":
    case "auth_provider.update":
    case "auth_provider.delete":
      return {
        accessMode: ["Access", label(accessModeWords)],
        narrowOnRefresh: ["Narrow tokens per call", onOff],
        enabled: ["Enabled", onOff],
        pkce: ["PKCE", onOff],
        clientId: ["Client ID"],
        extraAuthorizeParams: ["Extra authorization parameters", params],
        hasClientSecret: null,
        clientSecretHint: null,
        id: null,
      };
    case "provider_connection.create":
    case "provider_connection.refresh_failed":
    case "provider_connection.revoke":
      return { providerId: null, userId: null, connectionId: null, providerRevoked: ["Revoked at the provider", revoked] };
    case "mcp_capability.requirement_set":
      return { mode: ["Requirement", label(overrideModeLabels)] };
    case "platform.bootstrap_role":
    case "platform.user_suspend":
    case "platform.user_reactivate":
    case "platform.user_role_change":
    case "platform.user_update":
      return { platformRole: ["Platform role", label(platformRoleLabels)], status: ["Status", label(userStatusLabels)] };
    case "team.member_add":
    case "team.member_role_change":
    case "team.invite_create":
      return { role: ["Role", label(roleLabels)] };
    case "team.create":
    case "team.update":
    case "team.archive":
    case "team.unarchive":
      return { status: ["Status", label(teamStatusLabels)] };
    default:
      return undefined;
  }
}

const acronyms: Record<string, string> = { id: "ID", ids: "IDs", url: "URL", urls: "URLs", api: "API", sso: "SSO", oidc: "OIDC", mcp: "MCP" };

/** A recorded key in plain words: "ownerEmail" → "Owner email", "userIds" → "User IDs", "warn_percent" → "Warn percent". */
export function plainKey(key: string): string {
  const words = key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[\s_]+/)
    .filter(Boolean)
    .map((w) => acronyms[w.toLowerCase()] ?? w.toLowerCase());
  const [first = "", ...rest] = words;
  return [first.charAt(0).toUpperCase() + first.slice(1), ...rest].join(" ");
}

/** One side of a change, with known fields relabelled and formatted, and empty values left out. */
function readable(side: unknown, fields: Fields): Record<string, unknown> {
  if (!side || typeof side !== "object" || Array.isArray(side)) return {};
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(side)) {
    if (value === null || value === undefined || value === "") continue;
    const field = fields[key];
    if (field === null) continue;
    out[field?.[0] ?? plainKey(key)] = field?.[1] ? field[1](value) : value;
  }
  return out;
}

/** The entry's before and after for the diff. */
export function auditChange(e: Pick<AuditEntry, "action" | "before" | "after">): { before: object; after: object } {
  const fields = fieldsFor(e.action) ?? {};
  const side = (v: unknown) => (v && typeof v === "object" && !Array.isArray(v) ? readable(v, fields) : (v ?? {}));
  return { before: side(e.before) as object, after: side(e.after) as object };
}

/** One changed field of an entry: its plain name, and its value before and after (undefined: not set). */
export type ChangeRow = { field: string; before?: unknown; after?: unknown };

/** The fields that differ between the two sides, in order (the before's fields first). */
export function changedRows(change: { before: object; after: object }): ChangeRow[] {
  const b = change.before as Record<string, unknown>;
  const a = change.after as Record<string, unknown>;
  const keys = [...Object.keys(b), ...Object.keys(a).filter((k) => !(k in b))];
  return keys.filter((k) => JSON.stringify(b[k]) !== JSON.stringify(a[k])).map((k) => ({ field: k, before: b[k], after: a[k] }));
}

/** A value for people: text as is, true and false as On and Off, a list of words joined, anything else as compact JSON; "Not set" without one. */
export function valueText(v: unknown, none = "Not set"): string {
  if (v === undefined || v === null || v === "") return none;
  if (typeof v === "string") return v;
  if (typeof v === "boolean") return v ? "On" : "Off";
  if (typeof v === "number") return String(v);
  if (Array.isArray(v) && v.every((x) => typeof x === "string" || typeof x === "number")) return v.length ? v.join(", ") : none;
  return JSON.stringify(v);
}

const simple = (v: unknown) => v === undefined || ((typeof v === "string" || typeof v === "number" || typeof v === "boolean") && String(v).length <= 40);

/**
 * A change in one line for the list, when it's simple: one or two fields with short values, such as "Role Member →
 * Editor". Null for creations, deletions and larger changes (the record page has them).
 */
export function changeSummary(e: Pick<AuditEntry, "action" | "before" | "after">): string | null {
  if (e.before == null || e.after == null) return null;
  const rows = changedRows(auditChange(e));
  if (rows.length === 0 || rows.length > 2 || !rows.every((r) => simple(r.before) && simple(r.after))) return null;
  // "Not set", as the record page's diff says it.
  return rows.map((r) => `${r.field} ${valueText(r.before)} → ${valueText(r.after)}`).join("; ");
}
