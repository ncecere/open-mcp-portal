/*
 * An audit entry's before and after, in words people use: roles and statuses
 * by their labels, internal ids left out, and no value as a missing key (the
 * diff says "Not set" for it, the one word for no value). Entries without a
 * known shape are shown as recorded. This file is the field table (which
 * recorded field gets which label and formatter) and what reads it; the
 * formatters themselves are in change-formats.ts.
 */
import type { Schemas } from "@/api/client";
import { roleLabels } from "@/components/roles";
import {
  type Format,
  accessModeWords,
  authModeWords,
  capturedByLabels,
  clientKindLabels,
  credentialParts,
  eventNames,
  label,
  limitItems,
  listed,
  networkEntries,
  onOff,
  overrideModeLabels,
  ownKeySettings,
  params,
  patternItems,
  payloadViewWords,
  periodItems,
  personName,
  platformRoleLabels,
  presenceWords,
  registrationWords,
  revoked,
  serviceAccountRoleLabels,
  teamStatusLabels,
  tokenKindWords,
  trustedClients,
  userStatusLabels,
  yesNo,
} from "./change-formats";

type AuditEntry = Schemas["AuditEntry"];

/** A field's label and formatting; null leaves the field out. */
type Fields = Record<string, [label: string, format?: Format] | null>;

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
    case "mcp_capability.class_set":
      return { toolClass: ["Tool class", (v) => v === null ? "Unclassified" : label({ read: "Read", write: "Write", destructive: "Destructive" })(v)] };
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
