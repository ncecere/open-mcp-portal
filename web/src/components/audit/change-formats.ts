/*
 * How an audit entry's recorded values read in words: the formatters and label maps the field table in
 * changes.ts points at (roles and statuses by their labels, lists joined, never a secret's value).
 */
import { eventLabel } from "@/components/notifications/events";
import { roleLabels } from "@/components/roles";

export type Format = (value: unknown) => unknown;
/** A switch's value in words: "On", "Off". */
export const onOff = (v: unknown) => (typeof v === "boolean" ? (v ? "On" : "Off") : v);
export const label =
  (labels: Record<string, string>): Format =>
  (v) =>
    typeof v === "string" ? (labels[v] ?? v) : v;
export const userStatusLabels: Record<string, string> = { active: "Active", suspended: "Suspended" };
export const teamStatusLabels: Record<string, string> = { active: "Active", archived: "Archived" };
export const platformRoleLabels: Record<string, string> = { none: "None", platform_admin: "Platform admin", platform_auditor: "Platform auditor" };

/** Internal network entries as words: "10.20.0.0/16", "*.corp.example.com (http) · Build farm". */
export const networkEntries: Format = (v) =>
  Array.isArray(v)
    ? v.map((e: { value?: string; allowHttp?: boolean; note?: string }) => `${e.value ?? ""}${e.allowHttp ? " (http)" : ""}${e.note ? ` · ${e.note}` : ""}`)
    : v;

/** Trusted clients as words: "Claude Code (https://claude.ai/oauth/claude-code-client-metadata)". */
export const trustedClients: Format = (v) =>
  Array.isArray(v) ? v.map((c: { clientId?: string; label?: string }) => (c.label ? `${c.label} (${c.clientId ?? ""})` : (c.clientId ?? ""))) : v;

export const clientKindLabels: Record<string, string> = { metadata: "Yes (metadata document)", registered: "No (registered itself)" };

/** Extra authorization parameters as words: "access_type=offline". */
export const params: Format = (v) => (v && typeof v === "object" && !Array.isArray(v) ? Object.entries(v as Record<string, unknown>).map(([k, x]) => `${k}=${String(x)}`) : v);

export const accessModeWords: Record<string, string> = { open: "Open to every team", restricted: "Restricted to the listed teams and servers" };
/** A provider's listed teams or servers as words: "Platform tools (platform)", "Wiki (docs)". */
export const listed: Format = (v) => (Array.isArray(v) ? v.map((e: { name?: string; slug?: string; teamSlug?: string }) => `${e.name ?? e.slug ?? ""} (${e.teamSlug ?? e.slug ?? ""})`) : v);

/** Whether a disconnected account was revoked at the provider too. */
export const revoked: Format = (v) => (v === true ? "Yes" : v === false ? "No (failed)" : v === "not_supported" ? "Not supported by the provider" : v);

export const presenceWords: Record<string, string> = { inherit: "Same as the server", required: "Needs a present person", not_required: "Doesn't need a present person" };
/** A server's credential parts as words (never a value): "Header X-Tenant", "Query parameter sig", "Basic". */
export const credentialParts: Format = (v) =>
  Array.isArray(v)
    ? v.map((c: { kind?: string; name?: string }) => (c.kind === "bearer" ? "Bearer token" : c.kind === "basic" ? "Basic (user and password)" : `${c.kind === "query" ? "Query parameter" : "Header"} ${c.name ?? ""}`.trim()))
    : v;
export const authModeWords: Record<string, string> = {
  none: "None",
  static_header: "Static header",
  oauth: "OAuth sign-in per person",
  person_secret: "Each person's own key",
  machine_oauth: "The portal's own OAuth client",
};
/** How people's own keys are sent (never a key): "Header X-Api-Key", "Bearer token", "Query parameter k". */
export const ownKeySettings: Format = (v) => {
  if (!v || typeof v !== "object") return v;
  const c = v as { placement?: string; name?: string };
  return c.placement === "bearer" ? "Bearer token" : `${c.placement === "query" ? "Query parameter" : "Header"} ${c.name ?? ""}`.trim();
};
export const registrationWords: Record<string, string> = {
  dcr: "Automatic (dynamic registration)",
  cimd: "Automatic (client metadata document)",
  manual: "Client entered by the team",
  platform_provider: "Platform provider's client",
};
export const yesNo: Format = (v) => (typeof v === "boolean" ? (v ? "Yes" : "No") : v);
/** A person recorded as an object ({ id, name }) or a name. */
export const personName: Format = (v) => (v && typeof v === "object" && "name" in v && typeof v.name === "string" ? v.name : v);

export const overrideModeLabels: Record<string, string> = { inherit: "Same as the server", none: "No account", scopes: "Other scopes" };

const limitKeyLabels: Record<string, string> = {
  person_per_minute: "Per person",
  credential_per_minute: "Per API key or connected app",
  service_account_per_minute: "Per service account",
  gateway_per_minute: "Per gateway",
};
const perMinute = (v: unknown) => (typeof v === "number" ? `${v.toLocaleString()}/min` : "unlimited");

/** Platform limits as words: "Per person: 600/min (ceiling none)". */
export const limitItems: Format = (v) =>
  Array.isArray(v)
    ? v.map((i: { key?: string; default?: unknown; ceiling?: unknown; value?: unknown }) =>
        "value" in i
          ? `${limitKeyLabels[i.key ?? ""] ?? i.key}: ${i.value === null ? "inherit" : perMinute(i.value)}`
          : `${limitKeyLabels[i.key ?? ""] ?? i.key}: ${perMinute(i.default)}${i.ceiling === null || i.ceiling === undefined ? "" : `, ceiling ${perMinute(i.ceiling)}`}`,
      )
    : v;

const retentionKindLabels: Record<string, string> = { call_metadata: "Call records", captured_payloads: "Recorded call contents", audit_log: "Audit log", usage_rollups: "Usage totals" };

/** Retention periods as words: "Call records: 90 days". */
export const periodItems: Format = (v) =>
  Array.isArray(v)
    ? v.map((p: { kind?: string; days?: unknown }) => `${retentionKindLabels[p.kind ?? ""] ?? p.kind}: ${typeof p.days === "number" ? `${p.days} days` : "inherit"}`)
    : v;

/** Redaction patterns as words: "EMP-[0-9]{6} · Employee numbers". */
export const patternItems: Format = (v) => (Array.isArray(v) ? v.map((p: { pattern?: string; note?: string }) => `${p.pattern ?? ""}${p.note ? ` · ${p.note}` : ""}`) : v);

export const payloadViewWords: Record<string, string> = { team: "On the team's page", admin: "In Admin (platform staff)" };
export const capturedByLabels: Record<string, string> = { gateway: "The gateway", server: "The server" };

export const tokenKindWords: Record<string, string> = { platform_admin: "Platform admin token", team_publisher: "Team publisher token" };
/** A list of event names (server.unhealthy…) as the words the app uses for them. */
export const eventNames: Format = (v) => (Array.isArray(v) ? v.map((e) => eventLabel(String(e))) : v);

export const serviceAccountRoleLabels: Record<string, string> = { member: roleLabels.member, editor: roleLabels.editor };
