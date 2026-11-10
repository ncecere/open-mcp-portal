/* Who did an audited action, and how: the Person filter's special entries, actor names and "via" wording. */
import type { Schemas } from "../../api/client";
import type { FacetOption } from "@/components/ui/filter-bar/filter-bar";

type AuditEntry = Schemas["AuditEntry"];

/** The Person filter's entry for changes the system made (the API's actorKind=system). */
export const systemPerson = "system";
export const systemPersonOption: FacetOption = { value: systemPerson, label: "System" };

/** The Person filter's entry for what automation tokens did (the API's actorKind=automation_token). */
export const tokenPerson = "automation_token";
export const tokenPersonOption: FacetOption = { value: tokenPerson, label: "Automation tokens" };

/** The Person filter's value as API filters: a person's ID, the system or automation tokens as the actor. */
export function personFilter(value: string | undefined): { actorUserId?: string; actorKind?: "system" | "automation_token" } {
  if (!value) return {};
  if (value === tokenPerson) return { actorKind: "automation_token" };
  return value === systemPerson ? { actorKind: "system" } : { actorUserId: value };
}

/** The kind of an automation token that acted, as a badge's words. */
export const tokenKindLabels = { platform_admin: "Platform admin token", team_publisher: "Team publisher token" } as const;

/** "Team publisher token" for an automation token's actor; undefined for other actors. */
export function tokenKindLabel(actor: AuditEntry["actor"]): string | undefined {
  return actor.kind === "automation_token" ? (actor.automationTokenKind ? tokenKindLabels[actor.automationTokenKind] : "Automation token") : undefined;
}

/** Who did it: a person's name, the token's name (as recorded when it acted), or "System". */
export function actorName(actor: AuditEntry["actor"], _entry?: Pick<AuditEntry, "metadata" | "teamName">) {
  if (actor.kind === "system") return "System";
  if (actor.kind === "automation_token") return actor.automationTokenName || "Automation token";
  return actor.displayName || actor.email || (actor.userId ? "Unknown user" : "Unknown");
}

/** How the person acted, in words ("Signed in", "API key: Nightly sync", "Connected app: Claude Code"); "" for the system. */
export function viaLabel(via: AuditEntry["via"]) {
  if (!via) return "";
  const named = (what: string) => (via.name ? `${what}: ${via.name}` : what);
  return via.kind === "api_key" ? named("API key") : via.kind === "oauth" ? named("Connected app") : "Signed in";
}

type ActedFields = Pick<AuditEntry, "actor" | "metadata"> & Partial<Pick<AuditEntry, "via">>;

/** How the person acted, when it wasn't in the app: "API key: Nightly sync" or "Connected app: Claude Code". */
export function actedVia(e: ActedFields): string | undefined {
  if (e.via) return e.via.kind === "api_key" || e.via.kind === "oauth" ? viaLabel(e.via) : undefined;
  if (e.actor.kind === "api_key") return `API key${e.actor.apiKeyName ? `: ${e.actor.apiKeyName}` : ""}`;
  return undefined;
}

/** The same for the record page's How row: a person without a key or an app acted in the app. */
export function actedHow(e: ActedFields): string | undefined {
  if (e.actor.kind === "automation_token") return `Automation token (${tokenKindLabel(e.actor)?.toLowerCase().replace(/ token$/, "")})`;
  if (e.via) return viaLabel(e.via) || undefined;
  return actedVia(e) ?? (e.actor.kind === "user" ? "Signed in" : undefined);
}
