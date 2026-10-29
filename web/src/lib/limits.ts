/*
 * Rate limits on /mcp/{slug} (docs/phase6-operations.md "Rate limits"): the keys' words, values as text, and
 * the checks the forms run before the server does (whole requests per minute, 1 to 1,000,000; empty means unlimited,
 * or for a ceiling, none).
 */
import { queryOptions } from "@tanstack/react-query";
import { api, type Schemas, unwrap } from "../api/client";

export type RateLimitKey = Schemas["RateLimitKey"];
export type RateLimitValue = number | null;

/** The most any limit can be (PlatformRateLimit.max). */
export const maxRate = 1_000_000;

export const rateKeys: RateLimitKey[] = ["person_per_minute", "credential_per_minute", "service_account_per_minute", "gateway_per_minute", "server_per_minute"];

/** Short names, used where the server's label isn't loaded (audit entries, call errors). */
export const rateKeyLabels: Record<RateLimitKey, string> = {
  person_per_minute: "Per person",
  credential_per_minute: "Per API key or connected app",
  service_account_per_minute: "Per service account",
  gateway_per_minute: "Per gateway",
  server_per_minute: "Per upstream server",
};

/** "600 per minute", or "Unlimited" (`none` for a ceiling: "No ceiling"). */
export function rateText(v: RateLimitValue | undefined, none = "Unlimited") {
  return v === null || v === undefined ? none : `${v.toLocaleString()} per minute`;
}

/** A value as the input's text ("" for unlimited). */
export const rateInput = (v: RateLimitValue | undefined) => (v === null || v === undefined ? "" : String(v));

/** The input's text as a value: null when empty; NaN when it isn't a whole number. */
export function parseRate(text: string): RateLimitValue {
  const t = text.trim();
  if (t === "") return null;
  return /^\d+$/.test(t) ? Number(t) : Number.NaN;
}

/** What's wrong with a typed value (empty is fine: unlimited), checked against an optional ceiling. */
export function rateProblem(text: string, ceiling?: RateLimitValue): string | undefined {
  const v = parseRate(text);
  if (v === null) return undefined;
  if (!Number.isInteger(v) || v < 1 || v > maxRate) return `Enter a whole number from 1 to ${maxRate.toLocaleString()}, or leave it empty.`;
  if (ceiling !== null && ceiling !== undefined && v > ceiling) return `At most the ceiling, ${ceiling.toLocaleString()} per minute.`;
  return undefined;
}

/** The query key of the platform limits (Admin › Limits; a platform gateway's settings read the ceiling). */
export const limitSettingsKey = ["admin", "limits"];

export const limitSettingsQuery = () =>
  queryOptions({ queryKey: limitSettingsKey, queryFn: async () => unwrap(await api.GET("/v1/admin/settings/limits")) });

/** The limits that apply to a team (members read them; the team's gateway settings read the ceiling). */
export const teamLimitsQuery = (team: string) =>
  queryOptions({
    queryKey: ["team", team, "limits"],
    queryFn: async () => unwrap(await api.GET("/v1/teams/{team}/limits", { params: { path: { team } } })),
  });

/** A team's overrides in Admin (with the team's revision for If-Match). */
export const adminTeamLimitsQuery = (team: string) =>
  queryOptions({
    queryKey: ["admin", "team", team, "limits"],
    queryFn: async () => unwrap(await api.GET("/v1/admin/teams/{team}/limits", { params: { path: { team } } })),
  });
