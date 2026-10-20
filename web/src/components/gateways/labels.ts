/*
 * The gateways' words (gateways, their capabilities, access and calls), shared by the team's pages, Admin,
 * My gateways and the Connect section.
 */
import type { Schemas } from "../../api/client";
import { plural } from "../../lib/format";

export type Gateway = Schemas["Gateway"];
export type GatewayCapability = Schemas["GatewayCapability"];
export type GatewayOption = Schemas["GatewayOption"];
export type GatewayGrant = Schemas["GatewayGrant"];
export type GatewayKind = Schemas["GatewayCapabilityKind"];
export type UnavailableReason = Schemas["GatewayUnavailableReason"];
export type MyGateway = Schemas["MyGateway"];
export type MyAccess = Schemas["MyGatewayAccess"];
export type McpCall = Schemas["McpCall"];
export type CallOutcome = Schemas["McpCallOutcome"];
export type ApiKey = Schemas["ApiKey"];
export type TeamRole = Schemas["TeamRole"];

/** What a gateway is, for empty lists and the create form. */
export const whatIsAGateway =
  "A gateway is a curated set of tools, prompts and resources at one MCP address. Pick capabilities from your team's servers and the company catalog; the team's members connect their AI clients to the gateway's URL with an API key and see only what it offers.";

/** The same for platform gateways (Admin). */
export const whatIsAPlatformGateway =
  "A platform gateway is a curated set of approved tools, prompts and resources from the catalog at one MCP address, shared with the teams, people or SSO groups you grant it to.";

/** The most capabilities one gateway can hold (the API's maxItems). */
export const maxCapabilities = 200;

export const gatewayKinds: GatewayKind[] = ["tool", "prompt", "resource", "resource_template"];

export const gatewayKindLabels: Record<GatewayKind, { one: string; many: string; title: string }> = {
  tool: { one: "tool", many: "tools", title: "Tools" },
  prompt: { one: "prompt", many: "prompts", title: "Prompts" },
  resource: { one: "resource", many: "resources", title: "Resources" },
  resource_template: { one: "resource template", many: "resource templates", title: "Templates" },
};

/** Resources and templates are exposed as URIs (omp://{server}/{uri}); tools and prompts by name. */
export const isResourceKind = (k: GatewayKind) => k === "resource" || k === "resource_template";

/** "3 capabilities". */
export const capabilityCount = (n: number) => plural(n, "capability", "capabilities");

/** Why a selected capability isn't served now. */
export const unavailableLabels: Record<UnavailableReason, string> = {
  server_disabled: "Server disabled",
  not_published: "Left the catalog",
  not_approved: "Not approved",
  changed: "Changed, waiting for approval",
  gone: "No longer listed",
  team_archived: "Team archived",
};

export const unavailableHelp: Record<UnavailableReason, string> = {
  server_disabled: "Its server is turned off.",
  not_published: "Its server was taken off the company catalog.",
  not_approved: "Its current definition isn't approved for the catalog.",
  changed: "Its definition changed since it was approved; it's served again once the change is approved.",
  gone: "The server doesn't list it any more.",
  team_archived: "The owning team is archived. It's served again when the team is unarchived.",
};

/** Why the person may use a gateway. */
export const accessLabels: Record<MyAccess, string> = {
  team_member: "Team member",
  team_grant: "Granted to your team",
  user_grant: "Granted to you",
  group_grant: "Granted to your SSO group",
};

/** "Granted to your SSO group engineering" when the matching groups are known. */
export function accessLabel(access: MyAccess, groups?: string[]): string {
  if (access !== "group_grant" || !groups?.length) return accessLabels[access];
  return `${groups.length === 1 ? "Granted to your SSO group" : "Granted to your SSO groups"} ${groups.join(", ")}`;
}

export const outcomeLabels: Record<CallOutcome, string> = {
  ok: "OK",
  tool_error: "Tool error",
  denied: "Denied",
  upstream_error: "Upstream error",
  timeout: "Timed out",
  too_large: "Too large",
  bad_request: "Bad request",
  needs_authorization: "Needed a connection",
  rate_limited: "Rate limited",
};

export const outcomeHelp: Record<CallOutcome, string> = {
  ok: "Answered.",
  tool_error: "The tool reported an error.",
  denied: "Refused by policy. The client was told it wasn't found.",
  upstream_error: "The server was unreachable, refused or answered something malformed.",
  timeout: "The server didn't answer in time.",
  too_large: "The request or response was over 1 MiB.",
  bad_request: "The client's request was invalid.",
  needs_authorization: "Not sent to the server: the person had to connect or reconnect an account first, and their client got a link to do it.",
  rate_limited: "Not sent to the server: a rate limit was exceeded, so the client was told to try again later (HTTP 429).",
};

export const outcomeTone: Record<CallOutcome, "success" | "warning" | "danger" | "neutral"> = {
  ok: "success",
  tool_error: "warning",
  denied: "neutral",
  upstream_error: "danger",
  timeout: "danger",
  too_large: "warning",
  bad_request: "warning",
  needs_authorization: "warning",
  rate_limited: "warning",
};

export const callOutcomes = Object.keys(outcomeLabels) as CallOutcome[];

/** Outcomes of a call that never reached its server. */
const notForwarded: CallOutcome[] = ["denied", "needs_authorization", "rate_limited", "bad_request"];

/**
 * Whether the identity token went to the server (McpCall.identitySent, decision 64): "Sent", "Not sent" (the
 * server's Send identity token switch was off), "Not forwarded" (refused, or a list the portal answered itself), or
 * "Not recorded" (a forwarded call from before the portal recorded this).
 */
export function identitySentLabel(c: Pick<McpCall, "identitySent" | "outcome" | "method">): string {
  if (c.identitySent === true) return "Sent";
  if (c.identitySent === false) return "Not sent";
  return c.method.endsWith("/list") || c.method.endsWith("/templates/list") || notForwarded.includes(c.outcome) ? "Not forwarded" : "Not recorded";
}

export const identitySentHelp = {
  Sent: "The signed identity token (name, email, teams) went to the server with this call.",
  "Not sent": "The server's Send identity token switch was off, so the call carried no identity token.",
  "Not forwarded": "The call was refused, or the portal answered it itself, so nothing was sent to a server.",
  "Not recorded": "This call was recorded before the portal noted whether the identity token was sent.",
} as Record<string, string>;

/**
 * Why a call was refused or failed, in words (McpCall.errorClass). The backend
 * records: refusals (internal/mcpgw: gateway_disabled, no_access, role,
 * unknown, key_scope, or an unavailable reason), a capability's account
 * (not_connected, missing_scopes, needs_reconsent, service_account,
 * provider_disabled, provider_unavailable), invalid requests (invalid_params,
 * invalid_cursor) and the registry's upstream error classes.
 */
export const callErrorLabels: Record<string, string> = {
  // Refused by the gateway (outcome "denied").
  gateway_disabled: "Gateway turned off",
  no_access: "No access to the gateway",
  role: "Needs a higher team role",
  key_scope: "API key limited to other gateways",
  unknown: "Not offered by the gateway",
  ...unavailableLabels,
  // Capabilities that need a person's account (Phase 5).
  not_connected: "Account not connected",
  missing_scopes: "Account lacks the scopes needed",
  needs_reconsent: "Account needs reconnecting",
  service_account: "Service accounts can't use it",
  provider_disabled: "Auth provider turned off",
  provider_unavailable: "Auth provider unavailable",
  // The gateway's own rate limits (outcome "rate_limited").
  person_per_minute: "Over the per-person limit",
  credential_per_minute: "Over the per-key or per-app limit",
  service_account_per_minute: "Over the service account's limit",
  gateway_per_minute: "Over the gateway's limit",
  // The client's request.
  invalid_params: "Invalid parameters",
  invalid_cursor: "Invalid page cursor",
  // The server's answer (the registry's error classes).
  unavailable: "Couldn't reach the server",
  auth: "Server refused the credentials",
  not_found: "Server endpoint not found",
  rate_limited: "Rate limited by the server",
  bad_request: "Server refused the request",
  bad_response: "Unexpected response from the server",
  config: "Server settings problem",
  timeout: "No answer in time",
  too_large: "Over 1 MiB",
  not_allowed: "Server address not allowed",
};

/** "Gateway turned off" for a known error class; an unknown one humanised ("some_new_class" → "Some new class"). */
export function callErrorLabel(code: string): string {
  if (Object.hasOwn(callErrorLabels, code)) return callErrorLabels[code]!;
  const words = code.replace(/[_\-.]+/g, " ").trim().toLowerCase();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : "Other error";
}

/** A platform gateway's grants: "No grants", "1 grant", "3 grants". */
export const grantCountLabel = (n: number) => (n === 0 ? "No grants" : plural(n, "grant"));

/** "Team gateway" or "Platform gateway". */
export const ownerKindLabels: Record<Gateway["ownerKind"], string> = { team: "Team gateway", platform: "Platform gateway" };

/** The minimum-role choices: "" is every member. */
export const minRoleLabels: Record<TeamRole | "", string> = {
  "": "Every member",
  member: "Every member",
  editor: "Editors and above",
  admin: "Admins and owners",
  owner: "Owners only",
};

/** Roles a capability can require, lowest first ("" = no minimum). */
export const minRoleChoices: (TeamRole | "")[] = ["", "editor", "admin", "owner"];
