/*
 * Each person's own secret for a server (decision 72, docs/person-secrets.md):
 * how the server's team says it travels (a header, a bearer token or a query
 * parameter, a name, an optional prefix), the words the page where people
 * paste their key uses, and what saving a change does (everyone's keys are
 * deleted by a new address, mode or placement; a published server goes back to
 * review). The rules mirror the server's (api/openapi.yaml); the server still
 * decides.
 */
import type { Schemas } from "../../api/client";
import type { McpServer } from "./labels";

export type Placement = Schemas["PersonSecretPlacement"];
export type PersonSecretConfig = Schemas["PersonSecretInput"];
export type ServerSecret = Schemas["ServerSecret"];

export const placementLabels: Record<Placement, string> = { header: "A header", bearer: "A bearer token (Authorization: Bearer)", query: "A query parameter" };
export const placementHelp: Record<Placement, string> = {
  header: "Sent as Name: prefix + key, for example X-API-Key: abc…",
  bearer: "Sent as Authorization: Bearer key. The portal's identity token then goes in MCP-Gateway-Identity.",
  query: "Added to every request as ?name=key and never saved in the URL. Servers and proxies often log URLs: prefer a header.",
};

/** The settings as edited. name is empty for bearer. */
export type SecretForm = { placement: Placement; name: string; prefix: string; label: string; help: string };

export const blankSecret: SecretForm = { placement: "header", name: "", prefix: "", label: "", help: "" };

export function secretFormOf(s?: Pick<McpServer, "personSecret">): SecretForm {
  const p = s?.personSecret;
  return p ? { placement: p.placement, name: p.name ?? "", prefix: p.prefix, label: p.label, help: p.help } : blankSecret;
}

const headerPattern = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$/;
const queryPattern = /^[A-Za-z0-9_.-]{1,64}$/;
const reserved = new Set([
  "host", "content-type", "content-length", "accept", "connection", "transfer-encoding", "mcp-protocol-version", "mcp-session-id", "mcp-method", "mcp-name",
  "last-event-id", "user-agent", "cookie", "origin", "mcp-gateway-identity", "mcp-gateway-provider", "mcp-gateway-provider-token",
]);

export type SecretErrors = Partial<Record<"name" | "prefix" | "label" | "help", string>>;

/** What's wrong with the settings before they're sent. */
export function secretProblems(f: SecretForm): SecretErrors {
  const out: SecretErrors = {};
  const name = f.name.trim();
  if (f.placement === "header" && (!headerPattern.test(name) || reserved.has(name.toLowerCase()))) out.name = "Use a header name such as X-API-Key or Authorization (not one the portal sets itself).";
  if (f.placement === "query" && (!queryPattern.test(name) || name.toLowerCase().startsWith("mcp-"))) out.name = "Use 1 to 64 letters, digits, dots, hyphens or underscores, not starting with mcp-.";
  if (f.placement !== "bearer" && f.prefix.length > 64) out.prefix = "At most 64 characters.";
  if (f.label.length > 100) out.label = "At most 100 characters.";
  if (f.help.length > 2000) out.help = "At most 2000 characters.";
  return out;
}

/** The request's personSecret. */
export function secretInput(f: SecretForm): PersonSecretConfig {
  const bearer = f.placement === "bearer";
  return {
    placement: f.placement,
    ...(bearer ? {} : { name: f.name.trim(), ...(f.prefix ? { prefix: f.prefix } : {}) }),
    label: f.label.trim(),
    help: f.help,
  };
}

/** Whether the settings differ from what the server has. */
export function secretChanged(server: McpServer, f: SecretForm): boolean {
  const before = secretFormOf(server);
  return before.placement !== f.placement || before.name !== f.name.trim() || before.prefix !== f.prefix || before.label !== f.label.trim() || before.help !== f.help;
}

/** What saving does to the keys people entered: all deleted (a new placement), or kept. */
export function keysDeleted(server: McpServer, f: SecretForm, urlMovesOrigin: boolean, modeAfter: string): boolean {
  const p = server.personSecret;
  if (!p || p.people === 0) return false;
  return urlMovesOrigin || modeAfter !== "person_secret" || p.placement !== f.placement;
}

/** "Header X-API-Key: Token …", "Bearer token", "Query parameter ?api_key=…". */
export function placementText(c: { placement: Placement; name?: string | null; prefix?: string | null }): string {
  switch (c.placement) {
    case "header":
      return `Header ${c.name ?? ""}${c.prefix ? ` (prefix "${c.prefix}")` : ""}`;
    case "bearer":
      return "Bearer token (Authorization)";
    case "query":
      return `Query parameter ?${c.name ?? ""}=${c.prefix ? ` (prefix "${c.prefix}")` : ""}…`;
  }
}

/** The key's name on the page where people paste it. */
export const keyLabel = (c: { label?: string | null }) => c.label?.trim() || "API key";

/** "ends in 0002" or "not entered". */
export const hintText = (s: Pick<ServerSecret, "hasSecret" | "hint">) => (!s.hasSecret ? "Not entered" : s.hint ? `Ends in ${s.hint}` : "Entered");

/** What saving does to the keys people entered, in words. */
export function deletesText(server: McpServer): string {
  const n = server.personSecret?.people ?? 0;
  return `${n === 1 ? "One person has" : `${n} people have`} entered a key for ${server.name}. A new address, another way of sending it or leaving this mode makes their keys useless, so they're deleted when you save, and each person enters theirs again.`;
}
