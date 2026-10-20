/*
 * A server's own credential as the form edits it (decision 70): up to eight
 * parts (a header, a bearer token, Basic user and password, a query
 * parameter). Stored values never come back: a stored part shows its kind,
 * name and hint, and sending it again without a value keeps it (`keep`). A
 * URL on another origin never keeps a stored value (F-1), so every part's
 * value is entered again then.
 */
import type { Schemas } from "../../api/client";
import type { McpServer } from "./labels";

export type PartKind = Schemas["McpServerCredentialInput"]["kind"];
type CredentialInput = Schemas["McpServerCredentialInput"];

export const partKinds: PartKind[] = ["header", "bearer", "basic", "query"];
export const kindLabels: Record<PartKind, string> = { header: "Header", bearer: "Bearer token", basic: "Basic (user and password)", query: "Query parameter" };
export const maxParts = 8;

export type PartForm = {
  /** A stable key for the row (stored parts: their place on load). */
  key: string;
  kind: PartKind;
  /** The header or parameter name (empty for bearer and basic). */
  name: string;
  /** The value (Basic: the user name); empty on a stored part keeps the stored one. */
  value: string;
  /** The Basic password. */
  secondary: string;
  stored: boolean;
  hint: string;
};

let counter = 0;
export const newPart = (kind: PartKind = "header"): PartForm => ({ key: `new-${++counter}`, kind, name: "", value: "", secondary: "", stored: false, hint: "" });

/** The server's parts as the form starts: stored, without values (a server from before the list has its one header). */
export function partsOf(server?: McpServer): PartForm[] {
  const list: { kind: PartKind; name?: string; hint: string }[] =
    server?.credentials ?? (server?.hasAuth && server.authHeaderName ? [{ kind: "header", name: server.authHeaderName, hint: server.authValueHint }] : []);
  return list.map((c, i) => ({ key: `stored-${i}`, kind: c.kind, name: c.name ?? "", value: "", secondary: "", stored: true, hint: c.hint }));
}

const headerPattern = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$/;
const queryPattern = /^[A-Za-z0-9_.-]{1,64}$/;
const reservedPrefix = /^mcp-gateway-/i;

/** Whether the part sets the Authorization header: at most one may, and none in OAuth mode. */
export const setsAuthorization = (p: Pick<PartForm, "kind" | "name">) => p.kind === "bearer" || p.kind === "basic" || (p.kind === "header" && p.name.trim().toLowerCase() === "authorization");

export type PartErrors = { name?: string; value?: string; secondary?: string };

/**
 * What's wrong with the parts before they're sent, by part key. `originMoved`: the URL is on another origin, so
 * a stored part without a new value can't stay.
 */
export function partProblems(parts: PartForm[], opts: { originMoved?: boolean } = {}): Record<string, PartErrors> {
  const out: Record<string, PartErrors> = {};
  const seen = new Set<string>();
  let authorization = false;
  for (const p of parts) {
    const e: PartErrors = {};
    const name = p.name.trim();
    if (p.kind === "header" && !headerPattern.test(name)) e.name = "Use a header name such as X-API-Key (letters, digits and - only).";
    if (p.kind === "header" && reservedPrefix.test(name)) e.name = "Names starting with MCP-Gateway- belong to the portal.";
    if (p.kind === "query" && (!queryPattern.test(name) || name.toLowerCase().startsWith("mcp-"))) e.name = "Use 1 to 64 letters, digits, dots, hyphens or underscores, not starting with mcp-.";
    const key = `${p.kind}:${name.toLowerCase()}`;
    if (!e.name && seen.has(key)) e.name = p.kind === "header" || p.kind === "query" ? "Another part has this name." : "There is already a part of this kind.";
    seen.add(key);
    if (!e.name && setsAuthorization(p)) {
      if (authorization) e.name = "Only one part can set the Authorization header (a header named Authorization, a bearer or a basic part).";
      authorization = true;
    }
    const entered = p.value !== "" || p.secondary !== "";
    if (!p.stored || entered || opts.originMoved) {
      const why = !p.stored ? undefined : opts.originMoved && !entered ? "The URL moves to another host, so enter this value again, or remove the part." : undefined;
      if (!p.value) e.value = why ?? (p.kind === "basic" ? "Enter the user name." : "Enter the value.");
      if (p.kind === "basic" && !p.secondary) e.secondary = why ?? "Enter the password.";
      if (p.kind === "basic" && p.value.includes(":")) e.value = "A user name can't contain a colon.";
    }
    if (e.name || e.value || e.secondary) out[p.key] = e;
  }
  return out;
}

/** One stored part in a line, without its value: "X-Tenant: ••••0001", "?sig=••••1234", "Authorization: Bearer ••••abcd". */
export function partSummary(p: Pick<PartForm, "kind" | "name" | "hint">): string {
  const dots = `••••${p.hint}`;
  switch (p.kind) {
    case "header":
      return `${p.name}: ${dots}`;
    case "bearer":
      return `Authorization: Bearer ${dots}`;
    case "basic":
      return `Authorization: Basic (user and password ••••${p.hint})`;
    case "query":
      return `?${p.name}=${dots}`;
  }
}

/** The part as the request names it. */
function inputOf(p: PartForm): CredentialInput {
  const named = p.kind === "header" || p.kind === "query" ? { name: p.name.trim() } : {};
  if (p.stored && !p.value && !p.secondary) return { kind: p.kind, ...named, keep: true };
  return { kind: p.kind, ...named, value: p.value, ...(p.kind === "basic" ? { secondary: p.secondary } : {}) };
}

/** The request's `credentials`, or undefined when nothing about them changed (the server keeps them). */
export function credentialsBody(parts: PartForm[], server?: McpServer): CredentialInput[] | undefined {
  const before = partsOf(server);
  const same = parts.length === before.length && parts.every((p, i) => p.stored && p.kind === before[i]?.kind && p.name === before[i]?.name && !p.value && !p.secondary);
  return same ? undefined : parts.map(inputOf);
}
