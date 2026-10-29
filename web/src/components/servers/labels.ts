/*
 * The registry's words (MCP servers, their capabilities, health and
 * publishing), shared by the team's pages, the catalog and Admin.
 */
import type { Schemas } from "../../api/client";
import { plural } from "../../lib/format";

export type McpServer = Schemas["McpServer"];
export type McpCapability = Schemas["McpCapability"];
export type PublishState = Schemas["PublishState"];
export type PublishPolicy = Schemas["PublishPolicy"];
export type CapabilityKind = Schemas["CapabilityKind"];
export type CapabilityCounts = Schemas["CapabilityCounts"];
export type ServerHealth = Schemas["ServerHealth"];
export type ErrorClass = Schemas["McpErrorClass"];

export const publishStateLabels: Record<PublishState, string> = {
  private: "Private",
  pending: "Waiting for review",
  published: "Published",
  rejected: "Rejected",
};

/** What each publish state means, for the Catalog card. */
export const publishStateHelp: Record<PublishState, string> = {
  private: "Only this team sees the server. It can use it without any review.",
  pending: "A platform admin is reviewing the server. It's not in the company catalog yet.",
  published: "The server is in the company catalog with its approved capabilities.",
  rejected: "A platform admin didn't approve the server for the catalog. It stays private to the team.",
};

/**
 * What the server's publish state means. A pending server that was reviewed before (its URL changed after an
 * approval, or the team asked again after a rejection) waits for a review again.
 */
export function publishStateText(server: Pick<McpServer, "publishState" | "publishReviewedAt">) {
  if (server.publishState === "pending" && server.publishReviewedAt) return "It's waiting for a platform admin to review it again, and isn't in the company catalog until then.";
  return publishStateHelp[server.publishState];
}

export const policyLabels: Record<PublishPolicy, string> = {
  approval_required: "Approval required",
  self_publish: "Self-publish",
};

/** The effective policy in a sentence ("the team's" or a team's name as `who`). */
export function policyHelp(policy: PublishPolicy, who = "the team's") {
  return policy === "approval_required"
    ? "A platform admin reviews each server, and each changed capability, before it reaches the company catalog."
    : `${who.charAt(0).toUpperCase()}${who.slice(1)} owners and admins publish servers and approve changed capabilities themselves, without a review.`;
}

export const kindOrder: CapabilityKind[] = ["tool", "resource", "resource_template", "prompt"];

export const kindLabels: Record<CapabilityKind, { one: string; many: string }> = {
  tool: { one: "tool", many: "tools" },
  resource: { one: "resource", many: "resources" },
  resource_template: { one: "resource template", many: "resource templates" },
  prompt: { one: "prompt", many: "prompts" },
};

/** "Tools", "Resource templates". */
export const kindTitle = (kind: CapabilityKind) => {
  const many = kindLabels[kind].many;
  return many.charAt(0).toUpperCase() + many.slice(1);
};

/** The count of a kind in a CapabilityCounts. */
export const countOf = (counts: CapabilityCounts, kind: CapabilityKind) =>
  ({ tool: counts.tools, resource: counts.resources, resource_template: counts.resourceTemplates, prompt: counts.prompts })[kind];

export const totalCount = (counts: CapabilityCounts) => counts.tools + counts.resources + counts.resourceTemplates + counts.prompts;

/** "3 tools · 1 prompt", or "Nothing listed". */
export function countsText(counts: CapabilityCounts) {
  const parts = kindOrder.filter((k) => countOf(counts, k) > 0).map((k) => plural(countOf(counts, k), kindLabels[k].one, kindLabels[k].many));
  return parts.length ? parts.join(" · ") : "Nothing listed";
}

/** Why a connection failed, in words. */
export const errorClassLabels: Record<ErrorClass, string> = {
  unavailable: "Couldn't reach the server",
  auth: "Credentials refused",
  not_found: "Not found: check the URL",
  rate_limited: "Rate limited",
  bad_request: "Request refused",
  bad_response: "Unexpected response: is this an MCP server?",
  config: "Settings problem",
  timeout: "No answer in time",
  too_large: "Response too large",
  not_allowed: "Address not allowed: private, loopback or a redirect",
  tls: "TLS problem: certificate or client certificate",
  server_busy: "Server concurrency limit reached",
  circuit_open: "Server circuit open while it recovers",
};

export const healthLabels: Record<ServerHealth["status"], string> = { healthy: "Healthy", failing: "Failing", unknown: "Not checked yet" };

/** An oauth server's scheduled check got the expected sign-in challenge: reachable, and calls need each person's sign-in. */
export const signInRequiredLabel = "Reachable — requires sign-in";

/** The health in words: "Healthy", or "Reachable — requires sign-in" for an oauth server's unauthenticated check. */
export const healthText = (h: Pick<ServerHealth, "status" | "signInRequired">) => (h.status === "healthy" && h.signInRequired ? signInRequiredLabel : healthLabels[h.status]);

/** A failure in one line: "Credentials refused (HTTP 401)". */
export function failureText(r: { errorClass?: ErrorClass; httpStatus?: number }) {
  const what = r.errorClass ? errorClassLabels[r.errorClass] : "Failed";
  return r.httpStatus ? `${what} (HTTP ${r.httpStatus})` : what;
}

/** The portal's own wording for each error class: it says no more than the class label does. */
const genericMessages: RegExp[] = [
  /^The server refused the credentials \(HTTP \d+\)\.?$/,
  /^The server answered 404: check the URL\.?$/,
  /^The server is rate limiting requests \(HTTP \d+\)\.?$/,
  /^The server refused the request \(HTTP \d+\)\.?$/,
  /^The server answered HTTP \d+\.?$/,
  /^The server didn't answer in time\.?$/,
  /^The server's address is not allowed \(private, loopback or link-local, or a redirect\)\.?$/,
  /^The test failed\.?$/,
];

/** The server's message about a failure, when it adds something to the class label (else undefined). */
export function failureDetail(r: { message?: string | null }) {
  const msg = r.message?.trim();
  if (!msg || genericMessages.some((re) => re.test(msg))) return undefined;
  return msg;
}

/** The host of a URL ("status.example.com"), or the text as typed when it isn't one. */
export function urlHost(url: string) {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/** A server slug suggested from its name: lowercase, hyphen-separated, at most 48 characters. */
export function serverSlug(name: string) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+/, "")
    .slice(0, 48)
    .replace(/-+$/, "");
}

export const slugPattern = /^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/;

/** The untrusted-text warning, said the same way wherever capabilities are shown. */
export const untrustedText = "Names, descriptions and schemas come from the server, and a model reads them as instructions. Treat them as untrusted text.";

/** The warning for people who approve (platform admins; owners and admins under self_publish). */
export const untrustedApproverText = `${untrustedText} Read them before you approve, and again when they change.`;
