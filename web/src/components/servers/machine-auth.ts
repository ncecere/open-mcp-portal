/*
 * A server's machine OAuth client as the form edits it (decision 73,
 * docs/machine-oauth.md): the token endpoint, the client ID and secret, the
 * scopes and, optionally, an audience or resource. The portal gets its own
 * token with the client credentials grant and sends it to the server on every
 * request, so there is nothing for a person to sign in to. The secret is
 * replace-only and never comes back: a stored client shows only a hint of its ID
 * and secret, and the secret is entered again whenever the token endpoint, the
 * client ID or the server's address moves to another host (F-1). The rules
 * mirror the server's (api/openapi.yaml); the server still decides.
 */
import type { Schemas } from "../../api/client";
import { scopesProblem } from "../providers/labels";
import type { McpServer } from "./labels";
import { sameOrigin } from "./origin";
import type { DetectResult } from "./upstream-auth";

export type MachineConfig = Schemas["McpServerMachineOAuth"];
export type MachineMethod = NonNullable<Schemas["McpServerMachineOAuthInput"]["tokenAuthMethod"]>;

export const machineMethods: MachineMethod[] = ["client_secret_basic", "client_secret_post"];
export const machineMethodLabels: Record<MachineMethod, string> = {
  client_secret_basic: "HTTP Basic: the client ID and secret in the Authorization header",
  client_secret_post: "In the request body",
};

/** The client as edited. clientId empty keeps the stored one; the secret is kept apart (replace-only). */
export type MachineForm = { tokenUrl: string; clientId: string; tokenAuthMethod: MachineMethod; scopes: string[]; audience: string; resource: string };

export const blankMachine: MachineForm = { tokenUrl: "", clientId: "", tokenAuthMethod: "client_secret_basic", scopes: [], audience: "", resource: "" };

export function machineFormOf(s?: McpServer): MachineForm {
  const c = s?.machineOAuth;
  return c ? { tokenUrl: c.tokenUrl, clientId: "", tokenAuthMethod: c.tokenAuthMethod, scopes: c.scopes, audience: c.audience ?? "", resource: c.resource ?? "" } : blankMachine;
}

export type MachineErrors = Partial<Record<"tokenUrl" | "machineClientId" | "machineSecret" | "machineScopes" | "machineResource", string>>;

/** Why the secret must be entered again, or undefined: the token endpoint, the client or the server's host changed (F-1). */
export function secretWhy(f: MachineForm, stored: MachineConfig | null | undefined, opts: { originMoved: boolean }): string | undefined {
  if (!stored) return undefined;
  if (f.tokenUrl.trim() !== stored.tokenUrl) return "token endpoint";
  if (f.clientId.trim()) return "client ID";
  return opts.originMoved ? "server's host" : undefined;
}

type Context = { server?: McpServer; secret: string; url: string };

/** What's wrong with the machine client before it's sent. */
export function machineProblems(mode: string, f: MachineForm, { server, secret, url }: Context): MachineErrors {
  if (mode !== "machine_oauth") return {};
  const out: MachineErrors = {};
  const stored = server?.machineOAuth;
  const endpoint = f.tokenUrl.trim();
  if (!endpoint) out.tokenUrl = "Enter the authorization server's token endpoint.";
  else if (!validEndpoint(endpoint)) out.tokenUrl = "Enter a full https address without a query, such as https://login.example.com/oauth/token.";
  if (!stored && !f.clientId.trim()) out.machineClientId = "Enter the client ID the authorization server gave the portal.";
  if (!secret) {
    const why = stored ? secretWhy(f, stored, { originMoved: Boolean(server) && !sameOrigin(server?.url ?? "", url.trim()) }) : "client";
    if (why) out.machineSecret = stored ? `Enter the client secret again: the ${why} changed, and the stored secret was entered for the old one.` : "Enter the client secret.";
  }
  const scopes = scopesProblem(f.scopes);
  if (scopes) out.machineScopes = scopes;
  if (f.resource.trim() && !validResource(f.resource.trim())) out.machineResource = "Enter a full address without a fragment, such as https://api.example.com/mcp.";
  return out;
}

function validEndpoint(v: string) {
  try {
    const u = new URL(v);
    return (u.protocol === "https:" || u.protocol === "http:") && !u.search && !u.hash && !u.username && !u.password;
  } catch {
    return false;
  }
}

function validResource(v: string) {
  try {
    return Boolean(new URL(v).host) && !v.includes("#");
  } catch {
    return false;
  }
}

/** The machineOAuth input for a new configuration (Add, or switching a server to the mode). */
export function machineInput(f: MachineForm, secret: string): Schemas["McpServerMachineOAuthInput"] {
  return {
    tokenUrl: f.tokenUrl.trim(),
    clientId: f.clientId.trim(),
    clientSecret: secret,
    tokenAuthMethod: f.tokenAuthMethod,
    scopes: f.scopes,
    ...(f.audience.trim() ? { audience: f.audience.trim() } : {}),
    ...(f.resource.trim() ? { resource: f.resource.trim() } : {}),
  };
}

/** The machineOAuth input for a server that's in the mode already: only what changed; undefined when nothing did. */
export function machineChanges(f: MachineForm, secret: string, stored: MachineConfig): Schemas["McpServerMachineOAuthInput"] | undefined {
  const same = (a: string[], b: string[]) => JSON.stringify(a) === JSON.stringify(b);
  const changes: Schemas["McpServerMachineOAuthInput"] = {
    ...(f.tokenUrl.trim() !== stored.tokenUrl ? { tokenUrl: f.tokenUrl.trim() } : {}),
    ...(f.clientId.trim() ? { clientId: f.clientId.trim() } : {}),
    ...(secret ? { clientSecret: secret } : {}),
    ...(f.tokenAuthMethod !== stored.tokenAuthMethod ? { tokenAuthMethod: f.tokenAuthMethod } : {}),
    ...(!same(f.scopes, stored.scopes) ? { scopes: f.scopes } : {}),
    ...(f.audience.trim() !== (stored.audience ?? "") ? { audience: f.audience.trim() } : {}),
    ...(f.resource.trim() !== (stored.resource ?? "") ? { resource: f.resource.trim() } : {}),
  };
  return Object.keys(changes).length ? changes : undefined;
}

/** What a save does to review: a switch to the mode, another endpoint or client, a new scope, another audience or resource. */
export type MachineReview = "machine" | "machine_client" | "machine_scopes" | "machine_target";

export function machineReview(server: McpServer, f: MachineForm): MachineReview | undefined {
  const stored = server.machineOAuth;
  if (server.authMode !== "machine_oauth" || !stored) return "machine";
  if (f.tokenUrl.trim() !== stored.tokenUrl || f.clientId.trim()) return "machine_client";
  if (f.scopes.some((s) => !stored.scopes.includes(s))) return "machine_scopes";
  if (f.audience.trim() !== (stored.audience ?? "") || f.resource.trim() !== (stored.resource ?? "")) return "machine_target";
  return undefined;
}

/** The form after a detection: the authorization server's token endpoint and the server's resource, where nothing was entered yet. */
export function machineFromDetection(r: DetectResult, before: MachineForm): MachineForm {
  const d = r.machineOAuth;
  if (!d) return before;
  return {
    ...before,
    tokenUrl: before.tokenUrl || d.tokenEndpoint,
    resource: before.resource || d.resource,
    tokenAuthMethod: before.tokenAuthMethod === "client_secret_basic" && d.tokenAuthMethods.length && !d.tokenAuthMethods.includes("client_secret_basic") ? d.tokenAuthMethods[0]! : before.tokenAuthMethod,
  };
}
