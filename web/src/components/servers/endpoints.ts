import type { Schemas } from "../../api/client";
import type { McpServer } from "./labels";
import { credentialsBody, partProblems, partsOf, type PartForm } from "./credentials";
import { sameOrigin } from "./origin";
import { urlProblem } from "./server-fields";

export type EndpointForm = { key: string; id?: string; url: string; enabled: boolean; parts: PartForm[] };
let next = 0;
export const newEndpoint = (): EndpointForm => ({ key: `new-endpoint-${++next}`, url: "", enabled: true, parts: [] });
export function endpointFormsOf(server: McpServer): EndpointForm[] {
  return (server.endpoints ?? []).map((e) => ({ key: e.id, id: e.id, url: e.url, enabled: e.enabled, parts: partsOf({ ...server, credentials: e.credentials }) }));
}
function storedServer(server: McpServer, id?: string): McpServer {
  return { ...server, credentials: server.endpoints?.find((e) => e.id === id)?.credentials ?? [], hasAuth: false, authHeaderName: undefined };
}
export function endpointsBody(forms: EndpointForm[], server: McpServer, mode: string): Schemas["McpServerEndpointInput"][] | undefined {
  const same = JSON.stringify(forms) === JSON.stringify(endpointFormsOf(server));
  if (same && (forms.length === 0 || mode === (server.authMode ?? (server.hasAuth ? "static_header" : "none")))) return undefined;
  return forms.map((e) => ({ ...(e.id ? { id: e.id } : {}), url: e.url.trim(), enabled: e.enabled,
    ...(mode === "none" ? { credentials: [] } : { credentials: credentialsBody(e.parts, storedServer(server, e.id)) }),
  }));
}
export function endpointReviewChanged(forms: EndpointForm[], server: McpServer) {
  const shape = (rows: EndpointForm[]) => rows.map((e) => ({ id: e.id, url: e.url.trim(), enabled: e.enabled, parts: e.parts.map((p) => ({ kind: p.kind, name: p.name.trim() })) }));
  return JSON.stringify(shape(forms)) !== JSON.stringify(shape(endpointFormsOf(server)));
}
function urlKey(raw: string): string { try { const u = new URL(raw); return `${u.origin.toLowerCase().replace(/\.(?=:|$)/, "")}${u.pathname}${u.search}`; } catch { return raw; } }
export function endpointProblems(forms: EndpointForm[], server: McpServer, mode: string, dev: boolean, blocked: boolean) {
  const out: Record<string, { url?: string; parts: ReturnType<typeof partProblems>; noParts: boolean }> = {};
  const seen = new Set([urlKey(server.url)]);
  for (const e of forms) {
    const old = server.endpoints?.find((x) => x.id === e.id);
    const parts = mode === "static_header" ? partProblems(e.parts, { originMoved: Boolean(old && !sameOrigin(old.url, e.url.trim())) }) : {};
    const key = urlKey(e.url.trim());
    const url = urlProblem(e.url, dev) ?? (seen.has(key) ? "Every additional URL must differ from the primary and the other replicas." : undefined);
    seen.add(key);
    const noParts = mode === "static_header" && e.parts.length === 0;
    if (url || noParts || Object.keys(parts).length > 0 || blocked) out[e.key] = { url, parts, noParts };
  }
  return out;
}
