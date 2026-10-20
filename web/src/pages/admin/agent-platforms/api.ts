/*
 * Trusted agent platforms (decisions 65 and 66, docs/agent-platforms.md): the queries and operations of Admin →
 * Trusted agent platforms, the words for a failed key fetch, and the checks that catch a mistyped issuer before
 * the server does (it has the last word: 422 invalid_issuer, url_not_allowed). Never a secret: the keys are public.
 */
import { queryOptions } from "@tanstack/react-query";
import { api, ifMatch, type Schemas, unwrap } from "@/api/client";

export type AgentPlatform = Schemas["AgentPlatform"];
export type AgentPlatformRelay = Schemas["AgentPlatformRelay"];
export type TestResult = Schemas["AgentPlatformTestResult"];

export const platformsKey = ["admin", "agent-platforms"];
export const relaysKey = (id: string) => [...platformsKey, id, "relays"];

export const platformsQuery = () =>
  queryOptions({ queryKey: platformsKey, queryFn: async () => unwrap(await api.GET("/v1/admin/agent-platforms")) });

export const relaysQuery = (id: string) =>
  queryOptions({
    queryKey: relaysKey(id),
    queryFn: async () => unwrap(await api.GET("/v1/admin/agent-platforms/{platformId}/relays", { params: { path: { platformId: id } } })),
  });

export const createPlatform = async (body: Schemas["AgentPlatformCreate"]) => unwrap(await api.POST("/v1/admin/agent-platforms", { body }));

export const updatePlatform = async (p: AgentPlatform, body: Schemas["AgentPlatformUpdate"]) =>
  unwrap(await api.PATCH("/v1/admin/agent-platforms/{platformId}", { params: { path: { platformId: p.id }, header: ifMatch(p.revision) }, body }));

export const deletePlatform = async (p: AgentPlatform) => unwrap(await api.DELETE("/v1/admin/agent-platforms/{platformId}", { params: { path: { platformId: p.id } } }));

export const testPlatform = async (p: AgentPlatform) => unwrap(await api.POST("/v1/admin/agent-platforms/{platformId}/test", { params: { path: { platformId: p.id } } }));

export const markRelay = async (platformId: string, serviceAccountId: string) =>
  unwrap(await api.PUT("/v1/admin/agent-platforms/{platformId}/relays/{serviceAccountId}", { params: { path: { platformId, serviceAccountId } } }));

export const clearRelay = async (platformId: string, serviceAccountId: string) =>
  unwrap(await api.DELETE("/v1/admin/agent-platforms/{platformId}/relays/{serviceAccountId}", { params: { path: { platformId, serviceAccountId } } }));

/** The limits of the API. */
export const maxName = 100;
export const maxUrl = 500;

/** Why a key fetch failed, in words (AgentPlatformFetch.error). */
export const fetchErrorLabels: Record<string, string> = {
  not_allowed: "The portal may not connect to the JWKS address. It must use https (plain http is never allowed). Internal addresses need an entry in Admin › Internal networks; loopback and metadata addresses are never allowed.",
  redirect: "The JWKS address redirected. The portal never follows redirects: enter the final address.",
  timeout: "The platform didn't answer in 5 seconds.",
  unreachable: "The portal couldn't reach the platform.",
  http_status: "The platform answered with an error status.",
  content_type: "The answer isn't JSON (application/json or application/jwk-set+json).",
  too_large: "The answer is over 64 KiB.",
  invalid_json: "The answer isn't a JSON Web Key Set.",
  no_usable_keys: "The set has no usable keys: only public ES256 (P-256) keys with a key ID are accepted.",
};

export const fetchErrorLabel = (code: string | null | undefined, status?: number | null) => {
  const text = (code && fetchErrorLabels[code]) || "The key fetch failed.";
  return code === "http_status" && status ? `${text} (HTTP ${status})` : text;
};

/** What's wrong with an issuer before it reaches the server: https, no query or fragment. */
export function issuerProblem(value: string): string | undefined {
  const v = value.trim();
  if (!v) return "Enter the issuer: the platform's address exactly as it writes it in the iss claim.";
  if (v !== value || /\s/.test(v)) return "Remove the spaces.";
  let url: URL;
  try {
    url = new URL(v);
  } catch {
    return "Enter a full https address, such as https://agents.example.com.";
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return "The issuer must be an https address.";
  if (url.username || url.password) return "Remove the user name and password from the address.";
  if (url.search || url.hash) return "Remove the query and fragment: an issuer has none.";
  if (url.protocol === "http:") return "The issuer must be an https address.";
  return undefined;
}
