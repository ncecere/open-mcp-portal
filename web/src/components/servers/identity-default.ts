/*
 * The default of "Send identity token" on Add (decision 64): for a server with no authentication it follows the
 * address. The portal classifies the host (POST …/mcp-servers/identity-default: public, internal or unresolvable,
 * as saving would) and the switch starts off for public hosts, on for internal ones. The sentence says why.
 */
import { useQuery } from "@tanstack/react-query";
import { api, type Schemas, unwrap } from "../../api/client";
import { useDebounced } from "../../pages/admin/hooks";
import type { AuthMode } from "./upstream-auth";

export type IdentityDefault = Schemas["IdentityDefault"];

/** What Add knows about the default: the answer for the entered URL, and whether it is still being asked. */
export type IdentityBasis = { mode: AuthMode; hasUrl: boolean; checking: boolean; answer?: IdentityDefault };

/** Asks (after a pause in typing) only for a server with no authentication and a URL that is acceptable as typed. */
export function useIdentityDefault(team: string, url: string, mode: AuthMode, urlError: string | undefined): IdentityBasis {
  const typed = url.trim();
  const settled = useDebounced(typed, 400);
  const enabled = mode === "none" && !urlError && settled !== "" && settled === typed;
  const q = useQuery({
    queryKey: ["identity-default", team, settled],
    queryFn: async () => unwrap(await api.POST("/v1/teams/{team}/mcp-servers/identity-default", { params: { path: { team } }, body: { url: settled } })),
    enabled,
    retry: false,
    staleTime: 60_000,
  });
  const waiting = mode === "none" && !urlError && typed !== "" && (settled !== typed || q.isPending) && !q.isError;
  return { mode, hasUrl: typed !== "" && !urlError, checking: waiting, answer: enabled && !q.isError ? q.data : undefined };
}

/** The switch as the server will set it when it was not touched; undefined while that isn't known (the server decides). */
export function defaultIdentity(b: IdentityBasis): boolean | undefined {
  if (b.mode !== "none") return true;
  return b.answer?.sendIdentity;
}

/** Why the switch is where it is, in a sentence. */
export function identityBasisText(b: IdentityBasis): string {
  if (b.mode !== "none") return "Servers that use a header or their own sign-in start with this on.";
  if (b.answer?.basis === "public_host")
    return "This address is public and the server has no sign-in, so it is probably not run by your company. The switch starts off: no name, email or teams are sent. Turn it on if the server expects them.";
  if (b.answer?.basis === "internal_host") return "This address is on your internal network, so the server is probably your company's own. The switch starts on.";
  if (b.answer?.basis === "unresolved_host")
    return "The portal couldn't look this address up, so it can't tell whether the server is your company's. The switch starts off; turn it on if the server expects the token.";
  if (b.checking) return "Checking the address…";
  if (!b.hasUrl) return "Enter the address: for a server with no sign-in, the switch starts off when the address is public and on when it is internal.";
  return "The portal couldn't check this address. When you add the server, it sets the switch: off for a public address with no sign-in, on for an internal one.";
}
