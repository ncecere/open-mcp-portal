/*
 * The Settings tab's Authentication: what a save sends (only what changed:
 * the mode, the credential parts, the OAuth settings with a replace-only secret, the
 * identity switch), and what it does before it's saved: back to review
 * under approval_required (a switch to OAuth, another authorization server,
 * a new scope, another way of sending each person's own key, or the portal's own
 * OAuth client or its endpoint), everyone signed out of the server (a new URL,
 * authorization server or client), their sign-ins deleted (leaving OAuth), or
 * their keys deleted (a new URL, another placement, leaving the own-key mode).
 */
import type { Schemas } from "../../api/client";
import { plural } from "../../lib/format";
import { Alert } from "@/components/ui/alert/alert";
import type { McpServer } from "./labels";
import { credentialsBody, type PartForm, setsAuthorization } from "./credentials";
import { machineChanges, machineInput } from "./machine-auth";
import { secretChanged, secretInput } from "./person-secret";
import { type AuthChange, authModeOf, type DetectResult, oauthChanges, oauthInput, sendsIdentity, type UpstreamForm } from "./upstream-auth";

type Update = Schemas["McpServerUpdate"];

/** The PATCH's authentication fields; empty when nothing about it changed. */
export function settingsAuthBody(server: McpServer, f: { upstream: UpstreamForm }, parts: PartForm[], secret: string, detected?: DetectResult): Update {
  const before = authModeOf(server);
  const u = f.upstream;
  const identity = u.sendIdentity !== sendsIdentity(server) ? { sendIdentity: u.sendIdentity } : {};
  if (u.mode === "none") return { ...identity, ...(before !== "none" ? { authMode: "none" } : {}) };
  if (u.mode === "static_header") {
    const credentials = credentialsBody(parts, server);
    return { ...identity, ...(before !== "static_header" ? { authMode: "static_header" } : {}), ...(credentials ? { credentials } : {}) };
  }
  if (u.mode === "person_secret") {
    // Parts of the server's own credential may stay next to each person's key; they're sent only when edited.
    const credentials = credentialsBody(parts, server);
    const changed = before !== "person_secret" || secretChanged(server, u.secret);
    return {
      ...identity,
      ...(before !== "person_secret" ? { authMode: "person_secret" } : {}),
      ...(changed ? { personSecret: secretInput(u.secret) } : {}),
      ...(credentials ? { credentials } : {}),
    };
  }
  if (u.mode === "machine_oauth") {
    // The portal's own token goes in Authorization: a static part that sets it goes (other parts may stay).
    if (before !== "machine_oauth" || !server.machineOAuth) {
      const credentials = credentialsBody(parts.filter((p) => !setsAuthorization(p)), server);
      return { ...identity, authMode: "machine_oauth", machineOAuth: machineInput(u.machine, secret), ...(credentials ? { credentials } : {}) };
    }
    const changes = machineChanges(u.machine, secret, server.machineOAuth);
    return { ...identity, ...(changes ? { machineOAuth: changes } : {}) };
  }
  if (before !== "oauth" || !server.oauth) {
    // OAuth sends each person's token in Authorization: a static part that sets it goes (other parts may stay).
    const credentials = credentialsBody(parts.filter((p) => !setsAuthorization(p)), server);
    return { ...identity, authMode: "oauth", oauth: oauthInput(u.oauth, secret, detected), ...(credentials ? { credentials } : {}) };
  }
  const changes = oauthChanges(u.oauth, secret, server.oauth);
  return { ...identity, ...(changes ? { oauth: changes } : {}) };
}

const reviewWords: Record<NonNullable<AuthChange["review"]>, string> = {
  switch: "a switch to OAuth sign-in",
  secret: "another way of sending each person's own key",
  server: "another authorization server",
  scopes: "a scope it didn't ask for before",
  machine: "a switch to the portal's own OAuth client",
  machine_client: "another token endpoint or client",
  machine_scopes: "a scope it didn't ask for before",
  machine_target: "another audience or resource",
};

/** The warnings before a save: back to review, and what happens to the people signed in. */
export function AuthChangeNotes({ server, change, leavesCatalog }: { server: McpServer; change: AuthChange; leavesCatalog: boolean }) {
  const people = plural(server.oauth?.connectionCount ?? 0, "person", "people");
  return (
    <>
      {leavesCatalog && change.review && (
        <Alert tone="warning" title="The server will leave the catalog">
          Your team needs approval to publish, and this is {reviewWords[change.review]}, so it&apos;s reviewed again: once you save, {server.name} is out of the company
          catalog until a platform admin approves it. Narrowing scopes, a new secret or leaving OAuth never needs a review.
        </Alert>
      )}
      {change.connections === "reset" && (
        <Alert tone="warning" title="Everyone signs in again">
          {people} signed in to {server.name}. A new URL, authorization server or client makes their tokens useless, so they&apos;re erased when you save, and each
          person signs in again the next time they call it.
        </Alert>
      )}
      {change.connections === "deleted" && (
        <Alert tone="warning" title="Sign-ins are deleted">
          Leaving OAuth sign-in deletes the sign-ins of the {people} signed in to {server.name}, revoked at the authorization server where it allows it.
        </Alert>
      )}
    </>
  );
}
