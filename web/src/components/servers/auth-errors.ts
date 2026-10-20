/*
 * The words for the portal's refusals about an MCP server's sign-in
 * (docs/phase7-upstream-oauth.md), for ErrorAlert's `describe`: what went
 * wrong and what to do, instead of the server's terse message.
 */
import { ApiError } from "../../api/client";

type Described = { title?: string; message: string };

/** details.problems of 422 oauth_discovery_failed, as the server worded them. */
function problemsOf(details: Record<string, unknown> | undefined): string {
  const list = Array.isArray(details?.problems) ? details.problems : [];
  const words = list.map((p) => (p && typeof p === "object" && "message" in p && typeof p.message === "string" ? p.message : "")).filter(Boolean);
  return words.length ? ` ${words.join(" ")}` : "";
}

const conflictReasons: Record<string, string> = {
  static_authorization: "OAuth sign-in sends each person's token in the Authorization header, so the server can't also have a static Authorization header. Remove that part, or use another header name.",
  authorization_twice: "Only one part of the credential can set the Authorization header: a header named Authorization, a bearer token or Basic. Remove one of them.",
  requirement: "OAuth sign-in replaces User authorization: each call carries the person's own token for this server. Remove the server's requirement first.",
};

const machineConflictReasons: Record<string, string> = {
  static_authorization: "The portal's own OAuth client sends its token in the Authorization header, so the server can't also have a static Authorization header. Remove that part, or use another header name.",
  requirement: "The portal's own OAuth client replaces User authorization: every call carries the portal's token. Remove the server's requirement first.",
};

const secretReasons: Record<string, string> = {
  token_url_changed: "the token endpoint changed",
  client_id_changed: "the client ID changed",
  origin_changed: "the server's address moves to another host",
  new: "there is none stored yet",
};

/** The error's title and message for the sign-in error codes; undefined for any other error. */
export function describeAuthError(err: unknown): Described | undefined {
  if (!(err instanceof ApiError)) return undefined;
  const reason = typeof err.details?.reason === "string" ? err.details.reason : "";
  switch (err.code) {
    case "oauth_discovery_failed":
      return { title: "The server's sign-in couldn't be discovered", message: `Nothing was saved.${problemsOf(err.details)} Press Detect sign-in to see what the server answers.` };
    case "oauth_registration_failed":
      return {
        title: "The authorization server refused to register the portal",
        message: "Nothing was saved. Try again, or create an OAuth app at the authorization server and enter its client ID and secret instead.",
      };
    case "auth_value_required":
      return {
        title: "Enter the credential values again",
        message: "Nothing was saved. The URL moves to another host, so stored values can't be reused there: enter every part's value again, or remove the credential.",
      };
    case "credentials_in_use":
      return { title: "The credential has several parts", message: "Reload the page: this server's credential is a list of parts, edited as a list." };
    case "client_secret_required":
      return {
        title: "Enter the client secret again",
        message: `Nothing was saved, and nothing was sent anywhere. The secret was entered for the old token endpoint, client and server host; ${secretReasons[reason] ?? "something it belongs to changed"}, so enter it again.`,
      };
    case "invalid_machine_oauth":
      return { title: "The portal's OAuth client is incomplete", message: "Enter the token endpoint, the client ID and the client secret." };
    case "auth_conflict":
      if (reason === "authorization_twice") return { title: "Two parts set Authorization", message: conflictReasons[reason] ?? "" };
      if (err.message.includes("machine_oauth")) return { title: "The portal's OAuth client can't be combined with this", message: machineConflictReasons[reason] ?? err.message };
      return { title: "OAuth sign-in can't be combined with this", message: conflictReasons[reason] ?? "OAuth sign-in excludes a static Authorization header and a User authorization requirement." };
    case "registration_unavailable":
      return { title: "That registration isn't offered", message: "The authorization server no longer offers this kind of registration. Press Detect sign-in again and choose another." };
    case "client_required":
      return { title: "Enter the client", message: "Enter the client ID and secret of the OAuth app you created at the authorization server (no secret only for a public client)." };
    case "provider_mismatch":
      return { title: "The platform provider doesn't match", message: "The linked platform provider was turned off, or its endpoints no longer match this server's authorization server. Choose another registration." };
    case "setup_reconsent_required":
      return {
        title: "Nobody's sign-in can read the capabilities",
        message: "The sign-in used to read them lapsed, was disconnected, or its person can no longer edit the server. Authorize as yourself to read them again.",
      };
    case "upstream_oauth":
      return { message: "This server uses OAuth sign-in: every call carries the person's own token for it, and its scopes come from the server, so a capability can't ask for another account." };
    case "not_oauth":
      return { title: "Not an OAuth server any more", message: "This server no longer uses OAuth sign-in, so there's nothing to sign in to. Reload the page." };
    default:
      return undefined;
  }
}
