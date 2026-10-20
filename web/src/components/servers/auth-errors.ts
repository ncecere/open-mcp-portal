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
    case "auth_conflict":
      if (reason === "authorization_twice") return { title: "Two parts set Authorization", message: conflictReasons[reason] ?? "" };
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
