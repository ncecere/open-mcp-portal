/*
 * The notification events in plain words: what each is called, who receives it and where it can be sent. The names
 * are the contract's NotificationEventType (docs/notifications.md); the words are the web app's.
 */
import type { Schemas } from "../../api/client";

export type NotificationEvent = Schemas["NotificationEventType"];

export const allEvents = [
  "server.unhealthy",
  "server.recovered",
  "capability.changed",
  "publish.requested",
  "publish.decided",
  "connection.needs_reconsent",
  "upstream_signin.lapsed",
  "key.expiring",
] as const satisfies readonly NotificationEvent[];

export const eventLabels: Record<NotificationEvent, string> = {
  "server.unhealthy": "A server is failing",
  "server.recovered": "A server recovered",
  "capability.changed": "A published server's capabilities changed",
  "publish.requested": "A server is waiting for review",
  "publish.decided": "A review was decided",
  "connection.needs_reconsent": "A connected account needs you to sign in again",
  "upstream_signin.lapsed": "A server's sign-in lapsed",
  "key.expiring": "A key or token expires soon",
};

/** What happens and when, in a line. */
export const eventDescriptions: Record<NotificationEvent, string> = {
  "server.unhealthy": "Three health checks in a row failed. Sent once per incident, with a reminder every 24 hours while it lasts.",
  "server.recovered": "A server that was failing passed a check again.",
  "capability.changed": "A published server's tools, resources or prompts changed or grew. The changes are held back from the catalog until a platform admin approves them.",
  "publish.requested": "A server was sent for review: a first request, or sent back after its URL, sign-in or requirement changed.",
  "publish.decided": "A platform admin approved or rejected one of your team's servers.",
  "connection.needs_reconsent": "A personal or team-shared account (GitHub, Google…) stopped working and needs reconnecting.",
  "upstream_signin.lapsed": "The sign-in that discovers an OAuth server's tools expired and needs someone to sign in again.",
  "key.expiring": "A key or token will expire in 7 days: your own API key, a service account key, a publisher token or a platform token.",
};

/** Who receives each event in the portal and by email. */
export const eventRecipients: Record<NotificationEvent, string> = {
  "server.unhealthy": "Team owners, admins and editors",
  "server.recovered": "Team owners, admins and editors",
  "capability.changed": "Team owners, admins and editors",
  "publish.requested": "Platform admins",
  "publish.decided": "Team owners and admins",
  "connection.needs_reconsent": "The person whose account it is, or the owning team's owners and admins for a shared connection",
  "upstream_signin.lapsed": "Team owners, admins and editors",
  "key.expiring": "Your own keys: you. Service account keys and publisher tokens: team owners and admins. Platform tokens: platform admins",
};

/** Events a team's webhook can receive (key.expiring: service account keys and publisher tokens). */
export const teamDestinationEvents: NotificationEvent[] = ["server.unhealthy", "server.recovered", "capability.changed", "publish.decided", "upstream_signin.lapsed", "key.expiring"];

/** Events only a platform webhook receives of its own (platform tokens expiring and reviews waiting). */
export const platformOwnEvents: NotificationEvent[] = ["publish.requested", "key.expiring"];

/** Events a platform webhook receives when it also takes every team's events. */
export const platformDestinationEvents: NotificationEvent[] = ["publish.requested", "server.unhealthy", "server.recovered", "capability.changed", "publish.decided", "upstream_signin.lapsed", "key.expiring"];

/** The events a destination of this scope can subscribe to (the API refuses others with 422 invalid_events). */
export const destinationEvents = (scope: "team" | "platform", teamEvents: boolean): NotificationEvent[] =>
  scope === "team" ? teamDestinationEvents : teamEvents ? platformDestinationEvents : platformOwnEvents;

export const eventLabel = (event: string) => eventLabels[event as NotificationEvent] ?? event;
