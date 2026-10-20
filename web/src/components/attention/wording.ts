/*
 * The attention items in the app's own words, built from their fields (the API's `summary` is one English line for
 * scripts and logs). Each kind says what is wrong, which time matters ("since", "first expires") and what its button
 * does. docs/admin-overview.md lists the kinds.
 */
import type { Schemas } from "../../api/client";
import { plural } from "../../lib/format";

export type AttentionItem = Schemas["AttentionItem"];
export type AttentionKind = Schemas["AttentionKind"];
export type Severity = Schemas["AttentionSeverity"];

export const severityOrder: Severity[] = ["critical", "warning", "info"];
export const severityLabels: Record<Severity, string> = { critical: "Critical", warning: "Warnings", info: "For your information" };
export const severityTone = { critical: "danger", warning: "warning", info: "info" } as const;

export type Wording = {
  /** What is wrong, in a line. */
  title: string;
  /** The label of the time that matters ("Failing since"), when the item has one. */
  atLabel?: string;
  /** The button that follows the item's link. */
  action: string;
};

const server = (item: AttentionItem) => item.subject?.name ?? "A server";
const n = (item: AttentionItem) => item.count ?? 1;
const ofTeam = (item: AttentionItem) => (item.team ? ` of ${item.team.name}` : "");

const wording: Record<AttentionKind, (item: AttentionItem) => Wording> = {
  server_failing: (i) => ({ title: `${server(i)} is failing its health checks`, atLabel: "Failing since", action: "Open server" }),
  upstream_signin_lapsed: (i) => ({ title: `${server(i)} needs its sign-in renewed`, atLabel: "Lapsed", action: "Open server" }),
  review_pending: (i) => ({ title: `${plural(n(i), "server")}${i.team ? ` of ${i.team.name}` : ""} waiting for review`, atLabel: "Oldest waiting since", action: i.link?.type === "servers" ? "See servers" : "Open review queue" }),
  capabilities_changed: (i) => ({ title: `${server(i)} has ${plural(n(i), "capability change")} held back from the catalog`, action: "Review changes" }),
  personal_keys_expiring: (i) => ({ title: `${plural(n(i), "personal API key")} expire${n(i) === 1 ? "s" : ""} within 14 days`, atLabel: "First expires", action: "Open" }),
  service_account_keys_expiring: (i) => ({ title: `${plural(n(i), "service account key")}${ofTeam(i)} expire${n(i) === 1 ? "s" : ""} within 14 days`, atLabel: "First expires", action: "Open service accounts" }),
  automation_tokens_expiring: (i) => ({
    title: `${plural(n(i), i.team ? "publisher token" : "platform token")}${ofTeam(i)} expire${n(i) === 1 ? "s" : ""} within 14 days`,
    atLabel: "First expires",
    action: "Open automation tokens",
  }),
  connections_reconsent: (i) => ({ title: `${plural(n(i), "connected account")} need${n(i) === 1 ? "s" : ""} to be connected again`, action: "Open auth providers" }),
  gateways_disabled: (i) => ({ title: `${plural(n(i), "gateway")} switched off`, action: "Open gateways" }),
  rate_limited: (i) => ({ title: `${plural(n(i), "call")} refused by a rate limit in the last 24 hours`, action: "Open usage" }),
  server_certificate_expiring: (i) => ({
    title: `The client certificate of ${server(i)} ${i.severity === "critical" ? "has expired" : "expires within 14 days"}`,
    atLabel: i.severity === "critical" ? "Expired" : "Expires",
    action: "Open server",
  }),
  notification_failures: (i) => ({ title: `${plural(n(i), "notification destination")}${ofTeam(i)} failing or stopped`, atLabel: "Latest failure", action: "Open notification settings" }),
};

export const wordsFor = (item: AttentionItem): Wording => wording[item.kind](item);

/** What a kind counts when more exist than the list shows ("and 12 more failing servers"). */
export const moreNouns: Partial<Record<AttentionKind, string>> = {
  server_failing: "failing servers",
  upstream_signin_lapsed: "servers with a lapsed sign-in",
  capabilities_changed: "servers with held-back changes",
  server_certificate_expiring: "servers with an expiring client certificate",
  service_account_keys_expiring: "teams with expiring service account keys",
  automation_tokens_expiring: "teams with expiring tokens",
};
