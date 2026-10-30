/*
 * Server governance in words (decision 88): the sensitivity labels and what a
 * gateway's ceiling does with them, the lifecycle, and the banner a deprecated
 * or retired server shows. Shared by the team's server page, the catalog and
 * the gateway settings.
 */
import type { Schemas } from "../../api/client";

export type Sensitivity = Schemas["Sensitivity"];
export type ServerLifecycle = Schemas["ServerLifecycle"];

/** Lowest first, as the API orders them. */
export const sensitivities: Sensitivity[] = ["public", "internal", "confidential", "restricted"];

export const sensitivityLabels: Record<Sensitivity, string> = {
  public: "Public",
  internal: "Internal",
  confidential: "Confidential",
  restricted: "Restricted",
};

export const sensitivityHelp: Record<Sensitivity, string> = {
  public: "Nothing in it is secret; anyone may see what it returns.",
  internal: "For people at the company. The default until its owners label it.",
  confidential: "Business-sensitive data. A gateway whose ceiling is lower never serves it.",
  restricted: "The most sensitive data. Only gateways with no ceiling serve it.",
};

export const sensitivityTone = { public: "neutral", internal: "info", confidential: "warning", restricted: "danger" } as const;

/**
 * What an unconfirmed label means. A server is labelled Internal until someone says otherwise, so Internal on its own
 * doesn't say a person checked it; only an owner or admin of the team sending a label (even Internal) confirms it.
 * It is bookkeeping: gateways read the label, never this.
 */
export const unconfirmedTitle = "Sensitivity not confirmed";
export const unconfirmedText = (label: Sensitivity) =>
  label === "internal"
    ? "Internal is only the default until someone checks it, and nobody on the team has. Confirm that Internal is right for what this server returns, or choose another label."
    : `Nobody on the team has confirmed the label ${sensitivityLabels[label]}. Confirm it, or choose another label.`;
export const unconfirmedNote = "Confirming changes nothing about what gateways serve or who may use the server.";

/** Raising the label sends a published server back to review under approval_required. */
export const raises = (before: Sensitivity, after: Sensitivity) => sensitivities.indexOf(after) > sensitivities.indexOf(before);

export const lifecycleLabels: Record<ServerLifecycle, string> = { active: "Active", deprecated: "Deprecated", sunset: "Sunset" };

/** A gateway's ceiling in a sentence (the default, restricted, has none). */
export function ceilingText(ceiling: Sensitivity | undefined) {
  const c = ceiling ?? "restricted";
  return c === "restricted" ? "No ceiling: it serves servers of every label." : `It serves servers labelled ${sensitivityLabels[c].toLowerCase()} or lower, and lists the rest as unavailable.`;
}

type Retiring = { lifecycle: ServerLifecycle; sunsetAt?: string | null; replacement?: { name: string } | null };

/** The sentence under a deprecation or sunset banner's title. */
export function retirementText(g: Retiring): string {
  const replacement = g.replacement ? ` Use ${g.replacement.name} instead.` : "";
  if (g.lifecycle === "sunset") return `No gateway serves it any more.${replacement}`;
  const when = g.sunsetAt ? ` It stops being served on ${new Date(g.sunsetAt).toLocaleString()}.` : " It will be retired; no date is set yet.";
  return `It is still served.${when}${replacement}`;
}
