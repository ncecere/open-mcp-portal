/* Health, publish state, enabled and capability state badges of MCP servers. */
import type { Schemas } from "../../api/client";
import { Badge, StatusBadge } from "@/components/ui/badge/badge";
import { RelativeTime } from "../templates/list-page";
import s from "../../pages/shared.module.css";
import { healthText, type McpCapability, type PublishState, publishStateLabels, type ServerHealth } from "./labels";
import m from "./servers.module.css";

const healthTone = { healthy: "success", failing: "danger", unknown: "neutral" } as const;

/** "● Healthy since 3 hours ago", "● Reachable — requires sign-in", "● Failing since yesterday" or "● Not checked yet". */
/** `stacked`: the time under the badge, in small type (table cells: the column stays narrow on a phone). */
export function HealthBadge({ health, since = true, stacked = false }: { health: ServerHealth; since?: boolean; stacked?: boolean }) {
  const when = health.statusSince ?? health.checkedAt;
  return (
    <span className={stacked ? m.stacked : m.inline}>
      <StatusBadge tone={healthTone[health.status]}>{healthText(health)}</StatusBadge>
      {since && health.status !== "unknown" && when && (
        <span className={stacked ? m.since : s.muted}>
          since <RelativeTime value={when} />
        </span>
      )}
    </span>
  );
}

const publishTone = { private: "neutral", pending: "info", published: "success", rejected: "danger" } as const;

export function PublishStateBadge({ state }: { state: PublishState }) {
  return <Badge tone={publishTone[state]}>{publishStateLabels[state]}</Badge>;
}

/** "2 changes waiting": capabilities of a published server hidden from the catalog until approved. */
export function PendingChangesBadge({ count }: { count: number }) {
  if (count <= 0) return null;
  return (
    <Badge tone="warning" size="sm">
      {count === 1 ? "1 change waiting" : `${count} changes waiting`}
    </Badge>
  );
}

/** "Sign-in per person" for a server in oauth mode (each person signs in to its own service), "Own key per person" for person_secret; nothing otherwise. */
export function SignInBadge({ authMode }: { authMode?: Schemas["McpServerAuthMode"] }) {
  if (authMode === "person_secret") {
    return (
      <Badge size="sm" tone="info" title="Each person enters their own API key for the server before calling it.">
        Own key per person
      </Badge>
    );
  }
  if (authMode !== "oauth") return null;
  return (
    <Badge size="sm" tone="info" title="Each person signs in to the server's own service (OAuth) before calling it.">
      Sign-in per person
    </Badge>
  );
}

export function EnabledBadge({ enabled }: { enabled: boolean }) {
  return enabled ? <StatusBadge tone="success">Enabled</StatusBadge> : <StatusBadge tone="neutral">Disabled</StatusBadge>;
}

/**
 * A capability's state: gone (no longer listed), changed since approval, approved; or, on a server that's in or
 * on its way to the catalog, not approved. Private servers need no approval, so their capabilities get no badge.
 */
export function CapabilityStateBadge({ cap, inCatalog }: { cap: McpCapability; inCatalog: boolean }) {
  if (cap.goneAt) return <Badge tone="neutral">Gone</Badge>;
  if (cap.changed) return <Badge tone="warning">Changed</Badge>;
  if (cap.approved) return <Badge tone="success">Approved</Badge>;
  return inCatalog ? <Badge tone="neutral">Not approved</Badge> : null;
}
