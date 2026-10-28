/*
 * A gateway's capabilities grouped by server: the name clients see
 * (server__name), the title and description as the server wrote them (plain
 * text: untrusted), its kind, whether it's served now, the account it
 * needs ("Needs GitHub (repo)") and, on team gateways, the lowest team role
 * that may use it. In the person's own view (My gateways), whether their
 * connected account covers it.
 */
import type { ReactNode } from "react";
import { RequiresBadge } from "../providers/requires";
import { serviceAccountsCant } from "../providers/labels";
import { Badge, StatusBadge } from "@/components/ui/badge/badge";
import { CaptureBadge } from "../capture";
import { ClassificationBadges } from "../servers/classification";
import { AvailabilityBadge } from "./badges";
import { type GatewayCapability, gatewayKindLabels, minRoleLabels } from "./labels";
import g from "./gateways.module.css";

/** Items grouped by a key, in first-seen order. */
export function groupBy<T>(items: T[], key: (x: T) => string): [string, T[]][] {
  const out = new Map<string, T[]>();
  for (const x of items) {
    const k = key(x);
    const list = out.get(k);
    if (list) list.push(x);
    else out.set(k, [x]);
  }
  return [...out.entries()];
}

type Props = {
  items: GatewayCapability[];
  /** Show availability badges (the gateway's own pages; My gateways lists only available ones). */
  availability?: boolean;
  /** Show the minimum role (team gateways). */
  roles?: boolean;
  /** The person's own view: whether their connection covers each capability that needs an account. */
  connections?: boolean;
};

export function CapabilityList({ items, availability = true, roles = false, connections = false }: Props) {
  return (
    <div className={g.stack}>
      {groupBy(items, (c) => c.serverId).map(([id, caps]) => {
        const first = caps[0]!;
        return (
          <section key={id} className={g.group} aria-labelledby={`server-${id}`}>
            <h3 id={`server-${id}`} className={g.groupHead}>
              {first.serverName}
              <span className={g.groupMeta}>
                {first.serverSlug} · {first.teamSlug}
              </span>
            </h3>
            <ul className={g.list}>
              {caps.map((c) => (
                <CapabilityRow key={c.capabilityId} cap={c} side={<RowBadges cap={c} availability={availability} roles={roles} connections={connections} />} />
              ))}
            </ul>
          </section>
        );
      })}
    </div>
  );
}

function RowBadges({ cap, availability, roles, connections }: { cap: GatewayCapability; availability: boolean; roles: boolean; connections: boolean }) {
  return (
    <>
      <Badge size="sm" variant="outline">
        {gatewayKindLabels[cap.kind].one}
      </Badge>
      <ClassificationBadges cap={cap} />
      {cap.requires && <RequiresBadge req={cap.requires} note={connections ? undefined : serviceAccountsCant} />}
      {cap.serverCapturesPayloads && <CaptureBadge label={connections ? "Records what you send" : "Server records contents"} />}
      {cap.requires &&
        connections &&
        (cap.requires.connected ? (
          <StatusBadge size="sm" tone="success">
            Connected
          </StatusBadge>
        ) : (
          <StatusBadge size="sm" tone="warning">
            Not connected
          </StatusBadge>
        ))}
      {roles && cap.minRole && cap.minRole !== "member" && (
        <Badge size="sm" tone="info">
          {minRoleLabels[cap.minRole]}
        </Badge>
      )}
      {availability && <AvailabilityBadge cap={cap} />}
    </>
  );
}

type RowCap = Pick<GatewayCapability, "capabilityId" | "kind" | "name" | "exposedName" | "title" | "description">;

/** One capability's row: the exposed name, title and description, with badges or controls at the side. */
export function CapabilityRow({ cap, side, problem, children }: { cap: RowCap; side?: ReactNode; problem?: string; children?: ReactNode }) {
  return (
    <li className={g.row} data-problem={problem ? "" : undefined} aria-label={`${gatewayKindLabels[cap.kind].one}: ${cap.exposedName}`}>
      <div className={g.rowMain}>
        <span className={g.rowName}>
          <code className={g.exposed}>{cap.exposedName}</code>
          {cap.title && cap.title !== cap.name && <span className={g.groupMeta}>{cap.title}</span>}
        </span>
        {cap.description && <p className={g.description}>{cap.description}</p>}
        {problem && <p className={g.problem}>{problem}</p>}
        {children}
      </div>
      {side && <div className={g.rowSide}>{side}</div>}
    </li>
  );
}
