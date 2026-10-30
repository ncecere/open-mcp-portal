/*
 * The attention items, grouped by severity (critical, warnings, information), each row with what is wrong in the
 * app's words, its team, when it started ("since 3 days ago") and a button that follows the item's link. When a
 * kind has more items than the API lists (at most 20 per kind), a line says how many more. Shared by Admin ›
 * Overview and the team overview's card.
 */
import { Link } from "@tanstack/react-router";
import type { Schemas } from "../../api/client";
import { useCurrentUser } from "../../session";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { VisuallyHidden } from "@/components/ui/visually-hidden/visually-hidden";
import { linkElement } from "../link-target";
import { RelativeTime } from "../templates/list-page";
import a from "./attention.module.css";
import { type AttentionItem, moreNouns, severityLabels, severityOrder, severityTone, wordsFor } from "./wording";

/** The kinds that count servers: their "more" line continues in a server list. */
const serverKinds = new Set<string>(["server_failing", "upstream_signin_lapsed", "capabilities_changed", "server_certificate_expiring", "server_unlabelled"]);

type Props = {
  items: AttentionItem[];
  /** Exact number per kind (kinds with nothing are left out). */
  totals: Schemas["AdminOverview"]["totals"];
  /** Where the list of a kind with more items than shown continues: the platform's or a team's servers. */
  moreTo: { kind: "admin" } | { kind: "team"; team: string };
};

function Row({ item }: { item: AttentionItem }) {
  const me = useCurrentUser();
  const words = wordsFor(item);
  const link = linkElement(item.link, me);
  return (
    <li className={a.row}>
      <div className={a.text}>
        <span className={a.title}>{words.title}</span>
        <span className={a.meta}>
          {item.team && `${item.team.name}`}
          {item.team && item.at && words.atLabel ? " · " : ""}
          {item.at && words.atLabel && (
            <>
              {words.atLabel} <RelativeTime value={item.at} />
            </>
          )}
        </span>
      </div>
      {link && (
        <Button size="sm" variant="secondary" render={link}>
          {words.action}
          <VisuallyHidden>: {words.title}</VisuallyHidden>
        </Button>
      )}
    </li>
  );
}

export function AttentionList({ items, totals, moreTo }: Props) {
  const more = Object.entries(moreNouns).flatMap(([kind, noun]) => {
    const shown = items.filter((i) => i.kind === kind).length;
    const extra = (totals[kind] ?? 0) - shown;
    return extra > 0 ? [{ kind, noun, extra }] : [];
  });
  return (
    <div className={a.groups}>
      {severityOrder.map((severity) => {
        const group = items.filter((i) => i.severity === severity);
        if (group.length === 0) return null;
        return (
          <section key={severity} className={a.group} aria-label={severityLabels[severity]}>
            <h3 className={a.heading}>
              <Badge tone={severityTone[severity]} size="sm">
                {severityLabels[severity]}
              </Badge>
              <span className={a.meta}>{group.length}</span>
            </h3>
            <ul className={a.list}>
              {group.map((item, i) => (
                <Row key={`${item.kind}:${item.subject?.id ?? item.team?.id ?? ""}:${i}`} item={item} />
              ))}
            </ul>
          </section>
        );
      })}
      {more.map((m) => (
        <p key={m.kind} className={a.more}>
          and {m.extra.toLocaleString()} more {m.noun}
          {serverKinds.has(m.kind) ? (
            <>
              : see{" "}
              {moreTo.kind === "admin" ? <Link to="/admin/servers">Admin › MCP servers</Link> : <Link to="/teams/$team/servers" params={{ team: moreTo.team }}>the team&apos;s MCP servers</Link>}
            </>
          ) : null}
          .
        </p>
      ))}
    </div>
  );
}
