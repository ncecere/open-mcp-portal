/*
 * One notification, in the bell's popover and the inbox: its title (bold while unread), text, team and age. The row
 * opens its target (a LinkTarget, routed by components/link-target.tsx) and marks itself read; one without a target
 * is a button that only marks it read. Unread rows also have a "Mark as read" button of their own.
 */
import { Check } from "lucide-react";
import { cloneElement, type ReactElement } from "react";
import type { Schemas } from "../../api/client";
import { RelativeTime } from "../templates/relative-time";
import { Button } from "@/components/ui/button/button";
import { VisuallyHidden } from "@/components/ui/visually-hidden/visually-hidden";
import { linkElement, type LinkViewer } from "../link-target";
import { eventLabel } from "./events";
import n from "./notifications.module.css";

export type NotificationItem = Schemas["NotificationItem"];

type Props = {
  item: NotificationItem;
  viewer: LinkViewer;
  /** Marks it read (called when it was unread). */
  onRead: (item: NotificationItem) => void;
  /** Called after the person opened it (the popover closes). */
  onOpen?: () => void;
};

export function NotificationRow({ item, viewer, onRead, onOpen }: Props) {
  const unread = !item.readAt;
  const link = linkElement(item.link, viewer);
  const open = () => {
    if (unread) onRead(item);
    onOpen?.();
  };
  const content = (
    <>
      <span className={n.title} data-unread={unread ? "" : undefined}>
        {unread && <span className={n.dot} aria-hidden />}
        {unread && <VisuallyHidden>Unread: </VisuallyHidden>}
        {item.title}
      </span>
      {item.body && <span className={n.body}>{item.body}</span>}
      <span className={n.meta}>
        {item.team ? `${item.team.name} · ` : ""}
        {eventLabel(item.event)} · <RelativeTime value={item.createdAt} />
      </span>
    </>
  );
  return (
    <li className={n.row}>
      {link ? (
        cloneElement(link as ReactElement<{ className?: string; onClick?: () => void; children?: unknown }>, { className: n.main, onClick: open }, content)
      ) : (
        <button type="button" className={n.main} onClick={open}>
          {content}
        </button>
      )}
      {unread && (
        <Button size="sm" variant="ghost" iconOnly aria-label={`Mark “${item.title}” as read`} onClick={() => onRead(item)}>
          <Check aria-hidden />
        </Button>
      )}
    </li>
  );
}
