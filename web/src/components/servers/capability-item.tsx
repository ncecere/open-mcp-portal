/*
 * One capability as the server listed it: name and title, description, the
 * hints it declares about itself, and its full definition as JSON text. All
 * of it is untrusted: it renders as plain text (never as HTML or Markdown),
 * and the hints are shown, never relied on.
 */
import type { ReactNode } from "react";
import type { Schemas } from "../../api/client";
import { Badge } from "@/components/ui/badge/badge";
import { CodeBlock } from "@/components/ui/code-block/code-block";
import { Disclosure } from "@/components/ui/disclosure/disclosure";
import { VisuallyHidden } from "@/components/ui/visually-hidden/visually-hidden";
import s from "../../pages/shared.module.css";
import { kindLabels } from "./labels";
import { ClassificationBadges, type ToolClass } from "./classification";
import m from "./servers.module.css";

type Capability = Pick<Schemas["CatalogCapability"], "id" | "kind" | "name" | "title" | "description" | "definition"> & {
  toolClass?: ToolClass | null;
  suggestedClass?: ToolClass | null;
  classDrift?: boolean;
};

/** The hints a tool declares in its annotations (MCP): shown as what the server says, never trusted. */
export function declaredHints(definition: Record<string, unknown>): string[] {
  const a = definition.annotations;
  if (!a || typeof a !== "object") return [];
  const h = a as Record<string, unknown>;
  const out: string[] = [];
  if (h.readOnlyHint === true) out.push("Says read-only");
  if (h.destructiveHint === true) out.push("Says destructive");
  if (h.idempotentHint === true) out.push("Says idempotent");
  if (h.openWorldHint === true) out.push("Says open world");
  return out;
}

/** The definition as indented JSON text; never throws on odd input. */
export function definitionText(definition: unknown) {
  try {
    return JSON.stringify(definition ?? {}, null, 2);
  } catch {
    return String(definition);
  }
}

type Props = {
  cap: Capability;
  /** State badges (approved, changed, gone). */
  badges?: ReactNode;
  /** An action under the definition, e.g. Approve change. */
  action?: ReactNode;
  /** Extra lines, e.g. when it was approved. */
  meta?: ReactNode;
  muted?: boolean;
};

export function CapabilityItem({ cap, badges, action, meta, muted }: Props) {
  const hints = declaredHints(cap.definition);
  return (
    <li className={m.cap} data-muted={muted ? "" : undefined} aria-label={`${kindLabels[cap.kind].one}: ${cap.name}`}>
      <div className={m.capHead}>
        <span className={m.capName}>
          <code className={m.capCode}>{cap.name}</code>
          {cap.title && cap.title !== cap.name && <span className={s.muted}>{cap.title}</span>}
        </span>
        <span className={s.badges}>
          {badges}
          <ClassificationBadges cap={cap} />
        </span>
      </div>
      {/* Plain text in a pre-wrap paragraph: the server's words, line breaks kept, nothing interpreted. */}
      <p className={m.capDescription}>{cap.description || <span className={s.muted}>No description.</span>}</p>
      {hints.length > 0 && (
        <div className={s.badges} role="group" aria-label="Hints the server declares (not checked)">
          {hints.map((h) => (
            <Badge key={h} size="sm" variant="outline">
              {h}
            </Badge>
          ))}
        </div>
      )}
      {meta}
      <Disclosure
        title={
          <>
            Definition <VisuallyHidden>of {cap.name}</VisuallyHidden>
          </>
        }
      >
        <CodeBlock code={definitionText(cap.definition)} language="json" wrap maxHeight="24rem" />
      </Disclosure>
      {action && <div>{action}</div>}
    </li>
  );
}
