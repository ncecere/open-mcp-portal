/* An automation token that acted in the audit log: its kind as a badge next to the token's name. */
import type { Schemas } from "../../api/client";
import { Badge } from "@/components/ui/badge/badge";
import { tokenKindLabel } from "./actors";

/** The kind badge of a token actor ("Team publisher token"); nothing for people, keys and the system. */
export function TokenKindBadge({ actor }: { actor: Schemas["AuditActor"] }) {
  const label = tokenKindLabel(actor);
  return label ? (
    <Badge tone="info" size="sm">
      {label}
    </Badge>
  ) : null;
}
