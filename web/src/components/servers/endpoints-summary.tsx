import { CopyField } from "@/components/ui/copy-field/copy-field";
import type { McpServer } from "./labels";
import { kindLabels } from "./credentials";

/** Reviewer-visible trust destinations. Never values, ciphertext or executable links. */
export function EndpointsSummary({ server }: { server: McpServer }) {
  if (!server.endpoints?.length) return null;
  return (
    <section aria-label="Additional destinations under review">
      <p><strong>Additional destinations under review</strong></p>
      <p>These are replicas of the same trusted capabilities, with independent credentials and destination-specific identity audiences. Governed and NoReplay calls remain primary-only.</p>
      {server.endpoints.map((e, i) => (
        <section key={e.id} aria-label={`Reviewed endpoint ${i + 1}`}>
          <CopyField label={`Additional endpoint ${i + 1}${e.enabled ? " — enabled" : " — disabled"}`} name={`endpoint ${i + 1} URL`} value={e.url} />
          <p>{e.credentials.length ? e.credentials.map((c) => `${kindLabels[c.kind]}${c.name ? `: ${c.name}` : ""}`).join("; ") : "No static credential."}</p>
        </section>
      ))}
    </section>
  );
}
