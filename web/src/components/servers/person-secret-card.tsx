/*
 * A person_secret server's Overview card (decision 72): how each person's key
 * is sent, what it is called, how many people entered one (and how many the
 * server refused), and whose key reads the server's capabilities. Nobody's key
 * is shown. While no key can read the capabilities, an editor is sent to
 * Account › My connections to enter theirs (scheduled health checks send
 * nobody's key: a 401 from the server counts as healthy).
 */
import { Link } from "@tanstack/react-router";
import { KeyRound } from "lucide-react";
import { plural } from "../../lib/format";
import { Alert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { DescriptionList } from "@/components/ui/description-list/description-list";
import { Time } from "@/components/ui/time/time";
import s from "../../pages/shared.module.css";
import type { McpServer } from "./labels";
import { keyLabel, placementText } from "./person-secret";
import { canAuthorize } from "./setup";
import type { ServerAbilities, ServerScope } from "./scope";
import m from "./servers.module.css";

type Props = { server: McpServer; scope: ServerScope; abilities: ServerAbilities };

/** Whose key reads the capabilities, in words. */
function readAs(p: NonNullable<McpServer["personSecret"]>) {
  const who = p.setup.personName ?? "Someone no longer here";
  if (p.setup.status === "active") return who;
  if (p.setup.status === "rejected") return `${who} · the server refused the key`;
  return "Nobody yet";
}

export function PersonSecretCard({ server, scope, abilities }: Props) {
  const p = server.personSecret;
  if (server.authMode !== "person_secret" || !p) return null;
  const can = canAuthorize(scope, abilities);
  const active = p.setup.status === "active";
  const enter = can ? (
    <Button size="sm" variant={active ? "secondary" : "primary"} render={<Link to="/settings/connections" />}>
      <KeyRound aria-hidden /> {active ? "Change my key" : "Enter my key"}
    </Button>
  ) : undefined;
  return (
    <Card
      title="People's own keys"
      description={`Each person enters their own key for ${server.name} under Account › My connections. The portal keeps it encrypted and sends it only to this server's address.`}
      actions={enter}
    >
      <div className={m.stack}>
        {!active && (
          <Alert tone="warning" title={server.refreshedAt ? "No key can read the capabilities now" : "Nobody's key reads its capabilities yet"}>
            The portal reads {server.name}&apos;s tools, resources and prompts with one editor&apos;s own key.{" "}
            {can ? "Enter yours and choose to read the server with it." : "An editor, admin or owner of the team enters theirs."}
          </Alert>
        )}
        <DescriptionList
          dividers
          items={[
            { label: "How it's sent", value: placementText(p) },
            { label: "Called", value: keyLabel(p) },
            { label: "People with a key", value: `${plural(p.people, "person", "people")}${p.rejected ? `, ${p.rejected} refused by the server` : ""}` },
            {
              label: "Capabilities read with",
              value: (
                <span className={active ? undefined : m.danger}>
                  {readAs(p)}
                  {active && p.setup.at && (
                    <span className={s.muted}>
                      {" "}
                      · chosen <Time value={p.setup.at} />
                    </span>
                  )}
                </span>
              ),
            },
          ]}
        />
      </div>
    </Card>
  );
}
