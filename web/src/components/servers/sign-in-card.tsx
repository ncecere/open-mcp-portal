/*
 * How the portal authenticates to a server, in words, for its Overview and
 * for review (decisions 39-45): the mode, and for OAuth the authorization
 * server (its host flagged when it isn't the server's), issuer,
 * registration, scopes and the resource parameter; what the server receives
 * with each call; and whether it gets the identity token. The Overview's
 * card adds as whom the capabilities were read, Re-authorize as me, and how
 * many people signed in.
 */
import { Badge } from "@/components/ui/badge/badge";
import { Card } from "@/components/ui/card/card";
import { DescriptionList, type DescriptionEntry } from "@/components/ui/description-list/description-list";
import { Time } from "@/components/ui/time/time";
import { plural } from "../../lib/format";
import { scopesText } from "../providers/labels";
import s from "../../pages/shared.module.css";
import type { McpServer } from "./labels";
import type { ServerAbilities, ServerScope } from "./scope";
import { AuthorizeButton, canAuthorize } from "./setup";
import { partsOf, setsAuthorization } from "./credentials";
import { authModeLabels, authModeOf, type OAuthConfig, otherHost, readAsText, registrationLabels, sendsIdentity } from "./upstream-auth";
import m from "./servers.module.css";

function registrationText(o: OAuthConfig) {
  if (o.registration === "platform_provider") return `${registrationLabels.platform_provider}: ${o.platformProvider?.name ?? "removed"}`;
  if (o.registration === "manual") return `${registrationLabels.manual} (client ID ending in ${o.clientIdHint})`;
  return registrationLabels[o.registration];
}

/** What each call carries, by mode. */
function sentText(server: McpServer) {
  const identity = sendsIdentity(server);
  const mode = authModeOf(server);
  if (mode === "oauth") return `The caller's own token in Authorization: Bearer${identity ? ", and the portal's identity token in MCP-Gateway-Identity" : ""}.`;
  if (mode === "person_secret") {
    const p = server.personSecret;
    const how = !p ? "their own key" : p.placement === "bearer" ? "their own key in Authorization: Bearer" : p.placement === "header" ? `their own key in the ${p.name} header` : `their own key in the ${p.name} query parameter`;
    const moves = p && (p.placement === "bearer" || p.name?.toLowerCase() === "authorization") ? "MCP-Gateway-Identity" : "Authorization: Bearer";
    return `The caller's ${how}${identity ? `, and the portal's identity token in ${moves}` : ""}.`;
  }
  if (mode === "static_header") {
    const parts = partsOf(server);
    const where = parts.some(setsAuthorization) ? "MCP-Gateway-Identity" : "Authorization: Bearer";
    const names = parts.map((p) => (p.kind === "header" ? `${p.name} header` : p.kind === "query" ? `${p.name} query parameter` : p.kind === "bearer" ? "bearer token" : "Basic login"));
    return `The static credential (${names.join(", ")})${identity ? `, and the portal's identity token in ${where}` : ""}.`;
  }
  return identity ? "The portal's identity token in Authorization: Bearer." : "Nothing: no credentials and no identity token.";
}

/** The rows that describe the server's authentication (shared by the card and the review dialogs). */
export function signInItems(server: McpServer): DescriptionEntry[] {
  const o = authModeOf(server) === "oauth" ? server.oauth : null;
  const away = o ? otherHost(o.authorizationServer, server.url) : undefined;
  return [
    { label: "Authentication", value: authModeLabels[authModeOf(server)] },
    ...(o
      ? [
          {
            label: "Authorization server",
            value: (
              <span className={s.badges}>
                <code className={m.url}>{o.authorizationServer}</code>
                {away && <Badge size="sm" tone="warning">{`Another host: ${away}`}</Badge>}
              </span>
            ),
          },
          ...(o.issuer !== o.authorizationServer ? [{ label: "Issuer", value: <code className={m.url}>{o.issuer}</code> }] : []),
          { label: "Registration", value: registrationText(o) },
          { label: "Scopes", value: <span className={s.mono}>{scopesText(o.scopes, "None: the authorization server's default access")}</span> },
          { label: "Scopes supported", value: <span className={s.mono}>{scopesText(o.scopesSupported, "None listed")}</span> },
          { label: "Resource indicator", value: o.sendResource ? "Sent: tokens work only for this server" : "Not sent (turned off for this authorization server)" },
        ]
      : []),
    { label: "Sent with each call", value: sentText(server) },
    { label: "Identity token", value: sendsIdentity(server) ? "Sent: the caller's name, email and teams" : "Not sent: the server doesn't learn who's calling from the portal" },
  ];
}

/** The rows as a list (review dialogs). */
export function SignInSummary({ server }: { server: McpServer }) {
  return <DescriptionList dividers items={signInItems(server)} />;
}

/** An oauth server's Overview card. */
export function SignInCard({ server, scope, abilities }: { server: McpServer; scope: ServerScope; abilities: ServerAbilities }) {
  const o = server.oauth;
  if (authModeOf(server) !== "oauth" || !o) return null;
  const c = o.setupConnection;
  const active = c.status === "active";
  return (
    <Card
      title="Sign-in"
      description={`Each person signs in to ${server.name}'s own service once. The portal keeps their tokens and sends each one only to this server.`}
      actions={canAuthorize(scope, abilities) && active ? <AuthorizeButton server={server} label="Re-authorize as me" variant="secondary" /> : undefined}
    >
      <DescriptionList
        dividers
        items={[
          ...signInItems(server),
          {
            label: "Capabilities read as",
            value: (
              <span className={active ? undefined : m.danger}>
                {readAsText(c)}
                {active && c.authorizedAt && (
                  <span className={s.muted}>
                    {" "}
                    · signed in <Time value={c.authorizedAt} />
                  </span>
                )}
              </span>
            ),
          },
          { label: "People signed in", value: plural(o.connectionCount, "person", "people") },
        ]}
      />
    </Card>
  );
}
