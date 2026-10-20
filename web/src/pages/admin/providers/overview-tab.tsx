/*
 * An auth provider's Overview: the redirect URI to register at the provider
 * (with a copy button), its stored configuration (the client secret only as
 * "stored, ends in …"), and where it's used.
 */
import { Link } from "@tanstack/react-router";
import { accessModeLabels, accessSummary, type AuthProvider, scopesText, tokenAuthMethodLabels, tokenResponseFormatLabels } from "@/components/providers/labels";
import { Card } from "@/components/ui/card/card";
import { CopyField } from "@/components/ui/copy-field/copy-field";
import { DescriptionList } from "@/components/ui/description-list/description-list";
import { TextLink } from "@/components/ui/text-link/text-link";
import { Time } from "@/components/ui/time/time";
import { plural } from "@/lib/format";
import s from "../../shared.module.css";
import { paramsText } from "./form";

const url = (v: string | null) => (v ? <code className={s.mono}>{v}</code> : <span className={s.muted}>None</span>);

function secretText(p: AuthProvider) {
  if (p.tokenAuthMethod === "none") return "None: a public client";
  if (!p.hasClientSecret) return "Not set";
  return p.clientSecretHint ? `Stored, ends in ${p.clientSecretHint}` : "Stored";
}

export function ProviderOverviewTab({ provider: p }: { provider: AuthProvider }) {
  const params = paramsText(p.extraAuthorizeParams);
  return (
    <>
      <Card title="Redirect URI" description="Register this exact address as the callback URL of the OAuth app at the provider. People can't connect until it matches.">
        <CopyField label="Redirect URI" name="redirect URI" value={p.redirectUri} />
      </Card>
      <Card title="Configuration" description="The client secret is stored encrypted and never shown.">
        <DescriptionList
          dividers
          items={[
            { label: "Client ID", value: <code className={s.mono}>{p.clientId}</code> },
            { label: "Client secret", value: secretText(p) },
            { label: "Token endpoint authentication", value: tokenAuthMethodLabels[p.tokenAuthMethod] },
            { label: "PKCE", value: p.pkce ? "On (S256)" : "Off" },
            { label: "Authorization URL", value: url(p.authorizationUrl) },
            { label: "Token URL", value: url(p.tokenUrl) },
            { label: "Revocation URL", value: url(p.revocationUrl) },
            { label: "Userinfo URL", value: url(p.userinfoUrl) },
            { label: "Default scopes", value: <span className={s.mono}>{scopesText(p.defaultScopes)}</span> },
            { label: "Scope parameter", value: <code className={s.mono}>{`${p.scopeParam} (${p.scopeSeparator === "," ? "comma" : "space"}-separated)`}</code> },
            { label: "Token response format", value: tokenResponseFormatLabels[p.tokenResponseFormat] },
            { label: "Extra authorization parameters", value: params ? <span className={s.pre}>{params}</span> : <span className={s.muted}>None</span> },
          ]}
        />
      </Card>
      <Card title="Use">
        <DescriptionList
          dividers
          items={[
            {
              label: "Servers",
              value:
                p.serverCount > 0 ? (
                  <TextLink render={<Link to="/admin/servers" search={{ provider: p.id }} />}>{`${plural(p.serverCount, "server")} require it`}</TextLink>
                ) : (
                  "No server requires it yet"
                ),
            },
            {
              label: "Access",
              value: (
                <TextLink render={<Link to="/admin/auth-providers/$providerId" params={{ providerId: p.id }} search={{ tab: "access" }} />}>
                  {`${accessModeLabels[p.accessMode]}: ${accessSummary(p).toLowerCase()}`}
                </TextLink>
              ),
            },
            { label: "Token scopes per call", value: p.narrowOnRefresh ? "Narrowed: a call gets a token for only the scopes it needs (connections with a refresh token)" : "Not narrowed: servers get the stored token, with every scope granted" },
            { label: "Connections", value: `${plural(p.connectionCount, "person", "people")} connected an account` },
            { label: "Added", value: <>{<Time value={p.createdAt} />}{p.createdByName ? ` by ${p.createdByName}` : ""}</> },
            { label: "Last changed", value: <Time value={p.updatedAt} /> },
          ]}
        />
      </Card>
    </>
  );
}
