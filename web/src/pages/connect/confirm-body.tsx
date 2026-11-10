/*
 * The connect page's confirmation: the tool and gateway that asked, the
 * provider and the account connected now, each scope it will ask for
 * (already granted, or new), where the token goes, and Continue or Cancel.
 * For an MCP server in oauth mode (provider.kind mcp_server) the person
 * signs in to that server itself: the words name the server.
 * For a platform provider the link is for one server (F-3): the page says
 * "Allow <server> (<team>) to use your GitHub account", and the token goes
 * only to servers the person allowed. When the account is connected with the
 * scopes already (reason server_not_allowed) the button just allows the
 * server, with no trip to the provider.
 */
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { type ConnectRequest, connectionName, isServerSignIn, presetLabels, serverWithTeam } from "../../components/providers/labels";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Stack } from "@/components/ui/layout/layout";
import { TextLink } from "@/components/ui/text-link/text-link";
import { Time } from "@/components/ui/time/time";
import { VisuallyHidden } from "@/components/ui/visually-hidden/visually-hidden";
import styles from "../oauth/consent.module.css";
import c from "./connect.module.css";

const kindWords = { tool: "tool", prompt: "prompt", resource: "resource", resource_template: "resource template" } as const;

/** Why the tool asked, in a sentence. */
function reasonText(r: ConnectRequest, what: string) {
  const p = connectionName(r.provider);
  if (isServerSignIn(r.provider)) {
    if (r.reason === "missing_scopes") return `${what} needs more access at ${p} than you allowed before.`;
    if (r.reason === "needs_reconsent") return `Your sign-in to ${p} has to be renewed: it stopped working or the server's sign-in changed. ${what} needs it.`;
    return `${what} needs you to sign in to ${p}, so it can act as you there.`;
  }
  switch (r.reason) {
    case "server_not_allowed":
      return `${what} is served by ${r.server ? serverWithTeam(r.server) : "an MCP server"}, which you haven't allowed to use your ${p} account yet.`;
    case "missing_scopes":
      return `${what} needs more access to your ${p} account than you allowed before.`;
    case "needs_reconsent":
      return `Your ${p} connection has to be renewed: it stopped working or the provider's app changed. ${what} needs it.`;
    default:
      return `${what} needs your ${p} account to act as you.`;
  }
}

/**
 * The account connected now. A connection that needs renewing has no
 * tokens left (a changed client ID, a refused refresh), so it isn't
 * connected; its account is named only as the one to reconnect.
 */
function connectedNow(r: ConnectRequest) {
  if (r.reason === "needs_reconsent") {
    return r.accountLabel ? `None: ${r.accountLabel} has to be reconnected` : "None: the connection has to be renewed";
  }
  return r.accountLabel ?? (r.grantedScopes.length ? "An account (no name given)" : "No account");
}

type Action = { run: () => void; pending: boolean; error: unknown };

type Props = {
  request: ConnectRequest;
  titleId: string;
  email: string;
  start: Action;
  /** Allow the server without going to the provider (reason server_not_allowed). */
  allow: Action;
  leaving: string | null;
};

export function ConfirmBody({ request: r, titleId, email, start, allow, leaving }: Props) {
  const [cancelled, setCancelled] = useState(false);
  const p = connectionName(r.provider);
  const server = isServerSignIn(r.provider);
  const what = `The ${kindWords[r.capability.kind]} ${r.capability.exposedName}`;
  const granted = new Set(r.grantedScopes);
  const serverName = !server && r.server ? serverWithTeam(r.server) : null;
  // Connected with the scopes already: only the server's consent is missing, so there's no trip to the provider.
  const allowOnly = serverName !== null && r.reason === "server_not_allowed";
  const shownScopes = allowOnly ? r.requiredScopes : r.requestScopes;
  const busy = start.pending || allow.pending || leaving !== null;
  if (cancelled) {
    return (
      <Stack gap={4}>
        <h1 id={titleId} className={styles.title}>
          Nothing was connected
        </h1>
        <p className={styles.muted}>
          You cancelled, so {p} wasn&apos;t contacted. You can close this page. {what} keeps asking until you connect your account.
        </p>
      </Stack>
    );
  }
  return (
    <Stack gap={5}>
      <div>
        <h1 id={titleId} className={styles.title}>
          {server ? `Sign in to ${p}` : allowOnly ? `Allow ${serverName} to use your ${p} account` : `Connect your ${p} account`}
        </h1>
        <p className={styles.muted}>{reasonText(r, what)}</p>
      </div>
      <section aria-labelledby={`${titleId}-who`}>
        <h2 id={`${titleId}-who`} className={styles.heading}>
          The request
        </h2>
        <dl className={styles.facts}>
          <dt>Signed in as</dt>
          <dd>{email}</dd>
          <dt>Asked by</dt>
          <dd>
            <code>{r.capability.exposedName}</code>
            {r.capability.title && r.capability.title !== r.capability.exposedName ? ` (${r.capability.title})` : ""}
          </dd>
          <dt>Gateway</dt>
          <dd>{r.gateway.name}</dd>
          {serverName && (
            <>
              <dt>Server</dt>
              <dd>{serverName}</dd>
            </>
          )}
          <dt>{server ? "MCP server" : "Provider"}</dt>
          <dd>
            {server
              ? `${p}${r.provider.server ? ` (team ${r.provider.server.teamSlug})` : ""}`
              : r.provider.preset && presetLabels[r.provider.preset] !== p
                ? `${p} (${presetLabels[r.provider.preset]})`
                : p}
          </dd>
          <dt>Connected now</dt>
          <dd>{connectedNow(r)}</dd>
        </dl>
      </section>
      <section aria-labelledby={`${titleId}-scopes`}>
        <h2 id={`${titleId}-scopes`} className={styles.heading}>
          {server ? `Signing in to ${p} asks you to allow` : allowOnly ? `${r.server?.name} may use` : `${p} will ask you to allow`}
        </h2>
        {shownScopes.length === 0 ? (
          <p className={styles.muted}>The provider&apos;s default access.</p>
        ) : (
          <ul className={c.scopes} aria-labelledby={`${titleId}-scopes`}>
            {shownScopes.map((s) => (
              <li key={s} className={c.scope}>
                <span className={c.scopeName}>{s}</span>
                {granted.has(s) ? (
                  <Badge size="sm" tone="neutral">
                    Already granted
                  </Badge>
                ) : (
                  <Badge size="sm" tone="info">
                    New
                  </Badge>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
      <Alert tone="info">
        The portal keeps the token and sends it only to{" "}
        {server ? p : serverName ? `servers you allow, starting with ${serverName}, and only while it stays at its current address` : `the server behind ${r.capability.exposedName}`}.
        Your AI client and its model never see it. Disconnect any time
        from <TextLink render={<Link to="/settings/connections" target="_blank" rel="noreferrer" />}>
          Account › My connections<VisuallyHidden> (opens in a new tab)</VisuallyHidden>
        </TextLink>
        .
      </Alert>
      <p className={styles.muted}>
        {allowOnly ? (
          <>Nothing is sent to {p}: it already has your account. Then run the tool again.</>
        ) : (
          <>After you approve {server ? "the sign-in" : `at ${p}`}, you come back here{serverName ? ` and ${serverName} is allowed` : ""}. Then run the tool again.</>
        )}{" "}
        This link expires <Time value={r.expiresAt} />.
      </p>
      {start.error != null && <ErrorAlert error={start.error} title={`Couldn't start connecting ${p}`} />}
      {allow.error != null && <ErrorAlert error={allow.error} title={`Couldn't allow ${r.server?.name ?? "the server"}`} />}
      <p role="status" className={styles.muted}>
        {allow.pending ? "Allowing…" : leaving ? (server ? "Taking you to sign in…" : `Taking you to ${p}…`) : ""}
      </p>
      <div className={styles.actions}>
        <Button variant="secondary" disabled={busy} onClick={() => setCancelled(true)}>
          Cancel
        </Button>
        {allowOnly ? (
          <Button loading={allow.pending} disabled={busy} onClick={allow.run}>
            Allow {r.server?.name}
          </Button>
        ) : (
          <Button loading={start.pending} disabled={busy} onClick={start.run}>
            {server ? "Continue to sign in" : `Continue to ${p}`}
          </Button>
        )}
      </div>
    </Stack>
  );
}
