/*
 * Where the browser lands after connecting (/connect/done?provider=…&result=…):
 * the callback (a server route) sends it here with what happened. connected:
 * go back to the AI client and run the tool again. missing_scopes: connected,
 * but the provider didn't grant everything (the scopes it left out, one
 * ?missing= each, or space- or comma-separated), so the tool may ask again. denied:
 * the person said no at the provider. expired and wrong_person: the attempt
 * can't finish (a state older than 10 minutes, or another browser session).
 * not_allowed: connected, but the provider's access list excludes the server
 * the link was for (decision 69), so no server was allowed.
 * Anything else: a generic failure. The page only reads the address: it
 * never starts anything, and works whether or not the person is signed in.
 * Exact ?context=service changes only the guidance for a team-shared connection;
 * it grants no authority and identifies no owning team or return destination.
 * The address is untrusted (anyone can link here): the provider is named
 * only when ?provider= is a provider the person can see in GET
 * /v1/auth-providers (or, for an MCP server's own sign-in, one of the
 * person's connections in GET /v1/me/connections), and the left-out scopes are listed only when every
 * one looks like a scope (safeMissingScopes); otherwise the words are generic.
 */
import { useQuery } from "@tanstack/react-query";
import { Link, useSearch } from "@tanstack/react-router";
import { CircleAlert, CircleCheck, CircleX } from "lucide-react";
import { useEffect, useId } from "react";
import { authProvidersQuery, myConnectionsQuery } from "../../api/queries";
import { connectionName } from "../../components/providers/labels";
import { useInstance, useMe } from "../../session";
import { Card, CardBody } from "@/components/ui/card/card";
import { Stack } from "@/components/ui/layout/layout";
import { TextLink } from "@/components/ui/text-link/text-link";
import styles from "../oauth/consent.module.css";
import c from "./connect.module.css";

export type ConnectResult = "connected" | "missing_scopes" | "denied" | "expired" | "not_allowed" | "wrong_person" | "error";

const results: ConnectResult[] = ["connected", "missing_scopes", "denied", "expired", "not_allowed", "wrong_person", "error"];

/** The result's words: a title, what to do next, and its tone. */
export function resultText(result: ConnectResult, provider: string): { title: string; text: string; tone: "success" | "warning" | "danger" } {
  switch (result) {
    case "connected":
      return { tone: "success", title: `Connected to ${provider}`, text: "Go back to your AI client and run the tool again. You can close this page." };
    case "missing_scopes":
      return {
        tone: "warning",
        title: `Connected, but ${provider} didn't allow everything`,
        text: "The tool may ask again. Run it again; if it asks once more, allow everything it asks for at the provider. If the provider doesn't offer one of these, tell the server's team.",
      };
    case "denied":
      return { tone: "danger", title: "Not connected", text: `Access wasn't allowed at ${provider}, so nothing was connected. To try again, run the tool again and open its new link.` };
    case "expired":
      return { tone: "danger", title: "This attempt expired", text: "Connecting has to finish within 10 minutes. Run the tool again and open its new link." };
    case "not_allowed":
      return {
        tone: "warning",
        title: `Connected to ${provider}, but the server can't use it`,
        text: "A platform admin hasn't opened this account to the server's team, so nothing was allowed and the tool still can't use it. Ask a platform admin to add the team or server to the provider's access list.",
      };
    case "wrong_person":
      return {
        tone: "danger",
        title: "Sign in as the person who started connecting",
        text: "This browser is signed in with another account than the one that started connecting, so nothing was connected. Sign in as yourself, then run the tool again.",
      };
    default:
      return { tone: "danger", title: "Couldn't connect", text: "Something went wrong while connecting, and nothing was changed. Run the tool again; if it keeps failing, ask a platform admin to check the provider's settings." };
  }
}

/** Service context is an untrusted display hint, never proof of ownership or access. */
function serviceResultText(result: ConnectResult, provider: string): ReturnType<typeof resultText> {
  const review = "In the owning team's Service accounts › Connections, review explicit account assignments and destination grants before use.";
  const retry = "Return to the owning team's Service accounts › Connections to reconnect or retry, then review explicit account assignments and destination grants.";
  switch (result) {
    case "connected":
      return { tone: "success", title: `Team-shared connection to ${provider} connected`, text: review };
    case "missing_scopes":
      return { tone: "warning", title: `Team-shared connection: ${provider} didn't allow everything`, text: `Some requested permissions weren't granted. ${retry}` };
    case "denied":
      return { tone: "danger", title: "Team-shared connection not connected", text: `Access wasn't allowed at ${provider}. ${retry}` };
    case "expired":
      return { tone: "danger", title: "Team-shared connection attempt expired", text: `This attempt can no longer finish. ${retry}` };
    case "not_allowed":
      return { tone: "warning", title: "Team-shared connection isn't allowed for the destination", text: `Connecting alone doesn't allow a destination to use it. ${review}` };
    case "wrong_person":
      return { tone: "danger", title: "Team-shared connection needs the original browser session", text: `Sign in as the person who started connecting. ${retry}` };
    default:
      return { tone: "danger", title: "Couldn't connect the team-shared connection", text: `Something went wrong while connecting. ${retry}` };
  }
}

const icons = { success: CircleCheck, warning: CircleAlert, danger: CircleX };

/** The scopes the provider left out (?missing=, repeated or split on spaces and commas). */
export const missingScopes = (v: unknown): string[] =>
  Array.isArray(v) ? [...new Set(v.flatMap(missingScopes))] : typeof v === "string" ? v.split(/[\s,]+/).filter(Boolean) : [];

/** At most this many left-out scopes are listed. */
export const maxMissingScopes = 20;
const scopeLike = /^[A-Za-z0-9:._/-]{1,100}$/;

/**
 * The left-out scopes to show, or null when the address carries anything
 * that doesn't look like a scope (letters, digits and `:._/-`, at most 100
 * characters each, at most 20): then the page says so in general words.
 */
export function safeMissingScopes(v: unknown): string[] | null {
  const all = missingScopes(v);
  return all.length <= maxMissingScopes && all.every((s) => scopeLike.test(s)) ? all : null;
}

export function ConnectDonePage() {
  const instance = useInstance();
  const search = useSearch({ from: "/connect/done" });
  const shared = search.context === "service";
  const slug = typeof search.provider === "string" ? search.provider : "";
  const result: ConnectResult = results.includes(search.result as ConnectResult) ? (search.result as ConnectResult) : "error";
  const missing = result === "missing_scopes" ? safeMissingScopes(search.missing) : [];
  const me = useMe();
  const signedIn = Boolean(me.data);
  // The provider's name only when it is a provider this person can see; never the address's words.
  const providers = useQuery({ ...authProvidersQuery(), enabled: signedIn && Boolean(slug) });
  // Server sign-ins aren't platform providers: they're named by the person's own connection to them.
  const own = useQuery({
    ...myConnectionsQuery(),
    enabled: signedIn && Boolean(slug) && providers.isFetched && !providers.data?.some((p) => p.slug === slug),
  });
  const mine = own.data?.find((c) => c.provider.slug === slug)?.provider;
  const name = providers.data?.find((p) => p.slug === slug)?.name ?? (mine ? connectionName(mine) : "the provider");
  const { title, text, tone } = shared ? serviceResultText(result, name) : resultText(result, name);
  const Icon = icons[tone];
  const titleId = useId();
  useEffect(() => {
    document.title = `${title} · ${instance.name}`;
  }, [title, instance.name]);
  return (
    <main className={styles.page} aria-labelledby={titleId}>
      <div className={styles.column}>
        <p className={styles.instance}>{instance.name}</p>
        <Card>
          <CardBody>
            <Stack gap={4}>
              <div className={c.result} data-tone={tone}>
                <Icon aria-hidden />
                <h1 id={titleId} className={styles.title}>
                  {title}
                </h1>
              </div>
              <p className={styles.muted}>{text}</p>
              {missing === null && <p className={styles.muted}>{shared ? "Some requested permissions for the team-shared connection weren't allowed." : "Some of the permissions the tool needs weren't allowed."}</p>}
              {missing !== null && missing.length > 0 && (
                <section aria-labelledby={`${titleId}-missing`}>
                  <h2 id={`${titleId}-missing`} className={styles.heading}>
                    Not allowed
                  </h2>
                  <ul className={c.scopes}>
                    {missing.map((s) => (
                      <li key={s} className={c.scope}>
                        <span className={c.scopeName}>{s}</span>
                      </li>
                    ))}
                  </ul>
                </section>
              )}
              {shared && <TextLink render={<Link to="/" />}>Back to the portal</TextLink>}
              {!shared && signedIn && (result === "connected" || result === "missing_scopes") && (
                <p className={styles.muted}>
                  See or disconnect it in <TextLink render={<Link to="/settings/connections" />}>Account › My connections</TextLink>.
                </p>
              )}
            </Stack>
          </CardBody>
        </Card>
      </div>
    </main>
  );
}
