/*
 * The OAuth consent page (/oauth/consent, docs/phase4-client-auth.md): an
 * MCP client asks to use one gateway as the signed-in person (decision 21).
 * /oauth/authorize checked the request and sent the browser here with its
 * query string; this page reads it again (GET /v1/oauth/consent), shows the
 * client (the host that vouches for a metadata-document client, or
 * "Unverified" for one that registered itself), the gateway and what it
 * offers, and where the browser goes back to, and sends Allow or Deny
 * (POST, with the app's CSRF token). The server answers where to go: the
 * client, with a code or access_denied. A request that isn't valid (400,
 * 404) is explained here and never sent anywhere.
 *
 * A client the admins trust skips this page, except the first time it asks
 * with a loopback redirect (a program on this computer receives the answer;
 * decision 62): then the server marks the request `notice` and the page is
 * a short confirmation, "Continue" or "Cancel", once per person and gateway.
 *
 * No app shell: nothing to wander off to while the client waits. Signed
 * out, the session gate shows the sign-in page, which returns here with the
 * whole query.
 */
import { useMutation, useQuery } from "@tanstack/react-query";
import { Check } from "lucide-react";
import { useEffect, useId, useState } from "react";
import { ApiError, api, unwrap, type Schemas } from "../../api/client";
import { ScopeBadges, ScopeEditor, type ToolScope } from "../../components/tool-scope";
import { clientHostText, safeLogo } from "../../components/oauth/client-host";
import { capabilityCount } from "../../components/gateways/labels";
import { useCurrentUser, useInstance } from "../../session";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Avatar } from "@/components/ui/avatar/avatar";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Card, CardBody } from "@/components/ui/card/card";
import { Stack } from "@/components/ui/layout/layout";
import { Loading } from "@/components/ui/spinner/spinner";
import { TextLink } from "@/components/ui/text-link/text-link";
import { VisuallyHidden } from "@/components/ui/visually-hidden/visually-hidden";
import styles from "./consent.module.css";

type Consent = Schemas["OAuthConsent"];
type Submission = Pick<Schemas["OAuthConsentDecision"], "decision" | "toolScope">;

/** Leaves the app for the client (a seam for tests). */
export const redirectTo = { go: (url: string) => window.location.assign(url) };

/** The authorization request as the endpoint passed it on: the raw query (for the decision) and its parameters. */
export function consentRequest(search: string) {
  const raw = search.startsWith("?") ? search.slice(1) : search;
  const q = new URLSearchParams(raw);
  const get = (k: string) => q.get(k) ?? "";
  return {
    raw,
    params: {
      client_id: get("client_id"),
      redirect_uri: get("redirect_uri"),
      response_type: get("response_type"),
      code_challenge: get("code_challenge"),
      code_challenge_method: get("code_challenge_method"),
      resource: get("resource"),
      ...(q.has("state") ? { state: get("state") } : {}),
      ...(q.has("scope") ? { scope: get("scope") } : {}),
    },
  };
}

/** Only an http(s) address the browser can go back to (the server builds it; anything else is refused here too). */
export function safeRedirect(url: string): string | undefined {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.href : undefined;
  } catch {
    return undefined;
  }
}

/** Why the request can't go on, in words (400: an invalid request; 404: no gateway the person can use). */
function invalidReason(err: unknown): string {
  if (err instanceof ApiError && err.status === 404) return "The gateway this app asks for doesn't exist, is turned off, or isn't one you can use.";
  if (err instanceof ApiError && err.status === 400) return "The app's request isn't valid, so it can't be answered.";
  return "The request couldn't be checked.";
}

export function OAuthConsentPage() {
  const instance = useInstance();
  const me = useCurrentUser();
  // Read once: the address the browser was sent to, untouched by the router.
  const [request] = useState(() => consentRequest(window.location.search));
  const titleId = useId();
  const view = useQuery({
    queryKey: ["oauth", "consent", request.raw],
    queryFn: async () => unwrap(await api.GET("/v1/oauth/consent", { params: { query: request.params } })),
    retry: false,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
  const [leaving, setLeaving] = useState<string | null>(null);
  const decide = useMutation({
    mutationFn: async (submission: Submission) => {
      const out = unwrap(await api.POST("/v1/oauth/consent", { body: { query: request.raw, ...submission } }));
      const target = safeRedirect(out.redirectUrl);
      if (!target) throw new Error("The portal answered with an address your browser can't go to, so you weren't sent anywhere.");
      return target;
    },
    onSuccess: (target) => {
      setLeaving(target);
      redirectTo.go(target);
    },
  });
  const clientName = view.data?.client.name;
  useEffect(() => {
    if (clientName) document.title = `Connect ${clientName} · ${instance.name}`;
    else if (view.error != null) document.title = `Can't connect this app · ${instance.name}`;
  }, [clientName, view.error, instance.name]);

  return (
    <main className={styles.page} aria-labelledby={view.data || view.error != null ? titleId : undefined}>
      <div className={styles.column}>
        <p className={styles.instance}>{instance.name}</p>
        <Card>
          <CardBody>
            {view.isLoading && <Loading label="Checking the app's request…" />}
            {view.error != null && (
              <Stack gap={4}>
                <h1 id={titleId} className={styles.title}>
                  Can&apos;t connect this app
                </h1>
                <p className={styles.muted}>{invalidReason(view.error)}</p>
                <ErrorAlert error={view.error} />
                <p className={styles.muted}>Nothing was shared with the app, and this page won&apos;t send you anywhere. Close it and try connecting again from the app.</p>
              </Stack>
            )}
            {view.data && <ConsentBody consent={view.data} titleId={titleId} email={me.user.email} decide={decide} leaving={leaving} />}
          </CardBody>
        </Card>
      </div>
    </main>
  );
}

type BodyProps = {
  consent: Consent;
  titleId: string;
  email: string;
  decide: { mutate: (d: Submission) => void; isPending: boolean; variables?: Submission; error: unknown };
  leaving: string | null;
};

function ConsentBody({ consent: loaded, titleId, email, decide, leaving }: BodyProps) {
  // Bind the displayed request and ceiling once. Refetches cannot widen this consent.
  const [consent] = useState(loaded);
  const [toolScope, setToolScope] = useState<ToolScope>(consent.requestedToolScope ?? null);
  const { client, gateway } = consent;
  const unverified = client.kind === "registered";
  const logo = safeLogo(client);
  const busy = decide.isPending || leaving !== null;
  // A trusted client's first sign-in from this computer: a confirmation, not a consent.
  const notice = consent.notice;
  return (
    <Stack gap={5}>
      <div className={styles.client}>
        {logo ? <img src={logo} alt="" className={styles.logo} /> : <Avatar name={client.name} size="lg" decorative />}
        <div>
          <h1 id={titleId} className={styles.title}>
            {client.name} wants to use {gateway.name} as you
          </h1>
          <p className={styles.host}>
            {unverified ? (
              <>
                <Badge size="sm" tone="warning">
                  Unverified
                </Badge>
                <span>{clientHostText(client)}</span>
              </>
            ) : (
              <span>
                From <strong>{client.host}</strong>
              </span>
            )}
          </p>
        </div>
      </div>
      {unverified && (
        <Alert tone="warning">
          This app registered itself, so its name and website aren&apos;t checked. Allow it only if you just connected it yourself. Your answer goes to{" "}
          <strong>{consent.redirectHost}</strong>.
        </Alert>
      )}
      {notice && (
        <Alert tone="info" title={`Your administrators trust ${client.name}`}>
          It doesn&apos;t normally ask, but this is its first sign-in to {gateway.name} from you, so it asks once. After you continue, it receives the result on this
          computer, at <strong>{consent.redirectHost}</strong>. If you didn&apos;t just start signing in from {client.name}, choose Cancel.
        </Alert>
      )}
      {consent.remembered && <Alert tone="info">You allowed this app on this gateway before. Allowing again signs it in again.</Alert>}
      <section aria-labelledby={`${titleId}-gateway`}>
        <h2 id={`${titleId}-gateway`} className={styles.heading}>
          The gateway
        </h2>
        <dl className={styles.facts}>
          <dt>Name</dt>
          <dd>{gateway.name}</dd>
          <dt>Owner</dt>
          <dd>{gateway.ownerKind === "team" ? (gateway.teamName ?? gateway.teamSlug ?? "A team") : "Platform gateway"}</dd>
          <dt>Offers you</dt>
          <dd>
            <TextLink href={`/gateways/${gateway.id}`} target="_blank" rel="noreferrer">
              {capabilityCount(gateway.capabilityCount)}
              <VisuallyHidden> (opens in a new tab)</VisuallyHidden>
            </TextLink>
          </dd>
        </dl>
      </section>
      <section aria-labelledby={`${titleId}-can`}>
        <h2 id={`${titleId}-can`} className={styles.heading}>
          It will be able to
        </h2>
        <ul className={styles.list}>
          <li>
            <Check aria-hidden /> Use only the selected tools, plus the prompts and resources {gateway.name} offers you, as you
          </li>
          <li>
            <Check aria-hidden /> Only with your access: not other gateways, and nothing you can&apos;t do yourself
          </li>
        </ul>
        <p className={styles.muted}>Its calls are recorded under your name. You can disconnect it at any time from Account › Connected apps.</p>
      </section>
      <section aria-labelledby={`${titleId}-scope`}>
        <h2 id={`${titleId}-scope`} className={styles.heading}>Requested tool scope</h2>
        <ScopeBadges scope={consent.requestedToolScope} />
        <p>You may narrow the requested classes, never add to them. Exact tool names cannot be added.</p>
        <ScopeEditor value={toolScope} onChange={setToolScope} ceiling={consent.requestedToolScope ?? null} allowNames={false} disabled={busy} />
      </section>
      <p className={styles.muted}>
        Signed in as <strong>{email}</strong>. After you answer, your browser goes back to <strong>{consent.redirectHost}</strong>.
      </p>
      {decide.error != null && <ErrorAlert error={decide.error} title="Couldn't send your answer" />}
      <p role="status" className={styles.muted}>
        {leaving ? `Taking you back to ${consent.redirectHost}…` : ""}
      </p>
      <div className={styles.actions}>
        <Button variant="secondary" disabled={busy} loading={decide.isPending && decide.variables?.decision === "deny"} onClick={() => decide.mutate({ decision: "deny" })}>
          {notice ? "Cancel" : "Deny"}
        </Button>
        <Button disabled={busy} loading={decide.isPending && decide.variables?.decision === "allow"} onClick={() => decide.mutate({ decision: "allow", toolScope })}>
          {notice ? "Continue" : "Allow"}
        </Button>
      </div>
    </Stack>
  );
}
