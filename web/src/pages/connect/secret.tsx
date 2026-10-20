/*
 * The page a call's link opens when a server wants the person's own key
 * (/connect/secret/{request}, decision 72): the portal answered the call with
 * this link (JSON-RPC -32042, or an input request, or an error with the link).
 * The page reads the request (GET /v1/connect/secret-requests/R: only the
 * person it was made for gets it), names the tool and gateway that asked, the
 * server with its team and the address the key goes to (and only there), how
 * it is sent, and takes the key in a password field. Saving sends the origin
 * shown (PUT /v1/me/server-secrets/{server} with the app's CSRF token); the
 * key is never shown again. An agent's call never gets a link: it is told to
 * use Account › My connections instead.
 *
 * Another person's or an unknown link (404) and an expired or used one, or one
 * whose server moved (410), are explained here and never act. No app shell;
 * signed out, the session gate shows the sign-in page, which returns here.
 */
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { useEffect, useId, useState } from "react";
import { ApiError, api, unwrap } from "../../api/client";
import { describeKeyError, KeyFields, useKeyForm } from "../../components/secrets/key-form";
import { keyLabel } from "../../components/servers/person-secret";
import { useCurrentUser, useInstance } from "../../session";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card, CardBody } from "@/components/ui/card/card";
import { Form } from "@/components/ui/field/field";
import { Stack } from "@/components/ui/layout/layout";
import { Loading } from "@/components/ui/spinner/spinner";
import { TextLink } from "@/components/ui/text-link/text-link";
import styles from "../oauth/consent.module.css";

type SecretRequest = import("../../api/client").Schemas["SecretRequest"];

/** Why a link can't be used, in words: someone else's or unknown (404), or expired, used or for a server that moved (410). */
export function secretLinkProblem(err: unknown): { title: string; text: string } {
  if (err instanceof ApiError && err.status === 404)
    return {
      title: "This link was made for someone else",
      text: "A link to enter a key works only for the person whose tool asked for it, signed in as themselves. If you're signed in with another account, sign out and sign in as yourself, then open the link again. Otherwise, run the tool again to get a new link.",
    };
  if (err instanceof ApiError && err.status === 410)
    return {
      title: "This link expired",
      text: "Links work for 10 minutes and only once, and stop working if the server's address changed. Run the tool again in your AI client to get a new link, or enter your key under Account › My connections.",
    };
  return { title: "Can't check this link", text: "The link couldn't be checked right now. Try again in a moment." };
}

const kindWords = { tool: "tool", prompt: "prompt", resource: "resource", resource_template: "resource template" } as const;

export function ConnectSecretPage() {
  const instance = useInstance();
  const me = useCurrentUser();
  const { requestId } = useParams({ from: "/connect/secret/$requestId" });
  const titleId = useId();
  const view = useQuery({
    queryKey: ["connect", "secret-request", requestId],
    queryFn: async () => unwrap(await api.GET("/v1/connect/secret-requests/{requestId}", { params: { path: { requestId } } })),
    retry: false,
    staleTime: Infinity,
  });
  const name = view.data ? keyLabel(view.data.config) : "";
  useEffect(() => {
    if (view.error != null) document.title = `${secretLinkProblem(view.error).title} · ${instance.name}`;
    else if (view.data) document.title = `Enter your ${name} · ${instance.name}`;
  }, [view.data, view.error, name, instance.name]);
  return (
    <main className={styles.page} aria-labelledby={view.data || view.error != null ? titleId : undefined}>
      <div className={styles.column}>
        <p className={styles.instance}>{instance.name}</p>
        <Card>
          <CardBody>
            {view.isLoading && <Loading label="Checking the link…" />}
            {view.error != null && <Problem titleId={titleId} error={view.error} email={me.user.email} />}
            {view.data && <Body request={view.data} titleId={titleId} email={me.user.email} />}
          </CardBody>
        </Card>
      </div>
    </main>
  );
}

function Problem({ titleId, error, email }: { titleId: string; error: unknown; email: string }) {
  const { title, text } = secretLinkProblem(error);
  const known = error instanceof ApiError && (error.status === 404 || error.status === 410);
  return (
    <Stack gap={4}>
      <h1 id={titleId} className={styles.title}>
        {title}
      </h1>
      <p className={styles.muted}>{text}</p>
      {!known && <ErrorAlert error={error} />}
      <p className={styles.muted}>
        Signed in as <strong>{email}</strong>. Nothing was saved, and this page won&apos;t send you anywhere.
      </p>
    </Stack>
  );
}

function Body({ request: r, titleId, email }: { request: SecretRequest; titleId: string; email: string }) {
  const [saved, setSaved] = useState(false);
  const form = useKeyForm(r.secret, () => setSaved(true));
  const label = keyLabel(r.config);
  const what = `The ${kindWords[r.capability.kind]} ${r.capability.exposedName}`;
  const described = describeKeyError(form.save.error);
  if (saved) {
    return (
      <Stack gap={4}>
        <h1 id={titleId} className={styles.title}>
          Your {label} is saved
        </h1>
        <p className={styles.muted}>
          Go back to your AI client and run {r.capability.exposedName} again. Your key is stored encrypted and is sent only to {r.origin}; it won&apos;t be shown again.
          You can replace or remove it any time under{" "}
          <TextLink render={<Link to="/settings/connections" />}>Account › My connections</TextLink>.
        </p>
      </Stack>
    );
  }
  return (
    <Stack gap={4}>
      <h1 id={titleId} className={styles.title}>
        Enter your {label} for {r.server.name}
      </h1>
      <p className={styles.muted}>
        {r.reason === "secret_rejected"
          ? `${what} was refused by ${r.server.name}: the key you entered before no longer works. Enter it again.`
          : `${what} needs your own ${label}, because ${r.server.name} (team ${r.server.teamName}) asks each person for theirs.`}{" "}
        Nobody else can use it, and it can't be read back.
      </p>
      <Form
        onSubmit={(e) => {
          e.preventDefault();
          form.submit();
        }}
      >
        <KeyFields entry={r.secret} form={form} />
        <ErrorAlert error={form.save.error} title={described?.title ?? "Couldn't save the key"} describe={describeKeyError} />
        {r.secret.hasSecret && r.reason === "secret_missing" && <Alert tone="info">You entered a key for this server since this link was made. Saving replaces it.</Alert>}
        <div className={styles.actions}>
          <Button type="submit" loading={form.save.isPending}>
            Save key
          </Button>
          <Button variant="secondary" render={<Link to="/settings/connections" />}>
            Not now
          </Button>
        </div>
      </Form>
      <p className={styles.muted}>
        Signed in as <strong>{email}</strong>. The key goes only to {r.origin}.
      </p>
    </Stack>
  );
}
