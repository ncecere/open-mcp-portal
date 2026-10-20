/*
 * An auth provider's Settings: one form over the provider (If-Match on its
 * revision; edits survive a change made elsewhere, AD-01) and the
 * replace-only client secret (never loaded; empty keeps it). Saving asks
 * first when it disconnects people (a new client ID: their tokens belong to
 * the old app) or turns the provider off (their calls are refused). Delete,
 * in the Danger zone, is refused while servers require the provider (409
 * in_use names them); otherwise it erases every connection. Platform admins
 * change it; auditors read.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { api, ApiError, ifMatch, unwrap } from "@/api/client";
import { adminAuthProviderQuery, adminAuthProvidersKey, adminServersKey } from "@/api/queries";
import type { AuthProvider } from "@/components/providers/labels";
import { useRevisionForm } from "@/components/templates/revision-form";
import { DangerAction, DangerZone, SettingsPage, SettingsSection } from "@/components/templates/settings-page";
import { Button } from "@/components/ui/button/button";
import { AlertDialog } from "@/components/ui/dialog/dialog";
import { TextLink } from "@/components/ui/text-link/text-link";
import { toast } from "@/components/ui/toast/toast";
import { plural } from "@/lib/format";
import { adminOnly } from "@/lib/terms";
import { useAuthConfig } from "@/session";
import s from "../../shared.module.css";
import { useIsPlatformAdmin } from "../hooks";
import { AppFields, EndpointFields, IdentityFields, NarrowingFields, RequestFields } from "./fields";
import { formOf, labels, type ProviderForm, providerProblems, serverProblems, updateBody } from "./form";

/** What saving does to people, said in the confirmation (empty: nothing to confirm). */
function consequences(p: AuthProvider, f: ProviderForm): string[] {
  const out: string[] = [];
  if (f.clientId.trim() !== p.clientId && p.connectionCount > 0)
    out.push(`A new client ID disconnects ${plural(p.connectionCount, "person", "people")}: their tokens belong to the old app, so each of them connects again on their next call.`);
  if (p.enabled && !f.enabled) out.push(`Turning ${p.name} off refuses every call that needs it, and nobody can connect it until it's on again. Connections are kept.`);
  return out;
}

export function ProviderSettingsTab({ provider }: { provider: AuthProvider }) {
  const qc = useQueryClient();
  const isAdmin = useIsPlatformAdmin();
  const dev = Boolean(useAuthConfig().data?.devAuthEnabled);
  const saved = formOf(provider);
  const [form, setForm, revision] = useRevisionForm(saved, provider.revision, { labels });
  const [secret, setSecret] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [confirming, setConfirming] = useState<string[] | null>(null);
  const save = useMutation({
    mutationFn: async () =>
      unwrap(await api.PATCH("/v1/admin/auth-providers/{providerId}", { params: { path: { providerId: provider.id }, header: ifMatch(provider.revision) }, body: updateBody(form, secret) })),
    onSuccess: (updated) => {
      setSecret("");
      setSubmitted(false);
      setConfirming(null);
      qc.setQueryData(adminAuthProviderQuery(updated.id).queryKey, updated);
      void qc.invalidateQueries({ queryKey: adminAuthProvidersKey });
      void qc.invalidateQueries({ queryKey: ["auth-providers"] });
      toast.success("Provider settings saved", secret ? "The new client secret is stored." : undefined);
    },
    onError: () => setConfirming(null),
  });
  const problems = providerProblems(form, { creating: false, secret, hasSecret: provider.hasClientSecret, dev });
  const invalid = Object.keys(problems).length > 0;
  const refused = serverProblems(save.error);
  const errors = { ...(submitted ? problems : {}), ...refused };
  const set = (patch: Partial<ProviderForm>) => {
    if (Object.keys(refused).length) save.reset();
    setForm((f) => ({ ...f, ...patch }));
  };
  const fields = { form, set, errors, disabled: !isAdmin };
  const dirty = JSON.stringify(form) !== JSON.stringify(saved) || Boolean(secret);
  return (
    <SettingsPage
      revision={revision}
      canEdit={isAdmin}
      readOnlyNote={adminOnly}
      dirty={dirty}
      saving={save.isPending}
      error={Object.keys(refused).length ? undefined : save.error}
      message={submitted && invalid ? "Not saved: fix the highlighted fields" : Object.keys(refused).length ? "Not saved: see the highlighted field" : undefined}
      onSave={() => {
        setSubmitted(true);
        if (invalid) return;
        const c = consequences(provider, form);
        if (c.length) setConfirming(c);
        else save.mutate();
      }}
      onDiscard={() => {
        setForm(saved);
        setSecret("");
        setSubmitted(false);
        save.reset();
      }}
    >
      <SettingsSection title="Provider" description="How people see the provider when they connect.">
        <IdentityFields {...fields} creating={false} />
      </SettingsSection>
      <SettingsSection title="OAuth app" description="The app registered at the provider. The client secret is replace-only.">
        <AppFields {...fields} redirectUri={provider.redirectUri} secret={secret} setSecret={setSecret} hasSecret={provider.hasClientSecret} hint={provider.clientSecretHint} />
      </SettingsSection>
      <SettingsSection title="Endpoints" description="Checked like MCP server addresses: https, and internal addresses only where a platform admin allowed them.">
        <EndpointFields {...fields} />
      </SettingsSection>
      <SettingsSection title="Authorization request">
        <RequestFields {...fields} />
      </SettingsSection>
      <SettingsSection title="Token scopes per call" description="Whether a server gets only the scopes its call needs.">
        <NarrowingFields {...fields} />
      </SettingsSection>
      {isAdmin && <DeleteProvider provider={provider} />}
      <AlertDialog
        open={confirming !== null}
        onOpenChange={(o) => {
          if (!o) setConfirming(null);
        }}
        title={`Save ${provider.name}?`}
        description="Saving affects the people who connected it."
        confirmLabel="Save provider"
        busy={save.isPending}
        onConfirm={() => save.mutate()}
      >
        {confirming?.map((c) => <p key={c}>{c}</p>)}
      </AlertDialog>
    </SettingsPage>
  );
}

type InUse = { count: number; servers: { id: string; slug: string; teamSlug: string }[] };

/** Servers listed in the dialog before a delete is tried. */
const inUsePreview = 10;

/** 409 in_use: the servers that still require the provider. */
function inUse(err: unknown): InUse | undefined {
  if (!(err instanceof ApiError) || err.code !== "in_use") return undefined;
  const list = Array.isArray(err.details?.servers) ? (err.details.servers as InUse["servers"]) : [];
  const count = typeof err.details?.serverCount === "number" ? err.details.serverCount : list.length;
  return { count, servers: list };
}

function DeleteProvider({ provider }: { provider: AuthProvider }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const del = useMutation({
    mutationFn: async () => unwrap(await api.DELETE("/v1/admin/auth-providers/{providerId}", { params: { path: { providerId: provider.id } } })),
    onSuccess: () => {
      setOpen(false);
      toast.success(`${provider.name} was deleted`, provider.connectionCount ? `${plural(provider.connectionCount, "connection")} erased.` : undefined);
      // Leave first: the record would load again and find nothing.
      void navigate({ to: "/admin/auth-providers", replace: true }).then(() => qc.invalidateQueries({ queryKey: adminAuthProvidersKey }));
    },
  });
  // The record knows how many servers require it: name them before Delete is tried.
  const requiring = useQuery({
    queryKey: [...adminServersKey, "requiring", provider.id],
    queryFn: async () =>
      unwrap(await api.GET("/v1/admin/mcp-servers", { params: { query: { provider: provider.id, limit: inUsePreview } } })).items.map((x) => ({
        id: x.id,
        slug: x.slug,
        teamSlug: x.teamSlug,
      })),
    enabled: open && provider.serverCount > 0,
  });
  const used = inUse(del.error) ?? (provider.serverCount > 0 ? { count: provider.serverCount, servers: requiring.data ?? [] } : undefined);
  return (
    <DangerZone>
      <DangerAction
        title="Delete this provider"
        description={`Erases every connection to ${provider.name} and revokes them at the provider where it can. Servers that require it must stop first. This can't be undone.`}
        action={
          <Button variant="danger" onClick={() => setOpen(true)}>
            Delete provider
          </Button>
        }
      />
      <AlertDialog
        open={open}
        onOpenChange={(o) => {
          if (!o) {
            setOpen(false);
            del.reset();
          }
        }}
        title={`Delete ${provider.name}?`}
        description={`${plural(provider.connectionCount, "person's account", "people's accounts")} will be disconnected, and the slug ${provider.slug} becomes free.`}
        confirmLabel="Delete provider"
        busy={del.isPending}
        error={used ? undefined : del.error}
        onConfirm={() => del.mutate()}
      >
        {used && (
          <div role={del.error ? "alert" : undefined} className={s.dangerText}>
            <p>
              {plural(used.count, "server")} still {used.count === 1 ? "requires" : "require"} {provider.name}, so it can&apos;t be deleted. Their teams remove the
              requirement first:
            </p>
            <ul className={s.inUseList}>
              {used.servers.map((x) => (
                <li key={x.id}>
                  <TextLink render={<Link to="/admin/servers/$serverId" params={{ serverId: x.id }} />}>{`${x.teamSlug} / ${x.slug}`}</TextLink>
                </li>
              ))}
            </ul>
            {used.count > used.servers.length && (
              <TextLink render={<Link to="/admin/servers" search={{ provider: provider.id }} />}>{`See all ${plural(used.count, "server")}`}</TextLink>
            )}
          </div>
        )}
      </AlertDialog>
    </DangerZone>
  );
}
