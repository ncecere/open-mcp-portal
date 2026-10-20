/*
 * Admin → Trusted clients (decisions 12 and 24): the OAuth clients that skip
 * the consent screen. People still sign in with the company account, and a
 * trusted client still gets only their access, one gateway at a time. Only
 * Client ID Metadata Document clients (an https client_id) can be trusted.
 * The same page holds the switch "Allow open client registration" (threat
 * model H-4): off, apps can no longer register themselves. Platform admins
 * edit the list and the switch as staged changes and save them at once
 * (If-Match; edits survive a change made elsewhere) after a confirmation
 * naming what's added and removed; auditors read.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { useState } from "react";
import { api, ApiError, ifMatch, unwrap } from "@/api/client";
import { PageSkeleton } from "@/components/page-skeleton";
import { isRevisionConflict, useRevisionForm } from "@/components/templates/revision-form";
import { SettingsPage, SettingsSection } from "@/components/templates/settings-page";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { AlertDialog } from "@/components/ui/dialog/dialog";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import { Switch } from "@/components/ui/switch/switch";
import { toast } from "@/components/ui/toast/toast";
import { adminOnly, terms } from "@/lib/terms";
import s from "../../shared.module.css";
import { useIsPlatformAdmin } from "../hooks";
import { ClientDialog } from "./client-dialog";
import { ClientTable } from "./client-table";
import { clientsKey, maxClients, normalClient, refusedClient, type TrustedClient, type TrustedClients, trustedClientsKey } from "./clients";

export function AdminTrustedClientsPage() {
  const settings = useQuery({ queryKey: trustedClientsKey, queryFn: async () => unwrap(await api.GET("/v1/admin/settings/oauth-clients")) });
  return (
    <Stack gap={6} className={s.page}>
      <PageHeader
        title={terms.trustedClients}
        description="MCP clients that connect without the consent screen. Everyone still signs in with their company account, and a trusted client still gets only their access, one gateway at a time."
      />
      <Alert tone="info" title="Which clients can be trusted">
        Only clients identified by a Client ID Metadata Document: an https address with a path, published by the client&apos;s maker, so its host vouches for
        it. Clients that registered themselves can&apos;t be trusted: anyone can register any name, and their IDs change. They always ask, marked Unverified.
      </Alert>
      {settings.isLoading ? (
        <PageSkeleton />
      ) : settings.data ? (
        <ClientsForm saved={settings.data} />
      ) : (
        <ErrorAlert error={settings.error} title="Couldn't load the trusted clients" onRetry={() => void settings.refetch()} />
      )}
    </Stack>
  );
}

/** A 422 invalid_client_id as the row it's about. */
function clientProblem(err: unknown): { index: number; message: string } | undefined {
  if (!(err instanceof ApiError) || err.code !== "invalid_client_id" || typeof err.details?.index !== "number") return undefined;
  return { index: err.details.index, message: refusedClient(err.details.reason) };
}

const nameOf = (c: TrustedClient) => c.label || c.clientId;

function ClientsForm({ saved }: { saved: TrustedClients }) {
  const qc = useQueryClient();
  const isAdmin = useIsPlatformAdmin();
  const [editing, setEditing] = useState<number | "new" | null>(null);
  const [confirming, setConfirming] = useState(false);
  const base = { clients: saved.clients.map(normalClient), openRegistration: saved.openRegistration };
  const [form, setForm, revision] = useRevisionForm(base, saved.revision, { labels: { clients: "Trusted clients", openRegistration: "Open client registration" } });
  const save = useMutation({
    mutationFn: async () => unwrap(await api.PUT("/v1/admin/settings/oauth-clients", { params: { header: ifMatch(saved.revision) }, body: { clients: form.clients, openRegistration: form.openRegistration } })),
    // A failure shows on the save bar, which also handles a change made elsewhere (412).
    onSettled: () => setConfirming(false),
    onError: (err) => {
      if (isRevisionConflict(err)) void qc.invalidateQueries({ queryKey: trustedClientsKey });
    },
    onSuccess: (st) => {
      setForm({ clients: st.clients.map(normalClient), openRegistration: st.openRegistration });
      qc.setQueryData(trustedClientsKey, st);
      toast.success("Client settings saved", st.openRegistration ? "New connections from trusted clients skip the consent screen." : "Apps can no longer register themselves.");
    },
  });
  const clients = form.clients;
  const setClients = (next: TrustedClient[]) => {
    if (save.error) save.reset();
    setForm({ ...form, clients: next });
  };
  const setOpen = (openRegistration: boolean) => {
    if (save.error) save.reset();
    setForm({ ...form, openRegistration });
  };
  const registrationChanged = form.openRegistration !== base.openRegistration;
  const ids = (list: TrustedClient[]) => new Set(list.map((c) => c.clientId));
  const added = clients.filter((c) => !ids(base.clients).has(c.clientId));
  const removed = base.clients.filter((c) => !ids(clients).has(c.clientId));
  const add = isAdmin && (
    <Button size="sm" variant="secondary" disabled={clients.length >= maxClients} onClick={() => setEditing("new")}>
      <Plus aria-hidden /> Add client
    </Button>
  );
  // The dialogs sit outside the settings form: a submit inside one must not reach it.
  return (
    <>
      <SettingsPage
        revision={revision}
        canEdit={isAdmin}
        readOnlyNote={adminOnly}
        dirty={clientsKey(clients) !== clientsKey(base.clients) || registrationChanged}
        saving={save.isPending}
        error={save.error}
        onSave={() => setConfirming(true)}
        onDiscard={() => setForm(base)}
      >
        <SettingsSection
          title="Trusted clients"
          description={`Connections from these clients skip the consent screen. Removing one brings the consent screen back the next time someone connects it. At most ${maxClients}.`}
          actions={add || undefined}
        >
          <ClientTable
            clients={clients}
            empty={isAdmin ? "None: every client asks for consent. Add a client to let people connect it without the consent screen." : "None: every client asks for consent."}
            onEdit={isAdmin ? (i) => setEditing(i) : undefined}
            onRemove={isAdmin ? (i) => setClients(clients.filter((_, j) => j !== i)) : undefined}
            problem={clientProblem(save.error)}
          />
        </SettingsSection>
        <SettingsSection
          title="Client registration"
          description="Some apps, such as pi, register themselves when they first connect (Dynamic Client Registration). Anyone who can reach the portal can do that, so registered apps are always marked Unverified and ask for consent."
        >
          <Switch
            label="Allow open client registration"
            description="Turned off, the portal stops listing a registration address and refuses registrations. Apps that already registered keep working, and apps that use a metadata document, such as Claude Code, are not affected."
            disabled={!isAdmin}
            checked={form.openRegistration}
            onCheckedChange={setOpen}
          />
        </SettingsSection>
      </SettingsPage>
      <AlertDialog
        open={confirming}
        onOpenChange={(o) => {
          if (!o) setConfirming(false);
        }}
        tone="primary"
        title="Save the trusted clients?"
        description={`${clients.length} ${clients.length === 1 ? "client" : "clients"}. People connecting a trusted client won't see the consent screen: they only sign in.`}
        confirmLabel="Save trusted clients"
        busy={save.isPending}
        onConfirm={() => save.mutate()}
      >
        {added.length > 0 && <p>Trusted from now on: {added.map(nameOf).join(", ")}.</p>}
        {removed.length > 0 && <p>Asks for consent again: {removed.map(nameOf).join(", ")}.</p>}
        {registrationChanged && (
          <p>
            {form.openRegistration
              ? "Apps can register themselves again."
              : "Apps can no longer register themselves. Ones that already registered keep working; an app that needs to register will be refused."}
          </p>
        )}
      </AlertDialog>
      {editing !== null && (
        <ClientDialog
          client={editing === "new" ? undefined : clients[editing]}
          others={clients.filter((_, j) => j !== editing)}
          onClose={() => setEditing(null)}
          onSave={(c) => {
            setClients(editing === "new" ? [...clients, c] : clients.map((x, j) => (j === editing ? c : x)));
            setEditing(null);
          }}
        />
      )}
    </>
  );
}
