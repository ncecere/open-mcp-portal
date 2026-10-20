/*
 * Admin → Trusted agent platforms (decisions 65 and 66): the external agent platforms (Pi Durable Platform) whose
 * signed identity tokens the portal accepts, from service accounts a platform admin marked as relays, to know which
 * person an agent acts for. Platform admins add, edit, turn off, test and delete; auditors read. A Test fetches the
 * platform's keys the way a verification does. Never a secret: the keys are public.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { useState } from "react";
import { errorMessage } from "@/api/client";
import { PageSkeleton } from "@/components/page-skeleton";
import { ConfirmMutationDialog } from "@/components/confirm-dialog";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import { toast } from "@/components/ui/toast/toast";
import { friendly } from "@/lib/error-wording";
import { adminOnly, terms } from "@/lib/terms";
import s from "../../shared.module.css";
import { useIsPlatformAdmin } from "../hooks";
import { type AgentPlatform, deletePlatform, platformsKey, platformsQuery, updatePlatform } from "./api";
import { PlatformDialog } from "./platform-dialog";
import { PlatformTable } from "./platform-table";
import { RelaysDialog } from "./relays-dialog";
import { TestDialog } from "./test-dialog";

export function AdminAgentPlatformsPage() {
  const qc = useQueryClient();
  const isAdmin = useIsPlatformAdmin();
  const list = useQuery(platformsQuery());
  const [editing, setEditing] = useState<AgentPlatform | "new" | null>(null);
  const [testing, setTesting] = useState<AgentPlatform | null>(null);
  const [relays, setRelays] = useState<AgentPlatform | null>(null);
  const [deleting, setDeleting] = useState<AgentPlatform | null>(null);
  const remove = useMutation({
    mutationFn: (p: AgentPlatform) => deletePlatform(p),
    onSuccess: (_, p) => {
      setDeleting(null);
      toast.success(`${p.name} is no longer trusted`);
    },
    onSettled: () => void qc.invalidateQueries({ queryKey: platformsKey }),
  });
  const toggle = useMutation({
    mutationFn: (p: AgentPlatform) => updatePlatform(p, { enabled: !p.enabled }),
    onSuccess: (p) => toast.success(p.enabled ? `${p.name} is on` : `${p.name} is off`, p.enabled ? undefined : "Its tokens are refused from the next request."),
    onError: (err) => toast.error("Couldn't change the platform", errorMessage(err)),
    onSettled: () => void qc.invalidateQueries({ queryKey: platformsKey }),
  });
  const add = isAdmin && (
    <Button size="sm" onClick={() => setEditing("new")}>
      <Plus aria-hidden /> Trust a platform
    </Button>
  );
  return (
    <Stack gap={6} className={s.page}>
      <PageHeader
        title={terms.agentPlatforms}
        description={`External agent platforms the portal trusts to say which person an agent acts for. ${isAdmin ? "" : adminOnly}`.trim()}
        actions={add || undefined}
      />
      <Alert tone="info" title="How it works">
        An agent platform calls gateways with the key of a team service account that you mark as its relay, and sends a signed token naming the person the agent acts for.
        The portal checks the token against the keys the platform publishes, finds the person by their sign-in, and runs the call as them, limited to what the relay
        account could reach itself. The person&apos;s own connections are used; an agent never gets a sign-in link. Only the platform&apos;s own records vouch for who the
        person is, so only add platforms you operate or trust. Setup is in the administrator guide (docs/agent-platforms.md).
      </Alert>
      {list.isLoading ? (
        <PageSkeleton />
      ) : list.error ? (
        <ErrorAlert error={list.error} title="Couldn't load the trusted agent platforms" onRetry={() => void list.refetch()} />
      ) : (
        <PlatformTable
          platforms={list.data ?? []}
          canEdit={isAdmin}
          onEdit={setEditing}
          onTest={setTesting}
          onRelays={setRelays}
          onToggle={(p) => toggle.mutate(p)}
          onDelete={setDeleting}
        />
      )}
      {editing !== null && <PlatformDialog platform={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />}
      {testing && <TestDialog platform={testing} onClose={() => setTesting(null)} />}
      {relays && <RelaysDialog platform={relays} canEdit={isAdmin} onClose={() => setRelays(null)} />}
      <ConfirmMutationDialog
        target={deleting}
        onClose={() => setDeleting(null)}
        mutation={{ ...remove, error: friendly(remove.error) }}
        onConfirm={(p) => remove.mutate(p)}
        title={`Stop trusting ${deleting?.name ?? "this platform"}?`}
        description="Its tokens are refused from the next request. Its relay accounts become ordinary service accounts again: their keys keep working as they did, and a token sent with them is ignored. This can't be undone."
        confirmLabel="Stop trusting"
      />
    </Stack>
  );
}
