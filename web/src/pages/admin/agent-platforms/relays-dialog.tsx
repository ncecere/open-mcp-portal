/*
 * The service accounts that relay for a platform: only their calls may carry its tokens. Platform admins mark an
 * account (searching every team's service accounts) and remove the mark; auditors read. A team's own owners and
 * admins can't: they would be choosing who may speak for the platform.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, unwrap } from "@/api/client";
import { V02ErrorAlert } from "@/components/errors";
import { RelativeTime } from "@/components/templates/list-page";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Dialog, DialogClose } from "@/components/ui/dialog/dialog";
import { Field } from "@/components/ui/field/field";
import { Input } from "@/components/ui/input/input";
import { Loading } from "@/components/ui/spinner/spinner";
import { Table, Td, Tr } from "@/components/ui/table/table";
import { toast } from "@/components/ui/toast/toast";
import s from "../../shared.module.css";
import { type AgentPlatform, clearRelay, markRelay, platformsKey, relaysKey, relaysQuery } from "./api";

type Props = { platform: AgentPlatform; canEdit: boolean; onClose: () => void };

export function RelaysDialog({ platform, canEdit, onClose }: Props) {
  const qc = useQueryClient();
  const relays = useQuery(relaysQuery(platform.id));
  const [q, setQ] = useState("");
  const term = q.trim();
  const found = useQuery({
    queryKey: ["admin", "service-accounts", "relay-search", term],
    enabled: canEdit && term.length >= 2,
    queryFn: async () => unwrap(await api.GET("/v1/admin/service-accounts", { params: { query: { q: term, limit: 8 } } })),
  });
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: relaysKey(platform.id) });
    void qc.invalidateQueries({ queryKey: platformsKey });
    void qc.invalidateQueries({ queryKey: ["admin", "service-accounts"] });
  };
  const mark = useMutation({
    mutationFn: (id: string) => markRelay(platform.id, id),
    onSuccess: (r) => toast.success(`${r.name} relays for ${platform.name}`, `${r.teamName}'s key for it may now carry the platform's tokens.`),
    onSettled: refresh,
  });
  const clear = useMutation({
    mutationFn: (id: string) => clearRelay(platform.id, id),
    onSuccess: () => toast.success("The relay mark was removed", "Tokens sent with that account's keys are ignored from now on."),
    onSettled: refresh,
  });
  const marked = new Set((relays.data ?? []).map((r) => r.serviceAccountId));
  const candidates = (found.data?.items ?? []).filter((a) => !marked.has(a.id));
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={`Relay accounts of ${platform.name}`} description="Only these service accounts' calls may carry the platform's identity tokens." size="lg" footer={<DialogClose>Close</DialogClose>}>
      {relays.isLoading && <Loading label="Loading the relay accounts…" />}
      <ErrorAlert error={relays.error} title="Couldn't load the relay accounts" onRetry={() => void relays.refetch()} />
      {relays.data && (
        <Table
          caption={`Relay accounts of ${platform.name}`}
          columns={["Service account", "Team", "Role", "Marked", ...(canEdit ? [{ label: "", stickyEnd: true }] : [])]}
          stack
          empty={relays.data.length === 0 ? <p className={s.muted}>None yet: no calls can carry this platform&apos;s tokens.</p> : undefined}
        >
          {relays.data.map((r) => (
            <Tr key={r.serviceAccountId}>
              <Td>
                <span className={s.primary}>{r.name}</span>
                {!r.enabled && <Badge tone="neutral">Turned off</Badge>}
              </Td>
              <Td>{r.teamName}</Td>
              <Td>{r.role === "editor" ? "Editor" : "Member"}</Td>
              <Td>{r.markedAt ? <RelativeTime value={r.markedAt} /> : <span className={s.muted}>—</span>}</Td>
              {canEdit && (
                <Td stickyEnd>
                  <Button size="sm" variant="secondary" loading={clear.isPending && clear.variables === r.serviceAccountId} aria-label={`Remove the relay mark from ${r.name}`} onClick={() => clear.mutate(r.serviceAccountId)}>
                    Remove mark
                  </Button>
                </Td>
              )}
            </Tr>
          ))}
        </Table>
      )}
      <V02ErrorAlert error={clear.error ?? mark.error} title="Couldn't change the relay accounts" />
      {canEdit && (
        <>
          <Field label="Add a relay account" description="Search every team's service accounts by name or team. Create the account and its key in the team's Service accounts first.">
            <Input autoComplete="off" value={q} onChange={(e) => setQ(e.target.value)} />
          </Field>
          {term.length >= 2 && found.isLoading && <Loading label="Searching…" />}
          <ErrorAlert error={found.error} title="Couldn't search the service accounts" />
          {term.length >= 2 && found.data && (
            <Table caption="Matching service accounts" columns={["Service account", "Team", ""]} stack empty={candidates.length === 0 ? <p className={s.muted}>No other service account matches.</p> : undefined}>
              {candidates.map((a) => (
                <Tr key={a.id}>
                  <Td>
                    <span className={s.primary}>{a.name}</span>
                    {a.relayPlatform && <span className={s.secondary}>{`Relays for ${a.relayPlatform.name} now; marking it moves it here.`}</span>}
                  </Td>
                  <Td>{a.teamSlug}</Td>
                  <Td>
                    <Button size="sm" loading={mark.isPending && mark.variables === a.id} aria-label={`Mark ${a.name} as a relay`} onClick={() => mark.mutate(a.id)}>
                      Mark as relay
                    </Button>
                  </Td>
                </Tr>
              ))}
            </Table>
          )}
        </>
      )}
    </Dialog>
  );
}
