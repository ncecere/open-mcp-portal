/*
 * A service account's agent platform relay (decision 66): when a platform admin marked it as a relay for a trusted
 * agent platform, calls with its keys may carry that platform's identity token, and the portal runs them as the
 * person the token names, limited to what this account reaches itself. Everyone who can read the account sees
 * the mark; only platform admins can set or remove it (the team's own owners and admins would be choosing who
 * may speak for the platform).
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { serviceAccountsKey } from "../../../api/queries";
import { ConfirmMutationDialog } from "../../../components/confirm-dialog";
import { V02ErrorAlert } from "../../../components/errors";
import { friendly } from "../../../lib/error-wording";
import { useCurrentUser } from "../../../session";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { Field } from "@/components/ui/field/field";
import { NativeSelect } from "@/components/ui/input/input";
import { TextLink } from "@/components/ui/text-link/text-link";
import { toast } from "@/components/ui/toast/toast";
import { clearRelay, markRelay, platformsKey, platformsQuery } from "../../admin/agent-platforms/api";
import s from "../../shared.module.css";
import { useTeam } from "../common";
import type { ServiceAccount } from "./labels";

export function RelayCard({ account }: { account: ServiceAccount }) {
  const qc = useQueryClient();
  const { slug } = useTeam();
  const admin = useCurrentUser().capabilities.platformAdmin;
  const platform = account.relayPlatform;
  const platforms = useQuery({ ...platformsQuery(), enabled: admin && !platform });
  const [choice, setChoice] = useState("");
  const [removing, setRemoving] = useState<ServiceAccount | null>(null);
  const done = () => {
    void qc.invalidateQueries({ queryKey: serviceAccountsKey(slug) });
    void qc.invalidateQueries({ queryKey: platformsKey });
  };
  const mark = useMutation({
    mutationFn: () => markRelay(choice, account.id),
    onSuccess: (r) => toast.success(`${r.name} is a relay`, "Calls with its keys may now carry the platform's identity token."),
    onSettled: done,
  });
  const clear = useMutation({
    mutationFn: () => clearRelay(platform!.id, account.id),
    onSuccess: () => {
      setRemoving(null);
      toast.success("The relay mark was removed", "A token sent with its keys is ignored from now on.");
    },
    onSettled: done,
  });
  if (!platform && !admin) return null;
  const enabled = (platforms.data ?? []).filter((p) => p.enabled);
  return (
    <Card
      title="Agent platform relay"
      description={
        platform
          ? `Calls with this account's keys may carry ${platform.name}'s identity token. The portal then runs them as the person the token names, limited to what this account reaches itself, using that person's own connections.`
          : "Not a relay. A platform admin can mark it as the relay of a trusted agent platform, so calls with its keys may carry that platform's identity token."
      }
    >
      {platform ? (
        <p>
          Relay for <span className={s.primary}>{platform.name}</span>.{" "}
          {admin && (
            <>
              <TextLink render={<Link to="/admin/agent-platforms" />}>Open Trusted agent platforms</TextLink>{" "}
              <Button size="sm" variant="secondary" onClick={() => setRemoving(account)}>
                Remove the relay mark
              </Button>
            </>
          )}
        </p>
      ) : enabled.length === 0 ? (
        <p className={s.muted}>
          No agent platform is trusted yet. <TextLink render={<Link to="/admin/agent-platforms" />}>Trust one</TextLink> first.
        </p>
      ) : (
        <>
          <Field label="Agent platform" description="Only platform admins can mark an account as a relay.">
            <NativeSelect value={choice} onChange={(e) => setChoice(e.target.value)}>
              <option value="">Choose a platform…</option>
              {enabled.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </NativeSelect>
          </Field>
          <V02ErrorAlert error={mark.error} title="Couldn't mark the account" />
          <Button disabled={!choice} loading={mark.isPending} onClick={() => mark.mutate()}>
            Mark as a relay
          </Button>
        </>
      )}
      <ConfirmMutationDialog
        target={removing}
        onClose={() => setRemoving(null)}
        mutation={{ ...clear, error: friendly(clear.error) }}
        onConfirm={() => clear.mutate()}
        title={`Remove the relay mark from ${account.name}?`}
        description="Its keys keep working as an ordinary service account's. A token sent with them is ignored, and the person's own access no longer applies to them."
        confirmLabel="Remove the mark"
      />
    </Card>
  );
}
