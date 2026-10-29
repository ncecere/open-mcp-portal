import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useRef, useState } from "react";
import { accessRequestsKey, accessSettingsKey, accessSettingsQuery, requestableKey, saveAccessSettings } from "../../api/access-requests";
import { ApiError, type Schemas } from "../../api/client";
import { adminGatewaysKey } from "../../api/queries";
import { PageSkeleton } from "../page-skeleton";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { Checkbox } from "@/components/ui/checkbox/checkbox";
import { Field } from "@/components/ui/field/field";
import { Textarea } from "@/components/ui/input/input";
import { Stack } from "@/components/ui/layout/layout";

export function GatewayRequestSettings({ gatewayId, readOnly }: { gatewayId: string; readOnly: boolean }) {
  const query = useQuery(accessSettingsQuery(gatewayId));
  if (query.isLoading) return <PageSkeleton />;
  if (query.error) return <ErrorAlert error={query.error} title="Couldn't load gateway request settings" />;
  if (!query.data) return null;
  return <Editor key={`${gatewayId}:${query.data.revision}`} gatewayId={gatewayId} settings={query.data} readOnly={readOnly} />;
}

function Editor({ gatewayId, settings, readOnly }: { gatewayId: string; settings: Schemas["GatewayAccessSettings"]; readOnly: boolean }) {
  const qc = useQueryClient();
  const [enabled, setEnabled] = useState(settings.enabled);
  const [stewards, setStewards] = useState(settings.stewardIds.join("\n"));
  const [validation, setValidation] = useState("");
  const sending = useRef(false);
  const mutation = useMutation({
    mutationFn: saveAccessSettings,
    onSuccess: (_data, submitted) => {
      void qc.invalidateQueries({ queryKey: accessSettingsKey(submitted.id) });
      void qc.invalidateQueries({ queryKey: adminGatewaysKey });
      void qc.invalidateQueries({ queryKey: requestableKey });
      void qc.invalidateQueries({ queryKey: accessRequestsKey });
    },
    onSettled: () => { sending.current = false; },
  });
  const conflict = mutation.error instanceof ApiError && mutation.error.status === 412;
  const busy = mutation.isPending;
  const submit = () => {
    if (sending.current || busy || readOnly || conflict) return;
    const ids = stewards.split("\n").map((s) => s.trim()).filter(Boolean);
    if (ids.length > 50 || new Set(ids.map((s) => s.toLowerCase())).size !== ids.length || ids.some((s) => !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s))) {
      setValidation("Name at most 50 distinct active user UUIDs, one per line.");
      return;
    }
    setValidation("");
    sending.current = true;
    mutation.mutate({ id: gatewayId, revision: settings.revision, body: { enabled, stewardIds: ids } });
  };
  return <Stack gap={4}>
    <Card title="Access requests"><Stack gap={4}>
      <Alert tone="warning">Opting in exposes this gateway's name and description to every active signed-in person. Its capabilities, upstreams and MCP endpoint remain protected by normal access checks.</Alert>
      <Checkbox label="Allow people to discover this gateway and request access" checked={enabled} disabled={readOnly || busy || conflict} onCheckedChange={setEnabled} />
      <Field label="Gateway steward user IDs" description="Optional active user UUIDs, one per line, up to 50. Platform admins can always decide. Stewards can decide this gateway's requests only; no direct grants, edits, MCP access or platform role. A requester can never decide their own request.">
        <Textarea value={stewards} disabled={readOnly || busy || conflict} onChange={(e) => setStewards(e.target.value)} />
      </Field>
      {validation && <Alert tone="danger">{validation}</Alert>}
      <ErrorAlert error={mutation.error} title="Couldn't save request settings" />
      {conflict && <Alert tone="warning">This gateway changed. Reload and review the latest settings before saving again.</Alert>}
      {!readOnly && <Button disabled={busy || conflict} onClick={submit}>Save request settings</Button>}
      <Button variant="secondary" render={<Link to="/access-requests" />}>Open access request queues</Button>
    </Stack></Card>
    <p>Gateway access is separate from approval for a sensitive tool call. Expiring grants end at their deadline without waiting for cleanup. Drain older serving and background-worker replicas before enabling access requests or expiring grants.</p>
  </Stack>;
}
