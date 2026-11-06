import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Card } from "@/components/ui/card/card";
import { DescriptionList } from "@/components/ui/description-list/description-list";
import { Stack } from "@/components/ui/layout/layout";
import { unwrapAudit, type Status, type Tip } from "./api";

export function StreamStatus({ data }: { data: Status }) {
  const tip = useQuery({ queryKey: ["admin", "audit-stream-tip"], queryFn: async () => unwrapAudit(await api.GET("/v1/admin/audit/stream/tip")) as unknown as Tip, refetchInterval: 60_000 });
  const keys = useQuery({ queryKey: ["admin", "audit-stream-key-fingerprints"], queryFn: async () => {
    const response = await fetch("/.well-known/omp-audit-keys.json");
    if (!response.ok) throw new Error("Could not load public checkpoint keys");
    const body = await response.json() as { keys: { kid: string; x: string; retired_at_seq: number | null }[] };
    return Promise.all(body.keys.filter(k => k.retired_at_seq === null).map(async k => {
      const raw = Uint8Array.from(atob(k.x.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
      const digest = await crypto.subtle.digest("SHA-256", raw);
      return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join(":");
    }));
  }, refetchInterval: 60_000 });
  const t = data.tip;
  const age = t.last_checkpoint_seq != null && t.last_checkpoint_at ? Math.max(0, Math.floor((Date.now() - Date.parse(t.last_checkpoint_at)) / 60_000)) : null;
  return <Card title="Stream status"><Stack gap={4}>
    {!data.sealer_enabled && <Alert tone="warning" title="The audit sealer is off">
      This replica runs with AUDIT_STREAM_ENABLED=false, so it seals and delivers nothing. The operator sets AUDIT_STREAM_ENABLED=true on every replica and restarts the portal after completing rollout checks. Other replicas may be configured differently.
    </Alert>}
    {t.status !== "running" && <Alert tone="warning" title="Stream is not running">State: {t.status}. Ask the operator to investigate before resuming delivery.</Alert>}
    {!t.checkpoints_enabled && <Alert tone="warning" title="Checkpoints are disabled">After every replica supports checkpoints, the operator runs open-mcp-portal audit-stream enable-checkpoints --min-reader-version-ack with the migration role. This is a minimum reader version transition; disabling future checkpoints cannot remove existing ones.</Alert>}
    {!data.sink_settings.enabled && <Alert tone="warning" title="Sinks are disabled">Configuration and tests are available, but delivery is inert. After every replica supports sinks, the operator runs open-mcp-portal audit-stream enable-sinks --min-reader-version-ack with the migration role. Before rollback, run audit-stream disable-sinks, stop senders and drain pending sink notifications using the current release.</Alert>}
    <ErrorAlert error={keys.error} onRetry={() => void keys.refetch()} />
    <ErrorAlert error={tip.error} onRetry={() => void tip.refetch()} />
    <DescriptionList items={[
      { label: "Stream id", value: t.stream_id }, { label: "Epoch", value: t.epoch },
      { label: "Last sequence", value: t.last_seq }, { label: "Earliest available sequence", value: tip.data?.earliest_seq ?? "Unavailable" },
      { label: "Sealer (this replica)", value: data.sealer_enabled ? "On" : "Off" },
      { label: "Stream state", value: t.status }, { label: "Checkpoints", value: t.checkpoints_enabled ? "Enabled" : "Disabled" },
      { label: "Last checkpoint sequence", value: t.last_checkpoint_seq ?? "None" },
      { label: "Checkpoint age", value: age === null ? "No checkpoint yet" : `${age} minutes` },
      { label: "Active key id", value: data.checkpoint_keys.find(k => k.state === "active")?.kid ?? "None" },
      { label: "Active key fingerprint (SHA-256 of public key)", value: keys.data?.join(" · ") || "No active key available" },
      { label: "Sinks gate", value: data.sink_settings.enabled ? "Enabled" : "Disabled" },
      { label: "Minimum sink reader version", value: data.sink_settings.min_reader_version ?? "Not set" },
    ]} />
    <a href="/.well-known/omp-audit-keys.json">Public checkpoint keys</a>
  </Stack></Card>;
}
