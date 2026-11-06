import { api, ifMatch, unwrap } from "@/api/client";

// The API currently describes these projections as generic JSON objects. Keep
// the UI projection here until the contract supplies named response schemas.
export function unwrapAudit(res: { data?: unknown; error?: unknown; response: Response }): Record<string, unknown> {
  return unwrap(res as { data?: { data: Record<string, unknown> }; error?: unknown; response: Response });
}
export type Sink = {
  id: string; name: string; kind: string; profile: "summary" | "full";
  required: boolean; enabled: boolean; batch_max_records: number; revision: number;
  url_hint: string; cursor_seq: number; state: string; lag: number;
  last_error_class: string; consecutive_failures: number; held_oversized_seq: number | null;
};
export type Consumer = { name: string; profile: "summary" | "full"; required: boolean; acked_seq: number; lag: number };
export type Status = {
  tip: { stream_id: string; epoch: number; last_seq: number; status: string; checkpoints_enabled: boolean; last_checkpoint_seq: number | null; last_checkpoint_at: string | null };
  sink_settings: { enabled: boolean; min_reader_version: string | null };
  sinks: Sink[]; consumers: Consumer[];
  checkpoint_keys: { kid: string; state: string }[];
};
export type Tip = { earliest_seq: number };
export const statusKey = ["admin", "audit-stream"];
export const getStatus = async () => unwrapAudit(await api.GET("/v1/admin/audit/stream/status")) as unknown as Status;
export type Action = "test" | "rotate-secret" | "resume" | "acknowledge" | "delete";
export async function sinkAction(s: Sink, action: Action) {
  const params = { path: { id: s.id }, header: ifMatch(s.revision) };
  switch (action) {
    case "delete": return unwrapAudit(await api.DELETE("/v1/admin/settings/audit-sinks/{id}", { params }));
    case "test": return unwrapAudit(await api.POST("/v1/admin/settings/audit-sinks/{id}/test", { params }));
    case "rotate-secret": return unwrapAudit(await api.POST("/v1/admin/settings/audit-sinks/{id}/rotate-secret", { params }));
    case "resume": return unwrapAudit(await api.POST("/v1/admin/settings/audit-sinks/{id}/resume", { params, body: { cursor_seq: s.cursor_seq } }));
    case "acknowledge": return unwrapAudit(await api.POST("/v1/admin/settings/audit-sinks/{id}/oversized/{seq}/acknowledge", { params: { ...params, path: { id: s.id, seq: s.held_oversized_seq! } } }));
  }
}
export const verificationDocs = "https://github.com/ncecere/open-mcp-portal/blob/main/docs/audit-sinks.md#35-receiver-rules-added-to-the-slice-1-protocol";
