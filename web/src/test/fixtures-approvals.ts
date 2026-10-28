import type { Schemas } from "../api/client";
import { gatewayId, serverId, team } from "./fixtures";

export const approvalId = "31313131-3131-4131-8131-313131313131";
export const ruleId = "32323232-3232-4232-8232-323232323232";
export const requesterId = "11111111-1111-4111-8111-111111111111";
export const capabilityId = "33333333-3333-4333-8333-333333333333";
export const approval = (extra: Partial<Schemas["ApprovalReceipt"]> = {}): Schemas["ApprovalReceipt"] => ({
  id: approvalId, ruleId, ruleRevision: 4, contextEpoch: 18,
  requesterKind: "user", requesterId, requesterTeamId: null,
  gatewayId, serverId, capabilityId, exposedName: "delete_document", toolClass: "destructive",
  argsDigest: "a".repeat(64), capabilityFingerprint: "b".repeat(64), serverOrigin: "https://tools.example.com",
  status: "pending", reviewRevision: 7, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
  validUntil: null, decidedBy: null, decidedAt: null, usedAt: null, terminalAt: null,
  stale: false, canDecide: true, canCancel: false, canRenew: false,
  previewRedacted: true, previewTruncated: true, preview: '{"document":"<img src=x onerror=alert(1)>","token":"[REDACTED]"}', ...extra,
});
export const approvalRule = (extra: Partial<Schemas["ApprovalRule"]> = {}): Schemas["ApprovalRule"] => ({
  id: ruleId, teamId: team.id, name: "Review destructive calls", targetKind: "server", targetId: serverId,
  capabilityId: null, classes: ["destructive"], enabled: true, pendingMinutes: 1440, validMinutes: 15,
  allowServiceAccountAdmins: false, approvers: [], revision: 5,
  createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), ...extra,
});
export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}
