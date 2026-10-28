import { queryOptions } from "@tanstack/react-query";
import { api, ifMatch, type Schemas, unwrap } from "./client";

export type Approval = Schemas["ApprovalReceipt"];
export type ApprovalRule = Schemas["ApprovalRule"];
export type RuleInput = Schemas["ApprovalRuleInput"];
export type ApprovalAction = "approve" | "deny" | "cancel" | "renew";
export type ReviewSubmission = { id: string; action: ApprovalAction; revision: number; digest: string };
export const approvalsKey = ["approvals"];
export const approvalKey = (id: string) => [...approvalsKey, "detail", id];
export const rulesKey = (team?: string) => team ? ["approval-rules", "team", team] : ["approval-rules", "platform"];

/** Never retain a terminal/stale preview in this query cache, even if an old replica sends one. */
export function safeReceipt(receipt: Approval): Approval {
  const { preview, ...metadata } = receipt;
  const live = !receipt.stale && ["pending", "approved"].includes(receipt.status)
    && Date.parse(receipt.expiresAt) > Date.now()
    && (receipt.status !== "approved" || (receipt.validUntil !== null && Date.parse(receipt.validUntil) > Date.now()));
  return live && preview !== undefined ? { ...metadata, preview } : metadata;
}
export const approvalsQuery = (view: "actionable" | "requested", cursor?: string) => queryOptions({
  queryKey: [...approvalsKey, "list", view, cursor],
  queryFn: async () => {
    const page = unwrap(await api.GET("/v1/me/approvals", { params: { query: { view, cursor, limit: 25 } } }));
    return { ...page, items: page.items.map(({ preview: _preview, ...metadata }) => metadata) };
  },
});
export const approvalQuery = (approvalId: string) => queryOptions({
  queryKey: approvalKey(approvalId),
  queryFn: async ({ signal }) => safeReceipt(unwrap(await api.GET("/v1/approvals/{approvalId}", { params: { path: { approvalId } }, signal }))),
  gcTime: 0,
  staleTime: 0,
  refetchInterval: 30_000,
});

/** All request variables come from the displayed review at click time, not mutable editor state. */
export async function submitReview(s: ReviewSubmission) {
  const params = { path: { approvalId: s.id } };
  const body = { expectedReviewRevision: s.revision };
  const receipt = unwrap(s.action === "approve" || s.action === "deny"
    ? await api.POST("/v1/approvals/{approvalId}/decision", { params, body: { ...body, decision: s.action, expectedArgsDigest: s.digest } })
    : s.action === "cancel" ? await api.POST("/v1/approvals/{approvalId}/cancel", { params, body })
    : await api.POST("/v1/approvals/{approvalId}/renew", { params, body }));
  // Only an authorized GET is a new review. Never keep a mutation's preview in
  // the mutation cache or allow it to reappear after a later terminal transition.
  const { preview: _preview, ...metadata } = receipt;
  return metadata;
}

export const approvalRulesQuery = (team?: string, cursor?: string) => queryOptions({
  queryKey: [...rulesKey(team), cursor],
  queryFn: async () => unwrap(team
    ? await api.GET("/v1/teams/{team}/approval-rules", { params: { path: { team }, query: { cursor, limit: 25 } } })
    : await api.GET("/v1/admin/approval-rules", { params: { query: { cursor, limit: 25 } } })),
});
export type RuleSubmission = { team?: string; id?: string; revision?: number; body: RuleInput };
export async function saveApprovalRule(s: RuleSubmission) {
  if (s.id !== undefined && s.revision !== undefined) return unwrap(s.team
    ? await api.PUT("/v1/teams/{team}/approval-rules/{ruleId}", { params: { path: { team: s.team, ruleId: s.id }, header: ifMatch(s.revision) }, body: s.body })
    : await api.PUT("/v1/admin/approval-rules/{ruleId}", { params: { path: { ruleId: s.id }, header: ifMatch(s.revision) }, body: s.body }));
  return unwrap(s.team
    ? await api.POST("/v1/teams/{team}/approval-rules", { params: { path: { team: s.team } }, body: s.body })
    : await api.POST("/v1/admin/approval-rules", { body: s.body }));
}
export async function deleteApprovalRule(s: { team?: string; id: string; revision: number }) {
  return unwrap(s.team
    ? await api.DELETE("/v1/teams/{team}/approval-rules/{ruleId}", { params: { path: { team: s.team, ruleId: s.id }, header: ifMatch(s.revision) } })
    : await api.DELETE("/v1/admin/approval-rules/{ruleId}", { params: { path: { ruleId: s.id }, header: ifMatch(s.revision) } }));
}
