import { QueryClient } from "@tanstack/react-query";
import { approvalQuery, approvalsQuery, approvalRulesQuery, deleteApprovalRule, rulesKey, saveApprovalRule, submitReview } from "../api/approvals";
import type { RuleInput } from "../api/approvals";
import { approval, approvalId, approvalRule, ruleId } from "./fixtures-approvals";
import { gatewayId, team } from "./fixtures";
import { mockApi, Reply } from "./harness";

it("binds all 13 generated browser operations without raw RPC arguments or mutation previews", async () => {
  const base = `/v1/approvals/${approvalId}`;
  const teamBase = `/v1/teams/${team.slug}/approval-rules`;
  const adminBase = "/v1/admin/approval-rules";
  const calls = mockApi({
    "GET /v1/me/approvals": () => ({ items: [approval()], nextCursor: "next" }),
    [`GET ${base}`]: () => approval(),
    [`POST ${base}/decision`]: () => approval(),
    [`POST ${base}/cancel`]: () => approval(),
    [`POST ${base}/renew`]: () => approval(),
    [`GET ${teamBase}`]: () => ({ items: [approvalRule()], nextCursor: null }),
    [`POST ${teamBase}`]: () => new Reply(201, { data: approvalRule() }),
    [`PUT ${teamBase}/${ruleId}`]: () => approvalRule(),
    [`DELETE ${teamBase}/${ruleId}`]: () => ({ ok: true }),
    [`GET ${adminBase}`]: () => ({ items: [approvalRule({ teamId: null })], nextCursor: null }),
    [`POST ${adminBase}`]: () => new Reply(201, { data: approvalRule({ teamId: null }) }),
    [`PUT ${adminBase}/${ruleId}`]: () => approvalRule({ teamId: null }),
    [`DELETE ${adminBase}/${ruleId}`]: () => ({ ok: true }),
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const queue = await qc.fetchQuery(approvalsQuery("requested", "opaque"));
  expect(queue.items[0]).not.toHaveProperty("preview");
  const receipt = await qc.fetchQuery(approvalQuery(approvalId));
  expect(receipt.preview).toContain("[REDACTED]");
  for (const action of ["approve", "cancel", "renew"] as const) {
    const result = await submitReview({ id: approvalId, action, revision: 7, digest: "a".repeat(64) });
    expect(result).not.toHaveProperty("preview");
  }
  const { name, targetKind, targetId, capabilityId, classes, enabled, pendingMinutes, validMinutes, allowServiceAccountAdmins, approvers } = approvalRule();
  const body: RuleInput = { name, targetKind, targetId, capabilityId, classes, enabled, pendingMinutes, validMinutes, allowServiceAccountAdmins, approvers };
  for (const scope of [team.slug, undefined]) {
    await qc.fetchQuery(approvalRulesQuery(scope, "rule-cursor"));
    const scopedBody: RuleInput = scope ? body : { ...body, targetKind: "gateway", targetId: gatewayId };
    await saveApprovalRule({ team: scope, body: scopedBody });
    await saveApprovalRule({ team: scope, id: ruleId, revision: 5, body: scopedBody });
    await deleteApprovalRule({ team: scope, id: ruleId, revision: 5 });
  }
  expect(calls).toHaveLength(13);
  expect(new Set(calls.map((c) => `${c.method} ${c.url}`)).size).toBe(13);
  expect(calls[0]!.search.get("view")).toBe("requested");
  expect(calls[0]!.search.get("cursor")).toBe("opaque");
  expect(calls.filter((c) => c.method === "PUT" || c.method === "DELETE").every((c) => c.headers.get("If-Match") === '"5"')).toBe(true);
  expect(calls.filter((c) => c.method === "POST" && c.url.endsWith("decision"))[0]!.body).toEqual({ decision: "approve", expectedReviewRevision: 7, expectedArgsDigest: "a".repeat(64) });
  qc.clear();
});

it("isolates platform rules from a team literally named platform", () => {
  expect(rulesKey()).not.toEqual(rulesKey("platform"));
});
