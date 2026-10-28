/* Browser-contract fixtures only: these do not establish backend/runtime acceptance. */
import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { approvalKey, safeReceipt } from "../api/approvals";
import { eventLabel } from "../components/notifications/events";
import { identitySentLabel, outcomeLabels } from "../components/gateways/labels";
import { approval, approvalId, deferred } from "./fixtures-approvals";
import { meFor } from "./fixtures";
import { mockApi, renderApp, Reply, shellRoutes, type Handler } from "./harness";

const base = `/v1/approvals/${approvalId}`;
const detail = `/approvals/${approvalId}`;
const routes = (extra: Record<string, Handler> = {}) => ({
  ...shellRoutes(),
  [`GET ${base}`]: () => approval(),
  "GET /v1/me/approvals": () => ({ items: [approval()], nextCursor: null }),
  ...extra,
});

describe("Approval queues", () => {
  it("has accessible actionable/requested tabs and cursor pages, with no inline previews", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes({ "GET /v1/me/approvals": (_body, c) => ({
      items: [approval({ id: c.search.get("cursor") ? "second" : approvalId, exposedName: c.search.get("cursor") ? "second_call" : "delete_document" })],
      nextCursor: c.search.get("cursor") ? null : "opaque-next",
    }) }));
    const { container } = renderApp("/approvals");
    await screen.findByRole("link", { name: "delete_document" });
    expect(screen.queryByText(/onerror/)).toBeNull();
    expect(container.querySelector("pre")).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: /next page/i }));
    await screen.findByRole("link", { name: "second_call" });
    expect(calls.filter((c) => c.url === "/v1/me/approvals").at(-1)?.search.get("cursor")).toBe("opaque-next");
    await u.click(screen.getByRole("tab", { name: "Requested" }));
    await screen.findByRole("link", { name: "delete_document" });
    const request = calls.filter((c) => c.url === "/v1/me/approvals").at(-1)!;
    expect(request.search.get("view")).toBe("requested");
    expect(request.search.has("cursor")).toBe(false);
  });

  it("shows empty and permission-denied queues", async () => {
    const u = userEvent.setup();
    mockApi(routes({ "GET /v1/me/approvals": (_body, c) => c.search.get("view") === "requested" ? Reply.error(403, "forbidden", "Requests unavailable") : { items: [], nextCursor: null } }));
    renderApp("/approvals");
    await screen.findByText("No actionable approvals.");
    await u.click(screen.getByRole("tab", { name: "Requested" }));
    expect(await screen.findByText("Requests unavailable")).toBeInTheDocument();
  });
});

describe("Approval receipt", () => {
  it("renders receipt bindings and escaped plain text only, with warnings and axe", async () => {
    mockApi(routes({ [`GET ${base}`]: () => approval({ toolClass: null }) }));
    const { container } = renderApp(detail);
    await screen.findByRole("heading", { name: "delete_document", level: 1 });
    const pre = await waitFor(() => { const node = container.querySelector("pre"); expect(node).not.toBeNull(); return node!; });
    expect(pre.textContent).toContain("<img src=x onerror=alert(1)>");
    expect(pre.querySelector("img")).toBeNull();
    expect(screen.getByText("Credential or sensitive values were redacted.")).toBeInTheDocument();
    expect(screen.getByText(/Preview truncated/)).toBeInTheDocument();
    expect(screen.getByText(/Unclassified \(matches destructive rules for approval only\)/)).toBeInTheDocument();
    expect(screen.getByText("a".repeat(64))).toBeInTheDocument();
    expect(screen.getByText("https://tools.example.com")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it.each(["denied", "expired", "used", "cancelled"] as const)("never displays or retains a %s preview even if an old response includes it", async (status) => {
    mockApi(routes({ [`GET ${base}`]: () => approval({ status, canDecide: false, preview: "TERMINAL_SENTINEL", usedAt: status === "used" ? new Date().toISOString() : null }) }));
    const { container, qc } = renderApp(detail);
    await screen.findByRole("heading", { name: "delete_document", level: 1 });
    expect(container.querySelector("pre")).toBeNull();
    expect(JSON.stringify(qc.getQueryData(approvalKey(approvalId)))).not.toContain("TERMINAL_SENTINEL");
    if (status === "used") {
      expect(screen.getByText(/Authorization spent — execution is not confirmed/)).toBeInTheDocument();
      expect(screen.getByText(/Retrying may duplicate effects/)).toBeInTheDocument();
    }
  });

  it("hides stale previews and unavailable detail; does not expose forbidden cached text", async () => {
    let forbidden = false;
    mockApi(routes({ [`GET ${base}`]: () => forbidden ? Reply.error(403, "forbidden", "Receipt not accessible") : approval({ stale: true, preview: "STALE_SENTINEL", canDecide: false }) }));
    const { container, qc } = renderApp(detail);
    await screen.findByText("This review is stale");
    expect(container.querySelector("pre")).toBeNull();
    expect(JSON.stringify(qc.getQueryData(approvalKey(approvalId)))).not.toContain("STALE_SENTINEL");
    forbidden = true;
    await act(async () => { await qc.invalidateQueries({ queryKey: approvalKey(approvalId) }); });
    expect(await screen.findByText("Receipt not accessible")).toBeInTheDocument();
    expect(container.querySelector("pre")).toBeNull();
  });

  it("removes a previously visible preview on a live-to-terminal refresh", async () => {
    let spent = false;
    mockApi(routes({ [`GET ${base}`]: () => spent ? approval({ status: "used", canDecide: false, preview: "OLD_SECRET" }) : approval({ preview: "OLD_SECRET" }) }));
    const { container, qc } = renderApp(detail);
    await screen.findByText("OLD_SECRET");
    spent = true;
    await act(async () => { await qc.invalidateQueries({ queryKey: approvalKey(approvalId) }); });
    await screen.findByText(/Authorization spent — execution is not confirmed/);
    expect(container.querySelector("pre")).toBeNull();
    expect(JSON.stringify(qc.getQueryData(approvalKey(approvalId)))).not.toContain("OLD_SECRET");
  });

  it.each(["user", "service_account"] as const)("uses server flags, never platform role or requester guesses, for %s separation of duties", async (requesterKind) => {
    mockApi(routes({
      "GET /v1/me": () => meFor("platform_admin", "owner"),
      [`GET ${base}`]: () => approval({ requesterKind, requesterId: meFor().user.id, canDecide: false, canCancel: true, canRenew: false }),
    }));
    renderApp(detail);
    await screen.findByRole("heading", { name: "delete_document", level: 1 });
    expect(screen.queryByRole("button", { name: "Approve exact call" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Deny" })).toBeNull();
    expect(screen.getByRole("button", { name: "Cancel request" })).toBeEnabled();
    expect(screen.getByText(/separation of duties and fallback are checked by the portal/)).toBeInTheDocument();
  });

  it("does not second-guess an eligible reviewer even if metadata resembles their own identity", async () => {
    mockApi(routes({ [`GET ${base}`]: () => approval({ requesterId: meFor().user.id, canDecide: true }) }));
    renderApp(detail);
    expect(await screen.findByRole("button", { name: "Approve exact call" })).toBeEnabled();
  });

  it("freezes pending actions, captures revision/digest, drops preview and requires reload on 409 without resubmitting", async () => {
    const u = userEvent.setup();
    const response = deferred<Reply>();
    let current = approval();
    const calls = mockApi(routes({
      [`GET ${base}`]: () => current,
      [`POST ${base}/decision`]: () => response.promise,
    }));
    const { qc, container } = renderApp(detail);
    await screen.findByText(/onerror/);
    await u.click(screen.getByRole("button", { name: "Approve exact call" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "POST")).toHaveLength(1));
    expect(screen.getByRole("button", { name: "Deny" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Reload receipt" })).toBeDisabled();
    expect(container.querySelector("pre")).toBeNull();
    current = approval({ reviewRevision: 9, argsDigest: "c".repeat(64), preview: "LATEST_PREVIEW" });
    act(() => qc.setQueryData(approvalKey(approvalId), current));
    expect(screen.getByRole("button", { name: "Approve exact call" })).toBeDisabled();
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ decision: "approve", expectedReviewRevision: 7, expectedArgsDigest: "a".repeat(64) });
    await act(async () => response.resolve(Reply.error(409, "changed_since_review", "The receipt changed")));
    await screen.findByText("Changed since review");
    expect(container.querySelector("pre")).toBeNull();
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
    await u.click(screen.getByRole("button", { name: "Reload receipt" }));
    await screen.findByText("LATEST_PREVIEW");
    expect(screen.getByRole("button", { name: "Approve exact call" })).toBeEnabled();
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
  });

  it.each(["Deny", "Cancel request", "Request new attempt"])("submits %s only when offered, with the captured review revision", async (label) => {
    const u = userEvent.setup();
    const path = label === "Deny" ? "decision" : label === "Cancel request" ? "cancel" : "renew";
    const calls = mockApi(routes({
      [`GET ${base}`]: () => approval({ canCancel: true, canRenew: true }),
      [`POST ${base}/${path}`]: () => approval({ status: "denied", canDecide: false, canCancel: false, canRenew: true }),
    }));
    renderApp(detail);
    await u.click(await screen.findByRole("button", { name: label }));
    await waitFor(() => expect(calls.filter((c) => c.method === "POST")).toHaveLength(1));
    expect(calls.find((c) => c.method === "POST")?.body).toEqual(label === "Deny" ? { decision: "deny", expectedReviewRevision: 7, expectedArgsDigest: "a".repeat(64) } : { expectedReviewRevision: 7 });
  });

  it("ignores a late renewal navigation after leaving and reopening another receipt", async () => {
    const u = userEvent.setup();
    const response = deferred<ReturnType<typeof approval>>();
    const other = "34343434-3434-4434-8434-343434343434";
    mockApi(routes({ [`GET ${base}`]: () => approval({ status: "denied", canDecide: false, canRenew: true }), [`POST ${base}/renew`]: () => response.promise, [`GET /v1/approvals/${other}`]: () => approval({ id: other, exposedName: "other_tool" }) }));
    const { router } = renderApp(detail);
    await u.click(await screen.findByRole("button", { name: "Request new attempt" }));
    await act(async () => { await router.navigate({ to: "/approvals/$approvalId", params: { approvalId: other } }); });
    await screen.findByRole("heading", { level: 1, name: "other_tool" });
    await act(async () => response.resolve(approval({ id: "35353535-3535-4535-8535-353535353535" })));
    expect(router.state.location.pathname).toBe(`/approvals/${other}`);
    expect(screen.getByRole("heading", { level: 1, name: "other_tool" })).toBeInTheDocument();
  });

  it("shows a missing receipt safely and offers no actions", async () => {
    mockApi(routes({ [`GET ${base}`]: () => Reply.error(404, "not_found") }));
    const { container } = renderApp(detail);
    await screen.findByRole("heading", { level: 1, name: "Not found" });
    expect(container.querySelector("pre")).toBeNull();
    expect(screen.queryByRole("button", { name: "Approve exact call" })).toBeNull();
  });

  it("accepts an authorized approved preview but removes it and disables decision controls at local expiry", async () => {
    const validUntil = new Date(Date.now() - 50).toISOString();
    mockApi(routes({ [`GET ${base}`]: () => approval({ status: "approved", validUntil, preview: "EXPIRED_SENTINEL" }) }));
    const { container } = renderApp(detail);
    await screen.findByText("The displayed deadline has passed");
    expect(container.querySelector("pre")).toBeNull();
    expect(screen.getByRole("button", { name: "Approve exact call" })).toBeDisabled();
    expect(safeReceipt(approval({ status: "approved", validUntil: new Date(Date.now() + 60_000).toISOString() })).preview).toContain("onerror");
  });

  it("treats locally expired receipts as preview-inaccessible", () => {
    expect(safeReceipt(approval({ expiresAt: new Date(Date.now() - 100).toISOString() })).preview).toBeUndefined();
    expect(safeReceipt(approval({ status: "approved", validUntil: new Date(Date.now() - 100).toISOString() })).preview).toBeUndefined();
  });

  it("labels approval notifications and distinguishes an approval gate from execution", () => {
    expect(eventLabel("approval.requested")).toBe("A tool call is waiting for approval");
    expect(eventLabel("approval.decided")).toBe("A tool-call approval was decided");
    expect(outcomeLabels.needs_approval).toBe("Needs approval");
    expect(identitySentLabel({ identitySent: null, outcome: "needs_approval", method: "tools/call" })).toBe("Not forwarded");
  });
});
