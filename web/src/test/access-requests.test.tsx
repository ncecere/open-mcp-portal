import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { GatewayRequestSettings } from "../components/gateways/request-settings";
import { accessRequestKey } from "../api/access-requests";
import { deferred } from "./fixtures-approvals";
import { meFor, team, user } from "./fixtures";
import { mockApi, renderApp, renderBare, Reply, shellRoutes } from "./harness";

const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const gatewayId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const gateway = { id: gatewayId, name: "Support tools", description: "Requestable support gateway" };
const base = `/v1/access-requests/${id}`;
const receipt = (extra: Partial<Schemas["AccessRequest"]> = {}): Schemas["AccessRequest"] => ({
  id, gatewayId, gatewayName: gateway.name, requesterId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", requesterName: "Requester", subjectKind: "user",
  reason: "<img src=x onerror=alert(1)> Private reason", status: "pending", createdAt: "2026-10-29T02:00:00Z", decidedAt: null, decisionNote: "", grantId: null, grantExpiresAt: null, canDecide: true, ...extra,
});
const defaults = () => ({ ...shellRoutes(),
  "GET /v1/gateways/requestable": () => ({ items: [gateway], nextCursor: null }),
  "GET /v1/me/access-requests": () => ({ items: [receipt()], nextCursor: null, pendingReviewCount: 1 }),
  [`GET ${base}`]: () => receipt(),
});

describe("Gateway access requests", () => {
  it("offers opt-in discovery and a reason/team dialog, with accessible markup", async () => {
    const u = userEvent.setup();
    const response = deferred<Schemas["AccessRequest"]>();
    const calls = mockApi({ ...defaults(), "POST /v1/me/access-requests": () => response.promise });
    const { container } = renderApp("/access-requests");
    const request = await screen.findByRole("button", { name: "Request access to Support tools" });
    expect(request.textContent).toBe("Request access"); // Do not repeat a long gateway name in a nowrap button.
    await u.click(request);
    await u.selectOptions(screen.getByLabelText("Request for"), team.id);
    expect(screen.getByText(/all current and future members and the team's service accounts/)).toBeInTheDocument();
    await u.type(screen.getByLabelText("Reason"), "Support incident work");
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Submit access request" }));
    await waitFor(() => expect(screen.getByLabelText("Reason")).toBeDisabled());
    expect(screen.getByLabelText("Request for")).toBeDisabled();
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ gatewayId, teamId: team.id, reason: "Support incident work" });
    response.resolve(receipt());
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("keeps reasons out of queues and supports personal/reviewer views and counts", async () => {
    const u = userEvent.setup();
    const calls = mockApi(defaults());
    renderApp("/access-requests");
    await screen.findByRole("button", { name: "Request access to Support tools" });
    await u.click(screen.getByRole("tab", { name: "My requests" }));
    await screen.findByRole("link", { name: "Support tools" });
    expect(screen.queryByText(/Private reason/)).toBeNull();
    expect(calls.filter((c) => c.url === "/v1/me/access-requests").at(-1)?.search.get("view")).toBe("requested");
    await u.click(screen.getByRole("tab", { name: "Review requests" }));
    await screen.findByText(/1 pending requests you can review now/);
    expect(calls.filter((c) => c.url === "/v1/me/access-requests").at(-1)?.search.get("view")).toBe("review");
  });

  it("renders private text escaped, and freezes the exact submitted decision", async () => {
    const u = userEvent.setup();
    const response = deferred<Schemas["AccessRequest"]>();
    let current = receipt();
    const calls = mockApi({ ...defaults(), [`GET ${base}`]: () => current, [`POST ${base}/decision`]: () => response.promise.then((data) => { current = data; return data; }) });
    const { container } = renderApp(`/access-requests/${id}`);
    await screen.findByRole("heading", { level: 1, name: "Support tools" });
    expect(screen.getByText(/<img src=x onerror=alert\(1\)>/)).toBeInTheDocument();
    expect(container.querySelector('img[src="x"]')).toBeNull();
    await u.type(screen.getByLabelText("Grant lifetime (days)"), "7");
    await u.type(screen.getByLabelText("Decision note"), "Time-limited support");
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Approve gateway access" }));
    await waitFor(() => expect(screen.getByLabelText("Decision note")).toBeDisabled());
    expect(screen.getByRole("button", { name: "Deny access" })).toBeDisabled();
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ decision: "approve", note: "Time-limited support", expiresInDays: 7 });
    response.resolve(receipt({ status: "approved", canDecide: false, grantId: gatewayId, grantExpiresAt: "2026-11-05T02:00:00Z" }));
    await screen.findByText(/this receipt is history, not proof of current access/);
  });

  it("allows requester withdrawal but never displays requester approval controls", async () => {
    const u = userEvent.setup();
    const mine = receipt({ requesterId: user().id, canDecide: false });
    const calls = mockApi({ ...defaults(), [`GET ${base}`]: () => mine, [`POST ${base}/withdraw`]: () => ({ ...mine, status: "withdrawn" }) });
    renderApp(`/access-requests/${id}`);
    await screen.findByRole("button", { name: "Withdraw request" });
    expect(screen.queryByRole("button", { name: "Approve gateway access" })).toBeNull();
    await u.click(screen.getByRole("button", { name: "Withdraw request" }));
    await waitFor(() => expect(calls.some((c) => c.url === `${base}/withdraw`)).toBe(true));
  });

  it("hides cached private text on failed refresh and requires reload after a refused action", async () => {
    const u = userEvent.setup();
    let forbidden = false;
    mockApi({ ...defaults(), [`GET ${base}`]: () => forbidden ? Reply.error(404, "access_request_not_found", "Private request unavailable") : receipt(), [`POST ${base}/decision`]: () => Reply.error(409, "request_decided", "Already decided") });
    const { qc } = renderApp(`/access-requests/${id}`);
    await u.click(await screen.findByRole("button", { name: "Approve gateway access" }));
    await screen.findByText(/Reload and review the request again/);
    expect(screen.getByRole("button", { name: "Approve gateway access" })).toBeDisabled();
    forbidden = true;
    await qc.invalidateQueries({ queryKey: accessRequestKey(id) });
    await screen.findByRole("heading", { level: 1, name: "Not found" });
    expect(screen.queryByText(/Private reason/)).toBeNull();
  });

  it("rejects invalid expiry before a decision is submitted", async () => {
    const u = userEvent.setup();
    const calls = mockApi(defaults());
    renderApp(`/access-requests/${id}`);
    await u.type(await screen.findByLabelText("Grant lifetime (days)"), "0");
    expect(screen.getByRole("button", { name: "Approve gateway access" })).toBeDisabled();
    expect(calls.some((c) => c.method === "POST")).toBe(false);
  });
});

describe("Gateway request settings", () => {
  const path = `/v1/admin/gateways/${gatewayId}/access-settings`;
  const settings = { enabled: false, stewardIds: [], revision: 7 };
  it("requires explicit opt-in and captures gateway revision and steward UUIDs", async () => {
    const u = userEvent.setup();
    const calls = mockApi({ [`GET ${path}`]: () => settings, [`PUT ${path}`]: (body) => ({ ...(body as object), revision: 8 }) });
    const { container } = renderBare(<GatewayRequestSettings gatewayId={gatewayId} readOnly={false} />, meFor("platform_admin"));
    await u.click(await screen.findByRole("checkbox", { name: "Allow people to discover this gateway and request access" }));
    await u.type(screen.getByLabelText("Gateway steward user IDs"), user().id);
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Save request settings" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const submitted = calls.find((c) => c.method === "PUT")!;
    expect(submitted.headers.get("If-Match")).toBe('"7"');
    expect(submitted.body).toEqual({ enabled: true, stewardIds: [user().id] });
  });
  it("keeps auditors read-only", async () => {
    mockApi({ [`GET ${path}`]: () => settings });
    renderBare(<GatewayRequestSettings gatewayId={gatewayId} readOnly />, meFor("platform_auditor"));
    expect(await screen.findByRole("checkbox", { name: "Allow people to discover this gateway and request access" })).toHaveAttribute("aria-disabled", "true");
    expect(screen.queryByRole("button", { name: "Save request settings" })).toBeNull();
  });
});
