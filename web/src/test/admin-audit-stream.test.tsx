import { screen, within, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Status, Sink } from "../pages/admin/audit-stream/api";
import { activeAdminGroup, adminNav } from "../components/layout/nav";
import { mockApi, renderApp, shellRoutes, Reply, type Handler } from "./harness";

const sink: Sink = { id: "s1", name: "Evidence", kind: "webhook", profile: "full", required: true, enabled: true, batch_max_records: 100, revision: 3, url_hint: "receiver.example", cursor_seq: 10, state: "range_expired", lag: 15, last_error_class: "timeout", consecutive_failures: 2, held_oversized_seq: 11, last_ok_at: null };
const status = (): Status => ({ sealer_enabled: true, tip: { stream_id: "stream-id", epoch: 1, last_seq: 25, status: "running", checkpoints_enabled: true, last_checkpoint_seq: 20, last_checkpoint_at: new Date().toISOString() }, sink_settings: { enabled: true, min_reader_version: "0.15.0" }, sinks: [sink], consumers: [{ name: "Archive", profile: "full", required: false, acked_seq: 5, lag: 20 }], checkpoint_keys: [{ kid: "key-id", state: "active" }] });
function setup(data = status(), extra: Record<string, Handler> = {}, auditor = false) {
  const calls = mockApi({ ...shellRoutes(auditor ? "platform_auditor" : "platform_admin", null),
    "GET /v1/admin/audit/stream/status": () => data,
    "GET /.well-known/omp-audit-keys.json": () => new Response(JSON.stringify({ keys: [] }), { status: 200, headers: { "Content-Type": "application/json" } }),
    "GET /v1/admin/audit/stream/tip": () => ({ earliest_seq: 1 }),
    "GET /v1/admin/settings/audit-consumers": () => ({ revision: 4, items: data.consumers }), ...extra });
  return { calls, ...renderApp("/admin/audit-stream") };
}
async function loaded() { await screen.findByRole("heading", { name: "Sinks" }); }
async function dialogAxe() { expect(await axe(screen.queryByRole("dialog") ?? screen.getByRole("alertdialog"))).toHaveNoViolations(); }

describe("Admin audit stream", () => {
  it.each(["sealer-off", "checkpoints-off", "sinks-off", "all-on"])("renders status and accessible notices: %s", async state => {
    const data = status();
    if (state === "checkpoints-off") data.tip.checkpoints_enabled = false;
    if (state === "sinks-off") data.sink_settings.enabled = false;
    if (state === "sealer-off") data.sealer_enabled = false;
    const { container } = setup(data); await loaded();
    expect(screen.queryByText("The audit sealer is off") !== null).toBe(state === "sealer-off");
    expect(screen.queryByText("Checkpoints are disabled") !== null).toBe(state === "checkpoints-off");
    expect(screen.queryByText("Sinks are disabled") !== null).toBe(state === "sinks-off");
    expect(await screen.findByText("stream-id")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });
  it("does not treat the enablement baseline time as a completed checkpoint", async () => {
    const data = status(); data.tip.last_checkpoint_seq = null;
    setup(data); await loaded();
    expect(screen.getByText("No checkpoint yet")).toBeInTheDocument();
  });
  it("describes all retention effects and oversized holds without color", async () => {
    const data = status(); data.sinks = [sink, { ...sink, id: "s2", enabled: false }, { ...sink, id: "s3", required: false }];
    setup(data); await loaded();
    for (const text of [/Holding — retention/, /Holding while disabled —/, /Not holding — optional/]) expect(screen.getByText(text)).toBeInTheDocument();
    expect(screen.getAllByText("11")).toHaveLength(3);
    expect(screen.getAllByText(/range_expired ·/)).toHaveLength(3);
  });
  it("creates and shows a copyable secret once, without caching it", async () => {
    const u = userEvent.setup();
    const { qc } = setup(status(), { "POST /v1/admin/settings/audit-sinks": () => ({ sink, secret: "create-secret-once" }) }); await loaded();
    await u.click(screen.getByRole("button", { name: "Create sink" }));
    await u.type(screen.getByLabelText("Name"), "New sink"); await u.type(screen.getByLabelText("URL"), "https://receiver.example/audit");
    expect(screen.getByText(/A required sink holds audit retention/)).toBeInTheDocument(); await dialogAxe();
    await u.click(screen.getByRole("button", { name: "Save sink" }));
    const d = await screen.findByRole("dialog", { name: "Audit sink signing secret" });
    expect(within(d).getByText(/won't be shown again/)).toBeInTheDocument();
    expect(within(d).getByText("create-secret-once")).toBeInTheDocument(); await dialogAxe();
    await u.click(within(d).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(JSON.stringify(qc.getMutationCache().getAll().map(m => m.state.data))).not.toContain("create-secret-once");
    await u.click(screen.getByRole("button", { name: "Create sink" })); expect(screen.queryByText("create-secret-once")).not.toBeInTheDocument();
  });
  it.each(["Stale sink revision", "Resume and deliver the pending gap before promoting this sink to required"])("keeps edits on 409 and explains %s", async message => {
    const u = userEvent.setup(); const { calls } = setup(status(), { "PUT /v1/admin/settings/audit-sinks/s1": () => Reply.error(409, "sink_conflict", message) }); await loaded();
    await u.click(screen.getByRole("button", { name: "Edit" }));
    await u.clear(screen.getByLabelText("Name")); await u.type(screen.getByLabelText("Name"), "My edits");
    await u.click(screen.getByRole("button", { name: "Save sink" }));
    expect(await screen.findByText(message)).toBeInTheDocument(); expect(screen.getByDisplayValue("My edits")).toBeInTheDocument();
    expect(screen.getByText(/Your edits are still here/)).toBeInTheDocument();
    expect(calls.find(c => c.method === "PUT")?.headers.get("If-Match")).toBe('"3"'); await dialogAxe();
  });
  it.each(["", "timeout"])("shows test result %s", async error_class => {
    const u = userEvent.setup(); setup(status(), { "POST /v1/admin/settings/audit-sinks/s1/test": () => ({ error_class }) }); await loaded();
    await u.click(screen.getByRole("button", { name: "Test" })); await dialogAxe();
    await u.click(screen.getByRole("button", { name: "Test sink" }));
    expect(await screen.findByText(error_class ? "Evidence: Test failed: timeout" : "Evidence: Test succeeded")).toBeInTheDocument();
  });
  it("rotates and shows the secret once with 24 hour overlap", async () => {
    const u = userEvent.setup(); setup(status(), { "POST /v1/admin/settings/audit-sinks/s1/rotate-secret": () => ({ sink, secret: "rotated-once" }) }); await loaded();
    await u.click(screen.getByRole("button", { name: "Rotate secret" }));
    expect(screen.getByText(/previous secret remains valid for 24 hours/)).toBeInTheDocument(); await dialogAxe();
    await u.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Rotate secret" }));
    expect(await screen.findByText("rotated-once")).toBeInTheDocument(); await dialogAxe();
    await u.click(screen.getByRole("button", { name: "Done" })); await waitFor(() => expect(screen.queryByText("rotated-once")).not.toBeInTheDocument());
  });
  it.each([
    ["Resume", "Resume sink", "resume", /receiver must locally approve the discontinuity/],
    ["Acknowledge oversized", "Acknowledge oversized sequence", "oversized/11/acknowledge", /first retrieve and preserve the complete row/],
    ["Delete", "Delete sink", "", /releases this sink's retention hold/],
  ] as const)("confirms %s and sends the observed revision", async (button, confirm, suffix, copy) => {
    const u = userEvent.setup(); const method = button === "Delete" ? "DELETE" : "POST";
    const { calls } = setup(status(), { [`${method} /v1/admin/settings/audit-sinks/s1${suffix ? "/" + suffix : ""}`]: () => ({ sink, secret: null }) }); await loaded();
    await u.click(screen.getByRole("button", { name: button }));
    expect(screen.getByText(copy)).toBeInTheDocument(); expect(calls.filter(c => c.method !== "GET")).toHaveLength(0);
    expect(await axe(screen.getByRole("alertdialog"))).toHaveNoViolations();
    await u.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: confirm }));
    await waitFor(() => expect(calls.find(c => c.method === method)).toBeDefined());
    expect(calls.find(c => c.method === method)?.headers.get("If-Match")).toBe('"3"');
  });
  it("auditors see all data without sink or consumer actions", async () => {
    const { container, calls } = setup(status(), {}, true); await loaded();
    expect(screen.getByText("Archive")).toBeInTheDocument();
    for (const name of ["Edit", "Create sink", "Test", "Delete", "Resume", "Rotate secret", "Register consumer", "Remove", "Make required"]) expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    expect(calls.some(c => c.url.endsWith("audit-consumers"))).toBe(false); expect(await axe(container)).toHaveNoViolations();
  });
  it("registers, toggles and removes pull consumers with revision preconditions", async () => {
    const u = userEvent.setup(); const { calls } = setup(status(), {
      "POST /v1/admin/settings/audit-consumers": () => ({}), "PUT /v1/admin/settings/audit-consumers/Archive": () => ({}), "DELETE /v1/admin/settings/audit-consumers/Archive": () => ({}),
    }); await loaded();
    await u.click(screen.getByRole("button", { name: "Register consumer" })); await u.type(screen.getByLabelText("Consumer name"), "NewArchive"); await dialogAxe();
    await u.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Register consumer" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    for (const button of ["Make required", "Remove"]) {
      await u.click(screen.getByRole("button", { name: button }));
      await u.click(screen.getByRole("button", { name: "Confirm consumer change" }));
      await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
    }
    expect(calls.filter(c => c.method !== "GET").map(c => c.headers.get("If-Match"))).toEqual(['"4"', '"4"', '"4"']);
  });
  it("places Audit stream under Operations", () => {
    expect(activeAdminGroup("/admin/audit-stream")).toBe("Operations");
    expect(adminNav.find(n => n.to === "/admin/audit-stream")?.label).toBe("Audit stream");
  });
  it("shows each sink's last success time, or Never", async () => {
    const data = status(); data.sinks = [{ ...sink, last_ok_at: "2026-11-06T10:00:00Z" }, { ...sink, id: "s2", name: "Fresh", last_ok_at: null }];
    setup(data); await loaded();
    const table = screen.getAllByRole("table")[0]!;
    expect(within(table).getByText("Never")).toBeInTheDocument();
    expect(within(table).queryByText("Unavailable")).not.toBeInTheDocument();
    expect(within(table).getAllByRole("row")).toHaveLength(3);
  });
});
