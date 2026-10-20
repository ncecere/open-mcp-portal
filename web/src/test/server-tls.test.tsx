/*
 * TLS to the server (decision 74): the Settings card shows what is stored as facts (never a key), takes PEM text,
 * checks the obvious mistakes before sending, sends only what changed, says when a changed CA sends a published
 * server back to review, and keeps the old key from following a new address. There is no way to skip verification.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Schemas } from "../api/client";
import { wordsFor } from "../components/attention/wording";
import { changesCa, emptyTlsForm, expiryText, tlsBody, tlsProblems, tlsRefusal } from "../components/servers/tls";
import { ApiError } from "../api/client";
import { capabilities, healthCheck, mcpServer, serverId, team, teamPublishing, page } from "./fixtures";
import { type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

type McpServer = Schemas["McpServer"];
const base = `/v1/teams/${team.slug}/mcp-servers`;
const record = `/teams/${team.slug}/servers/${serverId}`;
const settings = `${record}?tab=settings`;

const certPem = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ0xJRU5U\n-----END CERTIFICATE-----";
const caPem = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ0E=\n-----END CERTIFICATE-----";
const keyPem = "-----BEGIN PRIVATE KEY-----\nQUFBQUFBQUFBQUFB\n-----END PRIVATE KEY-----";
const sha = "ab".repeat(32);

const cert = (extra: Partial<Schemas["TlsCertificate"]> = {}): Schemas["TlsCertificate"] => ({
  subject: "CN=omp-portal,O=Example",
  issuer: "CN=Internal CA,O=Example",
  sha256: sha,
  notBefore: "2026-01-01T00:00:00Z",
  notAfter: "2027-01-18T00:00:00Z",
  ...extra,
});

const withTls = (extra: Partial<McpServer> = {}, client: Partial<Schemas["McpServerTlsClient"]> = {}, ca = true): McpServer =>
  mcpServer({
    tls: {
      ca: ca ? { sha256: "cd".repeat(32), certificates: [cert({ subject: "CN=Internal CA,O=Example", issuer: "CN=Internal CA,O=Example", sha256: "cd".repeat(32) })] } : null,
      client: { certificate: cert(), chainLength: 1, hasKey: true, status: "valid", daysLeft: 90, ...client },
    },
    ...extra,
  });

const routes = (role: Schemas["TeamRole"], get: () => McpServer, extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", role),
  [`GET ${base}`]: () => page([get()]),
  [`GET ${base}/${serverId}`]: () => get(),
  [`GET ${base}/${serverId}/capabilities`]: () => capabilities,
  [`GET ${base}/${serverId}/health-checks`]: () => [healthCheck()],
  [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing({ effective: get().effectivePublishPolicy }),
  ...extra,
});

const patches = (calls: { method: string; body?: unknown }[]) => calls.filter((c) => c.method === "PATCH").map((c) => c.body as { tls?: Schemas["McpServerTlsInput"] } & Record<string, unknown>);

describe("The TLS card", () => {
  it("shows the stored certificates as facts and never a key; Overview shows the summary", async () => {
    mockApi(routes("editor", () => withTls()));
    const { container } = renderApp(settings);
    expect(await screen.findByText("TLS to the server")).toBeInTheDocument();
    expect(await screen.findByLabelText("Stored client certificate")).toHaveTextContent("CN=omp-portal,O=Example");
    expect(screen.getByLabelText("Stored client certificate")).toHaveTextContent("Issued by CN=Internal CA,O=Example");
    expect(screen.getByLabelText("Stored client certificate")).toHaveTextContent("The private key is stored encrypted and is never shown.");
    expect(screen.getByLabelText("Stored client certificate")).toHaveTextContent("ab:ab:ab:ab:ab:ab:ab:ab");
    expect(screen.getByLabelText("Stored CA")).toHaveTextContent("1 certificate");
    expect(container.textContent).not.toMatch(/BEGIN|PRIVATE KEY/);
    expect(screen.queryByRole("checkbox", { name: /skip|insecure|verif/i })).toBeNull();
    expect(screen.queryByRole("switch", { name: /skip|insecure|verif/i })).toBeNull();
  });

  it("warns on Overview when the client certificate is about to expire, and when it has", async () => {
    const soon = withTls(
      { health: { status: "healthy", checkedAt: "2026-10-16T07:55:00Z", statusSince: "2026-10-15T08:00:00Z", latencyMs: 42, warnings: [{ code: "tls_certificate_expiring", message: "The client certificate expires on 2026-10-25 (in 5 days). Upload a renewed certificate before then." }] } },
      { status: "expiring", daysLeft: 5 },
    );
    mockApi(routes("editor", () => soon));
    renderApp(record);
    expect(await screen.findByText("Client certificate expires soon")).toBeInTheDocument();
    expect(screen.getByText(/Upload a renewed certificate before then/)).toBeInTheDocument();
    expect(screen.getByText(/private CA, client certificate \(expires .*, in 5 days\)/)).toBeInTheDocument();
  });

  it("sends the pasted CA, certificate and key, then shows only facts and an empty form", async () => {
    const u = userEvent.setup();
    let current = mcpServer();
    const calls = mockApi(
      routes("editor", () => current, {
        [`PATCH ${base}/${serverId}`]: () => (current = withTls({ revision: 5 })),
      }),
    );
    renderApp(settings);
    await u.click(await screen.findByLabelText("CA certificates"));
    await u.paste(caPem);
    await u.click(screen.getByLabelText("Client certificate"));
    await u.paste(certPem);
    await u.click(screen.getByLabelText("Client private key"));
    await u.paste(keyPem);
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(1));
    expect(patches(calls)[0]!.tls).toEqual({ caPem, clientCertPem: certPem, clientKeyPem: keyPem });
    expect(await screen.findByLabelText("Stored client certificate")).toBeInTheDocument();
    expect(screen.getByLabelText("Replace the client certificate")).toHaveValue("");
    expect(screen.getByLabelText("Client private key")).toHaveValue("");
    expect(document.body.textContent).not.toContain("QUFBQUFBQUFBQUFB");
  });

  it("sends nothing about TLS when only another field changes", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("editor", () => withTls(), { [`PATCH ${base}/${serverId}`]: () => withTls({ name: "Renamed", revision: 5 }) }));
    renderApp(settings);
    const name = await screen.findByRole("textbox", { name: "Name" });
    await u.clear(name);
    await u.type(name, "Renamed");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(1));
    expect(patches(calls)[0]).not.toHaveProperty("tls");
  });

  it("catches a key pasted as the CA, a passphrase-protected key and a certificate without its key before sending", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("editor", () => mcpServer()));
    renderApp(settings);
    await u.click(await screen.findByLabelText("CA certificates"));
    await u.paste(keyPem);
    await u.click(screen.getByLabelText("Client certificate"));
    await u.paste(certPem);
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText("That contains a private key. This field takes certificates only.")).toBeInTheDocument();
    expect(screen.getByText("Paste the private key that goes with this certificate.")).toBeInTheDocument();
    await u.click(screen.getByLabelText("Client private key"));
    await u.paste("-----BEGIN ENCRYPTED PRIVATE KEY-----\nQUFB\n-----END ENCRYPTED PRIVATE KEY-----");
    expect(await screen.findByText(/protected by a passphrase/)).toBeInTheDocument();
    expect(patches(calls)).toHaveLength(0);
  });

  it("shows the server's refusal at the field it names, without echoing anything", async () => {
    const u = userEvent.setup();
    mockApi(
      routes("editor", () => mcpServer(), {
        [`PATCH ${base}/${serverId}`]: () => Reply.error(422, "invalid_tls", "The private key doesn't belong to the first certificate.", { field: "tls.clientKeyPem", reason: "key_mismatch" }),
      }),
    );
    renderApp(settings);
    await u.click(await screen.findByLabelText("Client certificate"));
    await u.paste(certPem);
    await u.click(screen.getByLabelText("Client private key"));
    await u.paste(keyPem);
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText("The private key doesn't belong to the first certificate.")).toBeInTheDocument();
  });

  it("removes the client certificate and its key, or the CA, with an explicit change", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("editor", () => withTls(), { [`PATCH ${base}/${serverId}`]: () => mcpServer({ revision: 5 }) }));
    renderApp(settings);
    await u.click(await screen.findByRole("button", { name: "Remove the certificate and key" }));
    expect(screen.getByText("Removed when you save, with its private key.")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Remove the CA" }));
    expect(screen.getByText(/the system's trusted roots apply to this server again/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(1));
    expect(patches(calls)[0]!.tls).toEqual({ caPem: "", clientCertPem: "" });
  });

  it("says a changed CA sends a published server back to review, and that it did; a new certificate doesn't", async () => {
    const u = userEvent.setup();
    const reviewed = { publishRequestedAt: "2026-10-11T10:00:00Z", publishReviewedAt: "2026-10-12T10:00:00Z", publishReviewedByName: "Ada Admin" };
    let current = mcpServer({ publishState: "published", ...reviewed });
    mockApi(
      routes("editor", () => current, {
        [`PATCH ${base}/${serverId}`]: () => (current = withTls({ publishState: "pending", ...reviewed, publishRequestedAt: "2026-10-16T09:00:00Z", revision: 5 })),
      }),
    );
    renderApp(settings);
    await u.click(await screen.findByLabelText("Client certificate"));
    await u.paste(certPem);
    await u.click(screen.getByLabelText("Client private key"));
    await u.paste(keyPem);
    expect(screen.queryByText("The server will leave the catalog")).toBeNull();
    await u.click(screen.getByLabelText("CA certificates"));
    await u.paste(caPem);
    expect(screen.getByText("The server will leave the catalog")).toBeInTheDocument();
    expect(screen.getByText(/Saving takes the server out of the catalog until it's reviewed again/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText("Service status left the catalog until a platform admin reviews its new CA.")).toBeInTheDocument();
  });

  it("warns that a new address needs the client certificate again, and maps the server's refusal to the key field", async () => {
    const u = userEvent.setup();
    const noAuth: Partial<McpServer> = { authMode: "none", hasAuth: false, credentials: [], authHeaderName: undefined, authValueHint: "" };
    const calls = mockApi(
      routes("editor", () => withTls(noAuth), {
        [`PATCH ${base}/${serverId}`]: () => Reply.error(422, "tls_key_required", "The URL moves to another host, so the stored TLS client key can't be reused there.", { field: "tls.clientKeyPem" }),
      }),
    );
    renderApp(settings);
    const url = await screen.findByRole("textbox", { name: "URL" });
    expect(screen.queryByText("The new address needs the certificate again")).toBeNull();
    await u.clear(url);
    await u.type(url, "https://other.example.com/mcp");
    expect(screen.getByText("The new address needs the certificate again")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText("The URL moves to another host, so the stored TLS client key can't be reused there.")).toBeInTheDocument();
    expect(patches(calls)).toHaveLength(1);
    // Pasting the new pair (or removing it) is what lets it through.
    await u.click(screen.getByLabelText("Replace the client certificate"));
    await u.paste(certPem);
    await u.click(screen.getByLabelText("Client private key"));
    await u.paste(keyPem);
    expect(screen.queryByText("The new address needs the certificate again")).toBeNull();
  });

  it("is read-only for members", async () => {
    mockApi(routes("member", () => withTls()));
    renderApp(settings);
    expect(await screen.findByLabelText("Stored client certificate")).toBeInTheDocument();
    expect(screen.queryByLabelText("CA certificates")).toBeNull();
    expect(screen.queryByLabelText("Client private key")).toBeNull();
    expect(screen.queryByRole("button", { name: "Remove the certificate and key" })).toBeNull();
  });
});

describe("TLS form helpers", () => {
  const server = mcpServer();
  it("sends only what changed, and removing wins over typed text", () => {
    expect(tlsBody(emptyTlsForm)).toBeUndefined();
    expect(tlsBody({ ...emptyTlsForm, caPem: `  ${caPem}\n` })).toEqual({ caPem });
    expect(tlsBody({ ...emptyTlsForm, removeCa: true, caPem })).toEqual({ caPem: "" });
    expect(tlsBody({ ...emptyTlsForm, removeClient: true, clientCertPem: certPem, clientKeyPem: keyPem })).toEqual({ clientCertPem: "" });
    expect(tlsBody({ ...emptyTlsForm, clientCertPem: certPem })).toEqual({ clientCertPem: certPem });
  });

  it("flags the obvious mistakes", () => {
    expect(tlsProblems({ ...emptyTlsForm, caPem: "hello" }, server).caPem).toMatch(/Paste PEM certificates/);
    expect(tlsProblems({ ...emptyTlsForm, caPem: "x".repeat(70000) }, server).caPem).toMatch(/at most 64 KiB/);
    expect(tlsProblems({ ...emptyTlsForm, clientCertPem: keyPem }, server).clientCertPem).toMatch(/contains a private key/);
    expect(tlsProblems({ ...emptyTlsForm, clientKeyPem: "nope" }, server).clientKeyPem).toMatch(/unencrypted private key/);
    expect(tlsProblems({ ...emptyTlsForm, clientKeyPem: keyPem }, server).clientCertPem).toMatch(/certificate that goes with this key/);
    expect(tlsProblems({ ...emptyTlsForm, clientCertPem: certPem }, server).clientKeyPem).toMatch(/private key that goes with this certificate/);
    // A renewal needs no key when one is stored.
    expect(tlsProblems({ ...emptyTlsForm, clientCertPem: certPem }, withTls())).toEqual({});
    expect(tlsProblems({ ...emptyTlsForm, caPem, clientCertPem: certPem, clientKeyPem: keyPem }, server)).toEqual({});
  });

  it("maps the server's refusals to fields", () => {
    expect(tlsRefusal(new ApiError(422, "invalid_tls", "bad", { field: "tls.caPem" }))).toEqual({ caPem: "bad" });
    expect(tlsRefusal(new ApiError(422, "invalid_tls", "bad", { field: "tls" }))).toEqual({ clientCertPem: "bad" });
    expect(tlsRefusal(new ApiError(422, "tls_key_required", "again", { field: "tls.clientKeyPem" }))).toEqual({ clientKeyPem: "again" });
    expect(tlsRefusal(new ApiError(422, "url_not_allowed", "no"))).toEqual({});
    expect(tlsRefusal(new Error("x"))).toEqual({});
  });

  it("knows when the CA changes and words the expiry", () => {
    expect(changesCa(emptyTlsForm, server)).toBe(false);
    expect(changesCa({ ...emptyTlsForm, caPem }, server)).toBe(true);
    expect(changesCa({ ...emptyTlsForm, removeCa: true }, server)).toBe(false);
    expect(changesCa({ ...emptyTlsForm, removeCa: true }, withTls())).toBe(true);
    const c = withTls().tls!.client!;
    expect(expiryText(c)).toMatch(/^Expires /);
    expect(expiryText({ ...c, status: "expiring", daysLeft: 1 })).toMatch(/in 1 day$/);
    expect(expiryText({ ...c, status: "expired", daysLeft: -2 })).toMatch(/^Expired /);
  });

  it("words the attention item for an expiring or an expired certificate", () => {
    const item = (severity: Schemas["AttentionSeverity"]): Schemas["AttentionItem"] => ({ kind: "server_certificate_expiring", severity, summary: "x", subject: { id: serverId, name: "Status", slug: "status" } });
    expect(wordsFor(item("warning"))).toEqual({ title: "The client certificate of Status expires within 14 days", atLabel: "Expires", action: "Open server" });
    expect(wordsFor(item("critical")).title).toBe("The client certificate of Status has expired");
  });
});

describe("The call error class", () => {
  it("has a plain label", async () => {
    mockApi(routes("editor", () => mcpServer({ health: { status: "failing", checkedAt: "2026-10-16T07:55:00Z", statusSince: "2026-10-15T08:00:00Z", errorClass: "tls", message: "The server's certificate is signed by an authority the portal doesn't trust." } })));
    renderApp(record);
    const row = await screen.findByText(/TLS problem: certificate or client certificate/);
    expect(within(row.closest("dd") ?? document.body).getByText(/signed by an authority the portal doesn't trust/)).toBeInTheDocument();
  });
});
