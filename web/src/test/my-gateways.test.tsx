/* Workspace › My gateways: why the person has access, what each offers them, and the Connect section. */
import { screen, waitFor, within } from "@testing-library/react";
import { axe } from "vitest-axe";
import { gatewayCapability, gatewayId, myGateway, team } from "./fixtures";
import { type Handler, Reply, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const platform = myGateway({
  id: "g-platform",
  slug: "company-tools",
  name: "Company tools",
  ownerKind: "platform",
  teamSlug: undefined,
  teamName: undefined,
  url: "https://mcp.example.com/mcp/company-tools",
  access: ["team_grant", "user_grant", "group_grant"],
  groups: ["engineering"],
  capabilityCount: 3,
});

const routes = (extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", "member"),
  "GET /v1/me/gateways": () => [myGateway(), platform],
  [`GET /v1/me/gateways/${gatewayId}`]: () => ({ gateway: myGateway(), capabilities: [gatewayCapability()] }),
  ...extra,
});

describe("My gateways", () => {
  it("lists the gateways the person can use, and why", async () => {
    mockApi(routes());
    const { container } = renderApp("/gateways");
    expect(await screen.findByRole("heading", { level: 1, name: "My gateways" })).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "My gateways" });
    const mine = (await within(table).findByText("Support tools")).closest("tr")!;
    expect(mine).toHaveTextContent(`Member of ${team.name}`);
    expect(mine).toHaveTextContent("1 capability");
    expect(within(mine).getByRole("link", { name: "Support tools" })).toHaveAttribute("href", `/gateways/${gatewayId}`);
    const shared = within(table).getByText("Company tools").closest("tr")!;
    expect(shared).toHaveTextContent("Granted to your team");
    expect(shared).toHaveTextContent("Granted to you");
    expect(within(shared).getByText("Granted to your SSO group engineering")).toBeInTheDocument();
    expect(shared).toHaveTextContent("3 capabilities");
    await waitFor(() => expect(document.title).toBe("My gateways · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("says where gateways come from when there are none", async () => {
    mockApi(routes({ "GET /v1/me/gateways": () => [] }));
    renderApp("/gateways");
    expect(await screen.findByText("No gateways for you yet.")).toBeInTheDocument();
  });

  it("shows what a gateway offers the person and how to connect with OAuth sign-in, without a key", async () => {
    mockApi(routes());
    const { container } = renderApp(`/gateways/${gatewayId}`);
    expect(await screen.findByRole("heading", { level: 1, name: "Support tools" })).toBeInTheDocument();
    expect(screen.getByRole("listitem", { name: "tool: service-status__get_status" })).toBeInTheDocument();
    // Only what's available is listed: no availability badges.
    expect(screen.queryByText("Available")).toBeNull();
    expect(screen.getByRole("button", { name: /Copy endpoint URL/ })).toBeInTheDocument();
    const claude = screen.getByText(/claude mcp add/);
    expect(claude.textContent).toContain("https://mcp.example.com/mcp/support-tools");
    expect(claude.textContent).not.toContain("--header");
    expect(screen.getByText(/On first use the client opens your browser/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Account › Connected apps" })).toHaveAttribute("href", "/settings/connected-apps");
    expect(screen.getByRole("link", { name: "Open in your team" })).toHaveAttribute("href", `/teams/${team.slug}/gateways/${gatewayId}`);
    await waitFor(() => expect(document.title).toBe("Support tools · My gateways · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("lists resources and templates with their exposed URIs", async () => {
    const resource = gatewayCapability({ capabilityId: "r1", kind: "resource", name: "status://services", exposedName: "omp://service-status/status://services", title: "Services" });
    const template = gatewayCapability({
      capabilityId: "r2",
      kind: "resource_template",
      name: "status://services/{service}",
      exposedName: "omp://service-status/status://services/{service}",
      title: "Service status",
    });
    mockApi(routes({ [`GET /v1/me/gateways/${gatewayId}`]: () => ({ gateway: myGateway(), capabilities: [gatewayCapability(), resource, template] }) }));
    renderApp(`/gateways/${gatewayId}`);
    expect(await screen.findByRole("listitem", { name: "resource: omp://service-status/status://services" })).toBeInTheDocument();
    expect(screen.getByRole("listitem", { name: "resource template: omp://service-status/status://services/{service}" })).toBeInTheDocument();
    expect(screen.getByText(/resources as omp:\/\/server\/uri/)).toBeInTheDocument();
  });

  it("shows the not-found page for a gateway the person can't use", async () => {
    mockApi(routes({ [`GET /v1/me/gateways/${gatewayId}`]: () => Reply.error(404, "not_found") }));
    renderApp(`/gateways/${gatewayId}`);
    expect(await screen.findByRole("heading", { level: 1, name: "Gateway not found" })).toBeInTheDocument();
  });
});
