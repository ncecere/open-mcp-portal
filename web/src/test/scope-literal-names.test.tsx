import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { axe } from "vitest-axe";
import { ScopeEditor, type ToolScope } from "../components/tool-scope";
import { apiKey, grant, myGateway, platformGateway, serviceAccount, serviceAccountId, serviceAccountKey, team } from "./fixtures";
import { mockApi, renderApp, shellRoutes } from "./harness";

function Editor() {
  const [scope, setScope] = useState<ToolScope>({});
  const [problem, setProblem] = useState<string>();
  return <><ScopeEditor value={scope} onChange={setScope} onProblemChange={setProblem} />
    <output aria-label="Stored scope">{JSON.stringify(scope)}</output>
    <output aria-label="Draft problem">{problem ?? ""}</output></>;
}

describe("Literal exact-name entry", () => {
  it("adds one literal permission, preserving commas, whitespace and case, with explicit removal", async () => {
    const u = userEvent.setup();
    const { container } = render(<Editor />);
    const input = screen.getByRole("textbox", { name: "Exact tool names" });
    await u.type(input, " mail,Delete ");
    expect(input).toHaveValue(" mail,Delete ");
    expect(screen.getByLabelText("Stored scope")).toHaveTextContent("{}");
    expect(screen.getByLabelText("Draft problem")).toHaveTextContent("Add the tool name or clear the draft before saving.");
    await u.click(screen.getByRole("button", { name: "Add tool name" }));
    expect(JSON.parse(screen.getByLabelText("Stored scope").textContent!)).toEqual({ tools: [" mail,Delete "] });
    expect(screen.getByLabelText("Draft problem")).toBeEmptyDOMElement();
    expect(input).toHaveValue("");
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Remove tool name mail,Delete" }));
    expect(JSON.parse(screen.getByLabelText("Stored scope").textContent!)).toEqual({ tools: [] });
  });

  it.each(["mail\nDelete", "mail\r\nDelete", "mail\tDelete", "mail\u0000Delete", "mail\u007fDelete", "mail\u0085Delete"])("rejects raw pasted controls instead of splitting or sanitizing %j", async (raw) => {
    const u = userEvent.setup();
    render(<Editor />);
    const input = screen.getByRole("textbox", { name: "Exact tool names" });
    await u.click(input);
    await u.paste(raw);
    expect(input).toHaveValue("");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByLabelText("Stored scope")).toHaveTextContent("{}");
    expect(screen.getByLabelText("Draft problem")).toHaveTextContent("Pasted names cannot contain control characters");
    await u.keyboard("{Enter}");
    expect(screen.getByLabelText("Stored scope")).toHaveTextContent("{}");
    await u.click(screen.getByRole("button", { name: "Clear name draft" }));
    expect(screen.getByLabelText("Draft problem")).toBeEmptyDOMElement();
  });

  it("accepts a literal comma paste as one name and enforces 1100 UTF-8 bytes on actual input without truncation", async () => {
    const u = userEvent.setup();
    render(<Editor />);
    const input = screen.getByRole("textbox", { name: "Exact tool names" });
    await u.click(input);
    await u.paste("mail,Delete");
    await u.click(screen.getByRole("button", { name: "Add tool name" }));
    const boundary = "é".repeat(550);
    await u.click(input);
    await u.paste(boundary);
    expect(input).toHaveValue(boundary);
    await u.click(screen.getByRole("button", { name: "Add tool name" }));
    expect(JSON.parse(screen.getByLabelText("Stored scope").textContent!)).toEqual({ tools: ["mail,Delete", boundary] });
    await u.click(input);
    await u.paste(boundary + "é");
    expect(input).toHaveValue(boundary + "é");
    expect(screen.getByRole("button", { name: "Add tool name" })).toBeDisabled();
    expect(screen.getByLabelText("Draft problem")).toHaveTextContent("1–1100 UTF-8 bytes");
    await u.keyboard("{Enter}");
    expect(JSON.parse(screen.getByLabelText("Stored scope").textContent!)).toEqual({ tools: ["mail,Delete", boundary] });
  });
});

const saBase = `/v1/teams/${team.slug}/service-accounts`;
const saOne = `${saBase}/${serviceAccountId}`;
const saPage = `/teams/${team.slug}/service-accounts/${serviceAccountId}`;
const gateway = platformGateway();
const grantsUrl = `/v1/admin/gateways/${gateway.id}/grants`;
const cases = [
  { name: "personal key", path: "/settings/api-keys", open: "Create API key", submit: "Create key", method: "POST", url: "/v1/me/api-keys", fill: "Literal" },
  { name: "service account", path: `/teams/${team.slug}/service-accounts?form=new`, submit: "Create service account", method: "POST", url: saBase, fill: "literal-bot" },
  { name: "account key", path: `${saPage}?tab=keys`, open: "Create key", submit: "Create key", method: "POST", url: `${saOne}/keys`, fill: "Literal" },
  { name: "account settings", path: `${saPage}?tab=settings`, submit: "Save settings", method: "PATCH", url: saOne },
  { name: "platform grant", path: `/admin/gateways/${gateway.id}?tab=access`, open: "Add grant", submit: "Grant access", method: "POST", url: grantsUrl },
];

describe("Parent forms cannot ignore a literal-name draft", () => {
  it.each(cases)("blocks pending/rejected drafts and saves one exact name for $name", async (testCase) => {
    const u = userEvent.setup();
    const calls = mockApi({
      ...shellRoutes("platform_admin", "owner"),
      "GET /v1/me/api-keys": () => [apiKey()],
      "GET /v1/me/gateways": () => [myGateway()],
      [`GET ${saBase}`]: () => [serviceAccount()],
      [`GET ${saOne}`]: () => serviceAccount(),
      [`GET ${saOne}/keys`]: () => [serviceAccountKey()],
      [`GET ${saOne}/gateways`]: () => [],
      [`GET /v1/admin/gateways/${gateway.id}`]: () => gateway,
      [`GET ${grantsUrl}`]: () => [grant()],
      [`${testCase.method} ${testCase.url}`]: () => testCase.name === "personal key" ? { key: apiKey(), secret: "one-time" }
        : testCase.name === "account key" ? { key: serviceAccountKey(), secret: "one-time" }
        : testCase.name === "platform grant" ? grant() : serviceAccount({ revision: 6 }),
    });
    renderApp(testCase.path);
    if (testCase.open) await u.click(await screen.findByRole("button", { name: testCase.open }));
    if (testCase.fill) await u.type(await screen.findByRole("textbox", { name: "Name" }), testCase.fill);
    if (testCase.name === "platform grant") {
      await u.click(await screen.findByRole("radio", { name: "An SSO group" }));
      await u.type(screen.getByRole("textbox", { name: "Group name" }), "engineering");
    }
    await u.click(await screen.findByRole("radio", { name: "Custom" }));
    const input = screen.getByRole("textbox", { name: "Exact tool names" });
    await u.click(input);
    await u.paste(" mail,Delete ");
    await u.click(screen.getByRole("button", { name: testCase.submit }));
    expect(calls.some((c) => c.method === testCase.method && c.url === testCase.url)).toBe(false);
    await u.click(screen.getByRole("button", { name: "Add tool name" }));
    await u.click(input);
    await u.paste("mail\nDelete");
    await u.click(screen.getByRole("button", { name: testCase.submit }));
    expect(calls.some((c) => c.method === testCase.method && c.url === testCase.url)).toBe(false);
    await u.click(screen.getByRole("button", { name: "Clear name draft" }));
    await u.click(screen.getByRole("button", { name: testCase.submit }));
    await waitFor(() => expect(calls.find((c) => c.method === testCase.method && c.url === testCase.url)?.body).toMatchObject({ toolScope: { tools: [" mail,Delete "] } }));
  });
});
