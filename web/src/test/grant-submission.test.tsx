import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { toast } from "@/components/ui/toast/toast";
import type { Schemas } from "../api/client";
import { AddGrantDialog } from "../components/gateways/add-grant-dialog";
import { grant, platformGateway, teamSummary, page } from "./fixtures";
import { mockApi, renderBare } from "./harness";

afterEach(() => vi.restoreAllMocks());

describe("Grant submission locking", () => {
  it("freezes subject and scope in mutation variables, locks every field, and closes only after the delayed result", async () => {
    const u = userEvent.setup();
    const original = platformGateway();
    const url = `/v1/admin/gateways/${original.id}/grants`;
    let finish!: (result: Schemas["GatewayGrant"]) => void;
    const calls = mockApi({
      "GET /v1/admin/teams": () => page([teamSummary()]),
      [`POST ${url}`]: () => new Promise<Schemas["GatewayGrant"]>((resolve) => { finish = resolve; }),
    });
    const onClose = vi.fn();
    const success = vi.spyOn(toast, "success");
    let changeGateway!: (value: Schemas["Gateway"]) => void;
    function Dialog() {
      const [gateway, setGateway] = useState(original);
      changeGateway = setGateway;
      return <AddGrantDialog gateway={gateway} onClose={onClose} />;
    }
    renderBare(<Dialog />);
    await u.click(await screen.findByRole("radio", { name: "An SSO group" }));
    await u.type(screen.getByRole("textbox", { name: "Group name" }), "engineering");
    await u.click(screen.getByRole("radio", { name: "Custom" }));
    await u.type(screen.getByRole("textbox", { name: "Exact tool names" }), "mail,Delete");
    await u.click(screen.getByRole("button", { name: "Add tool name" }));
    await u.click(screen.getByRole("button", { name: "Grant access" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "POST")).toHaveLength(1));
    const person = screen.getByRole("radio", { name: "A person" });
    expect(person).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("radio", { name: "A team" })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("textbox", { name: "Group name" })).toBeDisabled();
    expect(screen.getByRole("radio", { name: "Everything" })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("checkbox", { name: "Read" })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("textbox", { name: "Exact tool names" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Remove tool name mail,Delete" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Grant access" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
    await u.click(person);
    expect(screen.getByRole("radio", { name: "An SSO group" })).toBeChecked();
    expect(screen.queryByRole("textbox", { name: "Email" })).toBeNull();
    await u.click(screen.getByRole("button", { name: "Grant access" }));
    await u.keyboard("{Escape}");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
    const body = { subjectKind: "group", group: "engineering", toolScope: { classes: [], tools: ["mail,Delete"] } };
    expect(calls.find((c) => c.method === "POST")?.body).toEqual(body);
    // A prop/cache change during flight must not change the submitted target's success text.
    act(() => changeGateway(platformGateway({ id: "different-gateway", name: "Changed gateway" })));
    await act(async () => finish(grant({ subjectKind: "group", group: "engineering", team: undefined, toolScope: body.toolScope })));
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
    expect(success).toHaveBeenCalledWith("Access granted", `engineering can use ${original.name} from their next request.`);
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
  });

  it.each(["team", "user"] as const)("disables the %s subject control during a request", async (kind) => {
    const u = userEvent.setup();
    const gateway = platformGateway();
    let finish!: (result: Schemas["GatewayGrant"]) => void;
    mockApi({
      "GET /v1/admin/teams": () => page([teamSummary()]),
      [`POST /v1/admin/gateways/${gateway.id}/grants`]: () => new Promise<Schemas["GatewayGrant"]>((resolve) => { finish = resolve; }),
    });
    renderBare(<AddGrantDialog gateway={gateway} onClose={vi.fn()} />);
    if (kind === "team") {
      const select = await screen.findByRole("combobox", { name: "Team" });
      await screen.findByRole("option", { name: teamSummary().team.name });
      await u.selectOptions(select, teamSummary().team.slug);
    } else {
      await u.click(await screen.findByRole("radio", { name: "A person" }));
      await u.type(screen.getByRole("textbox", { name: "Email" }), "person@example.test");
    }
    await u.click(screen.getByRole("button", { name: "Grant access" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Grant access" })).toBeDisabled());
    expect(kind === "team" ? screen.getByRole("combobox", { name: "Team" }) : screen.getByRole("textbox", { name: "Email" })).toBeDisabled();
    await act(async () => finish(grant()));
  });
});
