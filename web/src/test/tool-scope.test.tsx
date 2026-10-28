import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { axe } from "vitest-axe";
import { ScopeBadges, ScopeEditor, scopeFormValue, scopeProblem, type ToolScope } from "../components/tool-scope";

function Editor({ initial = null, ceiling = null, allowNames = true }: { initial?: ToolScope; ceiling?: ToolScope; allowNames?: boolean }) {
  const [value, setValue] = useState<ToolScope>(initial);
  return <><ScopeEditor value={value} onChange={setValue} ceiling={ceiling} allowNames={allowNames} /><output aria-label="Stored scope">{JSON.stringify(value)}</output></>;
}

describe("Credential tool scopes", () => {
  it("distinguishes Everything, read only, empty custom and explicit three classes accessibly", async () => {
    const u = userEvent.setup();
    const { container } = render(<Editor />);
    const value = () => screen.getByLabelText("Stored scope").textContent;
    expect(value()).toBe("null");
    expect(screen.getByText(/Owner, gateway, account and key limits/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("radio", { name: "Read only" }));
    expect(JSON.parse(value()!)).toEqual({ classes: ["read"], tools: [] });
    expect(screen.getByText("Unclassified tools: excluded")).toBeInTheDocument();
    await u.click(screen.getByRole("radio", { name: "Custom" }));
    await u.click(screen.getByRole("checkbox", { name: "Read" }));
    expect(screen.getByText("No tools")).toBeInTheDocument();
    expect(screen.getByText("No tools. Prompts and resources are unaffected.")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    for (const name of ["Read", "Write", "Destructive"]) await u.click(screen.getByRole("checkbox", { name }));
    expect(JSON.parse(value()!)).toEqual({ classes: ["read", "write", "destructive"], tools: [] });
    expect(screen.getByText(/Even all three classes exclude unclassified tools/)).toBeInTheDocument();
    await u.click(screen.getByRole("radio", { name: "Everything" }));
    expect(value()).toBe("null");
  });

  it("preserves exact case-sensitive future names, deduplicates, and refuses wildcards and overlong names", async () => {
    const u = userEvent.setup();
    const { container } = render(<Editor initial={{}} />);
    const names = screen.getByRole("textbox", { name: "Exact tool names" });
    await u.type(names, "Future__Get.v2-1{Enter}Future__Get.v2-1{Enter}");
    expect(JSON.parse(screen.getByLabelText("Stored scope").textContent!)).toEqual({ tools: ["Future__Get.v2-1"] });
    expect(screen.getByText("Unclassified tools: exact names only")).toBeInTheDocument();
    await u.type(names, "server__*{Enter}");
    expect(screen.getByText(/Use exact exposed names: 1–1100 UTF-8/)).toHaveTextContent("No wildcards.");
    expect(names).toHaveAttribute("aria-invalid", "true");
    await u.click(screen.getByRole("button", { name: "Remove tool name server__*" }));
    expect(screen.queryByText(/Use exact exposed names: 1–1100 UTF-8/)).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
    expect(scopeProblem({ tools: ["x".repeat(1100)] })).toBeUndefined();
    expect(scopeProblem({ tools: ["RenamedFutureTool", "é".repeat(550), "a/b", "a b"] })).toBeUndefined();
    for (const name of ["", "x".repeat(1101), "é".repeat(551), "a?", "a[bc]", "a{b,c}", "a\u0000b", "a\nb"]) expect(scopeProblem({ tools: [name] })).toBeDefined();
    expect(scopeProblem({ tools: Array.from({ length: 501 }, (_, i) => `tool${i}`) })).toContain("500");
    expect(scopeProblem({ tools: Array.from({ length: 500 }, (_, i) => `tool${i}`) })).toBeUndefined();
  });

  it("normalizes optional arrays and canonical order for revisioned account forms", () => {
    expect(scopeFormValue(undefined)).toBeNull();
    expect(scopeFormValue({})).toEqual({ classes: [], tools: [] });
    expect(scopeFormValue({ classes: ["write", "read"], tools: ["z", "A", "z"] })).toEqual({ classes: ["read", "write"], tools: ["A", "z"] });
  });

  it("has read-only badges for old fixtures, empty scopes and class/name unions", () => {
    const { rerender } = render(<ScopeBadges />);
    expect(screen.getByText("Everything")).toBeInTheDocument();
    rerender(<ScopeBadges scope={{}} />);
    expect(screen.getByText("No tools")).toBeInTheDocument();
    rerender(<ScopeBadges scope={{ classes: ["write"], tools: ["mail__Search"] }} />);
    expect(screen.getByText("Write")).toBeInTheDocument();
    expect(screen.getByText("mail__Search")).toBeInTheDocument();
    expect(screen.queryByText("Read")).toBeNull();
  });

  it("limits OAuth to requested classes, with no names or unrestricted preset", async () => {
    const u = userEvent.setup();
    const { container } = render(<Editor initial={{ classes: ["read", "write"] }} ceiling={{ classes: ["read", "write"] }} allowNames={false} />);
    expect(screen.getByRole("radio", { name: "Everything" })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("checkbox", { name: "Destructive" })).toHaveAttribute("aria-disabled", "true");
    expect(screen.queryByRole("textbox")).toBeNull();
    await u.click(screen.getByRole("checkbox", { name: "Write" }));
    expect(JSON.parse(screen.getByLabelText("Stored scope").textContent!)).toEqual({ classes: ["read"] });
    expect(await axe(container)).toHaveNoViolations();
  });
});
