/* List pages: narrow-window column defaults follow resizing; a saved column choice wins at any width. */
import { act, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { NARROW_QUERY } from "@/lib/bitop-utils";
import { catalogServer, page } from "./fixtures";
import { mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

/** A matchMedia whose NARROW_QUERY result can be changed, notifying listeners like a resized window. */
function resizableWindow(narrow: boolean) {
  const listeners = new Set<(e: { matches: boolean }) => void>();
  vi.stubGlobal("matchMedia", (q: string) => ({
    get matches() {
      return q === NARROW_QUERY ? narrow : false;
    },
    media: q,
    addEventListener: (_: string, l: (e: { matches: boolean }) => void) => q === NARROW_QUERY && listeners.add(l),
    removeEventListener: (_: string, l: (e: { matches: boolean }) => void) => listeners.delete(l),
    addListener: (l: (e: { matches: boolean }) => void) => q === NARROW_QUERY && listeners.add(l),
    removeListener: (l: (e: { matches: boolean }) => void) => listeners.delete(l),
  }));
  return (next: boolean) =>
    act(() => {
      narrow = next;
      for (const l of listeners) l({ matches: next });
    });
}

const headers = (table: HTMLElement) => within(table).getAllByRole("columnheader").map((h) => h.textContent ?? "");

describe("List page columns", () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("hides the narrow-default columns when a desktop window shrinks to phone width, and shows them again", async () => {
    const resize = resizableWindow(false);
    mockApi({ ...shellRoutes("none", null), "GET /v1/catalog/servers": () => page([catalogServer()]) });
    renderApp("/catalog");
    const table = await screen.findByRole("table", { name: "Published MCP servers" });
    await within(table).findByText("Service status");
    expect(headers(table).some((h) => h.includes("Description"))).toBe(true);
    expect(headers(table).some((h) => h.includes("Offers"))).toBe(true);

    resize(true);
    expect(headers(table).some((h) => h.includes("Description"))).toBe(false);
    expect(headers(table).some((h) => h.includes("Offers"))).toBe(false);
    // What it offers moves under the name instead.
    expect(within(table).getByText("Service status").closest("tr")).toHaveTextContent("2 tools · 1 resource · 1 prompt");

    resize(false);
    expect(headers(table).some((h) => h.includes("Description"))).toBe(true);
    expect(localStorage.getItem("omp.columns.catalog")).toBeNull();
  });

  it("keeps a column someone chose, at any width, and remembers it", async () => {
    const u = userEvent.setup();
    const resize = resizableWindow(false);
    mockApi({ ...shellRoutes("none", null), "GET /v1/catalog/servers": () => page([catalogServer()]) });
    const { unmount } = renderApp("/catalog");
    const table = await screen.findByRole("table", { name: "Published MCP servers" });
    await within(table).findByText("Service status");
    await u.click(screen.getByRole("button", { name: /Columns/ }));
    await u.click(await screen.findByRole("menuitemcheckbox", { name: "Published" }));
    await u.keyboard("{Escape}");
    expect(headers(table).some((h) => h.includes("Published"))).toBe(true);
    expect(JSON.parse(localStorage.getItem("omp.columns.catalog") ?? "null")).toEqual([]);

    // An explicit choice is not overridden by the narrow defaults.
    resize(true);
    expect(headers(table).some((h) => h.includes("Description"))).toBe(true);
    unmount();

    // And it is remembered on the next visit.
    mockApi({ ...shellRoutes("none", null), "GET /v1/catalog/servers": () => page([catalogServer()]) });
    renderApp("/catalog");
    const again = await screen.findByRole("table", { name: "Published MCP servers" });
    await within(again).findByText("Service status");
    expect(headers(again).some((h) => h.includes("Published"))).toBe(true);
  });
});
