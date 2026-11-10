/* The page templates: DetailPage, SettingsPage (+ guard), ListPage, RecordPage (+ the takeover host). */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Link, Outlet, RouterProvider, createMemoryHistory, createRootRoute, createRoute, createRouter } from "@tanstack/react-router";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useState } from "react";
import { axe } from "vitest-axe";
import { useCurrentCrumbTail } from "../components/layout/crumb-tail";
import { orderActions } from "../components/templates/action-menu";
import { DetailPage } from "../components/templates/detail-page";
import { ListPage } from "../components/templates/list-page";
import { RecordPage, useRecordParam } from "../components/templates/record-page";
import { TakeoverHost } from "../components/templates/takeover";
import { DangerAction, DangerZone, SettingsPage, SettingsSection } from "../components/templates/settings-page";
import { Button } from "@/components/ui/button/button";
import { Field } from "@/components/ui/field/field";
import { Input } from "@/components/ui/input/input";

/** Renders `ui` at "/" (with a second page at "/other") and returns the router. */
function renderAt(ui: () => ReactNode, path = "/") {
  const root = createRootRoute({
    component: () => (
      <main>
        <Crumb />
        <Outlet />
      </main>
    ),
  });
  const home = createRoute({ getParentRoute: () => root, path: "/", component: ui });
  const other = createRoute({ getParentRoute: () => root, path: "/other", component: () => <h1>Other page</h1> });
  const router = createRouter({ routeTree: root.addChildren([home, other]), history: createMemoryHistory({ initialEntries: [path] }) });
  const qc = new QueryClient();
  const utils = render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router as never} />
    </QueryClientProvider>,
  );
  return { ...utils, router };
}

function Crumb() {
  const tail = useCurrentCrumbTail();
  return <p data-testid="crumb">{tail ?? "(none)"}</p>;
}

const search = (router: { state: { location: { search: unknown } } }) => router.state.location.search as Record<string, unknown>;

afterEach(() => localStorage.clear());

describe("orderActions", () => {
  it("puts destructive actions last and drops hidden ones", () => {
    const out = orderActions([
      { label: "Delete", danger: true },
      { label: "Pause" },
      { label: "Hidden", hidden: true },
      { label: "Duplicate" },
    ]);
    expect(out.map((a) => a.label)).toEqual(["Pause", "Duplicate", "Delete"]);
  });
});

describe("DetailPage", () => {
  const Page = () => (
    <DetailPage
      title="Handbook"
      facts={[{ label: "Type", value: "Upload" }, { label: "Documents", value: "42 documents" }, { label: "Empty", value: "" }]}
      primaryAction={<Button>Upload files</Button>}
      menuActions={[{ label: "Delete source", danger: true, onSelect: () => {} }, { label: "Pause", onSelect: () => {} }]}
      tabIds={["overview", "documents", "settings"] as const}
      tabsLabel="Source sections"
      tabs={[
        { value: "settings", label: "Settings", content: <p>Settings body</p> },
        { value: "overview", label: "Overview", content: <p>Overview body</p> },
        { value: "documents", label: "Documents", content: <p>Documents body</p> },
      ]}
    />
  );

  it("renders the header, facts, actions and tabs with Settings last, and has no axe violations", async () => {
    const { container } = renderAt(Page);
    expect(await screen.findByRole("heading", { level: 1, name: "Handbook" })).toBeInTheDocument();
    expect(screen.getByText("42 documents")).toBeInTheDocument();
    expect(screen.queryByText("Empty")).not.toBeInTheDocument();
    const tabs = within(screen.getByRole("tablist", { name: "Source sections" })).getAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual(["Overview", "Documents", "Settings"]);
    expect(screen.getByText("Overview body")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("keeps the tab in ?tab=, and the breadcrumb follows it", async () => {
    const user = userEvent.setup();
    const { router } = renderAt(Page);
    expect(await screen.findByTestId("crumb")).toHaveTextContent("(none)");
    await user.click(screen.getByRole("tab", { name: "Documents" }));
    await waitFor(() => expect(search(router).tab).toBe("documents"));
    expect(screen.getByTestId("crumb")).toHaveTextContent("Documents");
    expect(screen.getByText("Documents body")).toBeInTheDocument();
  });

  it("lists the menu's destructive action last", async () => {
    const user = userEvent.setup();
    renderAt(Page);
    await user.click(await screen.findByRole("button", { name: "More actions" }));
    const items = await screen.findAllByRole("menuitem");
    expect(items.map((i) => i.textContent)).toEqual(["Pause", "Delete source"]);
  });
});

describe("SettingsPage", () => {
  function Settings({ onSave }: { onSave: () => void }) {
    const [name, setName] = useState("Handbook");
    return (
      <>
        <Link to={"/other" as never}>Somewhere else</Link>
        <SettingsPage dirty={name !== "Handbook"} onSave={onSave} onDiscard={() => setName("Handbook")}>
          <SettingsSection title="General">
            <Field label="Name">
              <Input value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
          </SettingsSection>
          <DangerZone>
            <DangerAction
              title="Leave team"
              description="You lose access."
              action={<Button variant="danger" disabled>Leave team</Button>}
              disabledReason="You're the only owner."
            />
          </DangerZone>
        </SettingsPage>
      </>
    );
  }

  it("shows one save bar while dirty and saves on submit", async () => {
    const user = userEvent.setup();
    const onSave = vi.fn();
    const { container } = renderAt(() => <Settings onSave={onSave} />);
    const name = await screen.findByRole("textbox", { name: "Name" });
    expect(screen.queryByRole("button", { name: "Save settings" })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Danger zone" })).toBeInTheDocument();
    expect(screen.getByText("You're the only owner.")).toBeInTheDocument();
    await user.type(name, "!");
    expect(screen.getByRole("status")).toHaveTextContent("Unsaved changes");
    await user.click(screen.getByRole("button", { name: "Save settings" }));
    expect(onSave).toHaveBeenCalledTimes(1);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("asks before leaving with unsaved changes (F-17)", async () => {
    const user = userEvent.setup();
    const { router } = renderAt(() => <Settings onSave={() => {}} />);
    await user.type(await screen.findByRole("textbox", { name: "Name" }), "!");
    await user.click(screen.getByRole("link", { name: "Somewhere else" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Leave without saving?" });
    await user.click(within(dialog).getByRole("button", { name: "Keep editing" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
    expect(router.state.location.pathname).toBe("/");
    expect(screen.getByRole("textbox", { name: "Name" })).toHaveValue("Handbook!");

    await user.click(screen.getByRole("link", { name: "Somewhere else" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Discard changes" }));
    expect(await screen.findByRole("heading", { name: "Other page" })).toBeInTheDocument();
  });

  it("doesn't ask when nothing changed", async () => {
    const user = userEvent.setup();
    renderAt(() => <Settings onSave={() => {}} />);
    await user.click(await screen.findByRole("link", { name: "Somewhere else" }));
    expect(await screen.findByRole("heading", { name: "Other page" })).toBeInTheDocument();
  });
});

type Row = { id: string; name: string; status: "ready" | "failed"; updatedAt: string };
const rows: Row[] = [
  { id: "1", name: "Handbook", status: "ready", updatedAt: "2026-09-20T10:00:00Z" },
  { id: "2", name: "Catalog", status: "failed", updatedAt: "2026-09-21T10:00:00Z" },
  { id: "3", name: "Calendar", status: "ready", updatedAt: "2026-09-22T10:00:00Z" },
];

describe("ListPage", () => {
  const onDelete = vi.fn();
  const List = ({ data = rows }: { data?: Row[] }) => (
    <ListPage<Row>
      id="test-list"
      title="Documents"
      caption="Documents"
      columns={[
        { id: "name", header: "Name", accessor: "name", sortable: true, rowHeader: true },
        { id: "status", header: "Status", accessor: "status" },
      ]}
      data={data}
      getRowId={(r) => r.id}
      rowLabel={(r) => r.name}
      facets={[
        {
          id: "status",
          label: "Status",
          type: "toggle",
          allLabel: "All",
          accessor: (r) => r.status,
          options: [
            { value: "ready", label: "Ready" },
            { value: "failed", label: "Failed" },
          ],
        },
      ]}
      search={{ label: "Search documents" }}
      rowActions={(r) => [
        { label: "Delete", danger: true, onSelect: () => onDelete(r.id) },
        { label: "Open", onSelect: () => {} },
      ]}
      empty={{ title: "No documents yet." }}
    />
  );

  it("reads filters and search from the URL", async () => {
    renderAt(() => <List />, "/?status=failed");
    expect(await screen.findByRole("rowheader", { name: "Catalog" })).toBeInTheDocument();
    expect(screen.queryByRole("rowheader", { name: "Handbook" })).not.toBeInTheDocument();
  });

  it("writes filter and search changes to the URL, and has no axe violations", async () => {
    const user = userEvent.setup();
    const { router, container } = renderAt(() => <List />);
    await screen.findByRole("rowheader", { name: "Handbook" });
    await user.click(screen.getByRole("button", { name: /^Failed/ }));
    await waitFor(() => expect(search(router).status).toBe("failed"));
    await user.click(screen.getByRole("button", { name: /^All/ }));
    await waitFor(() => expect(search(router).status).toBeUndefined());
    await user.type(screen.getByRole("searchbox", { name: "Search documents" }), "cal");
    await waitFor(() => expect(search(router).q).toBe("cal"));
    expect(screen.queryByRole("rowheader", { name: "Handbook" })).not.toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("puts Delete last in the row menu", async () => {
    const user = userEvent.setup();
    renderAt(() => <List />);
    await user.click(await screen.findByRole("button", { name: "Actions for Handbook" }));
    const items = await screen.findAllByRole("menuitem");
    expect(items.map((i) => i.textContent)).toEqual(["Open", "Delete"]);
    await user.click(items[1]!);
    expect(onDelete).toHaveBeenCalledWith("1");
  });

  it("shows the empty state", async () => {
    renderAt(() => <List data={[]} />);
    expect(await screen.findByText("No documents yet.")).toBeInTheDocument();
  });
});

describe("RecordPage", () => {
  function Records() {
    const record = useRecordParam();
    const row = rows.find((r) => r.id === record.id);
    return (
      <TakeoverHost backLabel="Documents">
        <Button onClick={() => record.open("2")}>View Catalog</Button>
        <RecordPage
          open={Boolean(record.id)}
          onClose={record.close}
          title={row?.name ?? "Document"}
          description="A document in this source."
          facts={[{ label: "Status", value: row?.status }]}
          sections={[{ title: "Passages", content: <p>Three passages</p> }]}
          actions={<Button variant="danger">Delete</Button>}
        />
      </TakeoverHost>
    );
  }

  it("opens from ?record= (linkable) as a page over the list, and the back link closes it", async () => {
    const user = userEvent.setup();
    const { router, baseElement } = renderAt(Records, "/?record=2");
    const page = await screen.findByRole("region", { name: "Catalog" });
    expect(within(page).getByRole("heading", { level: 1, name: "Catalog" })).toBeInTheDocument();
    expect(within(page).getByText("failed")).toBeInTheDocument();
    expect(within(page).getByRole("heading", { name: "Passages" })).toBeInTheDocument();
    expect(within(page).getByRole("button", { name: "Delete" })).toBeInTheDocument();
    // The page underneath is hidden while the record is open.
    expect(screen.queryByRole("button", { name: "View Catalog" })).toBeNull();
    expect(await axe(baseElement)).toHaveNoViolations();
    await user.click(within(page).getByRole("link", { name: "Back to Documents" }));
    await waitFor(() => expect(search(router).record).toBeUndefined());
    expect(await screen.findByRole("button", { name: "View Catalog" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Catalog" })).toBeNull();
  });

  it("opening adds a history entry, so Back closes it", async () => {
    const user = userEvent.setup();
    const { router } = renderAt(Records);
    await user.click(await screen.findByRole("button", { name: "View Catalog" }));
    expect(await screen.findByRole("region", { name: "Catalog" })).toBeInTheDocument();
    // A numeric id stays plain in the address (not JSON-quoted as %222%22).
    expect(router.state.location.searchStr).toBe("?record=2");
    act(() => router.history.back());
    await waitFor(() => expect(screen.queryByRole("region", { name: "Catalog" })).not.toBeInTheDocument());
    expect(screen.getByRole("button", { name: "View Catalog" })).toBeInTheDocument();
  });
});
