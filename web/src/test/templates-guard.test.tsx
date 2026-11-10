/* ListPage row click (m2), the "Leave without saving?" guard of form pages and dialogs (m7), and plain numeric ids in the address. */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createMemoryHistory, createRootRoute, createRoute, createRouter } from "@tanstack/react-router";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useState } from "react";
import { axe } from "vitest-axe";
import { FormDialog } from "../components/form-dialog";
import { GuardedDialog, useEditTracker } from "../components/templates/close-guard";
import { FormPage } from "../components/templates/form-page";
import { ListPage } from "../components/templates/list-page";
import { RecordPage, useRecordParam } from "../components/templates/record-page";
import { fromSearchParams } from "../lib/url-search";
import { Button } from "@/components/ui/button/button";
import { Field, Form } from "@/components/ui/field/field";
import { Input } from "@/components/ui/input/input";

function renderAt(ui: () => ReactNode, path = "/") {
  const root = createRootRoute();
  const home = createRoute({ getParentRoute: () => root, path: "/", component: () => <main>{ui()}</main> });
  const router = createRouter({ routeTree: root.addChildren([home]), history: createMemoryHistory({ initialEntries: [path] }) });
  const utils = render(
    <QueryClientProvider client={new QueryClient()}>
      <RouterProvider router={router as never} />
    </QueryClientProvider>,
  );
  return { ...utils, router };
}

type Row = { id: string; name: string };
const rows: Row[] = [
  { id: "7", name: "Handbook" },
  { id: "8", name: "Catalog" },
];

afterEach(() => localStorage.clear());

describe("ListPage onRowClick", () => {
  function Records() {
    const record = useRecordParam();
    const row = rows.find((r) => String(r.id) === record.id);
    return (
      <>
        <ListPage<Row>
          id="t"
          caption="Documents"
          columns={[{ id: "name", header: "Name", accessor: "name", rowHeader: true }]}
          data={rows}
          getRowId={(r) => r.id}
          rowLabel={(r) => r.name}
          onRowClick={(r) => record.open(r.id)}
          rowActions={(r) => [{ label: "View details", onSelect: () => record.open(r.id) }]}
        />
        <RecordPage open={Boolean(record.id)} onClose={record.close} title={row?.name ?? "Document"} description="A document." />
      </>
    );
  }

  it("opens the record page from a row click or Enter, and the menu still works", async () => {
    const user = userEvent.setup();
    const { router, container } = renderAt(Records);
    await user.click(await screen.findByRole("rowheader", { name: "Catalog" }));
    const page = await screen.findByRole("region", { name: "Catalog" });
    expect(router.state.location.searchStr).toBe("?record=8");
    await user.click(within(page).getByRole("link", { name: "Back" }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "Catalog" })).toBeNull());

    // Each row's one tab stop is the button in its row header.
    within(screen.getByRole("rowheader", { name: "Handbook" })).getByRole("button").focus();
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("region", { name: "Handbook" })).toBeInTheDocument();
    await user.click(screen.getByRole("link", { name: "Back" }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "Handbook" })).toBeNull());

    await user.click(screen.getByRole("button", { name: "Actions for Catalog" }));
    await user.click(await screen.findByRole("menuitem", { name: "View details" }));
    expect(await screen.findByRole("region", { name: "Catalog" })).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });
});

describe("form pages and dialogs ask before discarding edits", () => {
  function KeyForm({ onClose }: { onClose: () => void }) {
    const [name, setName] = useState("");
    return (
      <FormPage label="Create a key" title="Create a key" description="A widget key." onClose={onClose} onSubmit={() => {}} submitLabel="Create key" dirty={name !== ""}>
        <Field label="Name">
          <Input value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
      </FormPage>
    );
  }

  it("FormPage: closes at once when untouched, asks once edited (Cancel and the back link)", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const { baseElement } = renderAt(() => <KeyForm onClose={onClose} />);
    const page = await screen.findByRole("region", { name: "Create a key" });
    expect(within(page).getByRole("heading", { level: 1, name: "Create a key" })).toBeInTheDocument();
    await user.click(within(page).getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalledTimes(1);

    await user.type(screen.getByRole("textbox", { name: "Name" }), "Main site");
    await user.click(within(page).getByRole("link", { name: "Back" }));
    const ask = await screen.findByRole("alertdialog", { name: "Leave without saving?" });
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(await axe(baseElement)).toHaveNoViolations();
    await user.click(within(ask).getByRole("button", { name: "Keep editing" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(screen.getByRole("textbox", { name: "Name" })).toHaveValue("Main site");

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Discard changes" }));
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it("FormPage asks before any other navigation once edited (browser Back, links)", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const { router } = renderAt(() => <KeyForm onClose={onClose} />, "/?form=new");
    await user.type(await screen.findByRole("textbox", { name: "Name" }), "Main site");
    act(() => void router.navigate({ to: "/", search: {} as never }));
    const ask = await screen.findByRole("alertdialog", { name: "Leave without saving?" });
    await user.click(within(ask).getByRole("button", { name: "Keep editing" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(router.state.location.searchStr).toBe("?form=new");
    expect(screen.getByRole("textbox", { name: "Name" })).toHaveValue("Main site");
  });

  it("FormPage submits only its own form, and tracks edits by itself", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const onSubmit = vi.fn();
    renderAt(() => (
      <FormPage label="New source" title="New source" onClose={onClose} onSubmit={onSubmit} submitLabel="Create">
        <Field label="Name">
          <Input />
        </Field>
      </FormPage>
    ));
    await user.type(await screen.findByRole("textbox", { name: "Name" }), "Catalog{Enter}");
    expect(onSubmit).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "Create" }));
    expect(onSubmit).toHaveBeenCalledTimes(2);
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(await screen.findByRole("alertdialog", { name: "Leave without saving?" })).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
  });

  it("GuardedDialog with useEditTracker: any typed field makes it ask", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    function Upload() {
      const edits = useEditTracker();
      return (
        <GuardedDialog dirty={edits.edited} onClose={onClose} title="Upload files" description="Add files.">
          <Form {...edits.formProps}>
            <Field label="Tags">
              <Input />
            </Field>
          </Form>
        </GuardedDialog>
      );
    }
    const { baseElement } = renderAt(() => <Upload />);
    await user.type(await screen.findByRole("textbox", { name: "Tags" }), "policy");
    await user.click(screen.getByRole("button", { name: "Close" }));
    const ask = await screen.findByRole("alertdialog", { name: "Leave without saving?" });
    expect(await axe(baseElement)).toHaveNoViolations();
    await user.click(within(ask).getByRole("button", { name: "Discard changes" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("FormDialog asks once something was typed", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    function Harness() {
      const [open, setOpen] = useState(true);
      return open ? (
        <FormDialog title="New knowledge base" onClose={() => (onClose(), setOpen(false))} onSubmit={() => {}} submitLabel="Create">
          <Field label="Name">
            <Input />
          </Field>
        </FormDialog>
      ) : (
        <Button>closed</Button>
      );
    }
    renderAt(() => <Harness />);
    await user.type(await screen.findByRole("textbox", { name: "Name" }), "Help");
    await user.keyboard("{Escape}");
    expect(await screen.findByRole("alertdialog", { name: "Leave without saving?" })).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
  });
});

describe("url-search", () => {
  it("hands numeric and boolean values to the router in parsed form, so they aren't JSON-quoted", () => {
    expect(fromSearchParams(new URLSearchParams("record=405&tab=audit&all=true&code=007"))).toEqual({ record: 405, tab: "audit", all: true, code: "007" });
  });
});
