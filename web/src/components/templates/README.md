# Page templates

Grounded's page shapes from the UI plan (`docs/ui-review/README.md`, D3–D5, Q13). They're composed from bitop-ui items. Build pages on them rather than laying out headers, tabs, save bars and tables by hand, so every page has the same structure. Tests: `src/test/templates.test.tsx`.

| Template | File | Use for |
|---|---|---|
| `DetailPage` | `detail-page.tsx` | A container's page: source, KB, agent, team, user (D3) |
| `SettingsPage`, `SettingsSection`, `DangerZone`, `DangerAction` | `settings-page.tsx` | A Settings tab or settings page (D3, F-17) |
| `useRevisionForm`, `RevisionSaveBar` | `revision-form.ts`, `conflict-notice.tsx` | A settings form over a revisioned object (If-Match): keeps the edits through a save conflict |
| `useUnsavedChangesGuard` | `unsaved-guard.tsx` | Any other page with a `SaveBar` |
| `ListPage`, `useListFilters`, `timeColumn` | `list-page.tsx` | Every list and log (D5) |
| `RelativeTime` | `relative-time.tsx` | A relative date with the full date as a tooltip (its own module: the shell uses it) |
| `RecordPage`, `useRecordParam` | `record-page.tsx` | Leaf records: documents, keys, requests, audit entries, crawl runs, models… as a page over their list (D4) |
| `FormPage`, `FormSection`, `useFormParam` | `form-page.tsx` | Long create and edit forms (a source, a connection, a model, a classification level) as a page (D4) |
| `TakeoverPage`, `TakeoverHost` | `takeover.tsx` | What RecordPage and FormPage build on; the shell holds the host |
| `GuardedDialog`, `useCloseGuard`, `useEditTracker` | `close-guard.tsx` | Any other dialog with input: "Leave without saving?" on close (m7) |
| `ActionMenu`, `orderActions` | `action-menu.tsx` | The "…" menu (used by the above) |
| `PageActions` | `page-actions.tsx` | A header's secondary buttons, primary and "…" menu for a page on `PageHeader` (DetailPage uses it) |

Words come from `src/lib/terms.ts` (D8): "Passages", not chunks; "Signed-in users"; "Danger zone"; Enabled/Disabled for switchable objects and Active/Retired/Archived/Suspended for lifecycle states.

## DetailPage

```tsx
<DetailPage
  title={source.name}
  meta={<StatusBadge …/>}
  facts={[{ label: "Type", value: "Web" }, { label: "Documents", value: plural(n, "document") }, { label: "Last sync", value: <RelativeTime value={…} /> }]}
  primaryAction={<Button>Sync now</Button>}
  secondaryActions={[{ label: "Chat", icon: <MessageSquare />, render: <Link to="…" /> }]}   // rare: buttons before the primary
  menuActions={[{ label: "Pause", icon: <Pause />, onSelect: pause }, { label: "Delete source", danger: true, onSelect: () => setDeleting(true) }]}
  notices={<ArchivedNotice />}
  tabIds={sourceTabs}                // from lib/tabs.ts, validated by the route with tabSearch()
  tabsLabel="Source sections"
  tabs={[{ value: "overview", label: "Overview", content: … }, { value: "documents", label: "Documents", content: … }, { value: "settings", label: "Settings", content: <SourceSettings /> }]}
/>
```

- One primary action at most. Everything else goes in the "…" menu, and destructive actions are always placed last. Give a disabled action a `disabledReason` (P-04).
- `secondaryActions` are buttons before the primary on wider windows; on a phone (below 600px) they move to the top of the "…" menu, so the header keeps one row. A page built on `PageHeader` gets the same with `<PageActions primary={…} secondary={[…]} menu={[…]} />`.
- Facts with an empty value are dropped. Keep them short: the line wraps.
- The tab lives in `?tab=`, and `"settings"` is always moved to the end. Stat cards belong in the Overview tab only.
- The breadcrumb follows the tab automatically (PageTabs sets the crumb tail; see `components/layout/crumb-tail.ts`). For a nested `PageTabs` inside a tab, pass `crumb="none"`.
- The route must declare the tabs: `teamTabs("sources/$sourceId", sourceTabs, …)`. If the page also uses `?record=` or list filters, use `tabSearch(tabs, { passthrough: true })`, or the router drops those parameters.

## SettingsPage

```tsx
<SettingsPage dirty={changed} saving={save.isPending} error={save.error} saveLabel="Save settings"
  onSave={() => save.mutate(form)} onDiscard={reset} canEdit={canEdit}
  message={invalid ? "Not saved: fix the highlighted field" : undefined} saveDisabled={invalid}>
  <SettingsSection title="General" description="…">…fields…</SettingsSection>
  <SettingsSection title="Crawling">…</SettingsSection>
  <DangerZone>
    <DangerAction title="Pause this source" description="…" action={<Button variant="secondary">Pause</Button>} />
    <DangerAction title="Delete this source" description="…" action={<Button variant="danger" onClick={…}>Delete source</Button>} />
  </DangerZone>
</SettingsPage>
```

- There is one form and **one** sticky save bar per page. Don't add Save buttons to sections.
- The unsaved-changes guard is built in. Leaving the page (a link, the sidebar or Back) asks "Leave without saving?", and closing the tab gets the browser prompt. Switching the page's tabs (`?tab=`) asks too, since the settings are one form (pass `guard={{ samePath: false }}` for a form that spans tabs).
- Danger-zone actions aren't part of the save: each one opens its own confirmation (`AlertDialog` / `ConfirmMutationDialog`). Use `disabledReason` when an action can't run, for example "You're the only owner".
- Field errors need text, not only a red border (F-05). Pass `error="…"` to `Field` and keep `invalid` in sync.

### Save conflicts (If-Match)

A form over an object with a revision holds its state in `useRevisionForm` and passes the control to the page (v0.4.2, AD-01):

```tsx
const [form, setForm, revision] = useRevisionForm(formOf(team), team.revision, { labels: { maxClassification: "Approved classification" } });
<SettingsPage revision={revision} dirty={…} onSave={() => save.mutate(form)} onDiscard={() => setForm(formOf(team))}>…</SettingsPage>
```

- When the object changes elsewhere while the person edits (another tab, another admin), or a save comes back 412, the form keeps their edits and takes the other changes into the fields they didn't touch. A notice lists what changed ("Description: now “…” (yours: “…”)"), and the save bar offers **Overwrite with mine** (saves the form on the latest revision) and **Discard mine and load theirs**.
- Their own save is told apart by its content (allowing for the server trimming text), so the form shows the saved values afterwards.
- **Don't key the editor by the revision** (`key={x.revision}`): that remounts it and throws the edits away. The mutation's If-Match uses the latest loaded revision; a 412 refetches every query (`main.tsx`), so the latest version arrives.
- A form with its own layout (not `SettingsPage`) renders `RevisionSaveBar` inside its `<form>` instead of a `SaveBar`.

## ListPage

```tsx
<ListPage<Source>
  id="team-sources"                  // remembers hidden columns per list
  title="Data sources" primaryAction={<Button>New source</Button>}
  caption="Data sources" columns={columns} data={rows} getRowId={(r) => r.id} rowLabel={(r) => r.name}
  facets={[{ id: "status", label: "Status", type: "toggle", allLabel: "All", accessor: (r) => r.status, options }]}
  search={{ label: "Search sources" }}
  rowActions={(r) => [{ label: "Open", render: <Link … /> }, { label: "Delete", danger: true, onSelect: … }]}
  empty={{ icon: <Database />, title: "No data sources yet.", action: <Button>New source</Button> }}
  loading={q.isLoading} error={q.error} onRetry={q.refetch}
/>
```

- Filters (`?status=failed`) and search (`?q=`) live in the URL and replace the history entry. Date facets use the same presets as `DateRangeFilter`.
- The search box's label is for screen readers; `search={{ label, showLabel: true }}` shows it above the box, like the filters' labels, where the placeholder alone wouldn't say what it searches.
- A single-choice toggle filter (Status: All · Active · Released) gets no "Status: Active ×" chip: its pressed item shows the choice. Other filters get a chip while active.
- Filtering is in memory by default. For server-side lists, read the values with `useListFilters(facets)`, pass them to the query, and set `manual` (plus `tableProps={{ loadMore }}` or `cursor`).
- Dates use `timeColumn(id, header, get)` or `<RelativeTime value=…/>`, which show relative text with the full date as the title.
- Rows that open a RecordPage get `onRowClick={(r) => record.open(r.id)}`: a click anywhere on the row (except its links and buttons) or Enter on the focused row opens it. Keep "View details" in the row menu too.
- Fit at 1280 px: the list sits in a 976 px column there. Give long text a one-line `max-width` with an ellipsis (the full text as `title`), keep short cells `nowrap`, and start low-priority columns hidden (`defaultHidden`, still in the Columns menu). On a phone (below 600px) `defaultHiddenNarrow` columns start hidden too. A table never widens the page; it scrolls inside its own wrapper only as a last resort.
- Without `title`, only the table renders (for a list inside a tab or card).
- A small list leaves out the Columns menu with `tableProps={{ columnsMenuMin: 5 }}`: it shows once that many columns can be hidden, or once one is hidden (a `defaultHiddenNarrow` column on a phone), so a hidden column can always come back.
- `tableProps` passes anything else to `DataTable`: `selectable`, `bulkActions`, `toolbar`, `loadMore`, `cursor`, `defaultSort`, `stickyHeader`.

## Record and form pages (no side sheets)

The rule (owner decision, 2026-09-28): no drawers or side sheets. Short forms and confirmations are **dialogs** (`FormDialog`, `GuardedDialog`, `ConfirmMutationDialog`); records and long forms are **pages**. The only drawer left is the chat page's conversation list on narrow screens.

```tsx
const record = useRecordParam();         // ?record=<id>
…rowActions={(d) => [{ label: "View details", onSelect: () => record.open(d.id) }, …]}
…onRowClick={(d) => record.open(d.id)}
<RecordPage open={Boolean(record.id)} onClose={record.close} title={doc.data?.title ?? "Document"}
  description="A document in this source." loading={doc.isLoading} error={doc.error}
  facts={[{ label: "Status", value: … }, { label: "Size", value: … }]}
  sections={[{ title: "Passages", content: … }, { title: "Tags", content: … }]}
  actions={<><Button variant="danger">Delete</Button><Button>Re-fetch</Button></>} />

const form = useFormParam();             // ?form=new or ?form=<id>
<Button onClick={() => form.open("new")}>Add connection</Button>
{form.id && <FormPage label="Add connection" title="Add connection" description=… onClose={form.close}
  onSubmit={() => save.mutate()} submitLabel="Add connection" busy={save.isPending}>
  <FormSection title="Endpoint">…fields…</FormSection>
</FormPage>}
```

- A record or form page replaces the route's page in the main area; the list stays mounted underneath, hidden, so closing returns to the same filters and scroll position. Pages stack: an edit form opened from a record covers it.
- Each page has a back link ("← Back to Connections"), and its title is the last breadcrumb. The crumb under it closes it.
- `open(value)` pushes a history entry, so the browser's Back closes the page. A pasted link with `?record=` or `?form=` opens it directly; reloading keeps it open.
- Fetch the record by id (not from the list's page), so links work for rows that aren't loaded.
- A record opened from another record's page (a run's result) uses its own parameter: `useRecordParam("result")` and `<RecordPage param="result" …>` stack it over the first, and its back link returns there.
- A record's actions go in the header (`actions`: destructive first, the main action last). A form's buttons go under the form: Cancel, then the submit button; `startActions` holds "Change type" or a destructive action.
- `FormPage` asks "Leave without saving?" on Cancel, the back link and the breadcrumb once anything was typed or picked; pass `dirty` when the form tracks its own changes. A `RecordPage` with edits passes `dirty` too.
- After a create that goes to the new object's page, navigate with `replace: true`, so Back from it returns to the list, not to the form.

## Shell pieces for pages

- `useCrumbTail(label)` (`components/layout/crumb-tail.ts`) sets the last breadcrumb, for example a record name. PageTabs calls it for tabs.
- `NotFoundState` (`components/not-found.tsx`) renders the not-found page for an unknown team or object id. Use it instead of an inline error when the API returns 404.
- The team section of the sidebar, the team switcher and the ⌘K palette are handled by the shell. Pages don't need to register anything.
