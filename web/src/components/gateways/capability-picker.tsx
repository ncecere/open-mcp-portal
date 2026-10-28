/*
 * Editing a gateway's selection: what it may select (gateway-options, a
 * page at a time, searched and filtered by kind and server on the server)
 * grouped by server, with "Load more" and, on team gateways, a minimum team
 * role per capability. The selection is kept apart from what's loaded, so
 * it survives searching, filtering and paging; options seen once are
 * remembered for their names ("Selected only" shows those). Saved explicitly with
 * If-Match on the gateway's revision. When the gateway changes elsewhere
 * (or a save comes back 412), the person's selection stays and they choose:
 * overwrite theirs, or discard and load theirs. A refused selection (422)
 * marks the capabilities it's about.
 */
import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListTree } from "lucide-react";
import { useRef, useState } from "react";
import { api, type Schemas, unwrap } from "../../api/client";
import { useDebounced } from "../../pages/admin/hooks";
import { conflictLabels } from "../templates/conflict-notice";
import { isRevisionConflict } from "../templates/revision-form";
import { useUnsavedChangesGuard } from "../templates/unsaved-guard";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { Checkbox } from "@/components/ui/checkbox/checkbox";
import { EmptyState } from "@/components/ui/empty-state/empty-state";
import { Field } from "@/components/ui/field/field";
import { Input, NativeSelect } from "@/components/ui/input/input";
import { SaveBar } from "@/components/ui/save-bar/save-bar";
import { SkeletonText } from "@/components/ui/skeleton/skeleton";
import { toast } from "@/components/ui/toast/toast";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group/toggle-group";
import { untrustedText } from "../servers/labels";
import { CurationDialog } from "./curation-dialog";
import type { GatewayCapability } from "./labels";
import { CapabilityRow } from "./capability-list";
import { AvailabilityBadge } from "./badges";
import { capabilityCount, type Gateway, type GatewayKind, gatewayKinds, gatewayKindLabels, type GatewayOption, maxCapabilities } from "./labels";
import { selectionProblem } from "./picker-errors";
import { filterOptions, OptionGroups, optionOf, type PickerSelection } from "./picker-options";
import { gatewayCapabilitiesQuery, gatewayOptionsQuery, type GatewayScope, gatewayQuery, invalidateGateway, setCapabilities } from "./scope";
import g from "./gateways.module.css";

type Current = Schemas["GatewayCapabilities"];
type Version = { revision: number; sel: PickerSelection };

const selOf = (c: Current): PickerSelection => Object.fromEntries(c.items.map((i) => [i.capabilityId, i.minRole && i.minRole !== "member" ? i.minRole : ""]));
const same = (a: PickerSelection, b: PickerSelection) => JSON.stringify(Object.entries(a).sort()) === JSON.stringify(Object.entries(b).sort());

type Props = { gateway: Gateway; scope: GatewayScope; current: Current; onDone: () => void };

type ServerChoice = { id: string; name: string };

/** Servers to filter by: the catalog's and (team gateways) the team's own, plus any seen in an option. */
function useServerChoices(scope: GatewayScope, seen: Iterable<GatewayOption>): ServerChoice[] {
  const catalog = useQuery({
    queryKey: ["catalog", "servers", "picker"],
    queryFn: async () => unwrap(await api.GET("/v1/catalog/servers", { params: { query: { limit: 200 } } })).items,
    retry: false,
  });
  const team = scope.kind === "team" ? scope.team : "";
  const own = useQuery({
    queryKey: ["team", team, "servers", "picker"],
    queryFn: async () => unwrap(await api.GET("/v1/teams/{team}/mcp-servers", { params: { path: { team }, query: { limit: 200 } } })).items.filter((s) => s.enabled),
    enabled: team !== "",
    retry: false,
  });
  const byId = new Map<string, ServerChoice>();
  for (const s of [...(own.data ?? []), ...(catalog.data ?? [])]) byId.set(s.id, { id: s.id, name: s.name });
  for (const o of seen) byId.set(o.serverId, { id: o.serverId, name: o.serverName });
  return [...byId.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export function CapabilityPicker({ gateway, scope, current, onDone }: Props) {
  const qc = useQueryClient();
  const roles = gateway.ownerKind === "team";
  const [base, setBase] = useState<Version>(() => ({ revision: current.revision, sel: selOf(current) }));
  const [sel, setSel] = useState<PickerSelection>(base.sel);
  const [theirs, setTheirs] = useState<Version | null>(null);
  const [lost, setLost] = useState(false);
  const [text, setText] = useState("");
  const q = useDebounced(text.trim());
  const [kind, setKind] = useState<GatewayKind | "">("");
  const [server, setServer] = useState("");
  const [onlySelected, setOnlySelected] = useState(false);
  const [curating, setCurating] = useState<GatewayCapability | null>(null);
  const options = useInfiniteQuery({ ...gatewayOptionsQuery(scope, { q, kind, server }), placeholderData: keepPreviousData });
  const dirty = !same(sel, base.sel);

  // Every option seen (on any page, search or filter) and the selection as loaded: the names of selected
  // capabilities that aren't on a loaded page, and what "Selected only" shows.
  const known = useRef(new Map<string, GatewayOption>()).current;
  for (const c of current.items) if (!known.has(c.capabilityId)) known.set(c.capabilityId, optionOf(c, gateway));
  const loaded = options.data?.pages.flatMap((p) => p.items) ?? [];
  for (const o of loaded) known.set(o.capabilityId, o);
  const servers = useServerChoices(scope, known.values());

  // A new version loaded (saved elsewhere, or after a 412): reconciled while rendering, like useRevisionForm.
  const [seen, setSeen] = useState(current.revision);
  if (seen !== current.revision) {
    setSeen(current.revision);
    const next = { revision: current.revision, sel: selOf(current) };
    if (lost || (dirty && !same(next.sel, base.sel))) setTheirs(next);
    else if (dirty) setBase({ ...base, revision: next.revision });
    else {
      setBase(next);
      setSel(next.sel);
    }
    setLost(false);
  }

  const save = useMutation({
    mutationFn: async (revision: number) =>
      setCapabilities(
        scope,
        gateway,
        Object.entries(sel).map(([capabilityId, minRole]) => (roles && minRole ? { capabilityId, minRole } : { capabilityId })),
        revision,
      ),
    onSuccess: (saved) => {
      qc.setQueryData(gatewayCapabilitiesQuery(scope, gateway.id).queryKey, saved);
      void qc.invalidateQueries({ queryKey: gatewayQuery(scope, gateway.id).queryKey });
      invalidateGateway(qc, gateway);
      setBase({ revision: saved.revision, sel });
      setSeen(saved.revision);
      toast.success("Capabilities saved", `${gateway.name} offers ${capabilityCount(saved.items.length)}.`);
      onDone();
    },
    // A 412: the next version to load is someone else's (main.tsx reloads every query; this one for certain).
    onError: (err) => {
      if (!isRevisionConflict(err)) return;
      setLost(true);
      void qc.invalidateQueries({ queryKey: gatewayCapabilitiesQuery(scope, gateway.id).queryKey });
    },
  });
  const guard = useUnsavedChangesGuard(dirty && !save.isPending, { samePath: true });

  const count = Object.keys(sel).length;
  // Selected, but not served now: gateway-options doesn't offer them (it offers what is served).
  const notOffered = current.items.filter((c) => c.capabilityId in sel && !c.available);
  const unavailable = new Set(notOffered.map((c) => c.capabilityId));
  const withNames = Object.keys(sel).map((id) => ({ capabilityId: id, exposedName: known.get(id)?.exposedName }));
  const problem = selectionProblem(save.error, withNames);
  const problemIds = (problem?.ids ?? []).filter((id) => id in sel);
  const showProblem = problem && (problem.code === "too_many" ? count > maxCapabilities : problemIds.length > 0);
  const problems = new Map(showProblem ? problemIds.map((id) => [id, problem.rowText]) : []);
  const selectedKnown = Object.keys(sel)
    .map((id) => known.get(id))
    .filter((o): o is GatewayOption => o !== undefined && !unavailable.has(o.capabilityId));
  const shown = onlySelected ? filterOptions(selectedKnown, text, kind, sel, server) : loaded;
  const filtered = Boolean(q || kind || server);
  const tooMany = count > maxCapabilities;

  const set = (next: PickerSelection) => setSel(next);
  const toggle = (id: string, on: boolean) => {
    if (on) set({ ...sel, [id]: "" });
    else set(Object.fromEntries(Object.entries(sel).filter(([k]) => k !== id)));
  };
  const remove = (ids: string[]) => set(Object.fromEntries(Object.entries(sel).filter(([k]) => !ids.includes(k))));

  return (
    <>
      <Alert tone="warning" title="Untrusted text">
        {untrustedText} Read what a capability does before you offer it to people.
      </Alert>
      {theirs && <ConflictAlert theirs={theirs} mine={sel} />}
      {showProblem && (
        <Alert
          tone="danger"
          title="The selection wasn't saved"
          actions={
            problem.code === "capability_not_selectable" ? (
              <Button size="sm" variant="secondary" onClick={() => remove(problemIds)}>
                Remove them
              </Button>
            ) : undefined
          }
        >
          {problem.message}
        </Alert>
      )}
      {!problem && !isRevisionConflict(save.error) && <ErrorAlert error={save.error} title="Couldn't save the capabilities" />}
      <Card
        title="Choose capabilities"
        description={
          roles
            ? "Your team's own servers and approved capabilities of published catalog servers. Every team member can use a capability unless you set a minimum role."
            : "Approved tools, prompts and resources of published catalog servers. Who may use the gateway is set on its Access tab."
        }
        actions={
          <Button size="sm" variant="ghost" disabled={save.isPending} onClick={onDone}>
            Cancel
          </Button>
        }
      >
        {/* Room under the last row for the sticky save bar while it's open. */}
        <div className={g.stack} data-save-bar={dirty || theirs ? "" : undefined}>
          <div className={g.toolbar}>
            <Field label="Search capabilities" hideLabel className={g.search}>
              <Input type="search" placeholder="Name, title or server" value={text} onChange={(e) => setText(e.target.value)} />
            </Field>
            <Field label="Server" hideLabel className={g.serverFilter}>
              <NativeSelect value={server} onChange={(e) => setServer(e.target.value)}>
                <option value="">All servers</option>
                {servers.map((sv) => (
                  <option key={sv.id} value={sv.id}>
                    {sv.name}
                  </option>
                ))}
              </NativeSelect>
            </Field>
            <ToggleGroup aria-label="Kind" joined size="sm" value={[kind || "all"]} onValueChange={(v) => setKind(v[0] && v[0] !== "all" ? (v[0] as GatewayKind) : "")}>
              <ToggleGroupItem value="all">All</ToggleGroupItem>
              {gatewayKinds.map((k) => (
                <ToggleGroupItem key={k} value={k}>
                  {gatewayKindLabels[k].title}
                </ToggleGroupItem>
              ))}
            </ToggleGroup>
            <Checkbox label="Selected only" checked={onlySelected} onCheckedChange={setOnlySelected} />
            <span className={g.count} role="status">
              {count.toLocaleString()} of at most {maxCapabilities} selected
            </span>
          </div>
          {current.items.some((c) => c.kind === "tool" && c.capabilityId in sel) && <section className={g.tight} aria-label="Selected tool policies">
            <p className={g.note}>Save selection changes before editing a tool policy.</p>
            {current.items.filter((c) => c.kind === "tool" && c.capabilityId in sel).map((c) => <Button key={c.capabilityId} size="sm" variant="secondary" disabled={dirty || save.isPending || !!theirs} onClick={() => setCurating(c)}>Curate {c.exposedName}</Button>)}
          </section>}
          {notOffered.length > 0 && (
            <section className={g.group} aria-labelledby="not-offered">
              <h3 id="not-offered" className={g.groupHead}>
                Selected, but can&apos;t be selected now
                <span className={g.groupMeta}>These may stay selected but are not served. Review stale tool policies above.</span>
              </h3>
              <ul className={g.list}>
                {notOffered.map((c) => (
                  <CapabilityRow
                    key={c.capabilityId}
                    cap={c}
                    problem={problems.get(c.capabilityId)}
                    side={
                      <>
                        <AvailabilityBadge cap={c} />
                        <Button size="sm" variant="secondary" onClick={() => remove([c.capabilityId])} aria-label={`Remove ${c.exposedName}`}>
                          Remove
                        </Button>
                      </>
                    }
                  />
                ))}
              </ul>
            </section>
          )}
          {onlySelected ? null : options.isLoading ? (
            <div role="status" aria-label="Loading capabilities…">
              <SkeletonText lines={4} />
            </div>
          ) : options.error ? (
            <ErrorAlert error={options.error} title="Couldn't load the capabilities you can choose from" onRetry={() => void options.refetch()} />
          ) : loaded.length === 0 && !filtered ? (
            <EmptyState
              size="compact"
              icon={<ListTree />}
              title="Nothing to choose from yet."
              description={roles ? "Register an MCP server for your team, or wait for servers to be published to the catalog." : "Teams publish servers to the catalog; their approved tools, prompts and resources show up here."}
            />
          ) : null}
          {(onlySelected || (!options.isLoading && !options.error && (loaded.length > 0 || filtered))) &&
            (shown.length === 0 ? (
              <p className={g.note}>No capabilities match.</p>
            ) : (
              <OptionGroups options={shown} selection={sel} roles={roles} problems={problems} onToggle={toggle} onRole={(id, role) => set({ ...sel, [id]: role })} />
            ))}
          {!onlySelected && options.hasNextPage && (
            <div className={g.loadMore}>
              <Button variant="secondary" loading={options.isFetchingNextPage} onClick={() => void options.fetchNextPage()}>
                Load more
              </Button>
              <span className={g.groupMeta}>{loaded.length.toLocaleString()} shown</span>
            </div>
          )}
        </div>
      </Card>
      <SaveBar open={dirty || Boolean(theirs)} message={theirs ? "Changed elsewhere while you were editing" : tooMany ? `Not saved: at most ${maxCapabilities} capabilities` : "Unsaved changes"}>
        {theirs ? (
          <>
            <Button
              variant="ghost"
              disabled={save.isPending}
              onClick={() => {
                setBase(theirs);
                setSel(theirs.sel);
                setTheirs(null);
                save.reset();
              }}
            >
              {conflictLabels.discard}
            </Button>
            <Button
              loading={save.isPending}
              disabled={tooMany}
              onClick={() => {
                setBase(theirs);
                setTheirs(null);
                save.mutate(theirs.revision);
              }}
            >
              {conflictLabels.overwrite}
            </Button>
          </>
        ) : (
          <>
            <Button variant="ghost" disabled={save.isPending} onClick={() => setSel(base.sel)}>
              Discard
            </Button>
            <Button loading={save.isPending} disabled={tooMany} onClick={() => save.mutate(base.revision)}>
              Save selection
            </Button>
          </>
        )}
      </SaveBar>
      {guard}
      {curating && <CurationDialog gateway={gateway} scope={scope} current={current} capability={curating} onClose={() => { setCurating(null); }} />}
    </>
  );
}

/** The selection changed elsewhere: the person's is still here; how theirs differs. */
function ConflictAlert({ theirs, mine }: { theirs: Version; mine: PickerSelection }) {
  const added = Object.keys(theirs.sel).filter((id) => !(id in mine)).length;
  const removed = Object.keys(mine).filter((id) => !(id in theirs.sel)).length;
  return (
    <Alert tone="warning" title="Someone else changed this gateway while you were editing">
      <p>
        Your selection is still here. <strong>{conflictLabels.overwrite}</strong> saves yours over theirs; <strong>{conflictLabels.discard}</strong> shows theirs (
        {capabilityCount(Object.keys(theirs.sel).length)}).
        {added + removed > 0 ? ` Theirs has ${added} you don't and lacks ${removed} you chose.` : ""}
      </p>
    </Alert>
  );
}
