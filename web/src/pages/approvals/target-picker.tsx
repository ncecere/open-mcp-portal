import { useQuery } from "@tanstack/react-query";
import { api, unwrap } from "../../api/client";
import { Field } from "@/components/ui/field/field";
import { Input, NativeSelect } from "@/components/ui/input/input";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { useState } from "react";
import { PagerBar, useCursorPager } from "../../components/pager";
import type { RuleInput } from "../../api/approvals";

export function TargetPicker({ team, kind, value, onChange, disabled }: { team?: string; kind: RuleInput["targetKind"]; value: string; onChange: (id: string) => void; disabled: boolean }) {
  const [search, setSearch] = useState("");
  const pager = useCursorPager();
  const targets = useQuery({
    queryKey: ["approval-targets", team, kind, search, pager.cursor],
    queryFn: async () => {
      const query = { q: search || undefined, limit: 50, cursor: pager.cursor };
      if (team && kind === "server") return unwrap(await api.GET("/v1/teams/{team}/mcp-servers", { params: { path: { team }, query } }));
      if (team) return unwrap(await api.GET("/v1/teams/{team}/gateways", { params: { path: { team }, query } }));
      const page = unwrap(await api.GET("/v1/admin/gateways", { params: { query: { ...query, ownerKind: "platform" } } }));
      return { ...page, items: page.items.filter((g) => g.ownerKind === "platform") };
    },
  });
  return <>
    <Field label="Find target" description={team ? "Choose a server or gateway owned by this team. Targets cannot be moved after creation." : "Only platform-owned gateways may have platform rules."}>
      <Input value={search} disabled={disabled} onValueChange={(v) => { setSearch(v); pager.reset(); }} placeholder="Search by name" />
    </Field>
    <Field label="Target" description="The portal validates target ownership and eligibility when saving.">
      <NativeSelect required value={value} disabled={disabled || targets.isLoading || !!targets.error} onChange={(e) => onChange(e.target.value)}>
        <option value="">Choose a target</option>
        {value && !targets.data?.items.some((t) => t.id === value) && <option value={value}>{value} (selected target)</option>}
        {targets.data?.items.map((t) => <option key={t.id} value={t.id}>{t.name} · {t.id}</option>)}
      </NativeSelect>
    </Field>
    <ErrorAlert error={targets.error} title="Couldn't load targets" />
    {targets.error && <Button variant="secondary" disabled={disabled} onClick={() => void targets.refetch()}>Retry targets</Button>}
    {!disabled && <PagerBar pager={pager} pageSize={50} shown={targets.data?.items.length ?? 0} nextCursor={targets.data?.nextCursor} label="Target pages" />}
  </>;
}
