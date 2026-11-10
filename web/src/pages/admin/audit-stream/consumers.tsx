import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ifMatch } from "@/api/client";
import { ConfirmMutationDialog } from "@/components/confirm-dialog";
import { FormDialog } from "@/components/form-dialog";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { Checkbox } from "@/components/ui/checkbox/checkbox";
import { Field } from "@/components/ui/field/field";
import { Input, NativeSelect } from "@/components/ui/input/input";
import { Inline } from "@/components/ui/layout/layout";
import { Table, Td, Tr } from "@/components/ui/table/table";
import { unwrapAudit, type Consumer, statusKey } from "./api";

const consumerKey = ["admin", "audit-consumers"];
export function Consumers({ items, canEdit }: { items: Consumer[]; canEdit: boolean }) {
  const qc = useQueryClient();
  const revision = useQuery({ queryKey: consumerKey, enabled: canEdit, queryFn: async () => unwrapAudit(await api.GET("/v1/admin/settings/audit-consumers")) as { revision: number } });
  const [register, setRegister] = useState(false);
  const [name, setName] = useState("");
  const [profile, setProfile] = useState<"summary" | "full">("summary");
  const [required, setRequired] = useState(false);
  const [target, setTarget] = useState<{ item: Consumer; remove: boolean } | null>(null);
  const change = useMutation({ mutationFn: async (v: { item: Consumer; remove: boolean } | null) => {
    if (!revision.data) throw new Error("Load the consumer revision before saving");
    const header = ifMatch(revision.data.revision);
    if (!v) return unwrapAudit(await api.POST("/v1/admin/settings/audit-consumers", { params: { header }, body: { consumer: name, profile, required } }));
    const params = { header, path: { consumer: v.item.name } };
    return v.remove
      ? unwrapAudit(await api.DELETE("/v1/admin/settings/audit-consumers/{consumer}", { params }))
      : unwrapAudit(await api.PUT("/v1/admin/settings/audit-consumers/{consumer}", { params, body: { required: !v.item.required } }));
  }, onSuccess: () => { setRegister(false); setTarget(null); setName(""); change.reset(); }, onSettled: () => {
    void qc.invalidateQueries({ queryKey: statusKey }); void qc.invalidateQueries({ queryKey: consumerKey });
  } });
  return <Card title="Pull consumers" actions={canEdit ? <Button disabled={!revision.data} onClick={() => { change.reset(); setRegister(true); }}>Register consumer</Button> : undefined}>
    <ErrorAlert error={revision.error} onRetry={() => void revision.refetch()} />
    <Table stack caption="Pull consumers" columns={["Name", "Profile", "Required", "Acknowledged sequence", "Lag (records)", ...(canEdit ? ["Actions"] : [])]} empty={!items.length ? "No pull consumers registered." : undefined}>
      {items.map(item => <Tr key={item.name}><Td>{item.name}</Td><Td>{item.profile}</Td><Td>{item.required ? "Yes" : "No"}</Td><Td>{item.acked_seq}</Td><Td>{item.lag}</Td>{canEdit && <Td><Inline gap={2}>
        <Button size="sm" disabled={!revision.data} onClick={() => { change.reset(); setTarget({ item, remove: false }); }}>{item.required ? "Make optional" : "Make required"}</Button>
        <Button size="sm" variant="danger" disabled={!revision.data} onClick={() => { change.reset(); setTarget({ item, remove: true }); }}>Remove</Button>
      </Inline></Td>}</Tr>)}
    </Table>
    {register && <FormDialog title="Register pull consumer" description="Required consumers hold audit retention until they acknowledge records." submitLabel="Register consumer"
      onClose={() => setRegister(false)} onSubmit={() => change.mutate(null)} busy={change.isPending} closeDisabled={change.isPending}>
      <ErrorAlert error={change.error} />
      <Field label="Consumer name"><Input required value={name} onChange={e => setName(e.target.value)} /></Field>
      <Field label="Consumer profile"><NativeSelect value={profile} onChange={e => setProfile(e.target.value as "summary" | "full")}><option value="summary">Summary</option><option value="full">Full</option></NativeSelect></Field>
      <Checkbox label="Required" checked={required} onCheckedChange={setRequired} />
    </FormDialog>}
    <ConfirmMutationDialog target={target} onClose={() => setTarget(null)} mutation={change} onConfirm={v => change.mutate(v)}
      title={target?.remove ? "Remove consumer?" : "Change retention requirement?"}
      description="Required consumers hold retention at their acknowledged sequence. Removing a consumer or making it optional releases that hold."
      confirmLabel="Confirm consumer change" />
  </Card>;
}
