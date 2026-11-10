/*
 * The capability picker's selection and its reconciliation with the saved one (capability-picker.tsx).
 *
 * `base` is the saved selection the person started from, `sel` theirs. When a new version of the gateway's
 * selection loads (saved elsewhere, or reloaded after a 412), it's reconciled while rendering, like
 * useRevisionForm: untouched, the picker follows it; edited, the person's selection stays, and when the
 * saved one really differs (or their save was refused) it's kept as `theirs` for them to choose: overwrite
 * theirs, or discard and take it.
 */
import { useState } from "react";
import type { Schemas } from "../../api/client";
import type { PickerSelection } from "./picker-options";

type Current = Schemas["GatewayCapabilities"];
export type SelectionVersion = { revision: number; sel: PickerSelection };

const selOf = (c: Current): PickerSelection => Object.fromEntries(c.items.map((i) => [i.capabilityId, i.minRole && i.minRole !== "member" ? i.minRole : ""]));
const same = (a: PickerSelection, b: PickerSelection) => JSON.stringify(Object.entries(a).sort()) === JSON.stringify(Object.entries(b).sort());

export function usePickerSelection(current: Current) {
  const [base, setBase] = useState<SelectionVersion>(() => ({ revision: current.revision, sel: selOf(current) }));
  const [sel, setSel] = useState<PickerSelection>(base.sel);
  const [theirs, setTheirs] = useState<SelectionVersion | null>(null);
  const [lost, setLost] = useState(false);
  const dirty = !same(sel, base.sel);

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

  return {
    /** The saved selection the person's edits are compared with, and the revision a save is conditional on. */
    base,
    sel,
    setSel,
    /** Someone else's saved selection, while the person decides between it and theirs. */
    theirs,
    dirty,
    /** The person's selection was saved as this revision. */
    saved: (revision: number) => {
      setBase({ revision, sel });
      setSeen(revision);
    },
    /** A save came back 412: the next version to load is someone else's. */
    conflicted: () => setLost(true),
    /** Back to the saved selection. */
    discard: () => setSel(base.sel),
    /** Take theirs and drop the person's edits. */
    takeTheirs: (their: SelectionVersion) => {
      setBase(their);
      setSel(their.sel);
      setTheirs(null);
    },
    /** Keep the person's selection, to be saved over theirs (on their revision). */
    keepMine: (their: SelectionVersion) => {
      setBase(their);
      setTheirs(null);
    },
  };
}
