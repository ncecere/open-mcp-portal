/*
 * A refused selection (422 from PUT …/capabilities) in the picker's words,
 * with the capabilities it's about, so their rows can say what's wrong:
 * capability_not_selectable (details.capabilityIds), too_many (over 200),
 * name_clash (details.exposedName: a name or an exposed resource URI).
 */
import { ApiError } from "../../api/client";
import { maxCapabilities } from "./labels";

export type SelectionProblem = {
  code: "capability_not_selectable" | "too_many" | "name_clash";
  message: string;
  /** Selected capabilities the problem is about. */
  ids: string[];
  /** Name clash: the exposed name two capabilities share. */
  exposedName?: string;
  /** What each affected row says. */
  rowText: string;
};

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

/** The problem, or undefined for any other error (shown as it is). */
export function selectionProblem(err: unknown, selected: { capabilityId: string; exposedName?: string }[]): SelectionProblem | undefined {
  if (!(err instanceof ApiError) || err.status !== 422) return undefined;
  if (err.code === "capability_not_selectable") {
    const ids = strings(err.details?.capabilityIds);
    const n = ids.length;
    const reasons = err.details?.reasons;
    const template = typeof reasons === "object" && reasons !== null && Object.values(reasons).includes("unsupported_template");
    return {
      code: err.code,
      ids,
      rowText: "Can't be selected now. Remove it to save.",
      message:
        n > 0
          ? `${n === 1 ? "1 selected capability can't" : `${n} selected capabilities can't`} be selected any more: ` +
            "the server may be another team's private one, or the capability unapproved or gone" +
            `${template ? ", or a resource template using expressions other than {var} and {+var}" : ""}. Remove ${n === 1 ? "it" : "them"} and save again.`
          : "Some selected capabilities can't be selected any more. Remove the ones marked here and save again.",
    };
  }
  if (err.code === "too_many") {
    const over = selected.length - maxCapabilities;
    return {
      code: err.code,
      ids: [],
      rowText: "",
      message: `A gateway can hold at most ${maxCapabilities} capabilities.${over > 0 ? ` Remove ${over} and save again.` : " Remove some and save again."}`,
    };
  }
  if (err.code === "name_clash") {
    const name = typeof err.details?.exposedName === "string" ? err.details.exposedName : undefined;
    // The server compares exposed names and URIs case-insensitively.
    const ids = name ? selected.filter((s) => s.exposedName?.toLowerCase() === name.toLowerCase()).map((s) => s.capabilityId) : [];
    return {
      code: err.code,
      ids,
      exposedName: name,
      rowText: "Clients would see two capabilities with this name. Keep one.",
      message: name
        ? `Two selected capabilities are both exposed as ${name}. Keep only one of them and save again.`
        : "Two selected capabilities would be exposed with the same name. Keep only one of them and save again.",
    };
  }
  return undefined;
}
