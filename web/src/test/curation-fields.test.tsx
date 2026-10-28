import { choicesOf, policyOf, previewOf, type Choice, type Definition } from "../components/gateways/curation-fields";

const properties = { value: { type: "number" } };
const fixed = (text: string) => policyOf("", "", { value: { mode: "fixed", text } }, properties);
const unsafe = [
  "9007199254740990.5", "9007199254740991.1", "9007199254740992", "-9007199254740993",
  "0.10000000000000001", "1.234567890123456789", "1e309", "1e100000000000000000000000",
  "1e-10001", "1e-324", "4e-324", "-1e-999", "0." + "0".repeat(511) + "1",
];

describe("Constraint number lexemes", () => {
  it.each(unsafe)("rejects lossy numeric input %s before parsing, including nested/allowed values", (text) => {
    for (const mode of ["fixed", "allowed"] as const) {
      for (const value of [text, `{"nested":[${text}]}`]) {
        expect(() => policyOf("", "", { value: { mode, text: mode === "allowed" ? `[${value}]` : value } }, properties)).toThrow(/Numbers must be finite, use safe integers, and round-trip through JSON/);
      }
    }
  });

  it.each(["0.1", "1e-1", "1.5", "15e-1", "1.50", "-0", "0e10000", "0e-9999", "1e-254", "1e-255", "1e-300", "5e-324", "0." + "0".repeat(323) + "5", "9007199254740991", "-9007199254740991"])("preserves safe decimal value %s across save/reload and rename", (text) => {
    const original = fixed(text);
    const reloaded = JSON.parse(JSON.stringify(original));
    expect(policyOf("renamed", "description", choicesOf(reloaded, properties), properties)).toEqual({ ...reloaded, nameOverride: "renamed", descriptionOverride: "description" });
    expect(original.constraints?.value?.fixed).toBe(Number(text));
  });

  it("ignores quoted numeric strings and preserves fixed string-mode input verbatim", () => {
    const value = { text: '9007199254740990.5 " escaped', nested: ["1e99999", "1e-99999"], "9007199254740993": 0.1 };
    expect(fixed(JSON.stringify(value)).constraints?.value?.fixed).toEqual(value);
    for (const text of unsafe) {
      expect(policyOf("", "", { value: { mode: "fixed", text } }, { value: { type: "string" } }).constraints?.value?.fixed).toBe(text);
      expect(policyOf("", "", { value: { mode: "allowed", text: JSON.stringify([text]) } }, properties).constraints?.value?.allowed).toEqual([text]);
    }
  });

  it.each(["", "[1,]", '{"bad":', "NaN", "Infinity", "01", '"unterminated'])("still rejects invalid JSON %s", (text) => {
    expect(() => fixed(text)).toThrow(/Enter valid JSON/);
  });

  it("bounds scanning and numeric token size without large exponent arithmetic", () => {
    expect(() => fixed("[" + "0,".repeat(33000) + "0]")).toThrow(/at most 64 KiB/);
    expect(() => fixed("0e" + "0".repeat(511))).toThrow(/Numbers must/);
  });
});

describe("Argument dictionaries", () => {
  const keys = ["__proto__", "constructor", "prototype", "normal"];
  const props = Object.fromEntries(keys.map((key) => [key, { type: "string" }]));

  it.each(["fixed", "allowed"] as const)("round-trips %s constraints for special and ordinary keys", (mode) => {
    const choices = Object.fromEntries(keys.map((key) => [key, { mode, text: mode === "fixed" ? `${key} value` : JSON.stringify([`${key} value`]) }]));
    const policy = policyOf("", "", choices, props);
    const reloaded = JSON.parse(JSON.stringify(policy));
    expect(Object.keys(reloaded.constraints)).toEqual(keys);
    for (const key of keys) expect(reloaded.constraints[key]).toEqual(mode === "fixed" ? { fixed: `${key} value` } : { allowed: [`${key} value`] });
    expect(choicesOf(reloaded, props)).toEqual(choices);
    expect(policyOf("renamed", "new description", choicesOf(reloaded, props), props).constraints).toEqual(reloaded.constraints);
    const preview = previewOf({ inputSchema: { type: "object", properties: props, required: keys } }, policy, "fallback");
    const schema = preview.inputSchema as Definition;
    expect(Object.keys(schema.properties as Definition)).toEqual(mode === "fixed" ? [] : keys);
    if (mode === "fixed") expect(schema.required).toEqual([]);
    else for (const key of keys) expect((schema.properties as Definition)[key]).toEqual({ type: "string", enum: [`${key} value`] });
  });

  it("never consults inherited properties or choices, even for removed arguments", () => {
    const inheritedProps = Object.create({ constructor: { type: "string" } }) as Definition;
    const removedChoices: Record<string, Choice> = Object.fromEntries([["constructor", { mode: "fixed", text: "not JSON" }]]);
    expect(() => policyOf("", "", removedChoices, inheritedProps)).toThrow();
    const policy = { constraints: { constructor: { fixed: "value" } } };
    expect(Object.entries(choicesOf(policy, inheritedProps))).toEqual([["constructor", { mode: "fixed", text: '"value"' }]]);
    const choices = Object.create({ normal: { mode: "fixed", text: "inherited" } }) as Record<string, Choice>;
    expect(policyOf("", "", choices, props).constraints).toEqual({});
    const preview = previewOf({ inputSchema: { properties: inheritedProps } }, { constraints: { constructor: { allowed: [1] } } }, "fallback");
    expect((preview.inputSchema as Definition).properties).toEqual({ constructor: { enum: [1] } });
  });
});
