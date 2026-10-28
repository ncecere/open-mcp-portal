const numericError = "Numbers must be finite, use safe integers, and round-trip through JSON without rounding or underflow.";
const numberToken = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

// Decimal equality, not binary-float equality: 0.1 and 1e-1 are equivalent.
// Keep only significant digits and a bounded base-ten exponent; never build powers.
function decimal(token: string): string {
  if (token.length > 256) throw new Error(numericError);
  const [mantissa = "", power = "0"] = token.toLowerCase().split("e");
  const exponent = Number(power);
  if (!Number.isInteger(exponent) || Math.abs(exponent) > 10000) throw new Error(numericError);
  const negative = mantissa.startsWith("-");
  const unsigned = negative ? mantissa.slice(1) : mantissa;
  const point = unsigned.indexOf(".");
  const fractionLength = point < 0 ? 0 : unsigned.length - point - 1;
  const digits = unsigned.replace(".", "").replace(/^0+/, "");
  if (!digits) return "0";
  const significant = digits.replace(/0+$/, "");
  return `${negative ? "-" : ""}${significant}e${exponent - fractionLength + digits.length - significant.length}`;
}

// Inspect original lexemes BEFORE JSON.parse can round them. JSON.parse remains
// responsible for syntax; quoted strings (including escaped quotes) are untouched.
export function assertExactConstraintNumbers(text: string): void {
  if (text.length > 65536) throw new Error("Constraint JSON must be at most 64 KiB.");
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const char = text.charAt(i);
    if (quoted) {
      if (char === "\\") i++;
      else if (char === '"') quoted = false;
    } else if (char === '"') quoted = true;
    else if (char === "-" || (char >= "0" && char <= "9")) {
      numberToken.lastIndex = i;
      const token = numberToken.exec(text)?.[0];
      if (!token) continue;
      const value = Number(token);
      if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)) || decimal(token) !== decimal(JSON.stringify(value))) throw new Error(numericError);
      i += token.length - 1;
    }
  }
}
