/*
 * An origin is scheme, host and port, in lower case without a default port: a
 * stored secret is for the origin it was entered for, so a URL on another one
 * needs every value entered again (F-1). Mirrors internal/registry/origin.go;
 * the server decides, this only warns before the save.
 */
export function originOf(raw: string): string {
  try {
    const u = new URL(raw.trim());
    return `${u.protocol}//${u.host}`.toLowerCase().replace(/\.(?=:|$)/, "");
  } catch {
    return `invalid:${raw}`;
  }
}

export const sameOrigin = (a: string, b: string) => originOf(a) === originOf(b);
