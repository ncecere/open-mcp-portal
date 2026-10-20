/*
 * The fields of an MCP server shared by Add (a form page) and the Settings
 * tab: the address, the timeout and the switch. A server's own credential (its
 * parts) is edited by credential-fields.tsx.
 */
import type { ReactNode } from "react";
import { ApiError } from "../../api/client";
import { Field } from "@/components/ui/field/field";
import { Input } from "@/components/ui/input/input";
import { NumberInput } from "@/components/ui/number-input/number-input";
import { Switch } from "@/components/ui/switch/switch";
import { PrivateAddressRefusal } from "./url-refusal";

export type ServerForm = { name: string; description: string; url: string; timeoutSeconds: number; enabled: boolean };

const isLoopback = (host: string) => host === "localhost" || host.endsWith(".localhost") || /^127\.\d+\.\d+\.\d+$/.test(host) || host === "[::1]";

/**
 * What's wrong with a server URL before it's sent. https, or plain http: on a loopback address in development, or
 * for an internal host a platform admin allowed it for (the server knows the list, so it decides those).
 */
export function urlProblem(url: string, dev: boolean): string | undefined {
  const v = url.trim();
  if (!v) return "Enter the server's URL.";
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return "Enter a full URL, such as https://tools.example.com/mcp.";
  }
  if (u.protocol === "https:") return undefined;
  if (u.protocol === "http:" && (dev || !isLoopback(u.hostname))) return undefined;
  return "Use an https address.";
}

export type ServerProblems = Partial<Record<"name" | "url" | "timeoutSeconds", string>>;

/** Field errors as shown: the form's own, or the server's refusal (which may hold a link). */
export type FieldErrors = Partial<Record<keyof ServerProblems, ReactNode>>;

/** The form's field errors. */
export function serverProblems(f: ServerForm, opts: { dev: boolean }): ServerProblems {
  const out: ServerProblems = {};
  if (!f.name.trim()) out.name = "Enter a name.";
  else if (f.name.trim().length > 100) out.name = "Use at most 100 characters.";
  const url = urlProblem(f.url, opts.dev);
  if (url) out.url = url;
  if (!Number.isInteger(f.timeoutSeconds) || f.timeoutSeconds < 1 || f.timeoutSeconds > 120) out.timeoutSeconds = "Use a whole number of seconds from 1 to 120.";
  return out;
}

/** Why the server refused a URL (422 url_not_allowed, details.reason), in a sentence. */
const urlReasons: Record<string, ReactNode> = {
  invalid: "This isn't a URL the portal can use. Enter a full address, such as https://tools.example.com/mcp.",
  too_long: "This URL is too long. Use a shorter address.",
  userinfo: "Remove the user name and password from the URL. Send credentials as a Basic part of the credential below instead.",
  query: "Remove the query (the part from ?) from the address. A key that belongs in the query is added as a query parameter part of the credential below instead.",
  fragment: "Remove the fragment (the part from #).",
  scheme: "Use an https address. Plain http works only for internal hosts a platform admin has allowed it for.",
  private_address: <PrivateAddressRefusal />,
  blocked_address: "The portal never connects to loopback, link-local (such as cloud metadata), multicast or broadcast addresses. Use the server's real address.",
};

/** A server's refusal as field errors: a taken slug, a URL the portal won't connect to. */
export function serverFieldErrors(err: unknown): { slug?: string; url?: ReactNode } {
  if (!(err instanceof ApiError)) return {};
  if (err.code === "slug_taken") return { slug: "Another server uses this slug. Choose another." };
  if (err.code === "url_not_allowed") {
    const reason = typeof err.details?.reason === "string" ? err.details.reason : "";
    return { url: urlReasons[reason] ?? `The portal won't connect to this address. ${err.message}`.trim() };
  }
  return {};
}

type FieldsProps = {
  form: ServerForm;
  set: (patch: Partial<ServerForm>) => void;
  errors: FieldErrors;
  disabled?: boolean;
  dev: boolean;
};

export function UrlField({ form, set, errors, disabled, dev }: FieldsProps) {
  return (
    <Field
      label="URL"
      description={
        dev
          ? "The server's Streamable HTTP endpoint, such as https://tools.example.com/mcp. In development, plain http also works on a loopback address (http://localhost:9000/mcp)."
          : "The server's Streamable HTTP endpoint, such as https://tools.example.com/mcp. https, unless a platform admin allowed plain http for an internal host."
      }
      error={errors.url}
    >
      <Input type="url" inputMode="url" autoComplete="off" spellCheck={false} disabled={disabled} value={form.url} onChange={(e) => set({ url: e.target.value })} />
    </Field>
  );
}

export function TimeoutField({ form, set, errors, disabled }: FieldsProps) {
  return (
    <Field label="Timeout (seconds)" description="How long one request to the server may take, 1 to 120." error={errors.timeoutSeconds}>
      <NumberInput maximumFractionDigits={0} min={1} max={120} disabled={disabled} value={String(form.timeoutSeconds)} onValueChange={(v) => set({ timeoutSeconds: Number(v) })} />
    </Field>
  );
}

export function EnabledSwitch({ form, set, disabled }: FieldsProps) {
  return <Switch label="Enabled" description="Turned off, nothing connects to the server, and it can't be published." disabled={disabled} checked={form.enabled} onCheckedChange={(v) => set({ enabled: v })} />;
}
