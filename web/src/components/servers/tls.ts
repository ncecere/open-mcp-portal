/*
 * A server's TLS settings as the Settings tab edits them (decision 74): a CA
 * bundle that replaces the system roots for this server only, and a client
 * certificate with its private key (mTLS). The key is write-only: the server
 * never returns it, only whether one is stored, and the fingerprint, subject,
 * issuer and expiry of the certificates. The checks here only catch what is
 * obviously wrong before a save (a key pasted as the CA, a passphrase-protected
 * key); the server validates for real and its reasons map back to the fields.
 * There is no option to skip verification, here or anywhere.
 */
import { ApiError, type Schemas } from "../../api/client";
import { formatDate } from "../../lib/format";
import type { McpServer } from "./labels";

export type TlsInput = Schemas["McpServerTlsInput"];
type TlsClient = Schemas["McpServerTlsClient"];

export const maxPem = 64 * 1024;
export const maxKeyPem = 16 * 1024;

export type TlsForm = {
  caPem: string;
  clientCertPem: string;
  clientKeyPem: string;
  /** Remove the stored CA (the system roots apply again). */
  removeCa: boolean;
  /** Remove the stored client certificate and its key. */
  removeClient: boolean;
};

export const emptyTlsForm: TlsForm = { caPem: "", clientCertPem: "", clientKeyPem: "", removeCa: false, removeClient: false };

export type TlsField = "caPem" | "clientCertPem" | "clientKeyPem";
export type TlsErrors = Partial<Record<TlsField, string>>;

/** The tls object to send (undefined: nothing changes). Removing wins over typed text. */
export function tlsBody(f: TlsForm): TlsInput | undefined {
  const out: TlsInput = {};
  if (f.removeCa) out.caPem = "";
  else if (f.caPem.trim()) out.caPem = f.caPem.trim();
  if (f.removeClient) out.clientCertPem = "";
  else {
    if (f.clientCertPem.trim()) out.clientCertPem = f.clientCertPem.trim();
    if (f.clientKeyPem.trim()) out.clientKeyPem = f.clientKeyPem.trim();
  }
  return Object.keys(out).length ? out : undefined;
}

export const tlsDirty = (f: TlsForm) => tlsBody(f) !== undefined;

const hasKeyBlock = (s: string) => /PRIVATE KEY-----/.test(s);

/** What is obviously wrong with the form before it is sent. */
export function tlsProblems(f: TlsForm, server: McpServer): TlsErrors {
  const out: TlsErrors = {};
  const ca = f.removeCa ? "" : f.caPem.trim();
  const cert = f.removeClient ? "" : f.clientCertPem.trim();
  const key = f.removeClient ? "" : f.clientKeyPem.trim();
  if (ca) {
    if (ca.length > maxPem) out.caPem = "Too large: at most 64 KiB.";
    else if (hasKeyBlock(ca)) out.caPem = "That contains a private key. This field takes certificates only.";
    else if (!ca.includes("-----BEGIN CERTIFICATE-----")) out.caPem = "Paste PEM certificates (-----BEGIN CERTIFICATE-----).";
  }
  if (cert) {
    if (cert.length > maxPem) out.clientCertPem = "Too large: at most 64 KiB.";
    else if (hasKeyBlock(cert)) out.clientCertPem = "That contains a private key. Paste the key in the private key field instead.";
    else if (!cert.includes("-----BEGIN CERTIFICATE-----")) out.clientCertPem = "Paste the PEM certificate (-----BEGIN CERTIFICATE-----).";
  }
  if (key) {
    if (key.length > maxKeyPem) out.clientKeyPem = "Too large: at most 16 KiB.";
    else if (/ENCRYPTED/.test(key)) out.clientKeyPem = "This key is protected by a passphrase, which isn't supported. Remove the passphrase first (openssl pkey -in key.pem -out key-plain.pem).";
    else if (!hasKeyBlock(key)) out.clientKeyPem = "Paste an unencrypted private key (-----BEGIN PRIVATE KEY-----).";
    else if (!cert) out.clientCertPem = "Paste the certificate that goes with this key.";
  } else if (cert && !server.tls?.client?.hasKey) {
    out.clientKeyPem = "Paste the private key that goes with this certificate.";
  }
  return out;
}

/** The server's refusal of the tls object (422 invalid_tls or tls_key_required) as field errors; empty for any other error. */
export function tlsRefusal(err: unknown): TlsErrors {
  if (!(err instanceof ApiError)) return {};
  const field = (err.details as { field?: string } | undefined)?.field;
  if (err.code === "tls_key_required") return { clientKeyPem: err.message };
  if (err.code === "invalid_tls") {
    const name = field?.replace(/^tls\./, "");
    if (name === "caPem" || name === "clientCertPem" || name === "clientKeyPem") return { [name]: err.message };
    return { clientCertPem: err.message };
  }
  return {};
}

/** Whether saving this form changes which CA the server is trusted against (a review trigger under approval). */
export const changesCa = (f: TlsForm, server: McpServer) => f.removeCa ? Boolean(server.tls?.ca) : Boolean(f.caPem.trim());

const days = (n: number) => (n === 1 ? "1 day" : `${n} days`);

/** "Expires 2027-01-18 (in 90 days)", "Expires soon: ...", "Expired ...". */
export function expiryText(c: TlsClient): string {
  const when = formatDate(c.certificate.notAfter);
  if (c.status === "expired") return `Expired ${when}`;
  if (c.status === "expiring") return `Expires ${when}, in ${days(Math.max(c.daysLeft, 0))}`;
  return `Expires ${when}`;
}

/** One line about the server's TLS settings, for the Overview tab (undefined: none). */
export function tlsSummary(server: McpServer): string | undefined {
  const t = server.tls;
  if (!t || (!t.ca && !t.client)) return undefined;
  const parts: string[] = [];
  if (t.ca) parts.push(t.ca.certificates.length === 1 ? "private CA" : `private CA (${t.ca.certificates.length} certificates)`);
  if (t.client) parts.push(`client certificate (${expiryText(t.client).toLowerCase()})`);
  return parts.join(", ");
}

/** A short fingerprint for display: the first eight bytes, in pairs. */
export const shortFingerprint = (sha: string) => (sha.match(/.{2}/g) ?? []).slice(0, 8).join(":");

/** Reads a chosen file as text (the file never leaves the browser except as the pasted text of a save). */
export function readPemFile(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result ?? ""));
    r.onerror = () => reject(r.error ?? new Error("The file couldn't be read."));
    r.readAsText(file);
  });
}
