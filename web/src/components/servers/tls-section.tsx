/*
 * "TLS to the server" in a server's Settings tab (decision 74): a private CA
 * that replaces the system roots for this server only, and a client
 * certificate with its private key for mTLS. Paste PEM text or choose a file
 * (read in the browser; nothing is uploaded until Save). The stored key is
 * never shown: only that there is one, and the certificates' fingerprints,
 * subjects, issuers and expiry. Verification and the host name check are
 * always on: there is nothing here to turn them off.
 */
import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { Alert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Field } from "@/components/ui/field/field";
import { Textarea } from "@/components/ui/input/input";
import { formatDate } from "../../lib/format";
import { SettingsSection } from "../templates/settings-page";
import type { McpServer } from "./labels";
import m from "./servers.module.css";
import { expiryText, maxKeyPem, maxPem, readPemFile, shortFingerprint, type TlsErrors, type TlsField, type TlsForm } from "./tls";

type Props = {
  server: McpServer;
  form: TlsForm;
  setForm: (patch: Partial<TlsForm>) => void;
  errors: TlsErrors;
  disabled?: boolean;
  /** The URL moves to another origin in the same save: the stored key and CA can't follow (F-1). */
  originMoved: boolean;
  /** Saving a changed CA sends this published server back to review. */
  reviewsCa: boolean;
};

const statusTone = { valid: "success", expiring: "warning", expired: "danger" } as const;

export function TlsSection({ server, form, setForm, errors, disabled, originMoved, reviewsCa }: Props) {
  const ca = server.tls?.ca;
  const client = server.tls?.client;
  const replacesClient = Boolean(form.clientCertPem.trim() && form.clientKeyPem.trim());
  return (
    <SettingsSection
      id="tls"
      title="TLS to the server"
      description="A private CA and a client certificate (mTLS) for this server only. The server's certificate and host name are always verified; there is no way to turn that off."
    >
      {ca && (
        <div className={m.part} aria-label="Stored CA">
          <div className={m.partHead}>
            <strong>
              <ShieldCheck aria-hidden /> Private CA: {ca.certificates.length === 1 ? "1 certificate" : `${ca.certificates.length} certificates`}
            </strong>
            {!disabled && (
              <Button variant="ghost" size="sm" onClick={() => setForm({ removeCa: !form.removeCa, caPem: "" })}>
                {form.removeCa ? "Keep the CA" : "Remove the CA"}
              </Button>
            )}
          </div>
          {form.removeCa ? (
            <p className={m.muted}>Removed when you save: the system&apos;s trusted roots apply to this server again.</p>
          ) : (
            <ul className={m.muted}>
              {ca.certificates.map((c) => (
                <li key={c.sha256}>
                  {c.subject} (fingerprint {shortFingerprint(c.sha256)}, expires {formatDate(c.notAfter)})
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {client && (
        <div className={m.part} aria-label="Stored client certificate">
          <div className={m.partHead}>
            <strong>
              <ShieldCheck aria-hidden /> Client certificate: {client.certificate.subject}
            </strong>
            <Badge tone={statusTone[client.status]}>{client.status === "valid" ? "Valid" : client.status === "expiring" ? "Expiring" : "Expired"}</Badge>
            {!disabled && (
              <Button variant="ghost" size="sm" onClick={() => setForm({ removeClient: !form.removeClient, clientCertPem: "", clientKeyPem: "" })}>
                {form.removeClient ? "Keep the certificate" : "Remove the certificate and key"}
              </Button>
            )}
          </div>
          {form.removeClient ? (
            <p className={m.muted}>Removed when you save, with its private key.</p>
          ) : (
            <p className={m.muted}>
              Issued by {client.certificate.issuer}. {expiryText(client)}. Fingerprint {shortFingerprint(client.certificate.sha256)}.{" "}
              {client.hasKey ? "The private key is stored encrypted and is never shown." : ""}
            </p>
          )}
        </div>
      )}
      {!disabled && (
        <>
          <PemField
            label={ca ? "Replace the CA certificates" : "CA certificates"}
            description="PEM, at most 10 certificates: the CA that signed the server's certificate, with any intermediates. It replaces the system roots for this server only."
            field="caPem"
            value={form.caPem}
            max={maxPem}
            error={errors.caPem}
            onChange={(caPem) => setForm({ caPem, removeCa: false })}
          />
          <PemField
            label={client ? "Replace the client certificate" : "Client certificate"}
            description="PEM, the certificate the portal presents first, then any intermediates. To renew it, paste only the new certificate: it must belong to the stored key."
            field="clientCertPem"
            value={form.clientCertPem}
            max={maxPem}
            error={errors.clientCertPem}
            onChange={(clientCertPem) => setForm({ clientCertPem, removeClient: false })}
          />
          <PemField
            label="Client private key"
            description="PEM, unencrypted (no passphrase). Stored encrypted and never shown again."
            field="clientKeyPem"
            value={form.clientKeyPem}
            max={maxKeyPem}
            error={errors.clientKeyPem}
            onChange={(clientKeyPem) => setForm({ clientKeyPem, removeClient: false })}
            secret
          />
        </>
      )}
      {originMoved && client && !form.removeClient && !replacesClient && (
        <Alert tone="warning" title="The new address needs the certificate again">
          The stored client key and CA were entered for the old host and never move to another one. Paste the client certificate and key (and the CA) for the new
          address, or remove them, before saving.
        </Alert>
      )}
      {originMoved && ca && !client && !form.caPem.trim() && (
        <Alert tone="info" title="The CA stays with the old address">
          Saving a new host drops the stored CA: paste it again if the new address uses the same private CA.
        </Alert>
      )}
      {reviewsCa && (
        <Alert tone="warning" title="The server will leave the catalog">
          The CA a server is trusted against is a trust setting. Your team needs approval to publish, so a new, changed or removed CA is reviewed again: once you save,{" "}
          {server.name} is out of the company catalog until a platform admin approves it. A new client certificate doesn&apos;t need a review.
        </Alert>
      )}
    </SettingsSection>
  );
}

function PemField({ label, description, field, value, max, error, onChange, secret }: {
  label: string;
  description: string;
  field: TlsField;
  value: string;
  max: number;
  error?: string;
  onChange: (v: string) => void;
  secret?: boolean;
}) {
  const [fileError, setFileError] = useState<string>();
  const choose = async (file?: File) => {
    setFileError(undefined);
    if (!file) return;
    if (file.size > max) {
      setFileError(`That file is larger than ${max / 1024} KiB.`);
      return;
    }
    try {
      onChange(await readPemFile(file));
    } catch {
      setFileError("The file couldn't be read.");
    }
  };
  return (
    <Field label={label} description={description} error={error ?? fileError}>
      <Textarea
        rows={secret ? 4 : 5}
        spellCheck={false}
        autoComplete="off"
        autoCapitalize="off"
        data-field={field}
        placeholder={secret ? "-----BEGIN PRIVATE KEY-----" : "-----BEGIN CERTIFICATE-----"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <input type="file" aria-label={`Choose a file for ${label.toLowerCase()}`} accept=".pem,.crt,.cer,.cert,.key,text/plain" onChange={(e) => void choose(e.target.files?.[0])} />
    </Field>
  );
}
