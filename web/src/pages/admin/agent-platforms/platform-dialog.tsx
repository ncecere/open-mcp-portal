/*
 * Trust a platform, or edit one: its name, its issuer (the iss of its tokens, exactly as it writes it), where it
 * publishes its keys (default <issuer>/.well-known/mcp-identity-jwks.json) and the audience a token must name
 * (default this portal's address, which the platform sets as its server's identityAudience). The server has the
 * last word: invalid_issuer, url_not_allowed, name_taken, issuer_taken.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError } from "@/api/client";
import { FormDialog } from "@/components/form-dialog";
import { V02ErrorAlert } from "@/components/errors";
import { Field } from "@/components/ui/field/field";
import { Input } from "@/components/ui/input/input";
import { toast } from "@/components/ui/toast/toast";
import { type AgentPlatform, createPlatform, issuerProblem, maxName, maxUrl, platformsKey, updatePlatform } from "./api";

/** What the server refused, on the field it is about. */
function refusal(err: unknown): { field: "name" | "issuer" | "jwksUrl" | "audience"; message: string } | undefined {
  if (!(err instanceof ApiError)) return undefined;
  switch (err.code) {
    case "name_taken":
      return { field: "name", message: "Another platform has this name." };
    case "invalid_name":
      return { field: "name", message: `Use 1-${maxName} characters on one line.` };
    case "issuer_taken":
      return { field: "issuer", message: "This issuer is already trusted." };
    case "invalid_issuer":
      return { field: "issuer", message: err.message };
    case "invalid_audience":
      return { field: "audience", message: err.message };
    case "url_not_allowed":
      return { field: "jwksUrl", message: err.message };
  }
  return undefined;
}

export function PlatformDialog({ platform, onClose }: { platform?: AgentPlatform; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(platform?.name ?? "");
  const [issuer, setIssuer] = useState(platform?.issuer ?? "");
  const [jwksUrl, setJwksUrl] = useState(platform?.jwksUrl ?? "");
  const [audience, setAudience] = useState(platform?.audience ?? "");
  const [submitted, setSubmitted] = useState(false);
  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), issuer: issuer.trim(), jwksUrl: jwksUrl.trim(), audience: audience.trim() };
      return platform ? updatePlatform(platform, body) : createPlatform({ ...body, jwksUrl: body.jwksUrl || undefined, audience: body.audience || undefined, enabled: true });
    },
    onSuccess: (p) => {
      toast.success(platform ? `${p.name} was saved` : `${p.name} is trusted`, platform ? undefined : "Mark a service account as its relay, then test the keys.");
      onClose();
    },
    onSettled: () => void qc.invalidateQueries({ queryKey: platformsKey }),
  });
  const refused = refusal(save.error);
  const problems: Partial<Record<"name" | "issuer" | "jwksUrl" | "audience", string | undefined>> = {
    name: !name.trim() ? "Enter a name." : name.trim().length > maxName ? `Use at most ${maxName} characters.` : undefined,
    issuer: issuerProblem(issuer),
  };
  const shown = (field: "name" | "issuer" | "jwksUrl" | "audience") => (submitted ? problems[field] : undefined) ?? (refused?.field === field ? refused.message : undefined);
  const edit = (set: (v: string) => void) => (e: { target: { value: string } }) => {
    if (save.error) save.reset();
    set(e.target.value);
  };
  return (
    <FormDialog
      title={platform ? `Edit ${platform.name}` : "Trust an agent platform"}
      description="The portal accepts this platform's signed identity tokens from service accounts you mark as its relays."
      onClose={onClose}
      onSubmit={() => {
        setSubmitted(true);
        if (!problems.name && !problems.issuer) save.mutate();
      }}
      submitLabel={platform ? "Save" : "Trust platform"}
      busy={save.isPending}
      formProps={{ noValidate: true }}
    >
      <Field label="Name" error={shown("name")}>
        <Input autoComplete="off" maxLength={maxName} value={name} onChange={edit(setName)} />
      </Field>
      <Field
        label="Issuer"
        description="The platform's own address (its APP_URL), exactly as it writes it in a token's iss claim: an https address without a path query or fragment."
        error={shown("issuer")}
      >
        <Input autoComplete="off" spellCheck={false} inputMode="url" maxLength={maxUrl} value={issuer} onChange={edit(setIssuer)} />
      </Field>
      <Field
        label="Keys address (JWKS URL)"
        labelHint="Optional"
        description="Where the platform publishes its public keys. Default: the issuer followed by /.well-known/mcp-identity-jwks.json. An internal address needs an entry in Admin › Internal networks."
        error={shown("jwksUrl")}
      >
        <Input autoComplete="off" spellCheck={false} inputMode="url" maxLength={maxUrl} value={jwksUrl} onChange={edit(setJwksUrl)} />
      </Field>
      <Field
        label="Audience"
        labelHint="Optional"
        description="What a token's aud must contain. Default: this portal's address. Set the same value as the platform's identityAudience for the portal's gateways."
        error={shown("audience")}
      >
        <Input autoComplete="off" spellCheck={false} maxLength={maxUrl} value={audience} onChange={edit(setAudience)} />
      </Field>
      <V02ErrorAlert error={refused ? undefined : save.error} title="Couldn't save the platform" />
    </FormDialog>
  );
}
