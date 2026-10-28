/*
 * One capability's account requirement (editors and above, on the team's
 * server record): the server's (inherit), none (no token, never asks), or
 * other scopes of the server's provider. PUT …/capabilities/{id}/requirement
 * with If-Match on the server's revision. Under approval_required, a
 * published server goes back to review when the change widens what the
 * capability receives: the dialog says so before saving.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiError, ifMatch, unwrap } from "../../api/client";
import { authProvidersQuery } from "../../api/queries";
import { FormDialog } from "../form-dialog";
import { invalidScopeText, needsText, normalizeScope, type RequirementOverride, scopesProblem } from "../providers/labels";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Field } from "@/components/ui/field/field";
import { RadioGroup } from "@/components/ui/radio-group/radio-group";
import { TagInput } from "@/components/ui/tag-input/tag-input";
import { toast } from "@/components/ui/toast/toast";
import { describeAuthError } from "./auth-errors";
import type { McpCapability, McpServer } from "./labels";
import { effectiveScopes, overrideEffective, reviewedAgain, widens } from "./requirement";
import { capabilitiesQuery, invalidateServer, type ServerScope } from "./scope";

type Mode = RequirementOverride["mode"];

type Props = { cap: McpCapability; server: McpServer; scope: ServerScope & { kind: "team" }; onClose: () => void };

export function OverrideDialog({ cap, server, scope, onClose }: Props) {
  const qc = useQueryClient();
  const providers = useQuery(authProvidersQuery());
  const req = server.requirement!;
  const [mode, setMode] = useState<Mode>(cap.requirementOverride.mode);
  const [scopes, setScopes] = useState<string[]>(cap.requirementOverride.scopes ?? []);
  const [submitted, setSubmitted] = useState(false);
  const body: RequirementOverride = mode === "scopes" ? { mode, scopes } : { mode };
  const after = overrideEffective(body, server, providers.data);
  const before = cap.requires ? { providerId: cap.requires.providerId, scopes: cap.requires.scopes } : null;
  const leaves = reviewedAgain(server) && widens(before, after);
  const problem = mode === "scopes" ? (scopes.length === 0 ? "Enter at least one scope, or choose another option." : scopesProblem(scopes)) : undefined;
  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PUT("/v1/teams/{team}/mcp-servers/{serverId}/capabilities/{capabilityId}/requirement", {
          params: { path: { team: scope.team, serverId: server.id, capabilityId: cap.id }, header: ifMatch(server.revision) },
          body,
        }),
      ),
    onSuccess: (updated) => {
      qc.setQueryData<McpCapability[]>(capabilitiesQuery(scope, server.id).queryKey, (list) => list?.map((c) => (c.id === updated.id ? updated : c)));
      // The server's revision moved on (and it may have gone back to review).
      invalidateServer(qc, server);
      toast.success(
        updated.requires ? `${cap.name} ${needsText(updated.requires).replace(/^N/, "n")}` : `${cap.name} needs no account`,
        leaves ? `${server.name} left the catalog until a platform admin reviews what it now receives.` : undefined,
      );
      onClose();
    },
  });
  const refused = save.error instanceof ApiError && save.error.code === "invalid_scope" ? invalidScopeText(save.error.details) : undefined;
  const serverScopes = effectiveScopes(req.providerId, req.scopes, providers.data);
  return (
    <FormDialog
      title={`Account for ${cap.name}`}
      description={`Whether calls to ${cap.name} need the caller's ${req.providerName} account, and with which scopes.`}
      onClose={onClose}
      onSubmit={() => {
        setSubmitted(true);
        if (!problem) save.mutate();
      }}
      submitLabel="Save"
      busy={save.isPending}
      formProps={{ noValidate: true }}
    >
      <RadioGroup<Mode>
        legend="Requirement"
        value={mode}
        onValueChange={(m) => {
          if (save.error) save.reset();
          setMode(m);
          if (m === "scopes" && scopes.length === 0) setScopes(serverScopes);
        }}
        options={[
          {
            value: "inherit",
            label: "Same as the server",
            description: `${needsText({ providerName: req.providerName, scopes: serverScopes })}. Callers connect with the server's scopes, and each call sends their token to ${server.name}. Service accounts require an explicitly allowed team service connection.`,
          },
          {
            value: "none",
            label: "No account",
            description: `Callers are never asked to connect, and calls send no token to ${server.name}. Service accounts can use it.`,
          },
          {
            value: "scopes",
            label: `Other ${req.providerName} scopes`,
            description: `Callers connect with only the scopes below, and each call sends that token to ${server.name}. Service accounts require an explicitly allowed team service connection.`,
          },
        ]}
      />
      {mode === "scopes" && (
        <Field label="Scopes" description="The provider's own names; press Enter after each." error={(submitted ? problem : undefined) ?? refused}>
          <TagInput value={scopes} onValueChange={setScopes} normalize={normalizeScope} maxTags={50} maxTagLength={200} noun={{ one: "scope", other: "scopes" }} />
        </Field>
      )}
      {leaves && (
        <Alert tone="warning" title="The server will leave the catalog">
          Your team needs approval to publish, and this sends {cap.name} more than before, so it&apos;s reviewed again: once you save, {server.name} is out of the company
          catalog until a platform admin approves it.
        </Alert>
      )}
      <ErrorAlert
        error={refused ? undefined : save.error}
        title="Couldn't save the requirement"
        describe={(e) =>
          e instanceof ApiError && e.code === "no_server_requirement"
            ? { message: "The server no longer requires a connection, so a capability can't ask for its own scopes. Set the server's requirement in Settings first." }
            : describeAuthError(e)
        }
      />
    </FormDialog>
  );
}
