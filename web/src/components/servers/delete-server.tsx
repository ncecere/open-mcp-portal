/* The Danger zone of a server's Settings tab: Delete (owners and admins), after a confirmation. */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { api, unwrap } from "../../api/client";
import { ConfirmMutationDialog } from "../confirm-dialog";
import { DangerAction, DangerZone } from "../templates/settings-page";
import { Button } from "@/components/ui/button/button";
import { toast } from "@/components/ui/toast/toast";
import { invalidateServer } from "./scope";
import type { McpServer } from "./labels";

export function DeleteServer({ server }: { server: McpServer }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [confirming, setConfirming] = useState<McpServer | null>(null);
  const del = useMutation({
    mutationFn: async () => unwrap(await api.DELETE("/v1/teams/{team}/mcp-servers/{serverId}", { params: { path: { team: server.teamSlug, serverId: server.id } } })),
    onSuccess: () => {
      setConfirming(null);
      toast.success(`${server.name} was deleted`);
      // Leave first: the record would load again and find nothing.
      void navigate({ to: "/teams/$team/servers", params: { team: server.teamSlug }, replace: true }).then(() => invalidateServer(qc, server));
    },
  });
  return (
    <DangerZone>
      <DangerAction
        title="Delete this server"
        description={`Removes ${server.name} and everything read from it${server.publishState === "published" ? ", and takes it off the catalog" : ""}. This can't be undone.`}
        action={
          <Button variant="danger" onClick={() => setConfirming(server)}>
            Delete server
          </Button>
        }
      />
      <ConfirmMutationDialog
        target={confirming}
        onClose={() => setConfirming(null)}
        mutation={del}
        onConfirm={() => del.mutate()}
        title={`Delete ${server.name}?`}
        description="Its capabilities, health checks and catalog entry are deleted. Its slug becomes free for another server."
        confirmLabel="Delete server"
      />
    </DangerZone>
  );
}
