/*
 * Test the keys: fetches the platform's JWKS now, through the same guarded path a verification takes, and says what
 * came back: the key IDs and how long the portal keeps them, or why it failed. The result is also stored as the
 * platform's last fetch.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Dialog, DialogClose } from "@/components/ui/dialog/dialog";
import { Loading } from "@/components/ui/spinner/spinner";
import s from "../../shared.module.css";
import { type AgentPlatform, fetchErrorLabel, platformsKey, testPlatform } from "./api";

export function TestDialog({ platform, onClose }: { platform: AgentPlatform; onClose: () => void }) {
  const qc = useQueryClient();
  const test = useMutation({ mutationFn: () => testPlatform(platform), onSettled: () => void qc.invalidateQueries({ queryKey: platformsKey }) });
  const run = test.mutate;
  useEffect(() => {
    run();
  }, [run]);
  const r = test.data;
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={`Test the keys of ${platform.name}`}
      description={platform.jwksUrl}
      footer={
        <>
          <Button variant="secondary" loading={test.isPending} onClick={() => test.mutate()}>
            Test again
          </Button>
          <DialogClose>Close</DialogClose>
        </>
      }
    >
      {test.isPending && <Loading label="Fetching the keys…" />}
      <ErrorAlert error={test.error} title="Couldn't run the test" />
      {r?.ok && (
        <Alert tone="success" title="The keys were fetched">
          {r.keyIds.length === 1 ? "One usable key" : `${r.keyIds.length} usable keys`}: <span className={s.mono}>{r.keyIds.join(", ")}</span>. The portal keeps them for{" "}
          {r.cacheSeconds ?? 0} seconds, and fetches again when a token names a key it doesn&apos;t know. Took {r.latencyMs} ms.
        </Alert>
      )}
      {r && !r.ok && (
        <Alert tone="danger" title="The keys couldn't be fetched">
          {fetchErrorLabel(r.error, r.httpStatus)}
        </Alert>
      )}
    </Dialog>
  );
}
