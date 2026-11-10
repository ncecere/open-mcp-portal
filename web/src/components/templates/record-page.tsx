/*
 * RecordPage (D4, revised 2026-09-28): a leaf record (document, key, domain
 * request, audit entry, crawl run, model, connection, profile, hold…) opens
 * as a page of its own over its list, not in a side sheet. The open record
 * is ?record=<id>, so the page can be linked to, opening it adds a history
 * entry, and Back (the browser's, the back link or the breadcrumb) closes it.
 *
 *   const record = useRecordParam();
 *   <ListPage … onRowClick={(d) => record.open(d.id)} rowActions={(d) => [{ label: "View details", onSelect: () => record.open(d.id) }]} />
 *   <RecordPage open={!!record.id} onClose={record.close} title={doc?.title ?? "Document"}
 *     description="A document in this source." facts={[{ label: "Status", value: <DocStatus … /> }]}
 *     sections={[{ title: "Passages", content: <PassageList … /> }]}
 *     actions={<><Button variant="danger">Delete</Button><Button>Re-fetch</Button></>}
 *     loading={doc.isLoading} error={doc.error} />
 */
import { useNavigate, useRouter } from "@tanstack/react-router";
import { useCallback, type ReactNode } from "react";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { isNotFound } from "../not-found";
import { Card } from "@/components/ui/card/card";
import { type DescriptionEntry, DescriptionList } from "@/components/ui/description-list/description-list";
import { SkeletonText } from "@/components/ui/skeleton/skeleton";
import { useSearchParams } from "@/lib/url-search";
import { useCloseGuard } from "./close-guard";
import { TakeoverPage } from "./takeover";

/** The URL parameter of the open record. */
export const RECORD_PARAM = "record";

/**
 * The open record's id (?record=), `open(id)` (pushes a history entry) and
 * `close()` (goes back when the page was opened here, so Back and × agree;
 * otherwise removes the parameter).
 */
export function useRecordParam(param = RECORD_PARAM) {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const router = useRouter();
  const id = params.get(param) ?? undefined;
  const open = useCallback(
    (next: string) => {
      setParams(
        (p) => {
          const out = new URLSearchParams(p);
          out.set(param, next);
          return out;
        },
        { replace: false },
      );
      openedHere.add(next);
    },
    [param, setParams],
  );
  const close = useCallback(() => {
    if (id && openedHere.has(id)) {
      openedHere.delete(id);
      // The router's history (the browser's in the app, a memory history in tests).
      router.history.back();
      return;
    }
    void navigate({ to: ".", search: ((prev: Record<string, unknown>) => ({ ...prev, [param]: undefined })) as never, replace: true });
  }, [id, navigate, param, router]);
  return { id, open, close };
}

// Records opened by open() in this page session (their history entry is ours to pop).
const openedHere = new Set<string>();

/** A titled card on a record page; `hidden` leaves it out (e.g. an action the viewer can't run). */
export type RecordSection = { title: ReactNode; content: ReactNode; id?: string; hidden?: boolean };

export type RecordPageProps = {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  /** Plain-text name for the breadcrumb, when `title` isn't a string. */
  label?: string;
  /** What the record is, under the title. */
  description: ReactNode;
  /** Status badges next to the title. */
  meta?: ReactNode;
  /** Key facts at the top, as a description list. */
  facts?: DescriptionEntry[];
  /** Titled sections under the facts (Passages, Error, Before/after…), each a card. */
  sections?: RecordSection[];
  /** Buttons in the header (destructive first, the main action last). */
  actions?: ReactNode;
  loading?: boolean;
  error?: unknown;
  /** Shown first, above the facts: why a header action is disabled or waiting (give the button aria-describedby its id). */
  notice?: ReactNode;
  /** Extra content after the sections. */
  children?: ReactNode;
  /**
   * The page holds unsaved edits: the back link and the breadcrumb ask
   * "Leave without saving?" first (m7).
   */
  dirty?: boolean;
  /** The back link's target when it isn't this page's list, e.g. the page that linked here ("Back to Costs"). */
  back?: { label: string; href: string };
  /** Its URL parameter, when not ?record= (a record opened from another record's page, e.g. ?result=). */
  param?: string;
};

export function RecordPage({ open, ...props }: RecordPageProps) {
  return open ? <OpenRecordPage {...props} /> : null;
}

function OpenRecordPage(props: Omit<RecordPageProps, "open">) {
  const { onClose, title, label, description, meta, facts, sections, actions, loading, error, notice, children, dirty = false, back, param = RECORD_PARAM } = props;
  const guard = useCloseGuard(dirty, onClose);
  const name = label ?? (typeof title === "string" ? title : "Details");
  return (
    <TakeoverPage param={param} label={name} title={title} meta={meta} description={description} actions={loading ? undefined : actions} onBack={guard.requestClose} back={back}>
      {Boolean(error) &&
        (isNotFound(error) ? (
          <Alert tone="warning" title="Not found.">
            It may have been deleted, or the link is wrong.
          </Alert>
        ) : (
          <ErrorAlert error={error} title="Couldn't load this record" />
        ))}
      {loading ? (
        <div role="status" aria-label="Loading…">
          <SkeletonText lines={4} />
        </div>
      ) : (
        <>
          {notice}
          {facts && facts.length > 0 && (
            <Card title="Details" titleAs="h2">
              <DescriptionList items={facts} dividers />
            </Card>
          )}
          {sections?.filter((sec) => !sec.hidden).map((sec, i) => (
            <Card key={sec.id ?? i} title={sec.title} titleAs="h2">
              {sec.content}
            </Card>
          ))}
          {children}
        </>
      )}
      {guard.dialog}
    </TakeoverPage>
  );
}
