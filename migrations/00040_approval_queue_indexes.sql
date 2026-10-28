-- +goose Up
-- Bound metadata queues filter requester or live pending context before their
-- keyset page. Keep unrelated retained history out of those access paths.
CREATE INDEX approval_requests_pending_queue ON public.approval_requests
    (context_epoch, created_at DESC, id DESC) WHERE status = 'pending';
CREATE INDEX approval_requests_requested_queue ON public.approval_requests
    (requester_kind, requester_id, created_at DESC, id DESC);

-- +goose Down
DROP INDEX public.approval_requests_requested_queue;
DROP INDEX public.approval_requests_pending_queue;
