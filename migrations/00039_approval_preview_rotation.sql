-- +goose Up
-- Terminal previews remain unavailable through the application and may never
-- be restored after clearing. Permit resealing a retained non-NULL ciphertext
-- with the current encryption key; no status/binding/decision can change.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.approval_request_lifecycle() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' OR NEW.review_revision <> 1 OR NEW.decided_by IS NOT NULL
           OR NEW.decided_at IS NOT NULL OR NEW.valid_until IS NOT NULL THEN
            RAISE EXCEPTION 'approval request must begin pending';
        END IF;
        RETURN NEW;
    END IF;
    IF (to_jsonb(NEW) - ARRAY['status','review_revision','decided_by','decided_at','valid_until','used_at','terminal_at','preview_cipher'])
       IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['status','review_revision','decided_by','decided_at','valid_until','used_at','terminal_at','preview_cipher']) THEN
        RAISE EXCEPTION 'approval request binding is immutable';
    END IF;
    IF NEW.status = OLD.status THEN
        IF ROW(NEW.review_revision,NEW.decided_by,NEW.decided_at,NEW.valid_until,NEW.used_at,NEW.terminal_at)
           IS DISTINCT FROM ROW(OLD.review_revision,OLD.decided_by,OLD.decided_at,OLD.valid_until,OLD.used_at,OLD.terminal_at) THEN
            RAISE EXCEPTION 'approval decision is immutable without a transition';
        END IF;
    ELSIF NOT ((OLD.status = 'pending' AND NEW.status IN ('approved','denied','expired','cancelled'))
           OR (OLD.status = 'approved' AND NEW.status IN ('used','expired','cancelled')))
           OR NEW.review_revision <> OLD.review_revision + 1 THEN
        RAISE EXCEPTION 'invalid approval transition';
    END IF;
    IF OLD.status <> 'pending' AND ROW(NEW.decided_by,NEW.decided_at,NEW.valid_until)
       IS DISTINCT FROM ROW(OLD.decided_by,OLD.decided_at,OLD.valid_until) THEN
        RAISE EXCEPTION 'approval decision is immutable';
    END IF;
    IF OLD.status IN ('denied','expired','used','cancelled') AND OLD.preview_cipher IS NULL
       AND NEW.preview_cipher IS NOT NULL THEN
        RAISE EXCEPTION 'terminal preview cannot be restored';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.approval_request_lifecycle() FROM PUBLIC;

-- +goose Down
-- Forward-only; reverting would block rotation of retained terminal previews.
SELECT 1;
