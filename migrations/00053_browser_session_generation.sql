-- +goose Up
-- Decision91: old browser cookies must not regain authority after a reducing
-- fence merely because manual standing later becomes active. This counter is
-- NOT the request epoch, an enrollment/deletion life, or group-policy version.
-- New non-key columns only; no session enumeration/deletion/provider work in
-- the user-local fence. Existing rows start together at generation1.
ALTER TABLE public.users ADD COLUMN session_generation bigint NOT NULL DEFAULT 1
    CONSTRAINT users_session_generation_positive CHECK (session_generation > 0);
ALTER TABLE public.sessions ADD COLUMN session_generation bigint NOT NULL DEFAULT 1
    CONSTRAINT sessions_generation_positive CHECK (session_generation > 0);

-- Non-approval helpers belong outside the exact closed omp_private catalog.
-- +goose StatementBegin
CREATE FUNCTION public.advance_user_session_generation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.session_generation < OLD.session_generation THEN
        RAISE EXCEPTION 'browser session generation cannot decrease'
            USING ERRCODE = '23514', CONSTRAINT = 'users_session_generation_monotonic';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NEW.status = 'suspended' THEN
        NEW.session_generation := greatest(NEW.session_generation, OLD.session_generation + 1);
    END IF;
    IF NEW.session_generation IS DISTINCT FROM OLD.session_generation THEN
        -- Also fence requests authenticated by the ended cookie before the
        -- generation change. greatest avoids counting one status fence twice.
        NEW.request_epoch := greatest(NEW.request_epoch, OLD.request_epoch + 1);
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.advance_user_session_generation() FROM PUBLIC;
CREATE TRIGGER user_session_generation_advance BEFORE UPDATE ON public.users
    FOR EACH ROW EXECUTE FUNCTION public.advance_user_session_generation();

-- Existing request_epoch approval-journal coverage also covers every session
-- generation advance above. Preserve its exact fields/private helper boundary.
-- A session's captured generation cannot be rewritten to revive its cookie.
-- +goose StatementBegin
CREATE FUNCTION public.stamp_session_generation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    current_generation bigint;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.session_generation IS DISTINCT FROM OLD.session_generation THEN
            RAISE EXCEPTION 'captured browser session generation is immutable'
                USING ERRCODE = '23514', CONSTRAINT = 'sessions_generation_immutable';
        END IF;
        RETURN NEW;
    END IF;
    SELECT u.session_generation INTO current_generation FROM public.users u WHERE u.id = NEW.user_id;
    IF NOT FOUND THEN
        -- Leave nonexistent-user rejection to the existing FK. No row can be
        -- created for that identity, even for a legacy omitted-column insert.
        IF NEW.session_generation = 0 THEN NEW.session_generation := 1; END IF;
        RETURN NEW;
    END IF;
    IF NEW.session_generation = 0 THEN
        -- SQL omission by the previous binary only. New application admission
        -- must supply its captured positive value, never silently refresh it.
        NEW.session_generation := current_generation;
    ELSIF NEW.session_generation <> current_generation THEN
        RAISE EXCEPTION 'browser session generation changed'
            USING ERRCODE = '23514', CONSTRAINT = 'sessions_generation_current';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.stamp_session_generation() FROM PUBLIC;
CREATE TRIGGER session_generation_stamp BEFORE INSERT OR UPDATE ON public.sessions
    FOR EACH ROW EXECUTE FUNCTION public.stamp_session_generation();

-- Change only after the BEFORE INSERT bridge exists. Old SQL does not know
-- this column; old serving code still ignores its check and must be drained
-- before enforcement. Existing metadata-default rows remain generation1.
ALTER TABLE public.sessions ALTER COLUMN session_generation SET DEFAULT 0;

-- +goose Down
-- Forward-only: removing generations would revive previously ended cookies.
SELECT 1;
