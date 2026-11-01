-- +goose Up
-- Decision 92, independent security review fixes.
--
-- F2: owner promotion held TEAM and then waited for the per-person
-- directory-protection lock, while adoption/enrollment held that lock and then
-- waited for TEAM in group reconciliation: a deadlock. Promotion now only tries
-- the lock and refuses at once while a directory change for that person is in
-- progress, so it never waits while holding a team.
--
-- F3: a status-only write (as previous binaries make for a manual decision)
-- that did not change the effective value, for example suspending someone the
-- directory had already suspended, was not recorded as manual standing, so a
-- later directory reactivation lifted it. A column-specific trigger now records
-- every explicit status write as manual standing. It fires only when status is
-- in the SET list, before the derivation trigger (BEFORE triggers run in name
-- order), and leaves writers that set manual_status or directory_standing
-- themselves alone.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.team_member_directory_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    standing text;
BEGIN
    IF NEW.role = 'owner' AND (TG_OP = 'INSERT' OR OLD.role IS DISTINCT FROM 'owner') THEN
        IF NOT pg_try_advisory_xact_lock(hashtextextended('omp-directory-protect:' || NEW.user_id::text, 0)) THEN
            RAISE EXCEPTION 'provisioning is changing this person; try again'
                USING ERRCODE = '23514', CONSTRAINT = 'team_members_directory_busy';
        END IF;
        SELECT u.directory_standing INTO standing FROM public.users u WHERE u.id = NEW.user_id;
        IF standing IS NOT NULL AND standing <> 'none' THEN
            RAISE EXCEPTION 'directory managed people cannot become team owners'
                USING ERRCODE = '23514', CONSTRAINT = 'team_members_directory_protected_owner';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.role IS DISTINCT FROM OLD.role
       AND current_setting('omp.directory_writer', true) IS DISTINCT FROM 'on' THEN
        DELETE FROM public.directory_team_memberships d WHERE d.team_id = NEW.team_id AND d.user_id = NEW.user_id;
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.user_status_write_is_manual() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.manual_status IS NOT DISTINCT FROM OLD.manual_status
       AND NEW.directory_standing IS NOT DISTINCT FROM OLD.directory_standing THEN
        NEW.manual_status := NEW.status;
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.user_status_write_is_manual() FROM PUBLIC;
-- "user_access_0..." sorts before "user_access_effective".
CREATE TRIGGER user_access_0_status_write BEFORE UPDATE OF status ON public.users
    FOR EACH ROW EXECUTE FUNCTION public.user_status_write_is_manual();

-- +goose Down
SELECT 1;
