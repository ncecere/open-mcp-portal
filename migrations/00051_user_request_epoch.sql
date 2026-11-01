-- +goose Up
-- Decision90: admitted requests are not reusable credentials. Status/role
-- changes advance a dedicated epoch, including change-and-revert. Profile
-- revision is not this fence. Initial application use is personal key creation;
-- this migration implements no directory provisioning or lifecycle cleanup.
--
-- Expand/contract: old binaries omit/default the new column and keep working.
-- Their access writes also advance it through this trigger, but older serving
-- code does NOT enforce captured epochs. Drain it before claiming consistent
-- request fencing. No credential/ciphertext or existing identity is rewritten.
ALTER TABLE public.users
    ADD COLUMN request_epoch bigint NOT NULL DEFAULT 1
        CONSTRAINT users_request_epoch_positive CHECK (request_epoch > 0);

-- This is deliberately a non-key column without a unique index. The trigger
-- does not acquire another row/advisory lock or call a provider. Explicit
-- future lifecycle advances may increase it; no writer may decrease it.
-- +goose StatementBegin
CREATE FUNCTION omp_private.advance_user_request_epoch() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.request_epoch < OLD.request_epoch THEN
        RAISE EXCEPTION 'request authority epoch cannot decrease'
            USING ERRCODE = '23514', CONSTRAINT = 'users_request_epoch_monotonic';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status
       OR NEW.platform_role IS DISTINCT FROM OLD.platform_role THEN
        NEW.request_epoch := greatest(NEW.request_epoch, OLD.request_epoch + 1);
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION omp_private.advance_user_request_epoch() FROM PUBLIC;
CREATE TRIGGER user_request_epoch_advance BEFORE UPDATE ON public.users
    FOR EACH ROW EXECUTE FUNCTION omp_private.advance_user_request_epoch();

-- Preserve every existing authority input (including migration38's email)
-- and cover explicit epoch-only fences too. Reuse the private owner-definer
-- journal function; do not introduce a blocking lock after a resource write.
DROP TRIGGER approval_authority_changed ON public.users;
CREATE TRIGGER approval_authority_changed AFTER INSERT OR UPDATE OR DELETE ON public.users
    FOR EACH ROW EXECUTE FUNCTION omp_private.approval_authority_changed('id','status','platform_role','groups','email','request_epoch');

-- +goose Down
-- Forward-only: removing the epoch would erase the meaning of admitted
-- requests. The previous release tolerates the extra column and trigger.
SELECT 1;
