-- +goose Up
-- Signed outbound identity includes email, and upstreams may authorize by it.
-- An email-only login update must invalidate exact-call approvals, including
-- a change-and-revert, without treating unchanged profile touches as authority.
DROP TRIGGER approval_authority_changed ON public.users;
CREATE TRIGGER approval_authority_changed AFTER INSERT OR UPDATE OR DELETE ON public.users
    FOR EACH ROW EXECUTE FUNCTION public.approval_authority_changed('id','status','platform_role','groups','email');

-- +goose Down
-- Forward-only: removing email coverage would resurrect stale authority.
SELECT 1;
