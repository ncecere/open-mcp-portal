-- +goose Up
-- Expand only: older code can read the schema, but does NOT enforce expiry.
-- Drain older serving binaries before creating any expiring gateway grant.
ALTER TABLE public.gateway_grants ADD COLUMN expires_at timestamptz;
ALTER TABLE public.gateway_grants ADD CONSTRAINT gateway_grant_expiry_finite
    CHECK (expires_at IS NULL OR isfinite(expires_at));
CREATE INDEX gateway_grants_expiry ON public.gateway_grants(expires_at, id)
    WHERE expires_at IS NOT NULL;

-- Expiry changes are authority changes, just like scope/subject changes. Keep
-- the existing journal/fence implementation and owner-only trigger function.
DROP TRIGGER approval_authority_changed ON public.gateway_grants;
CREATE TRIGGER approval_authority_changed AFTER INSERT OR UPDATE OR DELETE ON public.gateway_grants
    FOR EACH ROW EXECUTE FUNCTION omp_private.approval_authority_changed(
        'id','gateway_id','subject_kind','team_id','user_id','group_name','tool_scope','expires_at');

-- +goose Down
-- Forward-only. Dropping expiry would silently turn temporary grants permanent.
SELECT 1;
