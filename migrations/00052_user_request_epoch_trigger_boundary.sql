-- +goose Up
-- Forward correction of migration51, first applied in owned disposable tests.
-- omp_private is the exact closed approval-catalog boundary validated by the
-- previous release. A non-approval trigger helper must not add an unexpected
-- function there. Keep that boundary/allowlist unchanged; do not broaden grants.
--
-- ALTER preserves the function OID, ownership, ACL and the existing trigger's
-- dependency. The helper remains SECURITY INVOKER with its pinned search_path,
-- and is not a callable runtime interface. Final expanded compatibility is
-- schema52; schema51 alone correctly fails the existing split-role inspector.
ALTER FUNCTION omp_private.advance_user_request_epoch() SET SCHEMA public;
REVOKE ALL ON FUNCTION public.advance_user_request_epoch() FROM PUBLIC;

-- +goose Down
-- Forward-only: moving a non-approval helper back would break the preserved
-- private approval boundary and previous-release runtime safety checks.
SELECT 1;
