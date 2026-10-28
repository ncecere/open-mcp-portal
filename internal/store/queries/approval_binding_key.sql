-- name: EnsureApprovalBindingKey :one
SELECT public.omp_ensure_approval_binding_key(sqlc.arg(cipher)::bytea)::bytea;
