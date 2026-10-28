-- name: EnsureApprovalBindingKey :one
SELECT omp_private.omp_ensure_approval_binding_key(sqlc.arg(cipher)::bytea)::bytea;
