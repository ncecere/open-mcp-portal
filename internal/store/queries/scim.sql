-- SCIM provisioning (decision 92, docs/scim.md). Lock order everywhere:
-- directory -> scim_user/scim_group -> users -> teams (sorted) -> members.

-- name: GetSCIMDirectory :one
SELECT * FROM scim_directories LIMIT 1;

-- name: LockSCIMDirectoryShare :one
-- Sign-in reads policy under SHARE so a concurrent policy change serialises.
SELECT * FROM scim_directories LIMIT 1 FOR SHARE;

-- name: LockSCIMDirectory :one
SELECT * FROM scim_directories LIMIT 1 FOR UPDATE;

-- name: InsertSCIMDirectory :one
INSERT INTO scim_directories (issuer, enabled, enrollment, created_by)
VALUES (@issuer, @enabled, @enrollment, @created_by)
RETURNING *;

-- name: UpdateSCIMDirectory :one
UPDATE scim_directories
SET enabled = @enabled, enrollment = @enrollment, revision = revision + 1, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: InsertSCIMToken :one
INSERT INTO scim_tokens (directory_id, name, prefix, digest, pepper_id, created_by, created_by_name, expires_at)
VALUES (@directory_id, @name, @prefix, @digest, @pepper_id, @created_by, @created_by_name, now() + make_interval(days => @days::int))
RETURNING *;

-- name: ListSCIMTokens :many
SELECT * FROM scim_tokens WHERE directory_id = @directory_id ORDER BY created_at DESC, id DESC;

-- name: CountActiveSCIMTokens :one
SELECT count(*)::bigint FROM scim_tokens
WHERE directory_id = @directory_id AND revoked_at IS NULL AND expires_at > now();

-- name: GetSCIMToken :one
SELECT * FROM scim_tokens WHERE id = @id AND directory_id = @directory_id;

-- name: RevokeSCIMToken :one
UPDATE scim_tokens SET revoked_at = now(), revoked_by = @revoked_by
WHERE id = @id AND revoked_at IS NULL
RETURNING *;

-- name: GetSCIMTokenByDigest :one
SELECT sqlc.embed(t), d.enabled AS directory_enabled
FROM scim_tokens t JOIN scim_directories d ON d.id = t.directory_id
WHERE t.digest = @digest;

-- name: TouchSCIMToken :exec
UPDATE scim_tokens SET last_used_at = now()
WHERE id = @id AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');

-- name: RehashSCIMToken :execrows
UPDATE scim_tokens SET digest = @digest, pepper_id = @pepper_id WHERE id = @id AND digest = @old_digest;

-- name: InsertSCIMUser :one
INSERT INTO scim_users (directory_id, user_name, external_id, active, display_name, given_name, family_name, email)
VALUES (@directory_id, @user_name, @external_id, @active, @display_name, @given_name, @family_name, @email)
RETURNING *;

-- name: GetSCIMUser :one
SELECT * FROM scim_users WHERE id = @id AND directory_id = @directory_id;

-- name: LockSCIMUser :one
SELECT * FROM scim_users WHERE id = @id AND directory_id = @directory_id FOR UPDATE;

-- name: UpdateSCIMUser :one
UPDATE scim_users
SET user_name = @user_name, external_id = @external_id, active = @active, display_name = @display_name,
    given_name = @given_name, family_name = @family_name, email = @email,
    version = version + 1, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteSCIMUser :exec
DELETE FROM scim_users WHERE id = @id;

-- name: ListSCIMUsers :many
SELECT * FROM scim_users
WHERE directory_id = @directory_id
  AND (sqlc.narg(user_name)::text IS NULL OR lower(user_name) = lower(sqlc.narg(user_name)::text))
  AND (sqlc.narg(external_id)::text IS NULL OR external_id = sqlc.narg(external_id)::text)
ORDER BY created_at, id
OFFSET @skip LIMIT @page_size;

-- name: CountSCIMUsers :one
SELECT count(*)::bigint FROM scim_users
WHERE directory_id = @directory_id
  AND (sqlc.narg(user_name)::text IS NULL OR lower(user_name) = lower(sqlc.narg(user_name)::text))
  AND (sqlc.narg(external_id)::text IS NULL OR external_id = sqlc.narg(external_id)::text);

-- name: LockEnrollmentCandidates :many
-- Unlinked resources whose externalId equals a verified subject. Locked so a
-- concurrent deactivate/delete serialises with the enrolling sign-in.
SELECT * FROM scim_users
WHERE directory_id = @directory_id AND external_id = @subject AND linked_user_id IS NULL
ORDER BY id LIMIT 2 FOR UPDATE;

-- name: LinkSCIMUser :one
UPDATE scim_users SET linked_user_id = @user_id, updated_at = now()
WHERE id = @id AND linked_user_id IS NULL
RETURNING *;

-- name: UnlinkSCIMUser :exec
UPDATE scim_users SET linked_user_id = NULL, updated_at = now() WHERE id = @id;

-- name: GetUserByIdentity :one
SELECT * FROM users WHERE oidc_issuer = @oidc_issuer AND oidc_subject = @oidc_subject;

-- name: SetDirectoryStanding :one
-- users.status is derived by the user_access_effective trigger.
UPDATE users SET directory_standing = @directory_standing, revision = revision + 1, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: ListSCIMUsersAdmin :many
SELECT sqlc.embed(s),
       lu.email AS linked_email, lu.display_name AS linked_display_name, lu.status AS linked_status,
       lu.directory_standing AS linked_standing,
       cu.id AS candidate_user_id, cu.email AS candidate_email, cu.directory_standing AS candidate_standing,
       cu.platform_role AS candidate_platform_role,
       EXISTS (SELECT 1 FROM team_members m WHERE m.user_id = cu.id AND m.role = 'owner') AS candidate_is_owner,
       EXISTS (SELECT 1 FROM directory_cleanup_jobs j WHERE j.user_id = cu.id AND j.completed_at IS NULL) AS candidate_cleanup_pending
FROM scim_users s
JOIN scim_directories d ON d.id = s.directory_id
LEFT JOIN users lu ON lu.id = s.linked_user_id
LEFT JOIN users cu ON s.linked_user_id IS NULL AND s.external_id IS NOT NULL
     AND cu.oidc_issuer = d.issuer AND cu.oidc_subject = s.external_id
WHERE s.directory_id = @directory_id
  AND (sqlc.narg(after_id)::uuid IS NULL OR s.id > sqlc.narg(after_id)::uuid)
ORDER BY s.id
LIMIT @page_size;

-- name: ListDirectoryManagedUsers :many
-- Portal people under directory control, including deleted lives (no
-- remaining SCIM resource), for the admin view.
SELECT u.id, u.email, u.display_name, u.status, u.manual_status, u.directory_standing,
       s.id AS scim_user_id,
       EXISTS (SELECT 1 FROM directory_cleanup_jobs j WHERE j.user_id = u.id AND j.completed_at IS NULL) AS cleanup_pending
FROM users u LEFT JOIN scim_users s ON s.linked_user_id = u.id
WHERE u.directory_standing <> 'none'
ORDER BY u.email, u.id
LIMIT 500;

-- name: GetSCIMUserByLinkedUser :one
SELECT * FROM scim_users WHERE linked_user_id = @user_id;

-- name: InsertSCIMGroup :one
INSERT INTO scim_groups (directory_id, display_name, external_id)
VALUES (@directory_id, @display_name, @external_id)
RETURNING *;

-- name: GetSCIMGroup :one
SELECT * FROM scim_groups WHERE id = @id AND directory_id = @directory_id;

-- name: LockSCIMGroup :one
SELECT * FROM scim_groups WHERE id = @id AND directory_id = @directory_id FOR UPDATE;

-- name: UpdateSCIMGroup :one
UPDATE scim_groups SET display_name = @display_name, external_id = @external_id, version = version + 1, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: TouchSCIMGroup :one
UPDATE scim_groups SET version = version + 1, updated_at = now() WHERE id = @id RETURNING *;

-- name: DeleteSCIMGroup :exec
DELETE FROM scim_groups WHERE id = @id;

-- name: ListSCIMGroups :many
SELECT * FROM scim_groups
WHERE directory_id = @directory_id
  AND (sqlc.narg(display_name)::text IS NULL OR lower(display_name) = lower(sqlc.narg(display_name)::text))
  AND (sqlc.narg(external_id)::text IS NULL OR external_id = sqlc.narg(external_id)::text)
ORDER BY created_at, id
OFFSET @skip LIMIT @page_size;

-- name: CountSCIMGroups :one
SELECT count(*)::bigint FROM scim_groups
WHERE directory_id = @directory_id
  AND (sqlc.narg(display_name)::text IS NULL OR lower(display_name) = lower(sqlc.narg(display_name)::text))
  AND (sqlc.narg(external_id)::text IS NULL OR external_id = sqlc.narg(external_id)::text);

-- name: ListSCIMGroupMembers :many
SELECT gm.group_id, s.id, s.user_name, s.display_name
FROM scim_group_members gm JOIN scim_users s ON s.id = gm.scim_user_id
WHERE gm.group_id = ANY(@group_ids::uuid[])
ORDER BY gm.group_id, s.id;

-- name: ListSCIMUserGroups :many
SELECT gm.scim_user_id, g.id, g.display_name
FROM scim_group_members gm JOIN scim_groups g ON g.id = gm.group_id
WHERE gm.scim_user_id = ANY(@user_ids::uuid[])
ORDER BY gm.scim_user_id, g.id;

-- name: CountExistingSCIMUsers :one
SELECT count(*)::bigint FROM scim_users WHERE directory_id = @directory_id AND id = ANY(@ids::uuid[]);

-- name: AddSCIMGroupMembers :many
INSERT INTO scim_group_members (group_id, scim_user_id)
SELECT @group_id, s.id FROM scim_users s
WHERE s.directory_id = @directory_id AND s.id = ANY(@ids::uuid[])
ON CONFLICT DO NOTHING
RETURNING scim_user_id;

-- name: RemoveSCIMGroupMembers :many
DELETE FROM scim_group_members WHERE group_id = @group_id AND scim_user_id = ANY(@ids::uuid[])
RETURNING scim_user_id;

-- name: RemoveAllSCIMGroupMembers :many
DELETE FROM scim_group_members WHERE group_id = @group_id RETURNING scim_user_id;

-- name: InsertSCIMGroupMapping :one
INSERT INTO scim_group_mappings (group_id, team_id, role, created_by)
VALUES (@group_id, @team_id, @role, @created_by)
RETURNING *;

-- name: GetSCIMGroupMapping :one
SELECT * FROM scim_group_mappings WHERE id = @id;

-- name: DeleteSCIMGroupMapping :exec
DELETE FROM scim_group_mappings WHERE id = @id;

-- name: ListSCIMGroupMappings :many
SELECT sqlc.embed(m), g.display_name AS group_name, t.slug AS team_slug, t.name AS team_name,
       (SELECT count(*) FROM scim_group_members gm WHERE gm.group_id = g.id)::bigint AS member_count
FROM scim_group_mappings m
JOIN scim_groups g ON g.id = m.group_id
JOIN teams t ON t.id = m.team_id
ORDER BY g.display_name, t.name, m.id;

-- name: ListSCIMGroupsAdmin :many
SELECT g.id, g.display_name, g.external_id,
       (SELECT count(*) FROM scim_group_members gm WHERE gm.group_id = g.id)::bigint AS member_count
FROM scim_groups g WHERE g.directory_id = @directory_id
ORDER BY lower(g.display_name), g.id
LIMIT 500;

-- name: SCIMMembersOfGroup :many
SELECT s.id FROM scim_group_members gm JOIN scim_users s ON s.id = gm.scim_user_id
WHERE gm.group_id = @group_id;

-- name: DirectoryDesiredMemberships :many
-- The directory-derived team role per (team, person): the highest mapped role
-- among the person's groups. Only linked people, never deleted lives.
SELECT m.team_id, su.linked_user_id::uuid AS user_id,
       (ARRAY['member', 'editor', 'admin'])[max(CASE m.role WHEN 'admin' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END)]::text AS role
FROM scim_group_mappings m
JOIN scim_group_members gm ON gm.group_id = m.group_id
JOIN scim_users su ON su.id = gm.scim_user_id
JOIN users u ON u.id = su.linked_user_id
WHERE su.linked_user_id = ANY(@user_ids::uuid[]) AND u.directory_standing IN ('active', 'inactive')
GROUP BY m.team_id, su.linked_user_id;

-- name: DirectoryOwnedMemberships :many
SELECT dm.team_id, dm.user_id, tm.role
FROM directory_team_memberships dm
JOIN team_members tm ON tm.team_id = dm.team_id AND tm.user_id = dm.user_id
WHERE dm.user_id = ANY(@user_ids::uuid[]);

-- name: ExistingMemberships :many
SELECT team_id, user_id, role FROM team_members
WHERE user_id = ANY(@user_ids::uuid[]) AND team_id = ANY(@team_ids::uuid[]);

-- name: LinkedUsersOf :many
SELECT linked_user_id::uuid FROM scim_users WHERE id = ANY(@ids::uuid[]) AND linked_user_id IS NOT NULL;

-- name: ReleaseDirectoryMemberships :exec
-- Unlinking hands directory-created memberships to manual control.
DELETE FROM directory_team_memberships WHERE user_id = @user_id;

-- name: MarkDirectoryWriter :exec
SELECT set_config('omp.directory_writer', 'on', true);

-- name: InsertDirectoryMembership :execrows
WITH ins AS (
    INSERT INTO team_members (team_id, user_id, role)
    SELECT @team_id, @user_id, @role
    WHERE EXISTS (SELECT 1 FROM teams t WHERE t.id = @team_id AND t.status = 'active')
    ON CONFLICT DO NOTHING
    RETURNING team_id, user_id
)
INSERT INTO directory_team_memberships (team_id, user_id) SELECT team_id, user_id FROM ins;

-- name: UpdateDirectoryMembershipRole :execrows
UPDATE team_members tm SET role = @role, revision = revision + 1, updated_at = now()
WHERE tm.team_id = @team_id AND tm.user_id = @user_id AND tm.role <> @role
  AND EXISTS (SELECT 1 FROM directory_team_memberships dm WHERE dm.team_id = tm.team_id AND dm.user_id = tm.user_id);

-- name: DeleteDirectoryMembership :execrows
DELETE FROM team_members tm
WHERE tm.team_id = @team_id AND tm.user_id = @user_id
  AND EXISTS (SELECT 1 FROM directory_team_memberships dm WHERE dm.team_id = tm.team_id AND dm.user_id = tm.user_id);

-- name: InsertDirectoryCleanupJob :exec
INSERT INTO directory_cleanup_jobs (user_id) VALUES (@user_id)
ON CONFLICT (user_id) WHERE completed_at IS NULL DO NOTHING;

-- name: ListOpenDirectoryCleanupJobs :many
SELECT * FROM directory_cleanup_jobs WHERE completed_at IS NULL ORDER BY created_at, id LIMIT @page_size;

-- name: LockDirectoryCleanupJob :one
SELECT * FROM directory_cleanup_jobs WHERE id = @id AND completed_at IS NULL FOR UPDATE SKIP LOCKED;

-- name: RecordDirectoryCleanupAttempt :exec
UPDATE directory_cleanup_jobs SET attempts = attempts + 1, last_error = @last_error WHERE id = @id;

-- name: CompleteDirectoryCleanupJob :exec
UPDATE directory_cleanup_jobs SET completed_at = now(), attempts = attempts + 1, last_error = NULL WHERE id = @id;

-- name: CleanupDeletedUserCredentials :one
-- One bounded pass over a deleted directory life's personal artifacts.
-- Audit/call history is kept; team-owned credentials are not touched.
WITH s AS (DELETE FROM sessions WHERE user_id = sqlc.arg(target)::uuid RETURNING 1),
     pa AS (DELETE FROM provider_auth_states WHERE user_id = sqlc.arg(target)::uuid RETURNING 1),
     sa AS (DELETE FROM service_connection_auth_states WHERE user_id = sqlc.arg(target)::uuid RETURNING 1),
     k AS (UPDATE api_keys SET revoked_at = now() WHERE user_id = sqlc.arg(target)::uuid AND revoked_at IS NULL RETURNING 1),
     og AS (DELETE FROM oauth_grants WHERE user_id = sqlc.arg(target)::uuid RETURNING 1),
     pc AS (DELETE FROM provider_connections WHERE user_id = sqlc.arg(target)::uuid RETURNING 1),
     pr AS (DELETE FROM provider_connect_requests WHERE user_id = sqlc.arg(target)::uuid RETURNING 1),
     ps AS (DELETE FROM person_secrets WHERE user_id = sqlc.arg(target)::uuid RETURNING 1),
     sr AS (DELETE FROM secret_requests WHERE user_id = sqlc.arg(target)::uuid RETURNING 1),
     tm AS (DELETE FROM team_members WHERE user_id = sqlc.arg(target)::uuid RETURNING 1),
     gg AS (DELETE FROM gateway_grants WHERE user_id = sqlc.arg(target)::uuid RETURNING 1)
SELECT (SELECT count(*) FROM s)::bigint AS sessions, (SELECT count(*) FROM k)::bigint AS api_keys,
       (SELECT count(*) FROM og)::bigint AS oauth_grants, (SELECT count(*) FROM pc)::bigint AS provider_connections,
       (SELECT count(*) FROM ps)::bigint AS person_secrets, (SELECT count(*) FROM tm)::bigint AS memberships,
       (SELECT count(*) FROM gg)::bigint AS gateway_grants,
       ((SELECT count(*) FROM pa) + (SELECT count(*) FROM sa) + (SELECT count(*) FROM pr) + (SELECT count(*) FROM sr))::bigint AS pending_flows;

-- name: CountDeletedUserArtifacts :one
-- The stable recount under the user row lock: zero means complete.
SELECT ((SELECT count(*) FROM sessions WHERE user_id = sqlc.arg(target)::uuid)
      + (SELECT count(*) FROM provider_auth_states WHERE user_id = sqlc.arg(target)::uuid)
      + (SELECT count(*) FROM service_connection_auth_states WHERE user_id = sqlc.arg(target)::uuid)
      + (SELECT count(*) FROM api_keys WHERE user_id = sqlc.arg(target)::uuid AND revoked_at IS NULL)
      + (SELECT count(*) FROM oauth_grants WHERE user_id = sqlc.arg(target)::uuid)
      + (SELECT count(*) FROM provider_connections WHERE user_id = sqlc.arg(target)::uuid)
      + (SELECT count(*) FROM provider_connect_requests WHERE user_id = sqlc.arg(target)::uuid)
      + (SELECT count(*) FROM person_secrets WHERE user_id = sqlc.arg(target)::uuid)
      + (SELECT count(*) FROM secret_requests WHERE user_id = sqlc.arg(target)::uuid)
      + (SELECT count(*) FROM team_members WHERE user_id = sqlc.arg(target)::uuid)
      + (SELECT count(*) FROM gateway_grants WHERE user_id = sqlc.arg(target)::uuid))::bigint;

-- name: SetCleanupLockTimeout :exec
SELECT set_config('lock_timeout', '2s', true);
