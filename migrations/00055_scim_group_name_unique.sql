-- +goose Up
-- Decision 92: a directory group's displayName is unique per directory,
-- ignoring case, like a user's userName. A client that sends the same group
-- twice concurrently (observed with authentik's automatic and manual sync)
-- gets 409 uniqueness for the second instead of a duplicate group, so a
-- group-to-team mapping is never split across two groups.
--
-- scim_groups is new in migration54 and unreleased; only test databases can
-- hold duplicates, and this index refuses to build on them rather than guess.
CREATE UNIQUE INDEX scim_groups_display_name_key ON public.scim_groups (directory_id, lower(display_name));
DROP INDEX public.scim_groups_name_idx;

-- +goose Down
SELECT 1;
