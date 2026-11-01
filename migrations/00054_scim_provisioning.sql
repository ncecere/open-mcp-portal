-- +goose Up
-- Decision92: supported SCIM 2.0 provisioning (docs/scim.md).
--
--   * scim_directories: at most one directory, bound to one verified OIDC
--     issuer. Disabled until an admin enables it; enrollment optional|required.
--   * scim_tokens: directory bearer credentials ("ompscim_"), digest only,
--     always expiring, revocable; they authenticate nothing but /scim/v2.
--   * scim_users / scim_groups / scim_group_members: the directory's view.
--     A resource is not an identity: scim_users.linked_user_id is set only by
--     verified-subject enrollment or explicit admin adoption.
--   * scim_group_mappings: admin-reviewed group -> team role bridges.
--   * directory_team_memberships: memberships the directory created. Manual
--     memberships are never touched; a manual role edit takes ownership.
--   * directory_cleanup_jobs: per-user deprovisioning cleanup of a deleted
--     directory life.
--   * users.manual_status / users.directory_standing: separate provenance.
--     users.status stays the single effective standing every reader uses and
--     is derived by trigger, including for previous binaries' status writes.
--
-- Expand/contract: new tables and defaulted columns only. Previous binaries
-- keep working; their manual status writes are reinterpreted as manual
-- standing, so directory restrictions cannot be lifted by them. Older serving
-- code has no SCIM routes or enrollment gate; drain it before enabling SCIM.

CREATE TABLE public.scim_directories (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    singleton  boolean     NOT NULL DEFAULT true CONSTRAINT scim_directories_singleton UNIQUE CHECK (singleton),
    issuer     text        NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 2048),
    enabled    boolean     NOT NULL DEFAULT false,
    enrollment text        NOT NULL DEFAULT 'optional' CHECK (enrollment IN ('optional', 'required')),
    revision   bigint      NOT NULL DEFAULT 1,
    created_by uuid        REFERENCES public.users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.scim_tokens (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id    uuid        NOT NULL REFERENCES public.scim_directories (id) ON DELETE CASCADE,
    name            text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    prefix          text        NOT NULL CHECK (prefix ~ '^ompscim_[A-Za-z0-9_-]{8}$'),
    digest          text        NOT NULL CONSTRAINT scim_tokens_digest_key UNIQUE CHECK (digest ~ '^[0-9a-f]{64}$'),
    pepper_id       bytea       CHECK (octet_length(pepper_id) = 8),
    created_by      uuid        REFERENCES public.users (id) ON DELETE SET NULL,
    created_by_name text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    revoked_by      uuid        REFERENCES public.users (id) ON DELETE SET NULL,
    last_used_at    timestamptz,
    CONSTRAINT scim_tokens_expiry CHECK (expires_at > created_at AND expires_at <= created_at + interval '365 days')
);
CREATE INDEX scim_tokens_directory_idx ON public.scim_tokens (directory_id, created_at DESC);

CREATE TABLE public.scim_users (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id   uuid        NOT NULL REFERENCES public.scim_directories (id) ON DELETE CASCADE,
    user_name      text        NOT NULL CHECK (char_length(user_name) BETWEEN 1 AND 256),
    -- Client-issued, case-exact and not unique (RFC 7643 3.1). Enrollment uses
    -- it only as a candidate equal to the verified OIDC subject.
    external_id    text        CHECK (char_length(external_id) BETWEEN 1 AND 512),
    active         boolean     NOT NULL DEFAULT true,
    display_name   text        NOT NULL DEFAULT '' CHECK (char_length(display_name) <= 256),
    given_name     text        NOT NULL DEFAULT '' CHECK (char_length(given_name) <= 256),
    family_name    text        NOT NULL DEFAULT '' CHECK (char_length(family_name) <= 256),
    email          text        NOT NULL DEFAULT '' CHECK (char_length(email) <= 320),
    -- The adopted/enrolled portal user. Never changed by SCIM attributes.
    linked_user_id uuid        CONSTRAINT scim_users_linked_user_key UNIQUE REFERENCES public.users (id) ON DELETE SET NULL,
    version        bigint      NOT NULL DEFAULT 1,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);
-- userName is case-insensitive and unique per directory (RFC 7643 4.1.1).
CREATE UNIQUE INDEX scim_users_user_name_key ON public.scim_users (directory_id, lower(user_name));
CREATE INDEX scim_users_external_idx ON public.scim_users (directory_id, external_id) WHERE external_id IS NOT NULL;

CREATE TABLE public.scim_groups (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id uuid        NOT NULL REFERENCES public.scim_directories (id) ON DELETE CASCADE,
    display_name text        NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 256),
    external_id  text        CHECK (char_length(external_id) BETWEEN 1 AND 512),
    version      bigint      NOT NULL DEFAULT 1,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scim_groups_name_idx ON public.scim_groups (directory_id, lower(display_name));

CREATE TABLE public.scim_group_members (
    group_id     uuid NOT NULL REFERENCES public.scim_groups (id) ON DELETE CASCADE,
    scim_user_id uuid NOT NULL REFERENCES public.scim_users (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, scim_user_id)
);
CREATE INDEX scim_group_members_user_idx ON public.scim_group_members (scim_user_id);

-- Owners are protected principals: a mapping can grant admin at most.
CREATE TABLE public.scim_group_mappings (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id   uuid        NOT NULL REFERENCES public.scim_groups (id) ON DELETE CASCADE,
    team_id    uuid        NOT NULL REFERENCES public.teams (id) ON DELETE CASCADE,
    role       text        NOT NULL CHECK (role IN ('admin', 'editor', 'member')),
    created_by uuid        REFERENCES public.users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT scim_group_mappings_key UNIQUE (group_id, team_id)
);
CREATE INDEX scim_group_mappings_team_idx ON public.scim_group_mappings (team_id);

CREATE TABLE public.directory_team_memberships (
    team_id uuid NOT NULL,
    user_id uuid NOT NULL,
    PRIMARY KEY (team_id, user_id),
    FOREIGN KEY (team_id, user_id) REFERENCES public.team_members (team_id, user_id) ON DELETE CASCADE
);
CREATE INDEX directory_team_memberships_user_idx ON public.directory_team_memberships (user_id);

CREATE TABLE public.directory_cleanup_jobs (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    attempts     integer     NOT NULL DEFAULT 0,
    last_error   text        CHECK (char_length(last_error) <= 200)
);
CREATE UNIQUE INDEX directory_cleanup_jobs_open_key ON public.directory_cleanup_jobs (user_id) WHERE completed_at IS NULL;

ALTER TABLE public.users
    ADD COLUMN manual_status text NOT NULL DEFAULT 'active'
        CONSTRAINT users_manual_status_check CHECK (manual_status IN ('active', 'suspended')),
    ADD COLUMN directory_standing text NOT NULL DEFAULT 'none'
        CONSTRAINT users_directory_standing_check CHECK (directory_standing IN ('none', 'active', 'inactive', 'deleted'));
-- Existing suspensions are manual. Status is unchanged, so no epoch,
-- generation or approval-journal event follows from this backfill.
UPDATE public.users SET manual_status = status WHERE status <> 'active';

-- Runs before user_request_epoch_advance and user_session_generation_advance
-- (BEFORE triggers fire in name order), so they observe the effective status.
-- +goose StatementBegin
CREATE FUNCTION public.user_effective_access() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status IS DISTINCT FROM 'active' THEN
            NEW.manual_status := NEW.status;
        END IF;
    ELSE
        IF NEW.manual_status IS NOT DISTINCT FROM OLD.manual_status
           AND NEW.directory_standing IS NOT DISTINCT FROM OLD.directory_standing
           AND NEW.status IS DISTINCT FROM OLD.status THEN
            -- A writer that only knows status (including previous binaries)
            -- made a manual decision. It cannot lift a directory restriction.
            NEW.manual_status := NEW.status;
        END IF;
        IF OLD.directory_standing = 'deleted' AND NEW.directory_standing <> 'deleted' THEN
            IF EXISTS (SELECT 1 FROM public.directory_cleanup_jobs j
                       WHERE j.user_id = NEW.id AND j.completed_at IS NULL) THEN
                RAISE EXCEPTION 'directory cleanup of this account is still in progress'
                    USING ERRCODE = '23514', CONSTRAINT = 'users_directory_cleanup_pending';
            END IF;
        END IF;
    END IF;
    IF NEW.directory_standing <> 'none' THEN
        IF NEW.platform_role = 'platform_admin' THEN
            RAISE EXCEPTION 'platform admins cannot be directory managed'
                USING ERRCODE = '23514', CONSTRAINT = 'users_directory_protected_admin';
        END IF;
        IF TG_OP = 'INSERT' OR OLD.directory_standing = 'none' THEN
            PERFORM pg_advisory_xact_lock(hashtextextended('omp-directory-protect:' || NEW.id::text, 0));
            IF EXISTS (SELECT 1 FROM public.team_members m WHERE m.user_id = NEW.id AND m.role = 'owner') THEN
                RAISE EXCEPTION 'team owners cannot be directory managed'
                    USING ERRCODE = '23514', CONSTRAINT = 'users_directory_protected_owner';
            END IF;
        END IF;
    END IF;
    NEW.status := CASE WHEN NEW.manual_status = 'active' AND NEW.directory_standing IN ('none', 'active')
                       THEN 'active' ELSE 'suspended' END;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.user_effective_access() FROM PUBLIC;
CREATE TRIGGER user_access_effective BEFORE INSERT OR UPDATE ON public.users
    FOR EACH ROW EXECUTE FUNCTION public.user_effective_access();

-- +goose StatementBegin
CREATE FUNCTION public.team_member_directory_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    standing text;
BEGIN
    IF NEW.role = 'owner' AND (TG_OP = 'INSERT' OR OLD.role IS DISTINCT FROM 'owner') THEN
        -- Same per-user lock as linking: no owner promotion can interleave
        -- with an adoption check. Taken only on this path, after TEAM.
        PERFORM pg_advisory_xact_lock(hashtextextended('omp-directory-protect:' || NEW.user_id::text, 0));
        SELECT u.directory_standing INTO standing FROM public.users u WHERE u.id = NEW.user_id;
        IF standing IS NOT NULL AND standing <> 'none' THEN
            RAISE EXCEPTION 'directory managed people cannot become team owners'
                USING ERRCODE = '23514', CONSTRAINT = 'team_members_directory_protected_owner';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.role IS DISTINCT FROM OLD.role
       AND current_setting('omp.directory_writer', true) IS DISTINCT FROM 'on' THEN
        -- A manual role decision takes over a directory-created membership.
        DELETE FROM public.directory_team_memberships d WHERE d.team_id = NEW.team_id AND d.user_id = NEW.user_id;
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.team_member_directory_guard() FROM PUBLIC;
CREATE TRIGGER team_member_directory_guard BEFORE INSERT OR UPDATE ON public.team_members
    FOR EACH ROW EXECUTE FUNCTION public.team_member_directory_guard();

-- +goose Down
-- Forward-only: dropping provenance would let a manual reactivation lift a
-- directory restriction, and dropping links would orphan deprovisioning.
SELECT 1;
