-- +goose Up
-- Binding authentication outlives encryption-key retirement. Preserve the same
-- owner boundary as the context journal and authority tables.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_class
               WHERE oid IN ('public.approval_context'::regclass,'public.approval_context_events'::regclass,
                             'public.users'::regclass,'public.mcp_servers'::regclass)
               AND relowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc
                  WHERE oid IN ('public.omp_current_approval_context()'::regprocedure,
                                'public.omp_lock_approval_context(boolean)'::regprocedure)
                  AND proowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)) THEN
        RAISE EXCEPTION 'approval functions and protected tables must be owned by the migration role';
    END IF;
END
$$;
-- +goose StatementEnd
CREATE TABLE public.approval_binding_keys (
    id bigint PRIMARY KEY CHECK (id = 1),
    binding_key_cipher bytea NOT NULL CHECK (octet_length(binding_key_cipher) BETWEEN 37 AND 1024)
);
REVOKE ALL ON TABLE public.approval_binding_keys FROM PUBLIC;

-- Identity and existence are immutable even for owner writes. Ciphertext UPDATE
-- remains available for authenticated, same-AAD rewrapping by rotate-keys.
-- +goose StatementBegin
CREATE FUNCTION public.approval_binding_key_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'approval binding key cannot be removed';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id THEN
        RAISE EXCEPTION 'approval binding key identity is immutable';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.approval_binding_key_guard() FROM PUBLIC;
CREATE TRIGGER approval_binding_key_identity BEFORE UPDATE ON public.approval_binding_keys
    FOR EACH ROW EXECUTE FUNCTION public.approval_binding_key_guard();
CREATE TRIGGER approval_binding_key_removal BEFORE DELETE OR TRUNCATE ON public.approval_binding_keys
    FOR EACH STATEMENT EXECUTE FUNCTION public.approval_binding_key_guard();

-- No runtime INSERT rights: this narrowly scoped helper installs at most one
-- candidate and always returns the winner, including concurrent constructors.
-- +goose StatementBegin
CREATE FUNCTION public.omp_ensure_approval_binding_key(cipher bytea) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE stored_cipher bytea;
BEGIN
    INSERT INTO public.approval_binding_keys(id, binding_key_cipher) VALUES (1, cipher)
        ON CONFLICT (id) DO NOTHING;
    SELECT binding_key_cipher INTO STRICT stored_cipher FROM public.approval_binding_keys WHERE id = 1;
    RETURN stored_cipher;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.omp_ensure_approval_binding_key(bytea) FROM PUBLIC;

-- Exactly one deliberate invalidation of legacy derived-HMAC bindings. Bootstrap
-- needs no encryption configuration during DDL and never resets the context.
INSERT INTO public.approval_context_events DEFAULT VALUES;

-- +goose Down
-- Forward-only: removing the root would strand live approval bindings.
SELECT 1;
