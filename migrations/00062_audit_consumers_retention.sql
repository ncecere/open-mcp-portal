-- +goose Up
CREATE TABLE omp_audit.consumers (
 name text PRIMARY KEY CHECK (name ~ '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$'),
 profile text NOT NULL CHECK (profile IN ('summary','full')), required boolean NOT NULL,
 acked_seq bigint NOT NULL DEFAULT 0 CHECK (acked_seq>=0), acked_at timestamptz,
 created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE omp_audit.oversized_fetches (
 consumer text NOT NULL REFERENCES omp_audit.consumers(name) ON DELETE CASCADE,
 seq bigint NOT NULL REFERENCES omp_audit.chain(seq), PRIMARY KEY(consumer,seq)
);
CREATE TABLE omp_audit.retention_floor (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 min_days integer NOT NULL DEFAULT 30 CHECK(min_days BETWEEN 30 AND 3650),
 purged_seq bigint NOT NULL DEFAULT 0 CHECK(purged_seq>=0),
 consumer_revision bigint NOT NULL DEFAULT 1
);
INSERT INTO omp_audit.retention_floor DEFAULT VALUES;
CREATE INDEX chain_retention_age_idx ON omp_audit.chain(seq) WHERE kind='entry';
CREATE INDEX chain_oversized_idx ON omp_audit.chain(seq) WHERE kind='entry' AND flags&2<>0;
-- Strict shared SQL decoder. Missing key has caller-defined meaning; null never does.
-- +goose StatementBegin
CREATE FUNCTION omp_audit.call_days(settings jsonb, fallback integer) RETURNS integer
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE v jsonb; n integer;
BEGIN
 IF settings IS NULL OR jsonb_typeof(settings)<>'object' THEN RAISE EXCEPTION 'invalid retention object'; END IF;
 IF NOT settings ? 'call_metadata' THEN RETURN fallback; END IF;
 v:=settings->'call_metadata';
 IF jsonb_typeof(v)<>'number' OR v::text !~ '^[0-9]+$' THEN RAISE EXCEPTION 'invalid call_metadata'; END IF;
 n:=v::text::integer;
 IF n NOT BETWEEN 1 AND 3650 THEN RAISE EXCEPTION 'invalid call_metadata'; END IF;
 RETURN n;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit.register_consumer(consumer text, profile text, required boolean, created_by uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
BEGIN
 IF consumer IS NULL OR consumer !~ '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$' OR profile IS NULL OR profile NOT IN ('summary','full') OR required IS NULL OR created_by IS NULL THEN RAISE EXCEPTION 'invalid consumer'; END IF;
 PERFORM 1 FROM omp_audit.retention_floor WHERE singleton FOR UPDATE;
 IF (SELECT count(*) FROM omp_audit.consumers)>=100 THEN RAISE EXCEPTION 'consumer limit'; END IF;
 INSERT INTO omp_audit.consumers(name,profile,required,created_by) VALUES(consumer,profile,required,created_by);
 UPDATE omp_audit.retention_floor SET consumer_revision=consumer_revision+1 WHERE singleton;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit.set_required(consumer text, required boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
BEGIN
 IF consumer IS NULL OR length(consumer) NOT BETWEEN 1 AND 64 OR required IS NULL THEN RAISE EXCEPTION 'invalid consumer'; END IF;
 PERFORM 1 FROM omp_audit.retention_floor WHERE singleton FOR UPDATE;
 UPDATE omp_audit.consumers c SET required=set_required.required WHERE c.name=consumer;
 IF NOT FOUND THEN RAISE EXCEPTION 'consumer not found'; END IF;
 UPDATE omp_audit.retention_floor SET consumer_revision=consumer_revision+1 WHERE singleton;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit.remove_consumer(consumer text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
BEGIN
 IF consumer IS NULL OR length(consumer) NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION 'invalid consumer'; END IF;
 PERFORM 1 FROM omp_audit.retention_floor WHERE singleton FOR UPDATE;
 DELETE FROM omp_audit.consumers WHERE name=consumer;
 IF NOT FOUND THEN RAISE EXCEPTION 'consumer not found'; END IF;
 UPDATE omp_audit.retention_floor SET consumer_revision=consumer_revision+1 WHERE singleton;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit.record_oversized_fetch(consumer text, seq bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
BEGIN
 IF consumer IS NULL OR length(consumer) NOT BETWEEN 1 AND 64 OR seq IS NULL OR seq<1 THEN RAISE EXCEPTION 'invalid fetch'; END IF;
 PERFORM 1 FROM omp_audit.consumers c WHERE c.name=consumer AND c.profile='full' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'full consumer not found'; END IF;
 IF NOT EXISTS(SELECT 1 FROM omp_audit.chain c JOIN public.audit_log a ON a.id=c.audit_id AND (a.row_uid=c.row_uid OR (a.txid IS NULL AND a.id=c.legacy_id)) WHERE c.seq=record_oversized_fetch.seq AND c.flags&2<>0) THEN RAISE EXCEPTION 'oversized entry not found'; END IF;
 INSERT INTO omp_audit.oversized_fetches VALUES(consumer,seq) ON CONFLICT DO NOTHING;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit.ack(consumer text, seq bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE c omp_audit.consumers%ROWTYPE; tip bigint;
BEGIN
 IF consumer IS NULL OR length(consumer) NOT BETWEEN 1 AND 64 OR seq IS NULL OR seq<0 THEN RAISE EXCEPTION 'invalid ack'; END IF;
 SELECT last_seq INTO STRICT tip FROM omp_audit.state WHERE singleton;
 SELECT * INTO STRICT c FROM omp_audit.consumers WHERE name=consumer FOR UPDATE;
 IF seq<c.acked_seq OR seq>tip THEN RAISE EXCEPTION 'ack out of range'; END IF;
 IF c.profile='full' AND EXISTS(SELECT 1 FROM omp_audit.chain ch WHERE ch.seq>c.acked_seq AND ch.seq<=ack.seq AND ch.flags&2<>0 AND NOT EXISTS(SELECT 1 FROM omp_audit.oversized_fetches f WHERE f.consumer=c.name AND f.seq=ch.seq)) THEN RAISE EXCEPTION 'oversized_pending' USING ERRCODE='P0001'; END IF;
 UPDATE omp_audit.consumers SET acked_seq=ack.seq,acked_at=now() WHERE name=consumer;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.omp_purge_audit_log(days integer, batch_size integer) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE previous_flag text:=current_setting('omp.audit_purge',true); settings jsonb; floor_days integer; calls integer; team_calls integer; tip bigint; stop_seq bigint; prefix bigint; old_prefix bigint; cutoff timestamptz; r record; deleted bigint:=0; locked_id bigint;
BEGIN
 IF days IS NULL OR days>3650 OR batch_size IS NULL OR batch_size NOT BETWEEN 1 AND 100000 THEN RAISE EXCEPTION 'invalid purge arguments' USING ERRCODE='22023'; END IF;
 SELECT periods INTO STRICT settings FROM public.retention_settings WHERE id=1;
 SELECT last_seq INTO STRICT tip FROM omp_audit.state WHERE singleton;
 -- Serializes purges and consumer configuration, avoiding an ack/configuration race.
 SELECT min_days,purged_seq INTO STRICT floor_days,old_prefix FROM omp_audit.retention_floor WHERE singleton FOR UPDATE;
 calls:=omp_audit.call_days(settings,90);
 SELECT max(omp_audit.call_days(retention_overrides,NULL)) INTO team_calls FROM public.teams;
 calls:=greatest(calls,team_calls);
 cutoff:=now()-make_interval(days=>greatest(days,floor_days,calls));
 SELECT least(tip,coalesce(min(acked_seq),tip)) INTO prefix FROM omp_audit.consumers WHERE required;
 SELECT min(ch.seq) INTO stop_seq FROM omp_audit.chain ch WHERE ch.seq>old_prefix AND ch.seq<=prefix AND ch.kind='entry' AND
 (ch.occurred_at>=cutoff OR (ch.flags&2<>0 AND EXISTS(SELECT 1 FROM omp_audit.consumers c WHERE c.required AND c.profile='full' AND NOT EXISTS(SELECT 1 FROM omp_audit.oversized_fetches f WHERE f.consumer=c.name AND f.seq=ch.seq))));
 prefix:=least(prefix,coalesce(stop_seq-1,prefix));
 PERFORM set_config('omp.audit_purge','on',true);
 -- Stop at the FIRST locked entry: skipping it and deleting later entries would
 -- create an interior expiry. Each lookup uses chain PK and audit_log PK.
 FOR r IN SELECT * FROM omp_audit.chain WHERE seq>old_prefix AND seq<=prefix ORDER BY seq LIMIT batch_size LOOP
  IF r.kind='entry' THEN
   SELECT a.id INTO locked_id FROM public.audit_log a WHERE a.id=r.audit_id AND (a.row_uid=r.row_uid OR (a.txid IS NULL AND a.id=r.legacy_id)) FOR UPDATE SKIP LOCKED;
   IF NOT FOUND THEN
    IF EXISTS(SELECT 1 FROM public.audit_log a WHERE a.id=r.audit_id AND (a.row_uid=r.row_uid OR (a.txid IS NULL AND a.id=r.legacy_id))) THEN EXIT; END IF;
    RAISE EXCEPTION 'audit_row_missing at %',r.seq;
   END IF;
   DELETE FROM public.audit_log WHERE id=locked_id;
   deleted:=deleted+1;
  END IF;
  UPDATE omp_audit.retention_floor SET purged_seq=r.seq WHERE singleton;
 END LOOP;
 PERFORM set_config('omp.audit_purge',coalesce(previous_flag,''),true);
 RETURN deleted;
EXCEPTION WHEN OTHERS THEN
 PERFORM set_config('omp.audit_purge',coalesce(previous_flag,''),true);
 RAISE;
END $$;
-- +goose StatementEnd
REVOKE ALL ON ALL TABLES IN SCHEMA omp_audit FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA omp_audit FROM PUBLIC;
REVOKE ALL ON FUNCTION public.omp_purge_audit_log(integer,integer) FROM PUBLIC;
-- +goose StatementBegin
DO $$ DECLARE owner_name text; f text; BEGIN
 SELECT pg_get_userbyid(relowner) INTO STRICT owner_name FROM pg_class WHERE oid='public.audit_log'::regclass;
 FOREACH f IN ARRAY ARRAY['call_days(jsonb,integer)','register_consumer(text,text,boolean,uuid)','set_required(text,boolean)','remove_consumer(text)','record_oversized_fetch(text,bigint)','ack(text,bigint)'] LOOP
  EXECUTE format('ALTER FUNCTION omp_audit.%s OWNER TO %I',f,owner_name);
 END LOOP;
 EXECUTE format('ALTER FUNCTION public.omp_purge_audit_log(integer,integer) OWNER TO %I',owner_name);
END $$;
-- +goose StatementEnd
-- Preserve the existing boundary while allowing late oversized entries.
-- +goose StatementBegin
DO $$ DECLARE body text; BEGIN
 body:=pg_get_functiondef('omp_audit.seal_batch(text,jsonb)'::regprocedure);
 body:=replace(body,'IF flags<>1 OR','IF flags&1<>1 OR');
 EXECUTE body;
END $$;
-- +goose StatementEnd
-- +goose Down
SELECT 1;
