-- +goose Up
-- Sink transitions serialize with purge, never with the sealer's state lock.
CREATE TABLE omp_audit_ext.sink_settings (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 enabled boolean NOT NULL DEFAULT false,
 min_reader_version text CHECK(length(min_reader_version) BETWEEN 1 AND 100),
 CHECK(NOT enabled OR min_reader_version IS NOT NULL)
);
INSERT INTO omp_audit_ext.sink_settings DEFAULT VALUES;
CREATE TABLE omp_audit_ext.sinks (
 id uuid PRIMARY KEY, name text NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 100),
 kind text NOT NULL DEFAULT 'webhook' CHECK(kind='webhook'),
 profile text NOT NULL CHECK(profile IN ('summary','full')),
 required boolean NOT NULL, enabled boolean NOT NULL,
 batch_max_records integer NOT NULL DEFAULT 100 CHECK(batch_max_records BETWEEN 1 AND 1000),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 url_cipher bytea NOT NULL CHECK(octet_length(url_cipher) BETWEEN 1 AND 8192),
 url_hint text NOT NULL CHECK(length(url_hint) BETWEEN 1 AND 253),
 secret_cipher bytea NOT NULL CHECK(octet_length(secret_cipher) BETWEEN 1 AND 1024),
 secret_hint text NOT NULL DEFAULT '' CHECK(length(secret_hint)<=8),
 secret_previous_cipher bytea CHECK(octet_length(secret_previous_cipher) BETWEEN 1 AND 1024),
 secret_previous_until timestamptz,
 cursor_seq bigint NOT NULL CHECK(cursor_seq>=0),
 inflight_kind text CHECK(inflight_kind IN ('data','gap')),
 inflight_first bigint, inflight_last bigint, inflight_token uuid, inflight_revision bigint,
 next_attempt_at timestamptz NOT NULL DEFAULT now(),
 consecutive_failures integer NOT NULL DEFAULT 0 CHECK(consecutive_failures>=0),
 last_error_class text CHECK(last_error_class IN ('dns','connect','tls','timeout','http_3xx','http_4xx','http_5xx','too_large','policy_denied','integrity')),
 last_ok_at timestamptz, state text NOT NULL DEFAULT 'active' CHECK(state IN ('active','range_expired','paused')),
 streak_id uuid, streak_notified boolean NOT NULL DEFAULT false,
 gap_first bigint, gap_last bigint,
 CHECK((secret_previous_cipher IS NULL)=(secret_previous_until IS NULL)),
 CHECK((gap_first IS NULL AND gap_last IS NULL) OR (gap_first IS NOT NULL AND gap_last IS NOT NULL AND gap_first=cursor_seq+1 AND gap_last>=gap_first)),
 CHECK((inflight_kind IS NULL AND inflight_first IS NULL AND inflight_last IS NULL AND inflight_revision IS NULL AND inflight_token IS NULL)
 OR (inflight_kind IS NOT NULL AND inflight_first IS NOT NULL AND inflight_last>=inflight_first AND inflight_first>0 AND inflight_revision IS NOT NULL)),
 CHECK(NOT required OR state<>'range_expired'),
 CHECK(NOT streak_notified OR streak_id IS NOT NULL)
);
-- +goose StatementBegin
CREATE FUNCTION omp_audit_ext.validate_sink(p_name text,p_profile text,p_required boolean,p_enabled boolean,p_batch integer,p_url bytea,p_hint text,p_secret bytea,p_previous bytea,p_until timestamptz,p_secret_hint text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$

BEGIN
 IF p_name IS NULL OR length(p_name) NOT BETWEEN 1 AND 100 OR p_profile IS NULL OR p_profile NOT IN ('summary','full')
 OR p_required IS NULL OR p_enabled IS NULL OR p_batch IS NULL OR p_batch NOT BETWEEN 1 AND 1000
 OR p_url IS NULL OR octet_length(p_url) NOT BETWEEN 1 AND 8192 OR p_hint IS NULL OR length(p_hint) NOT BETWEEN 1 AND 253
 OR p_secret IS NULL OR octet_length(p_secret) NOT BETWEEN 1 AND 1024
 OR (p_previous IS NOT NULL AND octet_length(p_previous) NOT BETWEEN 1 AND 1024)
 OR (p_previous IS NULL)<>(p_until IS NULL) OR p_secret_hint IS NULL OR length(p_secret_hint)>8
 THEN RAISE EXCEPTION 'invalid sink settings' USING ERRCODE='22023'; END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit_ext.create_sink(p_id uuid,p_name text,p_profile text,p_required boolean,p_enabled boolean,p_batch integer,p_url bytea,p_hint text,p_secret bytea,p_previous bytea,p_until timestamptz,p_secret_hint text) RETURNS omp_audit_ext.sinks
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE f omp_audit.retention_floor%ROWTYPE; s omp_audit_ext.sinks%ROWTYPE;
BEGIN
 PERFORM omp_audit_ext.validate_sink(p_name,p_profile,p_required,p_enabled,p_batch,p_url,p_hint,p_secret,p_previous,p_until,p_secret_hint);
 IF p_id IS NULL THEN RAISE EXCEPTION 'invalid sink id'; END IF;
 SELECT * INTO STRICT f FROM omp_audit.retention_floor WHERE singleton FOR UPDATE;
 IF (SELECT count(*) FROM omp_audit_ext.sinks)>=100 THEN RAISE EXCEPTION 'sink limit'; END IF;
 INSERT INTO omp_audit_ext.sinks(id,name,profile,required,enabled,batch_max_records,url_cipher,url_hint,secret_cipher,secret_previous_cipher,secret_previous_until,secret_hint,cursor_seq)
 VALUES(p_id,p_name,p_profile,p_required,p_enabled,p_batch,p_url,p_hint,p_secret,p_previous,p_until,p_secret_hint,f.purged_seq) RETURNING * INTO s;
 UPDATE omp_audit.retention_floor SET consumer_revision=consumer_revision+1 WHERE singleton;
 RETURN s;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit_ext.update_sink(p_id uuid,p_revision bigint,p_name text,p_profile text,p_required boolean,p_enabled boolean,p_batch integer,p_url bytea,p_hint text,p_secret bytea,p_previous bytea,p_until timestamptz,p_secret_hint text) RETURNS omp_audit_ext.sinks
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE f omp_audit.retention_floor%ROWTYPE; s omp_audit_ext.sinks%ROWTYPE;
BEGIN
 PERFORM omp_audit_ext.validate_sink(p_name,p_profile,p_required,p_enabled,p_batch,p_url,p_hint,p_secret,p_previous,p_until,p_secret_hint);
 SELECT * INTO STRICT f FROM omp_audit.retention_floor WHERE singleton FOR UPDATE;
 SELECT * INTO STRICT s FROM omp_audit_ext.sinks WHERE id=p_id FOR UPDATE;
 IF p_revision IS NULL OR s.revision<>p_revision THEN RAISE EXCEPTION 'stale sink revision' USING ERRCODE='40001'; END IF;
 IF p_required AND (s.cursor_seq<f.purged_seq OR s.gap_first IS NOT NULL OR s.state='range_expired') THEN RAISE EXCEPTION 'sink recovery required'; END IF;
 UPDATE omp_audit_ext.sinks SET name=p_name,profile=p_profile,required=p_required,enabled=p_enabled,batch_max_records=p_batch,
 url_cipher=p_url,url_hint=p_hint,secret_cipher=p_secret,secret_previous_cipher=p_previous,secret_previous_until=p_until,secret_hint=p_secret_hint,
 revision=revision+1,inflight_kind=NULL,inflight_first=NULL,inflight_last=NULL,inflight_revision=NULL,inflight_token=NULL WHERE id=p_id RETURNING * INTO s;
 UPDATE omp_audit.retention_floor SET consumer_revision=consumer_revision+1 WHERE singleton;
 RETURN s;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit_ext.delete_sink(p_id uuid,p_revision bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE f omp_audit.retention_floor%ROWTYPE; s omp_audit_ext.sinks%ROWTYPE;
BEGIN
 SELECT * INTO STRICT f FROM omp_audit.retention_floor WHERE singleton FOR UPDATE;
 SELECT * INTO STRICT s FROM omp_audit_ext.sinks WHERE id=p_id FOR UPDATE;
 IF p_revision IS NULL OR s.revision<>p_revision THEN RAISE EXCEPTION 'stale sink revision' USING ERRCODE='40001'; END IF;
 DELETE FROM omp_audit_ext.sinks WHERE id=p_id;
 UPDATE omp_audit.retention_floor SET consumer_revision=consumer_revision+1 WHERE singleton;

END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit_ext.set_sinks_enabled(p_enabled boolean,p_min_reader_version text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$

BEGIN
 IF p_enabled IS NULL OR p_min_reader_version IS NULL OR length(p_min_reader_version) NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'minimum reader version required'; END IF;
 PERFORM 1 FROM omp_audit.retention_floor WHERE singleton FOR UPDATE;
 IF EXISTS(SELECT 1 FROM omp_audit_ext.sink_settings WHERE min_reader_version IS NOT NULL AND min_reader_version<>p_min_reader_version) THEN RAISE EXCEPTION 'minimum reader version already set'; END IF;
 UPDATE omp_audit_ext.sink_settings SET enabled=p_enabled,min_reader_version=p_min_reader_version WHERE singleton;
 UPDATE omp_audit.retention_floor SET consumer_revision=consumer_revision+1 WHERE singleton;

END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit_ext.begin_attempt(p_id uuid,p_revision bigint,p_cursor bigint,p_kind text,p_first bigint,p_last bigint) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE f omp_audit.retention_floor%ROWTYPE; s omp_audit_ext.sinks%ROWTYPE; token uuid;
BEGIN
 SELECT * INTO STRICT f FROM omp_audit.retention_floor WHERE singleton FOR UPDATE;
 SELECT * INTO STRICT s FROM omp_audit_ext.sinks WHERE id=p_id FOR UPDATE;
 IF p_revision IS NULL OR s.revision<>p_revision THEN RAISE EXCEPTION 'stale sink revision' USING ERRCODE='40001'; END IF;
 IF NOT (SELECT enabled FROM omp_audit_ext.sink_settings WHERE singleton) OR NOT s.enabled OR s.state<>'active' THEN RAISE EXCEPTION 'sinks disabled or inactive'; END IF;
 IF p_cursor IS NULL OR p_cursor<>s.cursor_seq THEN RAISE EXCEPTION 'stale sink cursor' USING ERRCODE='40001'; END IF;
 IF p_kind IS NULL OR p_kind NOT IN ('data','gap') OR p_first IS NULL OR p_last IS NULL OR p_first<1 OR p_last<p_first THEN RAISE EXCEPTION 'invalid attempt'; END IF;
 IF p_kind='data' THEN
  IF s.gap_first IS NOT NULL OR p_first<>s.cursor_seq+1 OR p_first<=f.purged_seq OR p_last>(SELECT last_seq FROM omp_audit.state WHERE singleton)
  OR NOT EXISTS(SELECT 1 FROM omp_audit.chain WHERE seq=p_last)
  OR (SELECT count(*) FROM omp_audit.chain WHERE seq BETWEEN p_first AND p_last)>s.batch_max_records THEN RAISE EXCEPTION 'invalid data range'; END IF;
 ELSE
  IF p_first IS DISTINCT FROM s.gap_first OR p_last IS DISTINCT FROM s.gap_last THEN RAISE EXCEPTION 'invalid gap range'; END IF;
 END IF;
 IF s.inflight_kind IS NOT NULL AND (s.inflight_kind<>p_kind OR s.inflight_first<>p_first OR s.inflight_last<>p_last OR s.inflight_revision<>p_revision) THEN RAISE EXCEPTION 'retry range conflict' USING ERRCODE='40001'; END IF;
 token:=gen_random_uuid();
 UPDATE omp_audit_ext.sinks SET inflight_kind=p_kind,inflight_first=p_first,inflight_last=p_last,inflight_revision=p_revision,inflight_token=token WHERE id=p_id;
 RETURN token;
END $$;
-- +goose StatementEnd
-- notify_intent is the caller's transactional notification decision. The caller
-- must use notify.InsertStrict in the SAME transaction, preserving the pre-finish
-- streak id for recovery. Part 1 deliberately does not emit notification events.
-- A consumed token leaves the retry identity (kind, endpoints, revision) intact
-- on failure. A new begin always replaces the token, even for that same identity.
-- +goose StatementBegin
CREATE FUNCTION omp_audit_ext.finish_attempt(p_id uuid,p_token uuid,p_outcome text,p_error_class text,p_notify_intent boolean) RETURNS omp_audit_ext.sinks
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE f omp_audit.retention_floor%ROWTYPE; s omp_audit_ext.sinks%ROWTYPE;
BEGIN
 SELECT * INTO STRICT f FROM omp_audit.retention_floor WHERE singleton FOR UPDATE;
 SELECT * INTO STRICT s FROM omp_audit_ext.sinks WHERE id=p_id FOR UPDATE;
 IF NOT (SELECT enabled FROM omp_audit_ext.sink_settings WHERE singleton) THEN RAISE EXCEPTION 'sinks disabled'; END IF;
 IF p_token IS NULL OR s.inflight_token IS DISTINCT FROM p_token OR s.inflight_revision IS DISTINCT FROM s.revision THEN RAISE EXCEPTION 'stale sink token' USING ERRCODE='40001'; END IF;
 IF p_outcome IS NULL OR p_outcome NOT IN ('ok','held','failed') OR p_notify_intent IS NULL THEN RAISE EXCEPTION 'invalid outcome'; END IF;
 IF (s.inflight_kind='data' AND (s.inflight_first<>s.cursor_seq+1 OR s.gap_first IS NOT NULL))
 OR (s.inflight_kind='gap' AND (s.inflight_first IS DISTINCT FROM s.gap_first OR s.inflight_last IS DISTINCT FROM s.gap_last)) THEN RAISE EXCEPTION 'attempt endpoints changed'; END IF;
 IF p_outcome='held' AND (s.inflight_kind<>'data' OR s.inflight_first<>s.inflight_last OR NOT s.required OR s.profile<>'full'
 OR NOT EXISTS(SELECT 1 FROM omp_audit.chain WHERE seq=s.inflight_first AND kind='entry' AND flags&2<>0)) THEN RAISE EXCEPTION 'invalid oversized hold'; END IF;
 IF p_outcome='ok' AND s.inflight_kind='data' AND s.required AND s.profile='full' AND EXISTS(SELECT 1 FROM omp_audit.chain WHERE seq BETWEEN s.inflight_first AND s.inflight_last AND flags&2<>0) THEN RAISE EXCEPTION 'oversized acknowledgement required'; END IF;
 IF p_outcome='failed' THEN
  IF p_error_class IS NULL OR p_error_class NOT IN ('dns','connect','tls','timeout','http_3xx','http_4xx','http_5xx','too_large','policy_denied','integrity') THEN RAISE EXCEPTION 'invalid error class'; END IF;
  IF p_notify_intent IS DISTINCT FROM (s.consecutive_failures>=2 AND NOT s.streak_notified) THEN RAISE EXCEPTION 'failure notification intent mismatch'; END IF;
  UPDATE omp_audit_ext.sinks SET consecutive_failures=consecutive_failures+1,last_error_class=p_error_class,
   streak_id=coalesce(streak_id,gen_random_uuid()),streak_notified=streak_notified OR p_notify_intent,
   next_attempt_at=clock_timestamp()+make_interval(secs=>least(300,power(2,least(s.consecutive_failures,9)))::double precision),inflight_token=NULL WHERE id=p_id RETURNING * INTO s;
 ELSE
  IF p_error_class IS NOT NULL OR p_notify_intent IS DISTINCT FROM s.streak_notified THEN RAISE EXCEPTION 'recovery notification intent mismatch'; END IF;
  UPDATE omp_audit_ext.sinks SET cursor_seq=CASE WHEN p_outcome='held' THEN s.inflight_first-1 ELSE s.inflight_last END,
   gap_first=NULL,gap_last=NULL,consecutive_failures=0,last_error_class=NULL,last_ok_at=clock_timestamp(),
   streak_id=NULL,streak_notified=false,next_attempt_at=clock_timestamp(),inflight_kind=NULL,inflight_first=NULL,inflight_last=NULL,inflight_revision=NULL,inflight_token=NULL WHERE id=p_id RETURNING * INTO s;
 END IF;
 UPDATE omp_audit.retention_floor SET consumer_revision=consumer_revision+1 WHERE singleton;
 RETURN s;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit_ext.expire_sink(p_id uuid,p_revision bigint,p_cursor bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE f omp_audit.retention_floor%ROWTYPE; s omp_audit_ext.sinks%ROWTYPE;
BEGIN
 SELECT * INTO STRICT f FROM omp_audit.retention_floor WHERE singleton FOR UPDATE;
 SELECT * INTO STRICT s FROM omp_audit_ext.sinks WHERE id=p_id FOR UPDATE;
 IF p_revision IS NULL OR s.revision<>p_revision THEN RAISE EXCEPTION 'stale sink revision' USING ERRCODE='40001'; END IF;
 IF p_cursor IS NULL OR p_cursor<>s.cursor_seq OR s.required OR s.cursor_seq>=f.purged_seq THEN RAISE EXCEPTION 'sink cannot expire'; END IF;
 UPDATE omp_audit_ext.sinks SET state='range_expired',inflight_kind=NULL,inflight_first=NULL,inflight_last=NULL,inflight_revision=NULL,inflight_token=NULL WHERE id=p_id;
 UPDATE omp_audit.retention_floor SET consumer_revision=consumer_revision+1 WHERE singleton;

END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit_ext.resume_sink(p_id uuid,p_revision bigint,p_cursor bigint) RETURNS omp_audit_ext.sinks
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE f omp_audit.retention_floor%ROWTYPE; s omp_audit_ext.sinks%ROWTYPE;
BEGIN
 SELECT * INTO STRICT f FROM omp_audit.retention_floor WHERE singleton FOR UPDATE;
 SELECT * INTO STRICT s FROM omp_audit_ext.sinks WHERE id=p_id FOR UPDATE;
 IF p_revision IS NULL OR s.revision<>p_revision THEN RAISE EXCEPTION 'stale sink revision' USING ERRCODE='40001'; END IF;
 IF p_cursor IS NULL OR p_cursor<>s.cursor_seq OR s.gap_first IS NOT NULL THEN RAISE EXCEPTION 'resume conflict' USING ERRCODE='40001'; END IF;
 UPDATE omp_audit_ext.sinks SET state='active',gap_first=CASE WHEN s.cursor_seq<f.purged_seq THEN s.cursor_seq+1 END,
 gap_last=CASE WHEN s.cursor_seq<f.purged_seq THEN f.purged_seq END,inflight_kind=NULL,inflight_first=NULL,inflight_last=NULL,inflight_revision=NULL,inflight_token=NULL WHERE id=p_id RETURNING * INTO s;
 UPDATE omp_audit.retention_floor SET consumer_revision=consumer_revision+1 WHERE singleton;
 RETURN s;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit_ext.acknowledge_oversized(p_id uuid,p_revision bigint,p_seq bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE f omp_audit.retention_floor%ROWTYPE; s omp_audit_ext.sinks%ROWTYPE;
BEGIN
 SELECT * INTO STRICT f FROM omp_audit.retention_floor WHERE singleton FOR UPDATE;
 SELECT * INTO STRICT s FROM omp_audit_ext.sinks WHERE id=p_id FOR UPDATE;
 IF p_revision IS NULL OR s.revision<>p_revision THEN RAISE EXCEPTION 'stale sink revision' USING ERRCODE='40001'; END IF;
 IF p_seq IS NULL OR p_seq<>s.cursor_seq+1 OR NOT s.required OR s.profile<>'full' OR s.gap_first IS NOT NULL
 OR NOT EXISTS(SELECT 1 FROM omp_audit.chain c JOIN public.audit_log a ON a.id=c.audit_id AND (a.row_uid=c.row_uid OR (a.txid IS NULL AND a.id=c.legacy_id)) WHERE c.seq=p_seq AND c.kind='entry' AND c.flags&2<>0) THEN RAISE EXCEPTION 'oversized acknowledgement refused'; END IF;
 UPDATE omp_audit_ext.sinks SET cursor_seq=p_seq,inflight_kind=NULL,inflight_first=NULL,inflight_last=NULL,inflight_revision=NULL,inflight_token=NULL WHERE id=p_id;
 INSERT INTO public.audit_log(actor_kind,action,target_type,target_id) VALUES('system','audit.sink_oversized_acknowledged','audit_sink',p_id::text);
 UPDATE omp_audit.retention_floor SET consumer_revision=consumer_revision+1 WHERE singleton;

END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.omp_purge_audit_log(days integer, batch_size integer) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE previous_flag text:=current_setting('omp.audit_purge',true); settings jsonb; floor_days integer; calls integer; team_calls integer; tip bigint; stop_seq bigint; prefix bigint; old_prefix bigint; cutoff timestamptz; r record; deleted bigint:=0; locked_id bigint;
BEGIN
 IF days IS NULL OR days>3650 OR batch_size IS NULL OR batch_size NOT BETWEEN 1 AND 100000 THEN RAISE EXCEPTION 'invalid purge arguments' USING ERRCODE='22023'; END IF;
 SELECT periods INTO STRICT settings FROM public.retention_settings WHERE id=1;
 -- Serializes purges, consumer configuration and the first-ever seal (seal_batch takes this
 -- lock while last_seq=0), avoiding ack/configuration and mode-switch races. Read the
 -- stream state only after taking it.
 SELECT min_days,purged_seq INTO STRICT floor_days,old_prefix FROM omp_audit.retention_floor WHERE singleton FOR UPDATE;
 SELECT last_seq INTO STRICT tip FROM omp_audit.state WHERE singleton;
 calls:=omp_audit.call_days(settings,90);
 SELECT max(omp_audit.call_days(retention_overrides,NULL)) INTO team_calls FROM public.teams;
 calls:=greatest(calls,team_calls);
 cutoff:=now()-make_interval(days=>greatest(days,floor_days,calls));
 -- Until the stream has ever sealed anything or a consumer exists, there is nothing to
 -- protect: purge by age (with the floor and call-metadata minimum) as before. Otherwise
 -- an install that never enables streaming would never purge audit rows at all. Once
 -- anything is sealed the interlock below applies for good (last_seq never decreases).
 IF tip=0 AND NOT EXISTS(SELECT 1 FROM omp_audit.consumers) AND NOT EXISTS(SELECT 1 FROM omp_audit_ext.sinks) THEN
  PERFORM set_config('omp.audit_purge','on',true);
  WITH doomed AS (
   SELECT id FROM public.audit_log WHERE occurred_at<cutoff ORDER BY id LIMIT batch_size FOR UPDATE SKIP LOCKED
  ), removed AS (
   DELETE FROM public.audit_log WHERE id IN (SELECT id FROM doomed) RETURNING id
  ) SELECT count(*) INTO deleted FROM removed;
  PERFORM set_config('omp.audit_purge',coalesce(previous_flag,''),true);
  RETURN deleted;
 END IF;
 SELECT least(tip,
  coalesce((SELECT min(acked_seq) FROM omp_audit.consumers WHERE required),tip),
  coalesce((SELECT min(cursor_seq) FROM omp_audit_ext.sinks WHERE required),tip)) INTO prefix;
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
-- Nine platform subscription choices now exist (including the two sink notices).
ALTER TABLE public.notification_destinations DROP CONSTRAINT notification_destinations_events_check;
ALTER TABLE public.notification_destinations ADD CONSTRAINT notification_destinations_events_check CHECK(cardinality(events) BETWEEN 1 AND 10);
-- Expand existing CHECKs rather than copying their historical event lists.
-- +goose StatementBegin
DO $$ DECLARE r record; body text; BEGIN
 FOR r IN SELECT conrelid::regclass AS rel,conname,pg_get_constraintdef(oid) AS def FROM pg_constraint
 WHERE contype='c' AND conrelid IN ('public.notification_events'::regclass,'public.notification_preferences'::regclass)
 AND conname IN ('notification_events_event_check','notification_preferences_event_check') LOOP
  body:=replace(r.def,$needle$'access.decided'::text$needle$,$replacement$'access.decided'::text, 'audit.sink_failing'::text, 'audit.sink_recovered'::text$replacement$);
  IF body=r.def THEN RAISE EXCEPTION 'notification CHECK expansion failed'; END IF;
  EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',r.rel,r.conname);
  EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',r.rel,r.conname,body);
 END LOOP;
END $$;
-- +goose StatementEnd
INSERT INTO omp_audit_ext.manifest(kind,identity,privileges) VALUES
 ('table','omp_audit_ext.sink_settings',ARRAY['select']),
 ('table','omp_audit_ext.sinks',ARRAY['select','update(secret_cipher)','update(secret_previous_cipher)','update(url_cipher)']),
 ('function','omp_audit_ext.validate_sink(text,text,boolean,boolean,integer,bytea,text,bytea,bytea,timestamp with time zone,text)',ARRAY[]::text[]),
 ('function','omp_audit_ext.create_sink(uuid,text,text,boolean,boolean,integer,bytea,text,bytea,bytea,timestamp with time zone,text)',ARRAY['execute']),
 ('function','omp_audit_ext.update_sink(uuid,bigint,text,text,boolean,boolean,integer,bytea,text,bytea,bytea,timestamp with time zone,text)',ARRAY['execute']),
 ('function','omp_audit_ext.delete_sink(uuid,bigint)',ARRAY['execute']),
 ('function','omp_audit_ext.set_sinks_enabled(boolean,text)',ARRAY[]::text[]),
 ('function','omp_audit_ext.begin_attempt(uuid,bigint,bigint,text,bigint,bigint)',ARRAY['execute']),
 ('function','omp_audit_ext.finish_attempt(uuid,uuid,text,text,boolean)',ARRAY['execute']),
 ('function','omp_audit_ext.expire_sink(uuid,bigint,bigint)',ARRAY['execute']),
 ('function','omp_audit_ext.resume_sink(uuid,bigint,bigint)',ARRAY['execute']),
 ('function','omp_audit_ext.acknowledge_oversized(uuid,bigint,bigint)',ARRAY['execute']);
REVOKE ALL ON ALL TABLES IN SCHEMA omp_audit_ext FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA omp_audit_ext FROM PUBLIC;
REVOKE ALL ON FUNCTION public.omp_purge_audit_log(integer,integer) FROM PUBLIC;
-- +goose StatementBegin
DO $$ DECLARE owner_name text; obj record; p record; BEGIN
 SELECT pg_get_userbyid(relowner) INTO STRICT owner_name FROM pg_class WHERE oid='public.audit_log'::regclass;
 FOR obj IN SELECT * FROM omp_audit_ext.manifest WHERE identity<>'omp_audit_ext.manifest' LOOP
  EXECUTE format('ALTER %s %s OWNER TO %I',obj.kind,obj.identity,owner_name);
 END LOOP;
 EXECUTE format('ALTER FUNCTION public.omp_purge_audit_log(integer,integer) OWNER TO %I',owner_name);
 SELECT * INTO STRICT p FROM pg_proc WHERE oid='public.omp_purge_audit_log(integer,integer)'::regprocedure;
 IF NOT p.prosecdef OR pg_get_userbyid(p.proowner)<>owner_name
 OR NOT p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp','TimeZone=UTC']
 OR position('omp_audit_ext.sinks WHERE required' IN p.prosrc)=0
 OR position('AND NOT EXISTS(SELECT 1 FROM omp_audit_ext.sinks)' IN p.prosrc)=0
 OR EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) WHERE grantee=0) THEN RAISE EXCEPTION 'purge restatement assertion failed'; END IF;
END $$;
-- +goose StatementEnd
-- +goose Down
SELECT 1;
