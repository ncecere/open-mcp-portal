-- +goose Up
CREATE SCHEMA omp_audit;
REVOKE ALL ON SCHEMA omp_audit FROM PUBLIC;
ALTER TABLE public.audit_log ADD COLUMN txid xid8, ADD COLUMN row_uid uuid;
ALTER TABLE public.audit_log ADD CONSTRAINT audit_log_stream_identity CHECK (txid IS NOT NULL AND row_uid IS NOT NULL) NOT VALID;
-- +goose StatementBegin
CREATE FUNCTION omp_audit.stamp() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
BEGIN
 NEW.txid := pg_current_xact_id(); NEW.row_uid := gen_random_uuid(); RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER audit_log_stream_stamp BEFORE INSERT ON public.audit_log FOR EACH ROW EXECUTE FUNCTION omp_audit.stamp();
CREATE TABLE omp_audit.state (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 stream_id uuid NOT NULL, system_identifier text NOT NULL, timeline bigint NOT NULL,
 epoch integer NOT NULL CHECK (epoch>0), status text NOT NULL CHECK (status IN ('running','halted_incarnation','rebasing')),
 cursor_txid xid8 NOT NULL DEFAULT '0', cursor_id bigint NOT NULL DEFAULT 0,
 last_seq bigint NOT NULL DEFAULT 0 CHECK (last_seq>=0), last_chain_hash bytea NOT NULL CHECK (octet_length(last_chain_hash)=32), sweep_at timestamptz
);
INSERT INTO omp_audit.state (stream_id,system_identifier,timeline,epoch,status,last_chain_hash)
SELECT u, (pg_control_system()).system_identifier::text,
 ('x'||substr(pg_walfile_name(pg_current_wal_lsn()),1,8))::bit(32)::bigint, 1,'running',
 sha256(convert_to('OMP-AUDIT-EVIDENCE','UTF8')||decode('00','hex')||convert_to('GENESIS','UTF8')||decode('00','hex')||convert_to('V2','UTF8')||decode('00','hex')||uuid_send(u))
FROM (SELECT gen_random_uuid() u) x;
CREATE TABLE omp_audit.chain (
 seq bigint PRIMARY KEY CHECK (seq>0), kind text NOT NULL CHECK (kind IN ('entry','epoch_start','checkpoint')),
 row_uid uuid UNIQUE, legacy_id bigint UNIQUE, audit_id bigint, epoch integer NOT NULL CHECK (epoch>0),
 flags smallint NOT NULL CHECK (flags BETWEEN 0 AND 3), occurred_at timestamptz NOT NULL,
 summary_hash bytea NOT NULL CHECK (octet_length(summary_hash)=32), entry_hash bytea NOT NULL CHECK (octet_length(entry_hash)=32),
 chain_hash bytea NOT NULL CHECK (octet_length(chain_hash)=32), sealed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK ((kind='entry' AND (row_uid IS NOT NULL)::int+(legacy_id IS NOT NULL)::int=1) OR (kind<>'entry' AND row_uid IS NULL AND legacy_id IS NULL))
);
-- +goose StatementBegin
CREATE FUNCTION omp_audit.append_only() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
BEGIN RAISE EXCEPTION 'audit chain is append-only'; END $$;
-- +goose StatementEnd
CREATE TRIGGER chain_append_only BEFORE UPDATE OR DELETE ON omp_audit.chain FOR EACH ROW EXECUTE FUNCTION omp_audit.append_only();
-- +goose StatementBegin
CREATE FUNCTION omp_audit.scalar(v bytea) RETURNS bytea LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
 SELECT CASE WHEN v IS NULL THEN decode('00','hex') ELSE decode('01','hex')||int4send(octet_length(v))||v END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit.fixed(v bytea) RETURNS bytea LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
 SELECT CASE WHEN v IS NULL THEN decode('00','hex') ELSE decode('01','hex')||v END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit.summary(a public.audit_log) RETURNS bytea LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
 SELECT sha256(decode('4f4d502d41554449542d53554d4d41525900563100','hex')||
omp_audit.fixed(int8send((extract(epoch FROM a.occurred_at)*1000000)::bigint))||
omp_audit.scalar(convert_to(a.action,'UTF8'))||
omp_audit.scalar(convert_to(a.actor_kind,'UTF8'))||
omp_audit.fixed(uuid_send(a.actor_user_id))||
omp_audit.fixed(uuid_send(a.team_id))||
omp_audit.scalar(convert_to(a.target_type,'UTF8'))||
omp_audit.scalar(convert_to(a.target_id,'UTF8'))||
omp_audit.scalar(convert_to(a.request_id,'UTF8'))||
omp_audit.fixed(uuid_send(a.actor_token_id)))
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit.seal_batch(mode text, records jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE s omp_audit.state%ROWTYPE; a public.audit_log%ROWTYPE; r jsonb;
 n bigint := 0; sh bytea; eh bytea; ch bytea; ident bytea; uid uuid; lid bigint; seq bigint; flags integer;
BEGIN
 IF mode IS NULL OR mode NOT IN ('history','fast','rebase') OR records IS NULL OR jsonb_typeof(records)<>'array' THEN RAISE EXCEPTION 'invalid batch'; END IF;
 IF jsonb_array_length(records) NOT BETWEEN 1 AND 1000 THEN RAISE EXCEPTION 'invalid batch length'; END IF;
 SELECT * INTO STRICT s FROM omp_audit.state WHERE singleton FOR UPDATE;
 IF (mode='rebase' AND s.status<>'rebasing') OR (mode<>'rebase' AND s.status<>'running') THEN RAISE EXCEPTION 'stale stream status' USING ERRCODE='40001'; END IF;
 IF mode='fast' AND EXISTS (SELECT 1 FROM public.audit_log h WHERE h.txid IS NULL AND NOT EXISTS (SELECT 1 FROM omp_audit.chain c WHERE c.legacy_id=h.id)) THEN RAISE EXCEPTION 'history pending'; END IF;
 FOR r IN SELECT value FROM jsonb_array_elements(records) LOOP
  seq := (r->>'seq')::bigint; flags := (r->>'flags')::integer;
  uid := (r->>'row_uid')::uuid; lid := (r->>'legacy_id')::bigint;
  IF seq IS NULL OR seq<>s.last_seq+1 OR flags IS NULL OR flags NOT BETWEEN 0 AND 3 OR r->>'kind' IS DISTINCT FROM 'entry' OR (uid IS NULL)=(lid IS NULL) THEN RAISE EXCEPTION 'invalid record'; END IF;
  IF uid IS NOT NULL THEN
   SELECT * INTO STRICT a FROM public.audit_log WHERE id=(r->>'audit_id')::bigint AND row_uid=uid;
  ELSE
   SELECT * INTO STRICT a FROM public.audit_log WHERE id=lid AND txid IS NULL;
  END IF;
  IF EXISTS (SELECT 1 FROM omp_audit.chain c WHERE c.row_uid=uid OR c.legacy_id=lid) THEN RAISE EXCEPTION 'stale identity' USING ERRCODE='40001'; END IF;
  IF mode='history' AND a.txid IS NOT NULL THEN RAISE EXCEPTION 'not history'; END IF;
  IF mode='fast' THEN
   IF a.txid IS NULL OR (a.txid,a.id)<=(s.cursor_txid,s.cursor_id) OR a.txid>=pg_snapshot_xmin(pg_current_snapshot()) THEN RAISE EXCEPTION 'cursor regression or unsafe watermark'; END IF;
  END IF;
  sh := decode(r->>'summary_hash','hex'); eh := decode(r->>'entry_hash','hex'); ch := decode(r->>'chain_hash','hex');
  IF sh IS NULL OR eh IS NULL OR ch IS NULL OR octet_length(sh)<>32 OR octet_length(eh)<>32 OR octet_length(ch)<>32 THEN RAISE EXCEPTION 'invalid digest'; END IF;
  IF sh<>omp_audit.summary(a) THEN RAISE EXCEPTION 'summary mismatch'; END IF;
  ident := CASE WHEN uid IS NULL THEN decode('ffffffffffffffff','hex')||int8send(lid) ELSE uuid_send(uid) END;
  IF ch<>sha256(decode('4f4d502d41554449542d45564944454e434500434841494e00563200','hex')||s.last_chain_hash||decode('0201','hex')||decode(lpad(to_hex(flags),2,'0'),'hex')||uuid_send(s.stream_id)||int4send(s.epoch)||int8send(seq)||ident||int8send((extract(epoch FROM a.occurred_at)*1000000)::bigint)||sh||eh) THEN RAISE EXCEPTION 'chain mismatch'; END IF;
  INSERT INTO omp_audit.chain(seq,kind,row_uid,legacy_id,audit_id,epoch,flags,occurred_at,summary_hash,entry_hash,chain_hash)
  VALUES(seq,'entry',uid,lid,a.id,s.epoch,flags,a.occurred_at,sh,eh,ch);
  s.last_seq := seq; s.last_chain_hash := ch;
  IF mode='fast' THEN s.cursor_txid:=a.txid; s.cursor_id:=a.id; END IF;
  n:=n+1;
 END LOOP;
 UPDATE omp_audit.state SET last_seq=s.last_seq,last_chain_hash=s.last_chain_hash,cursor_txid=s.cursor_txid,cursor_id=s.cursor_id WHERE singleton;
 RETURN n;
END $$;
-- +goose StatementEnd
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA omp_audit FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA omp_audit FROM PUBLIC;
-- +goose Down
SELECT 1;
