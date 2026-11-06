-- +goose Up
-- Expand-only: v0.14.0 owns the closed omp_audit object/grant boundary.
CREATE SCHEMA omp_audit_ext;
REVOKE ALL ON SCHEMA omp_audit_ext FROM PUBLIC;
CREATE TABLE omp_audit_ext.manifest (
 kind text NOT NULL CHECK (kind IN ('table','function')),
 identity text NOT NULL,
 privileges text[] NOT NULL,
 UNIQUE(kind,identity)
);
CREATE TABLE omp_audit_ext.checkpoint_keys (
 kid bytea PRIMARY KEY CHECK (octet_length(kid)=16),
 public_key bytea NOT NULL CHECK (octet_length(public_key)=32 AND kid=substring(sha256(public_key) FROM 1 FOR 16)),
 state text NOT NULL CHECK (state IN ('active','retired')),
 private_key_cipher bytea,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 active_from_seq bigint CHECK (active_from_seq>0),
 retired_at_seq bigint CHECK (retired_at_seq>=active_from_seq),
 CHECK ((state='active' AND private_key_cipher IS NOT NULL AND retired_at_seq IS NULL) OR
        (state='retired' AND private_key_cipher IS NULL AND retired_at_seq IS NOT NULL))
);
CREATE UNIQUE INDEX checkpoint_one_active ON omp_audit_ext.checkpoint_keys(state) WHERE state='active';
ALTER TABLE omp_audit.state ADD COLUMN checkpoints_enabled boolean,
 ADD COLUMN min_reader_version text, ADD COLUMN entries_since_checkpoint bigint CHECK (entries_since_checkpoint>=0),
 ADD COLUMN last_checkpoint_seq bigint, ADD COLUMN last_checkpoint_at timestamptz;
ALTER TABLE omp_audit.chain ADD COLUMN checkpoint_statement bytea, ADD COLUMN checkpoint_signatures bytea,
 ADD CONSTRAINT checkpoint_payload CHECK (
 (kind='checkpoint' AND checkpoint_statement IS NOT NULL AND checkpoint_signatures IS NOT NULL
  AND octet_length(checkpoint_signatures) IN (64,128)) OR
 (kind<>'checkpoint' AND checkpoint_statement IS NULL AND checkpoint_signatures IS NULL));
-- +goose StatementBegin
CREATE FUNCTION omp_audit_ext.ensure_checkpoint_key(new_kid bytea, new_public bytea, new_cipher bytea)
RETURNS SETOF omp_audit_ext.checkpoint_keys
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE tip bigint;
BEGIN
 SELECT last_seq INTO STRICT tip FROM omp_audit.state WHERE singleton FOR UPDATE;
 IF new_kid IS NULL OR new_public IS NULL OR new_cipher IS NULL OR octet_length(new_cipher)=0
 OR octet_length(new_kid)<>16 OR octet_length(new_public)<>32 OR new_kid<>substring(sha256(new_public) FROM 1 FOR 16) THEN RAISE EXCEPTION 'invalid checkpoint key'; END IF;
 IF NOT EXISTS(SELECT 1 FROM omp_audit_ext.checkpoint_keys WHERE state='active') THEN
  INSERT INTO omp_audit_ext.checkpoint_keys(kid,public_key,state,private_key_cipher,active_from_seq)
  VALUES(new_kid,new_public,'active',new_cipher,tip+1);
 END IF;
 RETURN QUERY SELECT * FROM omp_audit_ext.checkpoint_keys WHERE state='active';
END $$;
-- +goose StatementEnd
-- Owner-only one-way transition. No runtime manifest grant.
-- +goose StatementBegin
CREATE FUNCTION omp_audit_ext.enable_checkpoints(min_reader_version text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE s omp_audit.state%ROWTYPE;
BEGIN
 SELECT * INTO STRICT s FROM omp_audit.state WHERE singleton FOR UPDATE;
 IF s.status<>'running' OR s.epoch_pending IS NOT NULL OR s.system_identifier<>(pg_control_system()).system_identifier::text
 OR s.timeline<>('x'||substr(pg_walfile_name(pg_current_wal_lsn()),1,8))::bit(32)::bigint THEN RAISE EXCEPTION 'stream not running in live incarnation'; END IF;
 IF min_reader_version IS NULL OR length(min_reader_version) NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'minimum reader version required'; END IF;
 IF s.checkpoints_enabled IS TRUE THEN
  IF s.min_reader_version IS DISTINCT FROM min_reader_version THEN RAISE EXCEPTION 'minimum reader version already set'; END IF;
  RETURN;
 END IF;
 UPDATE omp_audit.state SET checkpoints_enabled=true,min_reader_version=enable_checkpoints.min_reader_version,
 entries_since_checkpoint=0,last_checkpoint_at=clock_timestamp() WHERE singleton;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit_ext.rotate_checkpoint_key(new_kid bytea,new_public bytea,new_cipher bytea,statement bytea,signatures bytea) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE s omp_audit.state%ROWTYPE; old_kid bytea; raw bytea:=statement; sigs bytea:=signatures; expected bytea; micros bigint; t timestamptz; sh bytea; ch bytea;
BEGIN
 SELECT * INTO STRICT s FROM omp_audit.state WHERE singleton FOR UPDATE;
 IF new_kid IS NULL OR new_public IS NULL OR new_cipher IS NULL OR octet_length(new_cipher)=0 OR octet_length(new_kid)<>16 OR octet_length(new_public)<>32 OR new_kid<>substring(sha256(new_public) FROM 1 FOR 16)
 OR EXISTS(SELECT 1 FROM omp_audit_ext.checkpoint_keys WHERE kid=new_kid) THEN RAISE EXCEPTION 'invalid new checkpoint key'; END IF;

 IF s.checkpoints_enabled IS NOT TRUE OR s.status<>'running' OR s.epoch_pending IS NOT NULL
 OR s.system_identifier<>(pg_control_system()).system_identifier::text
 OR s.timeline<>('x'||substr(pg_walfile_name(pg_current_wal_lsn()),1,8))::bit(32)::bigint THEN
  RAISE EXCEPTION 'stale or disabled checkpoint state' USING ERRCODE='40001';
 END IF;
 SELECT kid INTO STRICT old_kid FROM omp_audit_ext.checkpoint_keys WHERE state='active';
 IF raw IS NULL OR sigs IS NULL OR octet_length(raw)<>133 OR octet_length(sigs)<>128 THEN RAISE EXCEPTION 'invalid checkpoint payload'; END IF;
 -- issued_at is the sole timestamp. Retain its exact signed microseconds.
 micros := (('x'||encode(substring(raw FROM 93 FOR 8),'hex'))::bit(64)::bigint);
 t := timestamptz 'epoch' + (micros / 1000000) * interval '1 second' + (micros % 1000000) * interval '1 microsecond';
 expected := decode('4f4d502d41554449542d434845434b504f494e5400563100','hex')||uuid_send(s.stream_id)||int4send(s.epoch)||int8send(s.last_seq+1)||int8send(s.last_seq)||s.last_chain_hash||int8send(micros)||decode('02','hex')||old_kid||new_kid;
 IF raw<>expected THEN RAISE EXCEPTION 'stale checkpoint statement' USING ERRCODE='40001'; END IF;
 sh := sha256(decode('4f4d502d41554449542d434845434b504f494e542d53554d4d41525900563100','hex')||raw||sigs);
 ch := sha256(decode('4f4d502d41554449542d45564944454e434500434841494e00563200','hex')||s.last_chain_hash||decode('020300','hex')||uuid_send(s.stream_id)||int4send(s.epoch)||int8send(s.last_seq+1)||decode(repeat('00',16),'hex')||int8send(micros)||sh||decode(repeat('00',32),'hex'));
 
 INSERT INTO omp_audit.chain(seq,kind,epoch,flags,occurred_at,summary_hash,entry_hash,chain_hash,checkpoint_statement,checkpoint_signatures)
 VALUES(s.last_seq+1,'checkpoint',s.epoch,0,t,sh,decode(repeat('00',32),'hex'),ch,raw,sigs);
 UPDATE omp_audit.state SET last_seq=s.last_seq+1,last_chain_hash=ch,entries_since_checkpoint=0,
 last_checkpoint_seq=s.last_seq+1,last_checkpoint_at=t WHERE singleton;

 UPDATE omp_audit_ext.checkpoint_keys SET state='retired',retired_at_seq=s.last_seq+1,private_key_cipher=NULL WHERE kid=old_kid;
 INSERT INTO omp_audit_ext.checkpoint_keys(kid,public_key,state,private_key_cipher,active_from_seq)
 VALUES(new_kid,new_public,'active',new_cipher,s.last_seq+1);
 INSERT INTO public.audit_log(actor_kind,action,target_type,target_id) VALUES('system','audit.checkpoint_key_rotated','audit_checkpoint_key',translate(rtrim(encode(new_kid,'base64'),'='),'+/','-_'));
 RETURN s.last_seq+1;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $patch$ DECLARE body text; patched text; needle text; replacement text; BEGIN
 body:=pg_get_functiondef('omp_audit.seal_batch(text,jsonb)'::regprocedure);
 IF position('retention_floor' IN body)=0 OR position('flags&1<>1' IN body)=0
 OR position('SET search_path TO' IN body)=0 OR position('SET "TimeZone" TO' IN body)=0 THEN RAISE EXCEPTION 'unexpected seal_batch baseline'; END IF;
 patched:=replace(body,'''sweep_done'',''sweep_begin''','''sweep_done'',''sweep_begin'',''checkpoint''');
 IF patched=body THEN RAISE EXCEPTION 'checkpoint mode patch did not apply'; END IF;
 needle:='n bigint := 0;';
 replacement:='raw bytea; sigs bytea; expected bytea; old_kid bytea; micros bigint; t timestamptz; n bigint := 0;';
 IF position(needle IN patched)=0 THEN RAISE EXCEPTION 'checkpoint declarations patch did not apply'; END IF;
 patched:=replace(patched,needle,replacement);
 needle:=' live_timeline :=';
 replacement:=$checkpoint$
 IF mode='checkpoint' THEN
  IF jsonb_array_length(records)<>1 THEN RAISE EXCEPTION 'checkpoint batch must contain one record'; END IF;
  r:=records->0; raw:=decode(r->>'checkpoint_statement','hex'); sigs:=decode(r->>'checkpoint_signatures','hex');

 IF s.checkpoints_enabled IS NOT TRUE OR s.status<>'running' OR s.epoch_pending IS NOT NULL
 OR s.system_identifier<>(pg_control_system()).system_identifier::text
 OR s.timeline<>('x'||substr(pg_walfile_name(pg_current_wal_lsn()),1,8))::bit(32)::bigint THEN
  RAISE EXCEPTION 'stale or disabled checkpoint state' USING ERRCODE='40001';
 END IF;
 SELECT kid INTO STRICT old_kid FROM omp_audit_ext.checkpoint_keys WHERE state='active';
 IF raw IS NULL OR sigs IS NULL OR octet_length(raw)<>117 OR octet_length(sigs)<>64 THEN RAISE EXCEPTION 'invalid checkpoint payload'; END IF;
 -- issued_at is the sole timestamp. Retain its exact signed microseconds.
 micros := (('x'||encode(substring(raw FROM 93 FOR 8),'hex'))::bit(64)::bigint);
 t := timestamptz 'epoch' + (micros / 1000000) * interval '1 second' + (micros % 1000000) * interval '1 microsecond';
 expected := decode('4f4d502d41554449542d434845434b504f494e5400563100','hex')||uuid_send(s.stream_id)||int4send(s.epoch)||int8send(s.last_seq+1)||int8send(s.last_seq)||s.last_chain_hash||int8send(micros)||decode('01','hex')||old_kid;
 IF raw<>expected THEN RAISE EXCEPTION 'stale checkpoint statement' USING ERRCODE='40001'; END IF;
 sh := sha256(decode('4f4d502d41554449542d434845434b504f494e542d53554d4d41525900563100','hex')||raw||sigs);
 ch := sha256(decode('4f4d502d41554449542d45564944454e434500434841494e00563200','hex')||s.last_chain_hash||decode('020300','hex')||uuid_send(s.stream_id)||int4send(s.epoch)||int8send(s.last_seq+1)||decode(repeat('00',16),'hex')||int8send(micros)||sh||decode(repeat('00',32),'hex'));
 IF r->>'kind' IS DISTINCT FROM 'checkpoint' OR (r->>'seq')::bigint IS DISTINCT FROM s.last_seq+1
 OR (r->>'flags')::int IS DISTINCT FROM 0 OR r->>'row_uid' IS NOT NULL OR r->>'legacy_id' IS NOT NULL OR r->>'audit_id' IS NOT NULL
 OR decode(r->>'summary_hash','hex') IS DISTINCT FROM sh OR decode(r->>'chain_hash','hex') IS DISTINCT FROM ch
 OR decode(r->>'entry_hash','hex') IS DISTINCT FROM decode(repeat('00',32),'hex') THEN RAISE EXCEPTION 'checkpoint record mismatch'; END IF;
 INSERT INTO omp_audit.chain(seq,kind,epoch,flags,occurred_at,summary_hash,entry_hash,chain_hash,checkpoint_statement,checkpoint_signatures)
 VALUES(s.last_seq+1,'checkpoint',s.epoch,0,t,sh,decode(repeat('00',32),'hex'),ch,raw,sigs);
 UPDATE omp_audit.state SET last_seq=s.last_seq+1,last_chain_hash=ch,entries_since_checkpoint=0,
 last_checkpoint_seq=s.last_seq+1,last_checkpoint_at=t WHERE singleton;

  RETURN 1;
 END IF;
 live_timeline :=$checkpoint$;
 IF position(needle IN patched)=0 THEN RAISE EXCEPTION 'checkpoint append patch did not apply'; END IF;
 patched:=replace(patched,needle,replacement);
 needle:='SET sweep_scan_id=s.sweep_scan_id,last_seq=s.last_seq';
 IF position(needle IN patched)=0 THEN RAISE EXCEPTION 'entry counter patch did not apply'; END IF;
 patched:=replace(patched,needle,'SET entries_since_checkpoint=coalesce(entries_since_checkpoint,0)+n,sweep_scan_id=s.sweep_scan_id,last_seq=s.last_seq');
 EXECUTE patched;
END $patch$;
-- +goose StatementEnd
INSERT INTO omp_audit_ext.manifest(kind,identity,privileges) VALUES
 ('table','omp_audit_ext.manifest',ARRAY['select']),
 ('table','omp_audit_ext.checkpoint_keys',ARRAY['select','update(private_key_cipher)']),
 ('function','omp_audit_ext.ensure_checkpoint_key(bytea,bytea,bytea)',ARRAY['execute']),
 ('function','omp_audit_ext.rotate_checkpoint_key(bytea,bytea,bytea,bytea,bytea)',ARRAY['execute']),
 ('function','omp_audit_ext.enable_checkpoints(text)',ARRAY[]::text[]);
REVOKE ALL ON ALL TABLES IN SCHEMA omp_audit_ext FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA omp_audit_ext FROM PUBLIC;
-- +goose StatementBegin
DO $$ DECLARE owner_name text; obj record; BEGIN
 SELECT pg_get_userbyid(relowner) INTO STRICT owner_name FROM pg_class WHERE oid='public.audit_log'::regclass;
 EXECUTE format('ALTER SCHEMA omp_audit_ext OWNER TO %I',owner_name);
 EXECUTE format('ALTER TABLE omp_audit_ext.manifest OWNER TO %I',owner_name);
 FOR obj IN SELECT * FROM omp_audit_ext.manifest WHERE identity<>'omp_audit_ext.manifest' LOOP
  EXECUTE format('ALTER %s %s OWNER TO %I',obj.kind,obj.identity,owner_name);
 END LOOP;
END $$;
-- +goose StatementEnd
-- +goose Down
SELECT 1;
