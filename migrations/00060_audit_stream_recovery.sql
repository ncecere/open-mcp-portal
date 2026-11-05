-- +goose Up
ALTER TABLE omp_audit.state ADD COLUMN sweep_scan_id bigint, ADD COLUMN sweep_started_xmin xid8, ADD COLUMN epoch_pending jsonb, ADD COLUMN rebase_f xid8, ADD COLUMN rebase_resume_after bigint, ADD COLUMN sweep_pending boolean NOT NULL DEFAULT false;
ALTER TABLE omp_audit.chain ADD COLUMN epoch_summary jsonb;
-- +goose StatementBegin
CREATE FUNCTION omp_audit.epoch_summary(e jsonb) RETURNS bytea LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
 SELECT sha256(convert_to('OMP-AUDIT-EPOCH','UTF8')||decode('00563100','hex')||
 int4send((e->>'previous_epoch')::integer)||int8send((e->>'predecessor_seq')::bigint)||decode(e->>'predecessor_hash','hex')||
 omp_audit.scalar(convert_to(e->>'reason','UTF8'))||
 omp_audit.scalar(convert_to(e->>'old_system_identifier','UTF8'))||int8send((e->>'old_timeline')::bigint)||
 omp_audit.scalar(convert_to(e->>'new_system_identifier','UTF8'))||int8send((e->>'new_timeline')::bigint)||
 omp_audit.fixed(int8send((e->>'gap_from')::bigint))||omp_audit.fixed(int8send((e->>'gap_to')::bigint)))
$$;
-- +goose StatementEnd
-- Internal owner-only primitive. State row is locked before constructing the declaration.
-- +goose StatementBegin
CREATE FUNCTION omp_audit.prepare_epoch(reason text, resume_after bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE s omp_audit.state%ROWTYPE; e jsonb; n bigint; t timestamptz := clock_timestamp(); live_id text; live_t bigint;
BEGIN
 SELECT * INTO STRICT s FROM omp_audit.state WHERE singleton FOR UPDATE;
 IF reason NOT IN ('timeline','rebase') OR reason IS NULL OR (resume_after IS NOT NULL AND (reason<>'rebase' OR resume_after<=s.last_seq)) THEN RAISE EXCEPTION 'invalid epoch transition'; END IF;
 live_id := (pg_control_system()).system_identifier::text;
 live_t := ('x'||substr(pg_walfile_name(pg_current_wal_lsn()),1,8))::bit(32)::bigint;
 n := coalesce(resume_after,s.last_seq)+1;
 e := jsonb_build_object('previous_epoch',s.epoch,'predecessor_seq',s.last_seq,'predecessor_hash',encode(s.last_chain_hash,'hex'),
 'reason',reason,'old_system_identifier',s.system_identifier,'old_timeline',s.timeline,'new_system_identifier',live_id,'new_timeline',live_t,
 'gap_from',CASE WHEN n>s.last_seq+1 THEN s.last_seq+1 END,'gap_to',CASE WHEN n>s.last_seq+1 THEN n-1 END);
 UPDATE omp_audit.state SET epoch=s.epoch+1,system_identifier=live_id,timeline=live_t,sweep_pending=true,sweep_scan_id=NULL,sweep_started_xmin=NULL,
 epoch_pending=jsonb_build_object('summary',e,'seq',n,'occurred_at',t) WHERE singleton;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION omp_audit.append_epoch(claim text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE s omp_audit.state%ROWTYPE; e jsonb; sh bytea; ch bytea; n bigint; t timestamptz;
BEGIN
 SELECT * INTO STRICT s FROM omp_audit.state WHERE singleton FOR UPDATE;
 IF s.epoch_pending IS NULL THEN RAISE EXCEPTION 'no pending epoch'; END IF;
 e := s.epoch_pending->'summary'; n := (s.epoch_pending->>'seq')::bigint; t := (s.epoch_pending->>'occurred_at')::timestamptz;
 sh := omp_audit.epoch_summary(e);
 IF claim IS NOT NULL AND decode(claim,'hex')<>sh THEN RAISE EXCEPTION 'epoch summary mismatch'; END IF;
 ch := sha256(decode('4f4d502d41554449542d45564944454e434500434841494e00563200','hex')||s.last_chain_hash||decode('020200','hex')||uuid_send(s.stream_id)||int4send(s.epoch)||int8send(n)||decode(repeat('00',16),'hex')||int8send((extract(epoch FROM t)*1000000)::bigint)||sh||decode(repeat('00',32),'hex'));
 INSERT INTO omp_audit.chain(seq,kind,epoch,flags,occurred_at,summary_hash,entry_hash,chain_hash,epoch_summary)
 VALUES(n,'epoch_start',s.epoch,0,t,sh,decode(repeat('00',32),'hex'),ch,e);
 UPDATE omp_audit.state SET last_seq=n,last_chain_hash=ch,epoch_pending=NULL WHERE singleton;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION omp_audit.seal_batch(mode text, records jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE s omp_audit.state%ROWTYPE; a public.audit_log%ROWTYPE; r jsonb;
 n bigint := 0; sh bytea; eh bytea; ch bytea; ident bytea; uid uuid; lid bigint; seq bigint; flags integer; sweep_end bigint;
BEGIN
 IF mode IS NULL OR mode NOT IN ('history','fast','rebase','sweep','check','epoch','sweep_done','sweep_begin') OR records IS NULL OR jsonb_typeof(records)<>'array' THEN RAISE EXCEPTION 'invalid batch'; END IF;
 IF mode NOT IN ('check','sweep_begin') AND jsonb_array_length(records) NOT BETWEEN 1 AND 1000 THEN RAISE EXCEPTION 'invalid batch length'; END IF;
 IF mode IN ('check','sweep_begin') AND jsonb_array_length(records)<>0 THEN RAISE EXCEPTION 'control batch must be empty'; END IF;
 SELECT * INTO STRICT s FROM omp_audit.state WHERE singleton FOR UPDATE;
 IF s.system_identifier<>(pg_control_system()).system_identifier::text THEN
  UPDATE omp_audit.state SET status='halted_incarnation' WHERE singleton;
  RETURN 0;
 END IF;
 IF s.status='running' AND s.timeline<>('x'||substr(pg_walfile_name(pg_current_wal_lsn()),1,8))::bit(32)::bigint THEN
  PERFORM omp_audit.prepare_epoch('timeline',NULL);
  PERFORM omp_audit.append_epoch(NULL);
  SELECT * INTO STRICT s FROM omp_audit.state WHERE singleton;
 END IF;
 IF mode='epoch' THEN
  IF s.status<>'rebasing' OR jsonb_array_length(records)<>1 OR records->0->>'kind' IS DISTINCT FROM 'epoch_start' OR records->0->>'summary_hash' IS NULL OR records->0->>'row_uid' IS NOT NULL OR records->0->>'legacy_id' IS NOT NULL OR coalesce((records->0->>'flags')::int,0)<>0 THEN RAISE EXCEPTION 'invalid epoch batch'; END IF;
  PERFORM omp_audit.append_epoch(records->0->>'summary_hash'); RETURN 1;
 END IF;
 IF mode='check' THEN RETURN 0; END IF;
 IF (mode='rebase' AND s.status<>'rebasing') OR (mode<>'rebase' AND s.status<>'running') THEN RAISE EXCEPTION 'stale stream status' USING ERRCODE='40001'; END IF;
 IF s.epoch_pending IS NOT NULL THEN RAISE EXCEPTION 'epoch start required'; END IF;
 IF mode='sweep_begin' THEN
  UPDATE omp_audit.state SET sweep_started_xmin=pg_snapshot_xmin(pg_current_snapshot()) WHERE singleton AND sweep_started_xmin IS NULL;
  RETURN 0;
 END IF;
 IF mode='sweep_done' THEN
  IF jsonb_array_length(records)<>1 THEN RAISE EXCEPTION 'invalid sweep advance'; END IF;
  lid := (records->0->>'end')::bigint;
  IF lid IS NULL THEN
   IF EXISTS(SELECT 1 FROM public.audit_log WHERE id>=coalesce(s.sweep_scan_id,'-9223372036854775808'::bigint) AND (s.sweep_scan_id IS NULL OR id>s.sweep_scan_id)) THEN RAISE EXCEPTION 'unfinished sweep'; END IF;
   UPDATE omp_audit.state SET sweep_at=clock_timestamp(),sweep_pending=(rebase_f IS NOT NULL AND rebase_f>=coalesce(s.sweep_started_xmin,'0'::xid8)),sweep_scan_id=NULL,sweep_started_xmin=NULL WHERE singleton;
  ELSE
   IF lid<s.sweep_scan_id OR lid>(SELECT max(id) FROM (SELECT id FROM public.audit_log WHERE id>=coalesce(s.sweep_scan_id,'-9223372036854775808'::bigint) AND (s.sweep_scan_id IS NULL OR id>s.sweep_scan_id) ORDER BY id LIMIT 5000) w) THEN RAISE EXCEPTION 'unbounded sweep advance'; END IF;
   IF EXISTS(SELECT 1 FROM public.audit_log g WHERE g.id>=coalesce(s.sweep_scan_id,'-9223372036854775808'::bigint) AND (s.sweep_scan_id IS NULL OR g.id>s.sweep_scan_id) AND g.id<=lid AND
     ((g.txid IS NULL AND g.id<=s.history_id) OR (g.txid IS NOT NULL AND (g.txid,g.id)<=(s.cursor_txid,s.cursor_id) AND g.txid<pg_snapshot_xmin(pg_current_snapshot()))) AND
     NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.row_uid=g.row_uid) AND (g.txid IS NOT NULL OR NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.legacy_id=g.id))) THEN RAISE EXCEPTION 'sweep advance skips gap'; END IF;
   UPDATE omp_audit.state SET sweep_scan_id=lid WHERE singleton;
  END IF;
  RETURN 0;
 END IF;
 -- Index probes only (00059's partial indexes): no per-batch scan of audit_log.
 IF mode='fast' AND EXISTS (SELECT 1 FROM public.audit_log h WHERE h.txid IS NULL AND h.id>s.history_id AND NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.legacy_id=h.id)) THEN RAISE EXCEPTION 'history pending'; END IF;
 IF mode='sweep' THEN
  SELECT max(id) INTO sweep_end FROM (SELECT id FROM public.audit_log WHERE id>=coalesce(s.sweep_scan_id,'-9223372036854775808'::bigint) AND (s.sweep_scan_id IS NULL OR id>s.sweep_scan_id) ORDER BY id LIMIT 5000) w;
 END IF;
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
  IF mode='sweep' THEN
   IF sweep_end IS NULL OR a.id>sweep_end OR (s.sweep_scan_id IS NOT NULL AND a.id<=s.sweep_scan_id) THEN RAISE EXCEPTION 'row outside sweep window'; END IF;
   IF flags<>1 OR NOT ((a.txid IS NULL AND a.id<=s.history_id) OR
     (a.txid IS NOT NULL AND (a.txid,a.id)<=(s.cursor_txid,s.cursor_id) AND a.txid<pg_snapshot_xmin(pg_current_snapshot()))) THEN
    RAISE EXCEPTION 'row still owned by normal sealer';
   END IF;
   IF (SELECT g.id FROM public.audit_log g WHERE g.id>=coalesce(s.sweep_scan_id,'-9223372036854775808'::bigint) AND (s.sweep_scan_id IS NULL OR g.id>s.sweep_scan_id) AND
      ((g.txid IS NULL AND g.id<=s.history_id) OR (g.txid IS NOT NULL AND (g.txid,g.id)<=(s.cursor_txid,s.cursor_id) AND g.txid<pg_snapshot_xmin(pg_current_snapshot())))
      AND NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.row_uid=g.row_uid OR (g.txid IS NULL AND c.legacy_id=g.id)) ORDER BY g.id LIMIT 1) IS DISTINCT FROM a.id THEN RAISE EXCEPTION 'sweep gap'; END IF;
  ELSIF flags&1<>0 THEN RAISE EXCEPTION 'late flag requires sweep'; END IF;
  IF mode='history' THEN
   IF a.txid IS NOT NULL OR lid<=s.history_id THEN RAISE EXCEPTION 'not history or history regression'; END IF;
   -- A caller cannot skip history: this must be the next history row after the cursor
   -- (an index probe on audit_log_history_idx).
   IF (SELECT min(g.id) FROM public.audit_log g WHERE g.txid IS NULL AND g.id>s.history_id AND NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.legacy_id=g.id)) IS DISTINCT FROM lid THEN RAISE EXCEPTION 'history gap'; END IF;
  END IF;
  IF mode='fast' THEN
   IF a.txid IS NULL OR (a.txid,a.id)<=(s.cursor_txid,s.cursor_id) OR a.txid>=pg_snapshot_xmin(pg_current_snapshot()) THEN RAISE EXCEPTION 'cursor regression or unsafe watermark'; END IF;
   -- A caller cannot skip rows: this must be the next unchained row after the cursor (rows
   -- a rebase already sealed are passed over). Any earlier row has a txid below this row's,
   -- which is below the watermark, so it is committed and visible: no false positives.
   -- Written as ORDER BY ... LIMIT 1 so the plan is an ordered index scan with a unique-index
   -- probe per row, not a range anti-join the planner cannot estimate for xid8 rows.
   IF (SELECT g.row_uid FROM public.audit_log g WHERE g.txid IS NOT NULL AND (g.txid,g.id)>(s.cursor_txid,s.cursor_id)
       AND NOT EXISTS (SELECT 1 FROM omp_audit.chain c WHERE c.row_uid=g.row_uid) ORDER BY g.txid,g.id LIMIT 1) IS DISTINCT FROM uid THEN RAISE EXCEPTION 'watermark gap'; END IF;
  END IF;
  sh := decode(r->>'summary_hash','hex'); eh := decode(r->>'entry_hash','hex'); ch := decode(r->>'chain_hash','hex');
  IF sh IS NULL OR eh IS NULL OR ch IS NULL OR octet_length(sh)<>32 OR octet_length(eh)<>32 OR octet_length(ch)<>32 THEN RAISE EXCEPTION 'invalid digest'; END IF;
  IF sh<>omp_audit.summary(a) THEN RAISE EXCEPTION 'summary mismatch'; END IF;
  ident := CASE WHEN uid IS NULL THEN decode('ffffffffffffffff','hex')||int8send(lid) ELSE uuid_send(uid) END;
  IF ch<>sha256(decode('4f4d502d41554449542d45564944454e434500434841494e00563200','hex')||s.last_chain_hash||decode('0201','hex')||decode(lpad(to_hex(flags),2,'0'),'hex')||uuid_send(s.stream_id)||int4send(s.epoch)||int8send(seq)||ident||int8send((extract(epoch FROM a.occurred_at)*1000000)::bigint)||sh||eh) THEN RAISE EXCEPTION 'chain mismatch'; END IF;
  INSERT INTO omp_audit.chain(seq,kind,row_uid,legacy_id,audit_id,epoch,flags,occurred_at,summary_hash,entry_hash,chain_hash)
  VALUES(seq,'entry',uid,lid,a.id,s.epoch,flags,a.occurred_at,sh,eh,ch);
  s.last_seq := seq; s.last_chain_hash := ch;
  IF mode='sweep' THEN s.sweep_scan_id:=a.id; END IF;
  IF mode='fast' THEN s.cursor_txid:=a.txid; s.cursor_id:=a.id; END IF;
  -- Rebase visits the frozen legacy set in id order too. Advancing its
  -- separate history cursor keeps normal lag probes off the rebased prefix.
  IF mode IN ('history','rebase') AND lid IS NOT NULL THEN s.history_id:=greatest(s.history_id,lid); END IF;
  n:=n+1;
 END LOOP;
 UPDATE omp_audit.state SET sweep_scan_id=s.sweep_scan_id,last_seq=s.last_seq,last_chain_hash=s.last_chain_hash,cursor_txid=s.cursor_txid,cursor_id=s.cursor_id,history_id=s.history_id WHERE singleton;
 RETURN n;
END $$;
-- +goose StatementEnd
-- CREATE OR REPLACE retains the existing owner and explicit runtime ACL. All
-- helpers are owner-only; the reconciler grants only seal_batch to runtime.
REVOKE ALL ON FUNCTION omp_audit.epoch_summary(jsonb), omp_audit.prepare_epoch(text,bigint), omp_audit.append_epoch(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION omp_audit.seal_batch(text,jsonb) FROM PUBLIC;
-- Explicitly bind all new/replaced functions to the protected table owner.
-- ALTER OWNER does not change retained explicit runtime EXECUTE on seal_batch.
-- +goose StatementBegin
DO $$ DECLARE owner_name text; f text; BEGIN
 SELECT pg_get_userbyid(relowner) INTO STRICT owner_name FROM pg_class WHERE oid='public.audit_log'::regclass;
 FOREACH f IN ARRAY ARRAY['epoch_summary(jsonb)','prepare_epoch(text,bigint)','append_epoch(text)','seal_batch(text,jsonb)'] LOOP
  EXECUTE format('ALTER FUNCTION omp_audit.%s OWNER TO %I',f,owner_name);
 END LOOP;
END $$;
-- +goose StatementEnd
-- +goose Down
SELECT 1;
