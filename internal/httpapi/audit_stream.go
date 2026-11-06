package httpapi

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/auditstream"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"regexp"
)

func (a *api) auditStreamRoutes() []route {
	return []route{
		{"GET", "/.well-known/omp-audit-keys.json", http.HandlerFunc(a.auditKeys)},
		{"GET", "/v1/admin/audit/stream", a.admin(a.auditStream)},
		{"GET", "/v1/admin/audit/stream/tip", a.admin(a.auditTip)},
		{"GET", "/v1/admin/audit/verify", a.admin(a.auditVerify)},
		{"GET", "/v1/admin/audit/entries/{seq}/full", a.admin(a.auditFull)},
		{"POST", "/v1/admin/audit/stream/ack", a.admin(a.auditAck)},
		{"GET", "/v1/admin/settings/audit-consumers", a.admin(a.auditConsumers)},
		{"POST", "/v1/admin/settings/audit-consumers", a.admin(a.auditConsumerChange)},
		{"PUT", "/v1/admin/settings/audit-consumers/{consumer}", a.admin(a.auditConsumerChange)},
		{"DELETE", "/v1/admin/settings/audit-consumers/{consumer}", a.admin(a.auditConsumerChange)},
	}
}

var consumerNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func seqArg(s string, def int64) (int64, error) {
	if s == "" {
		return def, nil
	}
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n < 0 {
		return 0, fmt.Errorf("invalid sequence")
	}
	return n, nil
}
func streamFailure(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), "audit_row_missing") {
		httpx.Error(w, 500, "audit_row_missing", "A sealed audit row is missing")
		return
	}
	httpx.Internal(w, r, err)
}
func (a *api) snapshot(r *http.Request) (pgx.Tx, error) {
	return a.Pool.BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
}
func (a *api) auditStream(w http.ResponseWriter, r *http.Request) {
	after, err := seqArg(r.URL.Query().Get("after_seq"), 0)
	limit, e := seqArg(r.URL.Query().Get("limit"), 100)
	profile := r.URL.Query().Get("profile")
	if err != nil || e != nil || limit < 1 || limit > 1000 || (profile != "" && profile != "summary" && profile != "full") {
		httpx.Error(w, 400, "invalid_range", "Invalid stream range or profile")
		return
	}
	tx, err := a.snapshot(r)
	if failed(w, r, err) {
		return
	}
	defer tx.Rollback(r.Context())
	earliest, err := auditstream.CheckRange(r.Context(), tx, after, int(limit))
	if err != nil {
		if err.Error() == "range_expired" {
			httpx.ErrorDetails(w, 410, "range_expired", "Requested range expired", map[string]any{"earliest_seq": earliest})
		} else {
			streamFailure(w, r, err)
		}
		return
	}
	rows, err := tx.Query(r.Context(), `SELECT seq FROM omp_audit.chain WHERE seq>$1 ORDER BY seq LIMIT $2`, after, limit)
	if failed(w, r, err) {
		return
	}
	var seqs []int64
	for rows.Next() {
		var n int64
		if err = rows.Scan(&n); err != nil {
			break
		}
		if n != after+int64(len(seqs))+1 {
			rows.Close()
			observability.AuditStreamIntegrity.WithLabelValues("chain_gap").Inc()
			httpx.Error(w, 500, "audit_chain_gap", "Noncontiguous chain range")
			return
		}
		seqs = append(seqs, n)
	}
	rows.Close()
	if err == nil {
		err = rows.Err()
	}
	if failed(w, r, err) {
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	for _, n := range seqs {
		env, err := auditstream.Read(r.Context(), tx, n, profile == "full")
		if err != nil {
			return
		}
		raw, err := json.Marshal(env)
		if err != nil {
			return
		}
		if profile == "full" && (env.Flags&2 != 0 || len(raw)+1 > 16<<20) {
			env.Full = nil
			env.Oversized = true
			env.Reference = fmt.Sprintf("/v1/admin/audit/entries/%d/full", n)
			raw, err = json.Marshal(env)
			if err != nil {
				return
			}
		}
		if _, err = w.Write(append(raw, '\n')); err != nil {
			return
		}
	}
}
func (a *api) auditTip(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	err := a.Pool.QueryRow(r.Context(), `SELECT jsonb_build_object('stream_id',s.stream_id,'epoch',s.epoch,'last_seq',s.last_seq,'last_chain_hash',encode(s.last_chain_hash,'hex'),'earliest_seq',f.purged_seq+1,'advisory',true,'checkpoint',jsonb_build_object('checkpoints_enabled',coalesce(s.checkpoints_enabled,false),'min_reader_version',s.min_reader_version,'last_checkpoint_seq',s.last_checkpoint_seq,'last_checkpoint_at',s.last_checkpoint_at),'epochs',coalesce((SELECT jsonb_agg(jsonb_build_object('seq',seq,'epoch_summary',epoch_summary) ORDER BY seq) FROM omp_audit.chain WHERE kind='epoch_start'),'[]'::jsonb)) FROM omp_audit.state s CROSS JOIN omp_audit.retention_floor f`).Scan(&raw)
	if !failed(w, r, err) {
		httpx.JSON(w, 200, json.RawMessage(raw))
	}
}
func (a *api) auditAck(w http.ResponseWriter, r *http.Request) {
	var in apitypes.AuditConsumerRequest
	if !httpx.Decode(w, r, &in) {
		return
	}
	if in.Consumer == nil || in.Seq == nil {
		httpx.Error(w, 400, "invalid_ack", "consumer and seq required")
		return
	}
	_, err := a.Pool.Exec(r.Context(), `SELECT omp_audit.ack($1,$2)`, *in.Consumer, *in.Seq)
	if err != nil {
		code := "invalid_ack"
		if strings.Contains(err.Error(), "oversized_pending") {
			code = "oversized_pending"
			var pending []byte
			queryErr := a.Pool.QueryRow(r.Context(), `SELECT coalesce(jsonb_agg(seq ORDER BY seq),'[]'::jsonb) FROM (SELECT ch.seq FROM omp_audit.chain ch JOIN omp_audit.consumers c ON c.name=$1 WHERE ch.seq>c.acked_seq AND ch.seq<=$2 AND ch.flags&2<>0 AND NOT EXISTS(SELECT 1 FROM omp_audit.oversized_fetches f WHERE f.consumer=c.name AND f.seq=ch.seq) ORDER BY ch.seq LIMIT 1000) pending`, *in.Consumer, *in.Seq).Scan(&pending)
			if failed(w, r, queryErr) {
				return
			}
			httpx.ErrorDetails(w, 409, code, "Fetch these oversized entries before acknowledging", map[string]any{"seqs": json.RawMessage(pending), "limit": 1000})
			return
		}
		httpx.Error(w, 409, code, "Acknowledgement refused")
		return
	}
	writeOK(w, r, nil)
}
func (a *api) auditFull(w http.ResponseWriter, r *http.Request) {
	seq, err := seqArg(r.PathValue("seq"), 0)
	if err != nil || seq == 0 {
		httpx.Error(w, 400, "invalid_range", "Invalid sequence")
		return
	}
	consumer := r.URL.Query().Get("consumer")
	if consumer != "" {
		var exists bool
		err = a.Pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM omp_audit.consumers WHERE name=$1 AND profile='full')`, consumer).Scan(&exists)
		if failed(w, r, err) {
			return
		}
		if !exists {
			httpx.Error(w, 404, "consumer_not_found", "Full-profile consumer not found")
			return
		}
	}
	// Read under a snapshot so retention cannot truncate a response in progress.
	tx, err := a.snapshot(r)
	if failed(w, r, err) {
		return
	}
	defer tx.Rollback(r.Context())
	earliest, err := auditstream.CheckRange(r.Context(), tx, seq-1, 1)
	if err != nil {
		if err.Error() == "range_expired" {
			httpx.ErrorDetails(w, 410, "range_expired", "Requested range expired", map[string]any{"earliest_seq": earliest})
		} else {
			streamFailure(w, r, err)
		}
		return
	}
	var kind string
	if err := tx.QueryRow(r.Context(), `SELECT kind FROM omp_audit.chain WHERE seq=$1`, seq).Scan(&kind); err == nil && kind == "checkpoint" {
		env, e := auditstream.Read(r.Context(), tx, seq, true)
		if !failed(w, r, e) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(env)
		}
		return
	}
	// PostgreSQL sends bounded text chunks; no full snapshot is buffered in Go.
	var size int
	const source = `SELECT ` + auditstream.FullRowJSONSQL + ` body FROM omp_audit.chain c JOIN public.audit_log a ON a.id=c.audit_id AND (a.row_uid=c.row_uid OR (a.txid IS NULL AND a.id=c.legacy_id)) WHERE c.seq=$1`
	err = tx.QueryRow(r.Context(), `SELECT length(body) FROM (`+source+`) x`, seq).Scan(&size)
	if err == pgx.ErrNoRows {
		httpx.Error(w, 404, "not_found", "Entry not found")
		return
	}
	if failed(w, r, err) {
		return
	}

	rows, err := tx.Query(r.Context(), `WITH x AS MATERIALIZED (`+source+`) SELECT substr(body,n,16384) FROM x CROSS JOIN LATERAL generate_series(1,length(body),16384) n`, seq)
	if failed(w, r, err) {
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "application/json")
	for rows.Next() {
		var chunk string
		if rows.Scan(&chunk) != nil {
			return
		}
		if _, err = w.Write([]byte(chunk)); err != nil {
			return
		}
	}
	if rows.Err() != nil {
		return
	}

	var oversized bool
	if consumer != "" {
		err = tx.QueryRow(r.Context(), `SELECT flags&2<>0 FROM omp_audit.chain WHERE seq=$1`, seq).Scan(&oversized)
		if err != nil {
			return
		}
	}
	if consumer != "" && oversized {
		_, err = a.Pool.Exec(r.Context(), `SELECT omp_audit.record_oversized_fetch($1,$2)`, consumer, seq)
		if err != nil {
			a.Log.Error("audit fetch recording failed", "error", err)
		}
	}
}
func (a *api) auditVerify(w http.ResponseWriter, r *http.Request) {
	from, err := seqArg(r.URL.Query().Get("from"), 1)
	to, e := seqArg(r.URL.Query().Get("to"), from+999)
	if err != nil || e != nil || from < 1 || to < from || to-from >= 1000 {
		httpx.Error(w, 400, "invalid_range", "Verify 1 to 1000 records")
		return
	}
	tx, err := a.snapshot(r)
	if failed(w, r, err) {
		return
	}
	defer tx.Rollback(r.Context())
	var tip int64
	if err = tx.QueryRow(r.Context(), `SELECT last_seq FROM omp_audit.state WHERE singleton`).Scan(&tip); failed(w, r, err) {
		return
	}
	if from > tip {
		httpx.JSON(w, 200, map[string]any{"valid": true, "checked": 0})
		return
	}
	earliest, rangeErr := auditstream.CheckRange(r.Context(), tx, from-1, int(to-from+1))
	if rangeErr != nil {
		if rangeErr.Error() == "range_expired" {
			httpx.ErrorDetails(w, 410, "range_expired", "Requested range expired", map[string]any{"earliest_seq": earliest})
		} else {
			streamFailure(w, r, rangeErr)
		}
		return
	}

	first, err := auditstream.Read(r.Context(), tx, from, true)
	if err == pgx.ErrNoRows {
		httpx.JSON(w, 200, map[string]any{"valid": false, "first_bad_seq": from})
		return
	}
	if err != nil {
		httpx.JSON(w, 200, map[string]any{"valid": false, "first_bad_seq": from})
		return
	}
	anchor := from - 1
	if first.Kind == "epoch_start" && first.EpochSummary != nil {
		anchor = first.EpochSummary.PredecessorSeq
	}
	var prev [32]byte
	if anchor == 0 {
		prev = auditstream.Genesis(first.Stream)
	} else {
		var b []byte
		err = tx.QueryRow(r.Context(), `SELECT chain_hash FROM omp_audit.chain WHERE seq=$1`, anchor).Scan(&b)
		if err == pgx.ErrNoRows || (err == nil && len(b) != 32) {
			httpx.JSON(w, 200, map[string]any{"valid": false, "first_bad_seq": from})
			return
		}
		if failed(w, r, err) {
			return
		}
		copy(prev[:], b)
	}
	_, authorities, err := auditstream.CheckpointKeys(r.Context(), tx)
	if failed(w, r, err) {
		return
	}
	for n := from; n <= to; n++ {
		env := first
		var err error
		if n != from {
			env, err = auditstream.Read(r.Context(), tx, n, true)
		}
		if err == pgx.ErrNoRows {
			var tip int64
			if err = tx.QueryRow(r.Context(), `SELECT last_seq FROM omp_audit.state WHERE singleton`).Scan(&tip); err != nil {
				streamFailure(w, r, err)
				return
			}
			if n <= tip {
				httpx.JSON(w, 200, map[string]any{"valid": false, "first_bad_seq": n})
				return
			}
			break
		}
		if err != nil {
			httpx.JSON(w, 200, map[string]any{"valid": false, "first_bad_seq": n})
			return
		}
		ok := false
		if env.Kind == "entry" {
			ok, err = auditstream.VerifyEntry(env, prev)
		} else {
			ok = env.EpochSummary != nil
		} // epoch verification implemented by canonical helper below
		if env.Kind == "checkpoint" && env.Checkpoint != nil {
			err = auditstream.VerifyCheckpoint(env, *env.Checkpoint, prev, authorities)
			ok = err == nil
		}
		if env.Kind == "epoch_start" {
			ok = auditstream.VerifyEpoch(env, prev)
		}
		if err != nil || !ok {
			observability.AuditStreamIntegrity.WithLabelValues("digest_mismatch").Inc()
			httpx.JSON(w, 200, map[string]any{"valid": false, "first_bad_seq": n})
			return
		}
		b, _ := hex.DecodeString(env.Chain)
		copy(prev[:], b)
	}
	httpx.JSON(w, 200, map[string]any{"valid": true})
}
func (a *api) consumerAdmin(w http.ResponseWriter, r *http.Request) bool {
	if a.actor(r).Kind == "automation_token" {
		httpx.Error(w, 403, "token_not_allowed", "Browser session required")
		return false
	}
	if !a.actor(r).IsPlatformAdmin() {
		httpx.Error(w, 403, "forbidden", "Platform admin required")
		return false
	}
	return true
}
func (a *api) auditConsumers(w http.ResponseWriter, r *http.Request) {
	if !a.consumerAdmin(w, r) {
		return
	}
	var raw []byte
	var rev int64
	err := a.Pool.QueryRow(r.Context(), `SELECT consumer_revision,(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY name),'[]') FROM omp_audit.consumers c) FROM omp_audit.retention_floor`).Scan(&rev, &raw)
	if !failed(w, r, err) {
		writeRevised(w, 200, rev, map[string]any{"revision": rev, "items": json.RawMessage(raw)})
	}
}
func (a *api) auditConsumerChange(w http.ResponseWriter, r *http.Request) {
	if !a.consumerAdmin(w, r) {
		return
	}
	rev, ok := ifMatch(w, r)
	if !ok {
		return
	}
	var in apitypes.AuditConsumerRequest
	if r.Method != "DELETE" && !httpx.Decode(w, r, &in) {
		return
	}
	err := pgx.BeginFunc(r.Context(), a.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended('omp.audit-consumers',0))`); err != nil {
			return err
		}
		var current int64
		if err := tx.QueryRow(r.Context(), `SELECT consumer_revision FROM omp_audit.retention_floor WHERE singleton`).Scan(&current); err != nil {
			return err
		}
		if current != rev {
			return apperr.Stale()
		}
		name := r.PathValue("consumer")
		var err error
		switch r.Method {
		case "POST":
			if in.Consumer == nil || in.Profile == nil || in.Required == nil {
				return apperr.New(400, "invalid_consumer", "consumer, profile and required needed")
			}
			name = *in.Consumer
			if !consumerNameRE.MatchString(name) || (*in.Profile != "summary" && *in.Profile != "full") {
				return apperr.New(422, "invalid_consumer", "Invalid name or profile")
			}
			_, err = tx.Exec(r.Context(), `SELECT omp_audit.register_consumer($1,$2,$3,$4)`, name, *in.Profile, *in.Required, a.actor(r).UserID)
		case "PUT":
			if in.Required == nil {
				return apperr.New(400, "invalid_consumer", "required needed")
			}
			_, err = tx.Exec(r.Context(), `SELECT omp_audit.set_required($1,$2)`, name, *in.Required)
		case "DELETE":
			_, err = tx.Exec(r.Context(), `SELECT omp_audit.remove_consumer($1)`, name)
		}
		if err != nil {
			return err
		}
		entry := a.actor(r).Audit("settings.audit_consumer_update", "platform_settings", "audit_consumers")
		entry.Metadata = map[string]any{"method": r.Method, "name": name, "profile": in.Profile, "required": in.Required}
		return audit.Record(r.Context(), dbgen.New(tx), entry)
	})
	var pe *pgconn.PgError
	if errors.As(err, &pe) && (pe.Code == "P0001" || pe.Code == "P0002" || pe.Code == "23505") {
		httpx.Error(w, 409, "consumer_conflict", "Consumer configuration refused")
		return
	}
	writeOK(w, r, err)
}

func (a *api) auditKeys(w http.ResponseWriter, r *http.Request) {
	tx, err := a.snapshot(r)
	if failed(w, r, err) {
		return
	}
	defer tx.Rollback(r.Context())
	keys, _, err := auditstream.CheckpointKeys(r.Context(), tx)
	if failed(w, r, err) {
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}
