package httpapi

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/auditstream"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/notify"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// This explicit projection is shared by responses and audit metadata. Never
// serialize a database sink model: it carries sealed destination credentials.
const sinkView = `jsonb_build_object('id',id,'name',name,'kind',kind,'profile',profile,'required',required,'enabled',enabled,'batch_max_records',batch_max_records,'revision',revision,'url_hint',url_hint,'cursor_seq',cursor_seq,'state',state,'last_error_class',last_error_class,'consecutive_failures',consecutive_failures,'gap_first',gap_first,'gap_last',gap_last,'lag',greatest(0,(SELECT last_seq FROM omp_audit.state)-cursor_seq),'retention_effect',CASE WHEN NOT required THEN 'not holding' WHEN NOT enabled THEN 'holding-while-disabled' ELSE 'holding' END,'held_oversized_seq',CASE WHEN required AND profile='full' AND EXISTS(SELECT 1 FROM omp_audit.chain WHERE seq=cursor_seq+1 AND flags&2<>0) THEN cursor_seq+1 END)`

func (a *api) sinkRoutes() []route {
	return []route{
		{"GET", "/v1/admin/settings/audit-sinks", a.admin(a.auditSinks)},
		{"POST", "/v1/admin/settings/audit-sinks", a.admin(a.auditSinkChange)},
		{"GET", "/v1/admin/settings/audit-sinks/{id}", a.admin(a.auditSinks)},
		{"PUT", "/v1/admin/settings/audit-sinks/{id}", a.admin(a.auditSinkChange)},
		{"DELETE", "/v1/admin/settings/audit-sinks/{id}", a.admin(a.auditSinkChange)},
		{"POST", "/v1/admin/settings/audit-sinks/{id}/rotate-secret", a.admin(a.auditSinkChange)},
		{"POST", "/v1/admin/settings/audit-sinks/{id}/test", a.admin(a.auditSinkChange)},
		{"POST", "/v1/admin/settings/audit-sinks/{id}/resume", a.admin(a.auditSinkChange)},
		{"POST", "/v1/admin/settings/audit-sinks/{id}/oversized/{seq}/acknowledge", a.admin(a.auditSinkChange)},
		{"GET", "/v1/admin/audit/stream/status", a.admin(a.auditStreamStatus)},
	}
}
func (a *api) auditSinks(w http.ResponseWriter, r *http.Request) {
	if a.actor(r).IsToken() {
		httpx.Error(w, 403, "token_not_allowed", "Browser session required")
		return
	}
	var raw []byte
	if id := r.PathValue("id"); id != "" {
		uid, e := uuid.Parse(id)
		if e != nil {
			httpx.Error(w, 400, "invalid_sink", "Invalid sink id")
			return
		}
		e = a.Pool.QueryRow(r.Context(), `SELECT `+sinkView+` FROM omp_audit_ext.sinks WHERE id=$1`, uid).Scan(&raw)
		if errors.Is(e, pgx.ErrNoRows) {
			httpx.Error(w, 404, "sink_not_found", "Sink not found")
			return
		}
		if failed(w, r, e) {
			return
		}
	} else {
		if failed(w, r, a.Pool.QueryRow(r.Context(), `SELECT coalesce(jsonb_agg(v ORDER BY v->>'name'),'[]') FROM (SELECT `+sinkView+` v FROM omp_audit_ext.sinks) s`).Scan(&raw)) {
			return
		}
	}
	httpx.JSON(w, 200, json.RawMessage(raw))
}
func (a *api) auditStreamStatus(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	e := a.Pool.QueryRow(r.Context(), `SELECT jsonb_build_object('tip',to_jsonb(s),'sink_settings',(SELECT to_jsonb(g) FROM omp_audit_ext.sink_settings g),'sinks',(SELECT coalesce(jsonb_agg(v),'[]') FROM (SELECT `+sinkView+` v FROM omp_audit_ext.sinks) x),'consumers',(SELECT coalesce(jsonb_agg(to_jsonb(c)||jsonb_build_object('lag',greatest(0,s.last_seq-c.acked_seq))),'[]') FROM omp_audit.consumers c),'checkpoint_keys',(SELECT coalesce(jsonb_agg(jsonb_build_object('kid',encode(kid,'hex'),'state',state,'active_from_seq',active_from_seq,'retired_at_seq',retired_at_seq)),'[]') FROM omp_audit_ext.checkpoint_keys)) FROM omp_audit.state s`).Scan(&raw)
	if !failed(w, r, e) {
		httpx.JSON(w, 200, json.RawMessage(raw))
	}
}
func (a *api) sinkBox() (*secrets.Box, error) {
	k, e := secrets.ParseKey(a.Config.EncryptionKey)
	if e != nil {
		return nil, e
	}
	var prev [][]byte
	if a.Config.EncryptionKeyPrevious != "" {
		p, e := secrets.ParseKey(a.Config.EncryptionKeyPrevious)
		if e != nil {
			return nil, e
		}
		prev = append(prev, p)
	}
	return secrets.New(k, prev...)
}
func sinkError(w http.ResponseWriter, r *http.Request, e error) bool {
	if e == nil {
		return false
	}
	var pe *pgconn.PgError
	if errors.As(e, &pe) {
		if pe.Code == "22023" {
			httpx.Error(w, 400, "invalid_sink", "Invalid sink settings")
			return true
		}
		if pe.Code == "P0002" {
			httpx.Error(w, 404, "sink_not_found", "Sink not found")
			return true
		}
		reason := "Sink transition refused; refresh the revision and cursor"
		if pe.Message == "sink recovery required" {
			reason = "Resume and deliver the pending gap before promoting this sink to required"
		}
		if pe.Code == "40001" || pe.Code == "P0001" || pe.Code == "23505" {
			httpx.Error(w, 409, "sink_conflict", reason)
			return true
		}
	}
	// Do not forward SQL detail, destination URLs or crypto errors to logging.
	httpx.Error(w, 500, "sink_failed", "Sink operation failed")
	return true
}
func (a *api) auditSinkChange(w http.ResponseWriter, r *http.Request) {
	if !a.consumerAdmin(w, r) {
		return
	}
	create := r.Method == "POST" && r.PathValue("id") == ""
	var rev int64
	if !create {
		var ok bool
		rev, ok = ifMatch(w, r)
		if !ok {
			return
		}
	}
	var in apitypes.AuditSinkRequest
	resume := strings.HasSuffix(r.URL.Path, "/resume")
	if create || r.Method == "PUT" || resume {
		if !httpx.Decode(w, r, &in) {
			return
		}
	}
	id := uuid.New()
	if !create {
		var e error
		id, e = uuid.Parse(r.PathValue("id"))
		if e != nil {
			httpx.Error(w, 400, "invalid_sink", "Invalid sink id")
			return
		}
	}
	if in.BatchMaxRecords != nil && (*in.BatchMaxRecords < 1 || *in.BatchMaxRecords > 1000) {
		httpx.Error(w, 400, "invalid_sink", "batch_max_records must be 1-1000")
		return
	}
	client := a.AuditSinkClient
	if client == nil {
		client = notify.NewWebhookClient(a.Config.AuditStreamAllowedNetworks, a.Log)
	}
	if in.Url != nil {
		if e := notify.CheckWebhookURL(r.Context(), client, *in.Url, 2048, true); e != nil {
			httpx.Error(w, 422, "invalid_sink_url", "Destination violates audit sink URL policy")
			return
		}
	}
	box, e := a.sinkBox()
	if sinkError(w, r, e) {
		return
	}
	var out, before json.RawMessage
	var shown string
	test := strings.HasSuffix(r.URL.Path, "/test")
	e = pgx.BeginFunc(r.Context(), a.Pool, func(tx pgx.Tx) error {
		var name, profile, hint, secretHint string
		var required, enabled bool
		var batch int32
		var current, cursor int64
		var uc, sc, pc []byte
		var until *time.Time
		if create {
			profile = "summary"
			enabled = true
			batch = 100
		} else {
			e := tx.QueryRow(r.Context(), `SELECT name,profile,required,enabled,batch_max_records,revision,cursor_seq,url_cipher,url_hint,secret_cipher,secret_previous_cipher,secret_previous_until,secret_hint,`+sinkView+` FROM omp_audit_ext.sinks WHERE id=$1`, id).Scan(&name, &profile, &required, &enabled, &batch, &current, &cursor, &uc, &hint, &sc, &pc, &until, &secretHint, &before)
			if e != nil {
				return e
			}
			if current != rev {
				return apperr.Conflict("sink_conflict", "Stale sink revision")
			}
		}
		if in.Name != nil {
			name = *in.Name
		}
		if in.Profile != nil {
			profile = string(*in.Profile)
		}
		if in.Required != nil {
			required = *in.Required
		}
		if in.Enabled != nil {
			enabled = *in.Enabled
		}
		if in.BatchMaxRecords != nil {
			batch = int32(*in.BatchMaxRecords)
		}
		if create && (in.Name == nil || in.Url == nil) {
			return apperr.Invalid("invalid_sink", "name and url required")
		}
		if in.Url != nil {
			u, _ := url.Parse(*in.Url)
			hint = u.Hostname()
			var e error
			uc, e = box.Seal([]byte(*in.Url), auditstream.SinkAAD(id, "url"))
			if e != nil {
				return e
			}
		}
		rotate := strings.HasSuffix(r.URL.Path, "/rotate-secret")
		if create || rotate {
			if rotate {
				old, e := box.Open(sc, auditstream.SinkAAD(id, "secret"))
				if e != nil {
					return e
				}
				defer clear(old)
				pc, e = box.Seal(old, auditstream.SinkAAD(id, "secret_previous"))
				if e != nil {
					return e
				}
				t := time.Now().Add(24 * time.Hour)
				until = &t
			}
			raw := make([]byte, 32)
			if _, e := rand.Read(raw); e != nil {
				return e
			}
			shown = base64.RawURLEncoding.EncodeToString(raw)
			clear(raw)
			var e error
			sc, e = box.Seal([]byte(shown), auditstream.SinkAAD(id, "secret"))
			if e != nil {
				return e
			}
			secretHint = shown[len(shown)-4:]
		}
		switch {
		case test:
			// No row lock is held during network I/O. The revision is checked again
			// before recording the action; a test never touches the delivery cursor.
		case resume:
			if in.CursorSeq == nil {
				return apperr.Invalid("cursor_required", "cursor_seq required")
			}
			_, e = tx.Exec(r.Context(), `SELECT omp_audit_ext.resume_sink($1,$2,$3)`, id, rev, *in.CursorSeq)
		case r.PathValue("seq") != "":
			seq, err := strconv.ParseInt(r.PathValue("seq"), 10, 64)
			if err != nil {
				return apperr.Invalid("invalid_seq", "Invalid sequence")
			}
			_, e = tx.Exec(r.Context(), `SELECT omp_audit_ext.acknowledge_oversized($1,$2,$3)`, id, rev, seq)
		case r.Method == "DELETE":
			_, e = tx.Exec(r.Context(), `SELECT omp_audit_ext.delete_sink($1,$2)`, id, rev)
		case create:
			_, e = tx.Exec(r.Context(), `SELECT omp_audit_ext.create_sink($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, id, name, profile, required, enabled, batch, uc, hint, sc, pc, until, secretHint)
		default:
			_, e = tx.Exec(r.Context(), `SELECT omp_audit_ext.update_sink($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, id, rev, name, profile, required, enabled, batch, uc, hint, sc, pc, until, secretHint)
		}
		if e != nil {
			return e
		}
		if r.Method != "DELETE" {
			if e = tx.QueryRow(r.Context(), `SELECT `+sinkView+` FROM omp_audit_ext.sinks WHERE id=$1`, id).Scan(&out); e != nil {
				return e
			}
		}
		entry := a.actor(r).Audit("settings.audit_sink_change", "audit_sink", id.String())
		entry.Metadata = map[string]any{"action": r.Method + " " + r.Pattern, "before": before, "after": out}
		return audit.Record(r.Context(), dbgen.New(tx), entry)
	})
	// Preserve intentional validation failures, never raw database/transport errors.
	var ae *apperr.Error
	if errors.As(e, &ae) {
		failed(w, r, e)
		return
	}
	if sinkError(w, r, e) {
		return
	}
	if test {
		var uc, sc []byte
		if sinkError(w, r, a.Pool.QueryRow(r.Context(), `SELECT url_cipher,secret_cipher FROM omp_audit_ext.sinks WHERE id=$1 AND revision=$2`, id, rev).Scan(&uc, &sc)) {
			return
		}
		raw, e := box.Open(uc, auditstream.SinkAAD(id, "url"))
		if sinkError(w, r, e) {
			return
		}
		defer clear(raw)
		secret, e := box.Open(sc, auditstream.SinkAAD(id, "secret"))
		if sinkError(w, r, e) {
			return
		}
		defer clear(secret)
		body := []byte("{\"event\":\"audit.test\"}\n")
		req, e := http.NewRequestWithContext(r.Context(), "POST", string(raw), bytes.NewReader(body))
		if sinkError(w, r, e) {
			return
		}
		ts := time.Now().Unix()
		req.Header.Set("Content-Type", "application/x-ndjson")
		req.Header.Set(notify.HeaderEvent, "audit.test")
		req.Header.Set(notify.HeaderTimestamp, strconv.FormatInt(ts, 10))
		req.Header.Set(notify.HeaderSignature, notify.SignatureHeader(ts, body, string(secret)))
		httpx.JSON(w, 200, map[string]any{"error_class": auditstream.Send(auditstream.SinkHTTPClient(client), req)})
		return
	}
	httpx.JSON(w, 200, map[string]any{"sink": out, "secret": optionalSecret(shown)})
}
func optionalSecret(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
