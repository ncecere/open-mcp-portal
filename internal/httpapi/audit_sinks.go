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
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// This explicit projection is shared by responses and audit metadata. Never
// serialize a database sink model: it carries sealed destination credentials.
const sinkView = `jsonb_build_object('id',id,'name',name,'kind',kind,'profile',profile,'required',required,'enabled',enabled,'batch_max_records',batch_max_records,'revision',revision,'url_hint',url_hint,'cursor_seq',cursor_seq,'state',state,'last_error_class',last_error_class,'consecutive_failures',consecutive_failures,'last_ok_at',last_ok_at,'gap_first',gap_first,'gap_last',gap_last,'lag',greatest(0,(SELECT last_seq FROM omp_audit.state)-cursor_seq),'retention_effect',CASE WHEN NOT required THEN 'not holding' WHEN NOT enabled THEN 'holding-while-disabled' ELSE 'holding' END,'held_oversized_seq',CASE WHEN required AND profile='full' AND EXISTS(SELECT 1 FROM omp_audit.chain WHERE seq=cursor_seq+1 AND flags&2<>0) THEN cursor_seq+1 END)`

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
	w.Header().Set("Cache-Control", "no-store")
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
		var view struct {
			Revision int64 `json:"revision"`
		}
		if json.Unmarshal(raw, &view) == nil {
			setETag(w, view.Revision)
		}
	} else {
		if failed(w, r, a.Pool.QueryRow(r.Context(), `SELECT jsonb_build_object('items',coalesce(jsonb_agg(v ORDER BY v->>'name'),'[]')) FROM (SELECT `+sinkView+` v FROM omp_audit_ext.sinks) s`).Scan(&raw)) {
			return
		}
	}
	httpx.JSON(w, 200, json.RawMessage(raw))
}
func (a *api) auditStreamStatus(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	e := a.Pool.QueryRow(r.Context(), `SELECT jsonb_build_object('sealer_enabled',$1::boolean,'tip',to_jsonb(s),'sink_settings',(SELECT to_jsonb(g) FROM omp_audit_ext.sink_settings g),'sinks',(SELECT coalesce(jsonb_agg(v),'[]') FROM (SELECT `+sinkView+` v FROM omp_audit_ext.sinks) x),'consumers',(SELECT coalesce(jsonb_agg(to_jsonb(c)||jsonb_build_object('lag',greatest(0,s.last_seq-c.acked_seq))),'[]') FROM omp_audit.consumers c),'checkpoint_keys',(SELECT coalesce(jsonb_agg(jsonb_build_object('kid',encode(kid,'hex'),'state',state,'active_from_seq',active_from_seq,'retired_at_seq',retired_at_seq)),'[]') FROM omp_audit_ext.checkpoint_keys)) FROM omp_audit.state s`, a.Config.AuditStreamEnabled).Scan(&raw)
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
	if errors.Is(e, pgx.ErrNoRows) {
		httpx.Error(w, 404, "sink_not_found", "Sink not found")
		return true
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

// sinkChange is one sink mutation, as the route, If-Match and the body ask for it.
type sinkChange struct {
	id  uuid.UUID
	rev int64 // zero for a create, which has no If-Match
	in  apitypes.AuditSinkRequest

	create, resume, test, rotate bool
}

// sinkRow is a sink's stored settings: what a change starts from and writes back.
type sinkRow struct {
	name, profile, hint, secretHint string
	required, enabled               bool
	batch                           int32
	uc, sc, pc                      []byte // sealed URL, secret and previous secret
	until                           *time.Time
}

func (a *api) auditSinkChange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !a.consumerAdmin(w, r) {
		return
	}
	c, ok := readSinkChange(w, r)
	if !ok {
		return
	}
	client := a.AuditSinkClient
	if client == nil {
		client = notify.NewWebhookClient(a.Config.AuditStreamAllowedNetworks, a.Log)
	}
	if c.in.Url != nil {
		if e := notify.CheckWebhookURL(r.Context(), client, *c.in.Url, 2048, true); e != nil {
			httpx.Error(w, 422, "invalid_sink_url", "Destination violates audit sink URL policy")
			return
		}
	}
	box, e := a.sinkBox()
	if sinkError(w, r, e) {
		return
	}
	var out json.RawMessage
	var shown string
	e = pgx.BeginFunc(r.Context(), a.Pool, func(tx pgx.Tx) error {
		var e error
		out, shown, e = a.applySinkChange(r, tx, box, c)
		return e
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
	if c.test {
		a.sendSinkTest(w, r, box, client, c)
		return
	}
	httpx.JSON(w, 200, map[string]any{"sink": out, "secret": optionalSecret(shown)})
}

// readSinkChange reads the request: the revision (every route but create), the
// body (create, update and resume), the sink id and the batch size's range. It
// has answered the request when it returns false.
func readSinkChange(w http.ResponseWriter, r *http.Request) (sinkChange, bool) {
	c := sinkChange{create: r.Method == "POST" && r.PathValue("id") == ""}
	if !c.create {
		var ok bool
		c.rev, ok = ifMatch(w, r)
		if !ok {
			return c, false
		}
	}
	c.resume = strings.HasSuffix(r.URL.Path, "/resume")
	if c.create || r.Method == "PUT" || c.resume {
		if !httpx.Decode(w, r, &c.in) {
			return c, false
		}
	}
	c.id = uuid.New()
	if !c.create {
		var e error
		c.id, e = uuid.Parse(r.PathValue("id"))
		if e != nil {
			httpx.Error(w, 400, "invalid_sink", "Invalid sink id")
			return c, false
		}
	}
	if c.in.BatchMaxRecords != nil && (*c.in.BatchMaxRecords < 1 || *c.in.BatchMaxRecords > 1000) {
		httpx.Error(w, 400, "invalid_sink", "batch_max_records must be 1-1000")
		return c, false
	}
	c.test = strings.HasSuffix(r.URL.Path, "/test")
	c.rotate = strings.HasSuffix(r.URL.Path, "/rotate-secret")
	return c, true
}

// applySinkChange makes the change in tx and audits it there. It returns the
// sink's view afterwards (none for a delete) and the new signing secret, when
// one was issued, to show once.
func (a *api) applySinkChange(r *http.Request, tx pgx.Tx, box *secrets.Box, c sinkChange) (out json.RawMessage, shown string, err error) {
	row, before, err := loadSinkRow(r, tx, c)
	if err != nil {
		return nil, "", err
	}
	row.merge(c.in)
	if c.create && (c.in.Name == nil || c.in.Url == nil) {
		return nil, "", apperr.Invalid("invalid_sink", "name and url required")
	}
	if c.in.Url != nil {
		if err := row.sealURL(box, c.id, *c.in.Url); err != nil {
			return nil, "", err
		}
	}
	if c.rotate {
		if err := row.keepPreviousSecret(box, c.id); err != nil {
			return nil, "", err
		}
	}
	if c.create || c.rotate {
		if shown, err = row.issueSecret(box, c.id); err != nil {
			return nil, "", err
		}
	}
	if err := writeSinkChange(r, tx, c, row); err != nil {
		return nil, "", err
	}
	if r.Method != "DELETE" {
		if err := tx.QueryRow(r.Context(), `SELECT `+sinkView+` FROM omp_audit_ext.sinks WHERE id=$1`, c.id).Scan(&out); err != nil {
			return nil, "", err
		}
	}
	entry := a.actor(r).Audit("settings.audit_sink_change", "audit_sink", c.id.String())
	entry.Metadata = map[string]any{"action": r.Method + " " + r.Pattern, "before": before, "after": out}
	return out, shown, audit.Record(r.Context(), dbgen.New(tx), entry)
}

// loadSinkRow reads the sink a change applies to and its view before the
// change, refusing a stale revision. A create starts from the defaults.
func loadSinkRow(r *http.Request, tx pgx.Tx, c sinkChange) (sinkRow, json.RawMessage, error) {
	if c.create {
		return sinkRow{profile: "summary", enabled: true, batch: 100}, nil, nil
	}
	var row sinkRow
	var before json.RawMessage
	var current, cursor int64
	e := tx.QueryRow(r.Context(), `SELECT name,profile,required,enabled,batch_max_records,revision,cursor_seq,url_cipher,url_hint,secret_cipher,secret_previous_cipher,secret_previous_until,secret_hint,`+sinkView+` FROM omp_audit_ext.sinks WHERE id=$1`, c.id).Scan(&row.name, &row.profile, &row.required, &row.enabled, &row.batch, &current, &cursor, &row.uc, &row.hint, &row.sc, &row.pc, &row.until, &row.secretHint, &before)
	if e != nil {
		return row, nil, e
	}
	if current != c.rev {
		return row, nil, apperr.Conflict("sink_conflict", "Stale sink revision")
	}
	return row, before, nil
}

// merge overlays the settings the request gives.
func (s *sinkRow) merge(in apitypes.AuditSinkRequest) {
	if in.Name != nil {
		s.name = *in.Name
	}
	if in.Profile != nil {
		s.profile = string(*in.Profile)
	}
	if in.Required != nil {
		s.required = *in.Required
	}
	if in.Enabled != nil {
		s.enabled = *in.Enabled
	}
	if in.BatchMaxRecords != nil {
		s.batch = int32(*in.BatchMaxRecords)
	}
}

func (s *sinkRow) sealURL(box *secrets.Box, id uuid.UUID, raw string) error {
	u, _ := url.Parse(raw)
	s.hint = u.Hostname()
	var e error
	s.uc, e = box.Seal([]byte(raw), auditstream.SinkAAD(id, "url"))
	return e
}

// keepPreviousSecret keeps the current signing secret as the previous one for
// a day, so a receiver can verify with either while it rotates.
func (s *sinkRow) keepPreviousSecret(box *secrets.Box, id uuid.UUID) error {
	old, e := box.Open(s.sc, auditstream.SinkAAD(id, "secret"))
	if e != nil {
		return e
	}
	defer clear(old)
	s.pc, e = box.Seal(old, auditstream.SinkAAD(id, "secret_previous"))
	if e != nil {
		return e
	}
	t := time.Now().Add(24 * time.Hour)
	s.until = &t
	return nil
}

// issueSecret makes a new signing secret, seals it into the row and returns it.
func (s *sinkRow) issueSecret(box *secrets.Box, id uuid.UUID) (string, error) {
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		return "", e
	}
	shown := base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	var e error
	s.sc, e = box.Seal([]byte(shown), auditstream.SinkAAD(id, "secret"))
	if e != nil {
		return "", e
	}
	s.secretHint = shown[len(shown)-4:]
	return shown, nil
}

// writeSinkChange runs the one statement the route stands for.
func writeSinkChange(r *http.Request, tx pgx.Tx, c sinkChange, s sinkRow) error {
	var e error
	switch {
	case c.test:
		// No row lock is held during network I/O. The revision is checked again
		// before sending; a test never touches the delivery cursor.
	case c.resume:
		if c.in.CursorSeq == nil {
			return apperr.Invalid("cursor_required", "cursor_seq required")
		}
		_, e = tx.Exec(r.Context(), `SELECT omp_audit_ext.resume_sink($1,$2,$3)`, c.id, c.rev, *c.in.CursorSeq)
	case r.PathValue("seq") != "":
		seq, err := strconv.ParseInt(r.PathValue("seq"), 10, 64)
		if err != nil {
			return apperr.Invalid("invalid_seq", "Invalid sequence")
		}
		_, e = tx.Exec(r.Context(), `SELECT omp_audit_ext.acknowledge_oversized($1,$2,$3)`, c.id, c.rev, seq)
	case r.Method == "DELETE":
		_, e = tx.Exec(r.Context(), `SELECT omp_audit_ext.delete_sink($1,$2)`, c.id, c.rev)
	case c.create:
		_, e = tx.Exec(r.Context(), `SELECT omp_audit_ext.create_sink($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, c.id, s.name, s.profile, s.required, s.enabled, s.batch, s.uc, s.hint, s.sc, s.pc, s.until, s.secretHint)
	default:
		_, e = tx.Exec(r.Context(), `SELECT omp_audit_ext.update_sink($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, c.id, c.rev, s.name, s.profile, s.required, s.enabled, s.batch, s.uc, s.hint, s.sc, s.pc, s.until, s.secretHint)
	}
	return e
}

// sendSinkTest posts a signed test event to the sink's destination and answers
// with the class of error the delivery met, if any.
func (a *api) sendSinkTest(w http.ResponseWriter, r *http.Request, box *secrets.Box, client *upstream.Client, c sinkChange) {
	var uc, sc []byte
	if sinkError(w, r, a.Pool.QueryRow(r.Context(), `SELECT url_cipher,secret_cipher FROM omp_audit_ext.sinks WHERE id=$1 AND revision=$2`, c.id, c.rev).Scan(&uc, &sc)) {
		return
	}
	raw, e := box.Open(uc, auditstream.SinkAAD(c.id, "url"))
	if sinkError(w, r, e) {
		return
	}
	defer clear(raw)
	secret, e := box.Open(sc, auditstream.SinkAAD(c.id, "secret"))
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
}

func optionalSecret(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
