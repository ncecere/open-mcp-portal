package auditstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/notify"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Sender is started only under AUDIT_STREAM_ENABLED. Database rollout gating is
// checked independently on every pass and again by begin/finish_attempt.
type Sender struct {
	Pool   *pgxpool.Pool
	Box    *secrets.Box
	Client *upstream.Client
	// afterSend models a crash after acknowledgement but before durable finish.
	afterSend func() error
}

func SinkAAD(id uuid.UUID, field string) []byte {
	return []byte("audit_sink:" + id.String() + ":" + field)
}

func (s *Sender) Loop(ctx context.Context, log *slog.Logger) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var leader *pgx.Conn
	defer func() {
		if leader != nil {
			_ = leader.Close(context.WithoutCancel(ctx))
		}
	}()
	for {
		s.observe(ctx)
		if leader == nil {
			c, err := pgx.ConnectConfig(ctx, s.Pool.Config().ConnConfig.Copy())
			if err == nil {
				var got bool
				err = c.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended('omp.auditsinks',0))`).Scan(&got)
				if err == nil && got {
					leader = c
				} else {
					_ = c.Close(ctx)
				}
			}
		}
		if leader != nil {
			if err := s.pass(ctx, leader); err != nil {
				// Never log database or URL-bearing errors from this engine.
				if ctx.Err() == nil {
					log.Warn("audit sink pass failed")
				}
				_ = leader.Close(context.WithoutCancel(ctx))
				leader = nil
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Sender) pass(ctx context.Context, leader *pgx.Conn) error {
	var enabled bool
	if err := leader.QueryRow(ctx, `SELECT enabled FROM omp_audit_ext.sink_settings WHERE singleton`).Scan(&enabled); err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	rows, err := s.Pool.Query(ctx, `SELECT id FROM omp_audit_ext.sinks WHERE enabled AND state='active' AND next_attempt_at<=clock_timestamp()+interval '60 seconds' ORDER BY next_attempt_at,id LIMIT 100`)
	if err != nil {
		return err
	}
	var sinks []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			break
		}
		sinks = append(sinks, id)
	}

	rows.Close()
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		return err
	}
	var passErr error
	for _, id := range sinks {
		candidate, e := loadSink(ctx, s.Pool, id)
		if errors.Is(e, pgx.ErrNoRows) {
			continue
		}
		if e != nil {
			return e
		}
		if time.Now().Before(sinkDue(candidate)) {
			continue
		}
		if e = s.deliver(ctx, leader, id); e != nil {
			passErr = e
			if leader.IsClosed() {
				return e
			}
		}
	}
	return passErr
}
func loadSink(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id uuid.UUID) (dbgen.OmpAuditExtSink, error) {
	var s dbgen.OmpAuditExtSink
	err := q.QueryRow(ctx, `SELECT id,kind,profile,required,enabled,batch_max_records,revision,url_cipher,secret_cipher,secret_previous_cipher,secret_previous_until,cursor_seq,inflight_kind,inflight_first,inflight_last,consecutive_failures,streak_id,streak_notified,gap_first,gap_last,next_attempt_at FROM omp_audit_ext.sinks WHERE id=$1`, id).Scan(&s.ID, &s.Kind, &s.Profile, &s.Required, &s.Enabled, &s.BatchMaxRecords, &s.Revision, &s.UrlCipher, &s.SecretCipher, &s.SecretPreviousCipher, &s.SecretPreviousUntil, &s.CursorSeq, &s.InflightKind, &s.InflightFirst, &s.InflightLast, &s.ConsecutiveFailures, &s.StreakID, &s.StreakNotified, &s.GapFirst, &s.GapLast, &s.NextAttemptAt)
	return s, err
}
func (s *Sender) deliver(ctx context.Context, leader *pgx.Conn, id uuid.UUID) error {
	sink, err := loadSink(ctx, s.Pool, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	kind := "data"
	first := sink.CursorSeq + 1
	var last int64
	var body []byte
	var stream uuid.UUID
	held := false
	if sink.GapFirst != nil {
		kind = "gap"
		first = *sink.GapFirst
		last = *sink.GapLast
		if err = s.Pool.QueryRow(ctx, `SELECT stream_id FROM omp_audit.state WHERE singleton`).Scan(&stream); err != nil {
			return err
		}
		body, err = json.Marshal(struct {
			Stream uuid.UUID `json:"stream_id"`
			First  int64     `json:"gap_first"`
			Last   int64     `json:"gap_last"`
		}{stream, first, last})
		body = append(body, '\n')
	} else {
		if sink.InflightLast != nil {
			last = *sink.InflightLast
		}
		var batch Range
		err = pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
			var e error
			batch, e = readRange(ctx, tx, sink.CursorSeq, int(sink.BatchMaxRecords), sink.Profile == "full", last, 4<<20)
			return e
		})
		if err != nil {
			if errors.Is(err, ErrRangeExpired) || err.Error() == "range_expired" {
				if !sink.Required {
					_, err = leader.Exec(ctx, `SELECT omp_audit_ext.expire_sink($1,$2,$3)`, id, sink.Revision, sink.CursorSeq)
					return err
				}
			}
			return err
		}
		if len(batch.Envelopes) == 0 {
			return nil
		}
		for i, e := range batch.Envelopes {
			line := batch.Lines[i]
			if last == 0 && len(body) > 0 && (e.Oversized || len(body)+len(line) > 4<<20) {
				break
			}
			body = append(body, line...)
			stream = e.Stream
			if e.Oversized {
				held = sink.Required && sink.Profile == "full"
				if last == 0 {
					last = e.Seq
				}
				break
			}
		}
		// Count buffered lines to determine the endpoint without assuming seq adjacency.
		n := bytes.Count(body, []byte{'\n'})
		if sink.InflightLast == nil {
			last = batch.Envelopes[n-1].Seq
		}
		if sink.InflightLast != nil && batch.Envelopes[n-1].Seq != last {
			return ErrIntegrity
		}
	}
	var token uuid.UUID
	if err = leader.QueryRow(ctx, `SELECT omp_audit_ext.begin_attempt($1,$2,$3,$4,$5,$6)`, id, sink.Revision, sink.CursorSeq, kind, first, last).Scan(&token); err != nil {
		return err
	}
	class := s.post(ctx, sink, kind, first, last, stream, body)
	if s.afterSend != nil {
		if err = s.afterSend(); err != nil {
			return err
		}
	}
	outcome := "ok"
	if class != "" {
		outcome = "failed"
	} else if held {
		outcome = "held"
	}
	// Finish uses the leadership session itself: a lost session cannot commit a
	// late HTTP result, even before the next leader has installed its token.
	err = pgx.BeginFunc(ctx, leader, func(tx pgx.Tx) error {

		current, e := loadSink(ctx, tx, id)
		if e != nil {
			return e
		}
		intent := current.StreakNotified
		if outcome == "failed" {
			intent = current.ConsecutiveFailures >= 2 && !current.StreakNotified
		}
		var streak uuid.NullUUID
		var ec any
		if class != "" {
			ec = class
		}
		e = tx.QueryRow(ctx, `SELECT streak_id FROM omp_audit_ext.finish_attempt($1,$2,$3,$4,$5)`, id, token, outcome, ec, intent).Scan(&streak)
		if e != nil {
			return e
		}
		if intent {
			event := notify.AuditSinkFailing
			suffix := "failing"
			if outcome != "failed" {
				event = notify.AuditSinkRecovered
				suffix = "recovered"
				streak = current.StreakID
			}
			_, e = notify.InsertStrict(ctx, dbgen.New(tx), notify.Event{Type: event, DedupKey: fmt.Sprintf("audit-sink:%s:%s:%s", id, streak.UUID, suffix), SubjectType: "audit_sink", SubjectID: id.String(), Data: map[string]string{"sink_id": id.String(), "streak_id": streak.UUID.String()}})
		}
		return e
	})
	if err == nil {
		result := outcome
		if class != "" {
			result = class
		}
		observability.AuditStreamSinkDeliveries.WithLabelValues("webhook", result).Inc()
	}
	return err
}
func (s *Sender) post(ctx context.Context, sink dbgen.OmpAuditExtSink, kind string, first, last int64, stream uuid.UUID, body []byte) string {
	raw, err := s.Box.Open(sink.UrlCipher, SinkAAD(sink.ID, "url"))
	if err != nil {
		return "integrity"
	}
	defer clear(raw)
	if err = notify.CheckWebhookURL(ctx, s.Client, string(raw), 2048, false); err != nil {
		return "policy_denied"
	}
	secret, err := s.Box.Open(sink.SecretCipher, SinkAAD(sink.ID, "secret"))
	if err != nil {
		return "integrity"
	}
	defer clear(secret)
	keys := []string{string(secret)}
	if len(sink.SecretPreviousCipher) > 0 && sink.SecretPreviousUntil != nil && sink.SecretPreviousUntil.After(time.Now()) {
		prev, e := s.Box.Open(sink.SecretPreviousCipher, SinkAAD(sink.ID, "secret_previous"))
		if e != nil {
			return "integrity"
		}
		defer clear(prev)
		keys = append(keys, string(prev))
	}
	req, err := http.NewRequestWithContext(ctx, "POST", string(raw), bytes.NewReader(body))
	if err != nil {
		return "policy_denied"
	}
	delivery := fmt.Sprintf("%s:%d-%d:%d", kind, first, last, sink.Revision)
	event := "audit.batch"
	if kind == "gap" {
		event = "audit.gap"
	}
	for k, v := range map[string]string{"Content-Type": "application/x-ndjson", notify.HeaderEvent: event, "X-OMP-Audit-Stream": stream.String(), "X-OMP-Audit-First-Seq": strconv.FormatInt(first, 10), "X-OMP-Audit-Last-Seq": strconv.FormatInt(last, 10), notify.HeaderDelivery: delivery, "Idempotency-Key": delivery, notify.HeaderAttempt: strconv.Itoa(int(sink.ConsecutiveFailures) + 1)} {
		req.Header.Set(k, v)
	}
	ts := time.Now().Unix()
	req.Header.Set(notify.HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(notify.HeaderSignature, notify.SignatureHeader(ts, body, keys...))
	return Send(SinkHTTPClient(s.Client), req)
}
func (s *Sender) observe(ctx context.Context) {
	var failing float64
	if s.Pool.QueryRow(ctx, `SELECT count(*)::float8 FROM omp_audit_ext.sinks WHERE consecutive_failures>0`).Scan(&failing) == nil {
		observability.AuditStreamSinkFailing.Set(failing)
	}

	rows, err := s.Pool.Query(ctx, `SELECT required,max(greatest(0,(SELECT last_seq FROM omp_audit.state WHERE singleton)-cursor_seq))::float8 FROM omp_audit_ext.sinks GROUP BY required`)
	if err != nil {
		return
	}
	defer rows.Close()
	for _, required := range []string{"true", "false"} {
		observability.AuditStreamSinkLag.WithLabelValues("webhook", required).Set(0)
	}
	for rows.Next() {
		var required bool
		var lag float64
		if rows.Scan(&required, &lag) == nil {
			observability.AuditStreamSinkLag.WithLabelValues("webhook", strconv.FormatBool(required)).Set(lag)
		}
	}
}

// Jitter is derived from the persisted attempt timestamp and sink identity, so
// failover does not redraw eligibility on every tick. SQL owns the base delay.
func sinkDue(s dbgen.OmpAuditExtSink) time.Time {
	if s.ConsecutiveFailures == 0 {
		return s.NextAttemptAt
	}
	base := math.Min(300, math.Pow(2, math.Min(float64(s.ConsecutiveFailures-1), 9)))
	sum := sha256.Sum256([]byte(s.ID.String() + s.NextAttemptAt.UTC().Format(time.RFC3339Nano)))
	fraction := float64(binary.BigEndian.Uint64(sum[:8])>>11) / float64(uint64(1)<<53)
	delay := math.Min(300, base*(0.8+0.4*fraction))
	return s.NextAttemptAt.Add(time.Duration((delay - base) * float64(time.Second)))
}
