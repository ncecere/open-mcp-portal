package auditstream

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/notify"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestSenderCrashRetryAndStreak(t *testing.T) {
	p, _ := testutil.NewDB(t)
	cleanAuditFixture(t, p)
	owner := testutil.OwnerPool(t, p)
	box, err := secrets.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	var bodies, ids []string
	status := 204
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts, _ := strconv.ParseInt(r.Header.Get(notify.HeaderTimestamp), 10, 64)
		if !notify.Verify("secret", r.Header.Get(notify.HeaderSignature), ts, body, time.Now(), time.Minute) {
			t.Error("invalid HMAC")
		}
		bodies = append(bodies, string(body))
		ids = append(ids, r.Header.Get(notify.HeaderDelivery))
		w.WriteHeader(status)
	}))
	defer receiver.Close()
	client := notify.NewWebhookClient([]netpolicy.Entry{{Kind: netpolicy.KindHost, Value: "receiver.example", AllowHTTP: true}}, nil)
	client.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	client.Dial = func(c context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(c, n, receiver.Listener.Addr().String())
	}
	id := uuid.New()
	urlCipher, _ := box.Seal([]byte("http://receiver.example/path?secret=sentinel"), SinkAAD(id, "url"))
	secretCipher, _ := box.Seal([]byte("secret"), SinkAAD(id, "secret"))
	exec(t, p, `SELECT omp_audit_ext.create_sink($1,'sender','summary',false,true,100,$2,'receiver.example',$3,NULL,NULL,'hint')`, id, urlCipher, secretCipher)
	exec(t, owner, `SELECT omp_audit_ext.set_sinks_enabled(true,'0.15.0')`)
	exec(t, p, insert)
	drain(t, p)
	leader, err := pgx.ConnectConfig(ctx, p.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer leader.Close(ctx)
	s := Sender{Pool: p, Box: box, Client: client, afterSend: func() error { return errors.New("crash") }}
	if s.deliver(ctx, leader, id) == nil {
		t.Fatal("crash hook ignored")
	}
	if count(t, p, `SELECT cursor_seq FROM omp_audit_ext.sinks WHERE id=$1`, id) != 0 {
		t.Fatal("crash advanced cursor")
	}
	s.afterSend = nil
	if err = s.deliver(ctx, leader, id); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || bodies[0] != bodies[1] || ids[0] != ids[1] {
		t.Fatal("retry changed identity or range")
	}
	exec(t, p, insert)
	drain(t, p)
	status = 500
	for range 3 {
		if err = s.deliver(ctx, leader, id); err != nil {
			t.Fatal(err)
		}
	}
	if count(t, p, `SELECT count(*) FROM notification_events WHERE event='audit.sink_failing'`) != 1 {
		t.Fatal("missing atomic failure event")
	}
	status = 204
	if err = s.deliver(ctx, leader, id); err != nil {
		t.Fatal(err)
	}
	if count(t, p, `SELECT count(*) FROM notification_events WHERE event='audit.sink_recovered'`) != 1 {
		t.Fatal("missing recovery")
	}
}

func TestSenderLostSessionAndSettingsEdit(t *testing.T) {
	for _, edit := range []bool{false, true} {
		t.Run(strconv.FormatBool(edit), func(t *testing.T) {
			p, _ := testutil.NewDB(t)
			cleanAuditFixture(t, p)
			owner := testutil.OwnerPool(t, p)
			box, _ := secrets.New(make([]byte, 32))
			id := uuid.New()
			leader, err := pgx.ConnectConfig(ctx, p.Config().ConnConfig.Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer leader.Close(ctx)
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if edit {
					_, e := p.Exec(ctx, `SELECT omp_audit_ext.update_sink(id,revision,name,profile,required,enabled,batch_max_records,url_cipher,url_hint,secret_cipher,secret_previous_cipher,secret_previous_until,secret_hint) FROM omp_audit_ext.sinks WHERE id=$1`, id)
					if e != nil {
						t.Error(e)
					}
				} else {
					_, e := p.Exec(ctx, `SELECT pg_terminate_backend($1)`, leader.PgConn().PID())
					if e != nil {
						t.Error(e)
					}
				}
				w.WriteHeader(204)
			}))
			defer receiver.Close()
			client := notify.NewWebhookClient([]netpolicy.Entry{{Kind: netpolicy.KindHost, Value: "receiver.example", AllowHTTP: true}}, nil)
			client.Lookup = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			}
			client.Dial = func(c context.Context, n, a string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(c, n, receiver.Listener.Addr().String())
			}
			uc, _ := box.Seal([]byte("http://receiver.example"), SinkAAD(id, "url"))
			sc, _ := box.Seal([]byte("secret"), SinkAAD(id, "secret"))
			exec(t, p, `SELECT omp_audit_ext.create_sink($1,'sender','summary',false,true,100,$2,'receiver.example',$3,NULL,NULL,'hint')`, id, uc, sc)
			exec(t, owner, `SELECT omp_audit_ext.set_sinks_enabled(true,'0.15.0')`)
			exec(t, p, insert)
			drain(t, p)
			s := Sender{Pool: p, Box: box, Client: client}
			if err = s.deliver(ctx, leader, id); err == nil {
				t.Fatal("stale result committed")
			}
			if count(t, p, `SELECT cursor_seq FROM omp_audit_ext.sinks WHERE id=$1`, id) != 0 {
				t.Fatal("stale result advanced cursor")
			}
		})
	}
}

func senderReceiver(t *testing.T, required bool) (*Sender, *pgx.Conn, uuid.UUID, *int, *[][]byte) {
	t.Helper()
	p, owner, id := sinkFixture(t, required)
	box, _ := secrets.New(make([]byte, 32))
	status := 204
	var bodies [][]byte
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts, _ := strconv.ParseInt(r.Header.Get(notify.HeaderTimestamp), 10, 64)
		if !notify.Verify("secret", r.Header.Get(notify.HeaderSignature), ts, body, time.Now(), time.Minute) {
			t.Error("bad sink HMAC")
		}
		bodies = append(bodies, body)
		w.WriteHeader(status)
	}))
	t.Cleanup(receiver.Close)
	client := notify.NewWebhookClient([]netpolicy.Entry{{Kind: netpolicy.KindHost, Value: "receiver.example", AllowHTTP: true}}, nil)
	client.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	client.Dial = func(c context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(c, n, receiver.Listener.Addr().String())
	}
	uc, _ := box.Seal([]byte("http://receiver.example"), SinkAAD(id, "url"))
	sc, _ := box.Seal([]byte("secret"), SinkAAD(id, "secret"))
	exec(t, p, `UPDATE omp_audit_ext.sinks SET url_cipher=$2,secret_cipher=$3 WHERE id=$1`, id, uc, sc)
	exec(t, owner, `SELECT omp_audit_ext.set_sinks_enabled(true,'0.15.0')`)
	leader, err := pgx.ConnectConfig(ctx, p.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leader.Close(ctx) })
	return &Sender{Pool: p, Box: box, Client: client}, leader, id, &status, &bodies
}
func TestSenderOversizedSplitAndAck(t *testing.T) {
	s, leader, id, _, bodies := senderReceiver(t, true)
	exec(t, s.Pool, `INSERT INTO public.audit_log(actor_kind,action,target_type,metadata) VALUES('system','large','test',jsonb_build_object('x',repeat('x',5*1024*1024)))`)
	exec(t, s.Pool, `INSERT INTO public.audit_log(actor_kind,action,target_type,metadata) VALUES('system','oversized','test',jsonb_build_object('x',repeat('x',17*1024*1024)))`)
	exec(t, s.Pool, insert)
	drain(t, s.Pool)
	if err := s.deliver(ctx, leader, id); err != nil {
		t.Fatal(err)
	}
	if len((*bodies)[0]) < 4<<20 || len((*bodies)[0]) > LineCap {
		t.Fatal("4-16 MiB singleton not delivered")
	}
	if count(t, s.Pool, `SELECT cursor_seq FROM omp_audit_ext.sinks WHERE id=$1`, id) != 1 {
		t.Fatal("batch did not split")
	}
	if err := s.deliver(ctx, leader, id); err != nil {
		t.Fatal(err)
	}
	if count(t, s.Pool, `SELECT cursor_seq FROM omp_audit_ext.sinks WHERE id=$1`, id) != 1 {
		t.Fatal("oversized did not hold")
	}
	exec(t, s.Pool, `SELECT omp_audit_ext.acknowledge_oversized($1,1,2)`, id)
	if err := s.deliver(ctx, leader, id); err != nil {
		t.Fatal(err)
	}
	if count(t, s.Pool, `SELECT cursor_seq FROM omp_audit_ext.sinks WHERE id=$1`, id) < 3 {
		t.Fatal("ack did not resume delivery")
	}
}
func TestSenderExpiryResumeGapRetry(t *testing.T) {
	s, leader, id, status, bodies := senderReceiver(t, false)
	exec(t, s.Pool, `INSERT INTO public.audit_log(actor_kind,action,target_type,occurred_at) VALUES('system','old','test',now()-interval '4000 days')`)
	drain(t, s.Pool)
	exec(t, s.Pool, `SELECT public.omp_purge_audit_log(30,100)`)
	if err := s.deliver(ctx, leader, id); err != nil {
		t.Fatal(err)
	}
	if len(*bodies) != 0 {
		t.Fatal("expired data sent")
	}
	exec(t, s.Pool, `SELECT omp_audit_ext.resume_sink($1,1,0)`, id)
	*status = 500
	if err := s.deliver(ctx, leader, id); err != nil {
		t.Fatal(err)
	}
	*status = 204
	if err := s.deliver(ctx, leader, id); err != nil {
		t.Fatal(err)
	}
	if len(*bodies) != 2 || string((*bodies)[0]) != string((*bodies)[1]) {
		t.Fatal("gap changed across retry")
	}
	if count(t, s.Pool, `SELECT cursor_seq FROM omp_audit_ext.sinks WHERE id=$1`, id) != 1 {
		t.Fatal("gap did not advance exact endpoints")
	}
}

func TestSenderAtomicNotificationRollbackAndDedup(t *testing.T) {
	s, leader, id, status, _ := senderReceiver(t, false)
	owner := testutil.OwnerPool(t, s.Pool)
	exec(t, s.Pool, insert)
	drain(t, s.Pool)
	*status = 500
	for range 2 {
		if err := s.deliver(ctx, leader, id); err != nil {
			t.Fatal(err)
		}
	}
	exec(t, owner, `CREATE FUNCTION public.reject_sink_notice() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected insert failure'; END $$`)
	exec(t, owner, `CREATE TRIGGER reject_sink_notice BEFORE INSERT ON public.notification_events FOR EACH ROW EXECUTE FUNCTION public.reject_sink_notice()`)
	if s.deliver(ctx, leader, id) == nil {
		t.Fatal("notification failure swallowed")
	}
	if count(t, s.Pool, `SELECT consecutive_failures FROM omp_audit_ext.sinks WHERE id=$1`, id) != 2 {
		t.Fatal("finish survived insert rollback")
	}
	exec(t, owner, `DROP TRIGGER reject_sink_notice ON public.notification_events`)
	if err := s.deliver(ctx, leader, id); err != nil {
		t.Fatal(err)
	}
	if count(t, s.Pool, `SELECT count(*) FROM notification_events WHERE event='audit.sink_failing'`) != 1 {
		t.Fatal("notice lost across rollback")
	}
	var streak uuid.UUID
	if err := s.Pool.QueryRow(ctx, `SELECT streak_id FROM omp_audit_ext.sinks WHERE id=$1`, id).Scan(&streak); err != nil {
		t.Fatal(err)
	}
	// Preinsert a duplicate recovery: rows-affected zero must still commit finish.
	_, err := notify.InsertStrict(ctx, dbgen.New(s.Pool), notify.Event{Type: notify.AuditSinkRecovered, DedupKey: "audit-sink:" + id.String() + ":" + streak.String() + ":recovered", Data: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	*status = 204
	if err = s.deliver(ctx, leader, id); err != nil {
		t.Fatal(err)
	}
	if count(t, s.Pool, `SELECT consecutive_failures FROM omp_audit_ext.sinks WHERE id=$1`, id) != 0 {
		t.Fatal("dedup blocked recovery")
	}
	exec(t, s.Pool, insert)
	drain(t, s.Pool)
	*status = 500
	for range 3 {
		if err = s.deliver(ctx, leader, id); err != nil {
			t.Fatal(err)
		}
	}
	if count(t, s.Pool, `SELECT count(*) FROM notification_events WHERE event='audit.sink_failing'`) != 2 {
		t.Fatal("flapping reused closed streak")
	}
}

func TestSenderOptionalOversizedAdvances(t *testing.T) {
	s, leader, id, _, bodies := senderReceiver(t, false)
	exec(t, s.Pool, `SELECT omp_audit_ext.update_sink(id,revision,name,'full',required,enabled,batch_max_records,url_cipher,url_hint,secret_cipher,secret_previous_cipher,secret_previous_until,secret_hint) FROM omp_audit_ext.sinks WHERE id=$1`, id)
	exec(t, s.Pool, `INSERT INTO public.audit_log(actor_kind,action,target_type,metadata) VALUES('system','oversized','test',jsonb_build_object('x',repeat('x',17*1024*1024)))`)
	drain(t, s.Pool)
	if err := s.deliver(ctx, leader, id); err != nil {
		t.Fatal(err)
	}
	if len(*bodies) != 1 || !bytes.Contains((*bodies)[0], []byte(`"oversized":true`)) {
		t.Fatal("missing oversized envelope")
	}
	if count(t, s.Pool, `SELECT cursor_seq FROM omp_audit_ext.sinks WHERE id=$1`, id) != 1 {
		t.Fatal("optional sink held oversized row")
	}
}

func TestSenderPreviousSecretValidity(t *testing.T) {
	s, leader, id, _, _ := senderReceiver(t, false)
	var headers []string
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = append(headers, r.Header.Get(notify.HeaderSignature))
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	s.Client.Dial = func(c context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(c, n, receiver.Listener.Addr().String())
	}
	previous, _ := s.Box.Seal([]byte("old-secret"), SinkAAD(id, "secret_previous"))
	exec(t, s.Pool, `SELECT omp_audit_ext.update_sink(id,revision,name,profile,required,enabled,batch_max_records,url_cipher,url_hint,secret_cipher,$2,clock_timestamp()+interval '24 hours',secret_hint) FROM omp_audit_ext.sinks WHERE id=$1`, id, previous)
	exec(t, s.Pool, insert)
	drain(t, s.Pool)
	if err := s.deliver(ctx, leader, id); err != nil {
		t.Fatal(err)
	}
	exec(t, s.Pool, `SELECT omp_audit_ext.update_sink(id,revision,name,profile,required,enabled,batch_max_records,url_cipher,url_hint,secret_cipher,$2,clock_timestamp()-interval '1 second',secret_hint) FROM omp_audit_ext.sinks WHERE id=$1`, id, previous)
	exec(t, s.Pool, insert)
	drain(t, s.Pool)
	if err := s.deliver(ctx, leader, id); err != nil {
		t.Fatal(err)
	}
	if len(headers) != 2 || strings.Count(headers[0], "v1=") != 2 || strings.Count(headers[1], "v1=") != 1 {
		t.Fatalf("signature counts %v", headers)
	}
}

func TestSenderStaleRequestArrivesAfterNewerRange(t *testing.T) {
	s, leader, id, _, _ := senderReceiver(t, false)
	var arrivals []int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seq, _ := strconv.ParseInt(r.Header.Get("X-OMP-Audit-First-Seq"), 10, 64)
		arrivals = append(arrivals, seq)
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s.Client.Dial = func(c context.Context, n, a string) (net.Conn, error) {
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-c.Done():
				return nil, c.Err()
			}
		}
		return (&net.Dialer{}).DialContext(c, n, receiver.Listener.Addr().String())
	}
	exec(t, s.Pool, insert)
	drain(t, s.Pool)
	done := make(chan error, 1)
	go func() { done <- s.deliver(ctx, leader, id) }()
	<-started
	exec(t, s.Pool, `SELECT pg_terminate_backend($1)`, leader.PgConn().PID())
	newer, err := pgx.ConnectConfig(ctx, s.Pool.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer newer.Close(ctx)
	if err = s.deliver(ctx, newer, id); err != nil {
		t.Fatal(err)
	}
	exec(t, s.Pool, insert)
	drain(t, s.Pool)
	if err = s.deliver(ctx, newer, id); err != nil {
		t.Fatal(err)
	}
	cursor := count(t, s.Pool, `SELECT cursor_seq FROM omp_audit_ext.sinks WHERE id=$1`, id)
	close(release)
	if err = <-done; err == nil {
		t.Fatal("stale finish accepted")
	}
	if len(arrivals) != 3 || arrivals[2] >= arrivals[1] {
		t.Fatalf("receiver did not see out-of-order arrival: %v", arrivals)
	}
	if count(t, s.Pool, `SELECT cursor_seq FROM omp_audit_ext.sinks WHERE id=$1`, id) != cursor {
		t.Fatal("cursor regressed")
	}
}

func TestSenderDisabledGateProducesNoEvents(t *testing.T) {
	s, leader, id, status, bodies := senderReceiver(t, false)
	*status = 500
	exec(t, testutil.OwnerPool(t, s.Pool), `SELECT omp_audit_ext.set_sinks_enabled(false,'0.15.0')`)
	exec(t, s.Pool, insert)
	drain(t, s.Pool)
	for range 4 {
		if err := s.pass(ctx, leader); err != nil {
			t.Fatal(err)
		}
	}
	if len(*bodies) != 0 || count(t, s.Pool, `SELECT count(*) FROM notification_events WHERE event LIKE 'audit.sink_%'`) != 0 {
		t.Fatal("disabled gate sent or emitted")
	}
	if count(t, s.Pool, `SELECT consecutive_failures FROM omp_audit_ext.sinks WHERE id=$1`, id) != 0 {
		t.Fatal("disabled gate attempted")
	}
}
