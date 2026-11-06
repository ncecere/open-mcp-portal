package auditstream

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
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
