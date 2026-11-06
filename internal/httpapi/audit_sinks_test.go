package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/notify"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/auditstream"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/prometheus/client_golang/prometheus"
)

func (c *mctx) sinkID() string {
	c.e.exec(`SELECT count(*)::text FROM (SELECT omp_audit_ext.delete_sink(id,revision) FROM omp_audit_ext.sinks) s`)
	id := uuid.New()
	k, _ := secrets.ParseKey(testEncryptionKey)
	box, _ := secrets.New(k)
	u, _ := box.Seal([]byte("https://receiver.invalid/sentinel"), auditstream.SinkAAD(id, "url"))
	s, _ := box.Seal([]byte("matrix-secret"), auditstream.SinkAAD(id, "secret"))
	c.e.exec(`SELECT id::text FROM omp_audit_ext.create_sink($1,$2,'summary',false,true,100,$3,'receiver.invalid',$4,NULL,NULL,'')`, id, id.String(), u, s)
	return id.String()
}

func TestAuditSinkAPI(t *testing.T) {
	var logs bytes.Buffer
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OMP-Event") != "audit.test" {
			t.Error("wrong event")
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
	app := newTestAppDeps(t, func(c *config.Config) {}, slog.New(slog.NewTextHandler(&logs, nil)), func(d *httpapi.Deps) { d.AuditSinkClient = client })
	admin := app.signIn("admin")
	path := "/v1/admin/settings/audit-sinks"
	sentinel := "http://receiver.example/secret-url-sentinel?password=private"
	code, body := admin.raw("POST", path, map[string]any{"name": "sink-test", "url": sentinel, "required": true}, nil)
	if code != 200 {
		t.Fatalf("create: %d %s", code, body)
	}
	var created struct {
		Data struct {
			Sink struct {
				ID string `json:"id"`
			}
			Secret string
		}
	}
	if e := json.Unmarshal(body, &created); e != nil {
		t.Fatal(e)
	}
	id := created.Data.Sink.ID
	secret := created.Data.Secret
	if id == "" || len(secret) != 43 {
		t.Fatalf("bad create: %s", body)
	}
	allSecrets := []string{secret}
	check := func(b []byte) {
		t.Helper()
		for _, v := range append([]string{sentinel, "secret-url-sentinel", "password=private"}, allSecrets...) {
			if bytes.Contains(b, []byte(v)) {
				t.Fatalf("leaked sentinel: %q", v)
			}
		}
	}
	path += "/" + id
	for _, p := range []string{path, "/v1/admin/settings/audit-sinks", "/v1/admin/audit/stream/status"} {
		code, b := admin.raw("GET", p, nil, nil)
		if code != 200 {
			t.Fatalf("read %s: %d %s", p, code, b)
		}
		check(b)
		// The page shows the replica's sealer setting and each sink's last success.
		if p == "/v1/admin/audit/stream/status" && (!strings.Contains(string(b), `"sealer_enabled"`) || !strings.Contains(string(b), `"last_ok_at"`)) {
			t.Fatalf("status lacks sealer_enabled/last_ok_at: %s", b)
		}
	}
	rev := map[string]string{"If-Match": `"1"`}
	code, body = admin.raw("PUT", path, map[string]any{"enabled": false}, rev)
	if code != 200 {
		t.Fatalf("update %d %s", code, body)
	}
	check(body)
	code, body = admin.raw("PUT", path, map[string]any{"enabled": true}, rev)
	if code != 409 {
		t.Fatalf("stale: %d %s", code, body)
	}
	check(body)
	rev["If-Match"] = `"2"`
	code, body = admin.raw("POST", path+"/test", nil, rev)
	if code != 200 || !strings.Contains(string(body), `"error_class":""`) {
		t.Fatalf("test: %d %s", code, body)
	}
	check(body)
	code, body = admin.raw("POST", path+"/rotate-secret", nil, rev)
	if code != 200 {
		t.Fatalf("rotate %d %s", code, body)
	}
	var rotated struct{ Data struct{ Secret string } }
	_ = json.Unmarshal(body, &rotated)
	if rotated.Data.Secret == secret || len(rotated.Data.Secret) != 43 {
		t.Fatal("rotation did not generate fresh secret")
	}
	allSecrets = append(allSecrets, rotated.Data.Secret)
	code, body = admin.raw("PUT", path, map[string]any{"url": sentinel + "#fragment"}, map[string]string{"If-Match": `"3"`})
	if code != 422 {
		t.Fatalf("bad URL: %d %s", code, body)
	}
	check(body)
	metrics, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	metricJSON, _ := json.Marshal(metrics)
	check(metricJSON)
	var raw []byte
	if e := app.Pool.QueryRow(context.Background(), `SELECT coalesce(jsonb_agg(metadata)::text,'')::bytea FROM audit_log WHERE target_id=$1`, id).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	check(raw)
	check(logs.Bytes())
	var cursor int64
	if e := app.Pool.QueryRow(context.Background(), `SELECT cursor_seq FROM omp_audit_ext.sinks WHERE id=$1`, id).Scan(&cursor); e != nil || cursor != 0 {
		t.Fatalf("test moved cursor %d %v", cursor, e)
	}
}
func TestAuditAckRejectsSinkNames(t *testing.T) {
	app := newTestApp(t, nil)
	s := app.signIn("admin")
	for _, name := range []string{"sink.foo", "sink-bar"} {
		code, b := s.raw("POST", "/v1/admin/audit/stream/ack", map[string]any{"consumer": name, "seq": 0}, nil)
		if code != 400 || !strings.Contains(string(b), "invalid_consumer") {
			t.Fatalf("%s: %d %s", name, code, b)
		}
	}
}

func sinkMatrixRequest(c *mctx, method, suffix string, body any) request {
	return request{method: method, path: "/v1/admin/settings/audit-sinks/" + c.sinkID() + suffix, body: body, headers: map[string]string{"If-Match": fmt.Sprintf(`"%d"`, 1)}}
}

func (c *mctx) oversizedSinkRequest() request {
	req := sinkMatrixRequest(c, "POST", "/oversized/1/acknowledge", nil)
	if !c.allowed {
		return req
	}
	id := strings.Split(strings.TrimPrefix(req.path, "/v1/admin/settings/audit-sinks/"), "/")[0]
	c.e.exec(`SELECT (omp_audit_ext.update_sink(id,revision,name,'full',true,enabled,batch_max_records,url_cipher,url_hint,secret_cipher,secret_previous_cipher,secret_previous_until,secret_hint)).revision::text FROM omp_audit_ext.sinks WHERE id=$1`, id)
	row := c.e.exec(`INSERT INTO public.audit_log(actor_kind,action,target_type,metadata) VALUES('system','matrix.oversized','test',jsonb_build_object('x',repeat('x',17*1024*1024))) RETURNING id::text`)
	var seq int64
	for deadline := time.Now().Add(time.Minute); seq == 0; {
		c.sealAudit()
		var err error
		err = c.e.app.Pool.QueryRow(context.Background(), `SELECT coalesce(max(seq),0) FROM omp_audit.chain WHERE audit_id=$1`, row).Scan(&seq)
		if err != nil {
			c.e.t.Fatal(err)
		}
		if time.Now().After(deadline) {
			c.e.t.Fatal("oversized fixture not sealed")
		}
		if seq == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if _, err := testutil.OwnerPool(c.e.t, c.e.app.Pool).Exec(context.Background(), `SELECT omp_audit_ext.set_sinks_enabled(true,'0.15.0')`); err != nil {
		c.e.t.Fatal(err)
	}
	if seq > 1 {
		token := c.e.exec(`SELECT omp_audit_ext.begin_attempt($1,2,0,'data',1,$2)::text`, id, seq-1)
		c.e.exec(`SELECT cursor_seq::text FROM omp_audit_ext.finish_attempt($1,$2,'ok',NULL,false)`, id, token)
	}
	req.path = fmt.Sprintf("/v1/admin/settings/audit-sinks/%s/oversized/%d/acknowledge", id, seq)
	req.headers["If-Match"] = `"2"`
	return req
}
