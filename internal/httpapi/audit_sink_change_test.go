package httpapi_test

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/notify"
)

// TestAuditSinkChangeOrderAndRoutes pins what each audit sink mutation answers
// and which refusal wins when several apply: the session, then If-Match, then
// the sink id, then the batch size, then the URL policy, then the stored
// revision and the route's own requirements. A refused change writes nothing.
func TestAuditSinkChangeOrderAndRoutes(t *testing.T) {
	client := notify.NewWebhookClient([]netpolicy.Entry{{Kind: netpolicy.KindHost, Value: "receiver.example", AllowHTTP: true}}, nil)
	client.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	client.Dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("this test sends nothing")
	}
	app := newTestAppDeps(t, func(c *config.Config) {}, slog.New(slog.DiscardHandler), func(d *httpapi.Deps) { d.AuditSinkClient = client })
	admin, user := app.signIn("admin"), app.signIn("user")
	base := "/v1/admin/settings/audit-sinks"
	good, bad := "http://receiver.example/hook", "http://not-allowed.example/hook"

	var created struct {
		Sink struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
		}
		Secret *string
	}
	if code, errCode := admin.call("POST", base, map[string]any{"name": "order", "url": good}, &created, nil); code != 200 || created.Secret == nil {
		t.Fatalf("create: %d %s", code, errCode)
	}
	sink := base + "/" + created.Sink.ID
	rev := ifMatch(created.Sink.Revision)
	stale := ifMatch(created.Sink.Revision + 7)

	sinkChanges := func() int {
		t.Helper()
		var n int
		if err := app.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action='settings.audit_sink_change' AND target_id=$1`, created.Sink.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := sinkChanges(); n != 1 {
		t.Fatalf("create wrote %d audit rows, want 1", n)
	}

	refusals := []struct {
		what    string
		who     *session
		method  string
		path    string
		body    any
		headers map[string]string
		code    int
		errCode string
	}{
		{"create by a non-admin", user, "POST", base, map[string]any{"name": "x", "url": good}, nil, 403, "forbidden"},
		{"update by a non-admin, before If-Match", user, "PUT", sink, map[string]any{"enabled": false}, nil, 403, "forbidden"},
		{"update without If-Match", admin, "PUT", sink, map[string]any{"enabled": false}, nil, 428, "revision_required"},
		{"If-Match before the sink id", admin, "PUT", base + "/not-a-uuid", map[string]any{"enabled": false}, nil, 428, "revision_required"},
		{"bad sink id", admin, "PUT", base + "/not-a-uuid", map[string]any{"enabled": false}, rev, 400, "invalid_sink"},
		{"sink id before batch size", admin, "PUT", base + "/not-a-uuid", map[string]any{"batch_max_records": 0}, rev, 400, "invalid_sink"},
		{"batch size too small", admin, "PUT", sink, map[string]any{"batch_max_records": 0}, rev, 400, "invalid_sink"},
		{"batch size too large", admin, "PUT", sink, map[string]any{"batch_max_records": 1001}, rev, 400, "invalid_sink"},
		{"batch size before URL policy", admin, "PUT", sink, map[string]any{"batch_max_records": 0, "url": bad}, rev, 400, "invalid_sink"},
		{"URL policy", admin, "PUT", sink, map[string]any{"url": bad}, rev, 422, "invalid_sink_url"},
		{"URL policy before the stored revision", admin, "PUT", sink, map[string]any{"url": bad}, stale, 422, "invalid_sink_url"},
		{"URL policy on create, before name is required", admin, "POST", base, map[string]any{"url": bad}, nil, 422, "invalid_sink_url"},
		{"create without a name", admin, "POST", base, map[string]any{"url": good}, nil, 400, "invalid_sink"},
		{"create without a url", admin, "POST", base, map[string]any{"name": "x"}, nil, 400, "invalid_sink"},
		{"stale revision", admin, "PUT", sink, map[string]any{"enabled": false}, stale, 409, "sink_conflict"},
		{"unknown sink", admin, "PUT", base + "/" + uuid.NewString(), map[string]any{"enabled": false}, rev, 404, "sink_not_found"},
		{"stale revision before the cursor is required", admin, "POST", sink + "/resume", map[string]any{}, stale, 409, "sink_conflict"},
		{"resume without a cursor", admin, "POST", sink + "/resume", map[string]any{}, rev, 400, "cursor_required"},
		{"acknowledge with a bad sequence", admin, "POST", sink + "/oversized/abc/acknowledge", nil, rev, 400, "invalid_seq"},
		{"stale revision before the sequence is read", admin, "POST", sink + "/oversized/abc/acknowledge", nil, stale, 409, "sink_conflict"},
		{"rotate with a stale revision", admin, "POST", sink + "/rotate-secret", nil, stale, 409, "sink_conflict"},
		{"test with a stale revision", admin, "POST", sink + "/test", nil, stale, 409, "sink_conflict"},
		{"delete with a stale revision", admin, "DELETE", sink, nil, stale, 409, "sink_conflict"},
		{"delete without If-Match", admin, "DELETE", sink, nil, nil, 428, "revision_required"},
	}
	for _, c := range refusals {
		code, errCode := c.who.call(c.method, c.path, c.body, nil, c.headers)
		if code != c.code || errCode != c.errCode {
			t.Errorf("%s: got %d %q, want %d %q", c.what, code, errCode, c.code, c.errCode)
		}
	}
	if n := sinkChanges(); n != 1 {
		t.Errorf("refused changes wrote audit rows: %d, want 1", n)
	}
	var view struct {
		Revision int64  `json:"revision"`
		Name     string `json:"name"`
		Enabled  bool   `json:"enabled"`
	}
	if code := admin.get(sink, &view); code != 200 || view.Revision != created.Sink.Revision || view.Name != "order" || !view.Enabled {
		t.Fatalf("refused changes altered the sink: %d %+v", code, view)
	}

	// A test delivery is audited, changes nothing and reports how the send went.
	var tested struct {
		ErrorClass *string `json:"error_class"`
	}
	if code, errCode := admin.call("POST", sink+"/test", nil, &tested, rev); code != 200 || tested.ErrorClass == nil || *tested.ErrorClass == "" {
		t.Fatalf("test: %d %s %v", code, errCode, tested.ErrorClass)
	}
	if n := sinkChanges(); n != 2 {
		t.Errorf("after the test delivery: %d audit rows, want 2", n)
	}

	// A delete answers without a sink or a secret, and is the last audit row.
	var deleted struct {
		Sink   any
		Secret *string
	}
	if code, errCode := admin.call("DELETE", sink, nil, &deleted, rev); code != 200 || deleted.Sink != nil || deleted.Secret != nil {
		t.Fatalf("delete: %d %s %+v", code, errCode, deleted)
	}
	if code := admin.get(sink, nil); code != 404 {
		t.Fatalf("read after delete: %d", code)
	}
	var action, before, after string
	if err := app.Pool.QueryRow(context.Background(), `SELECT metadata->>'action', jsonb_typeof(metadata->'before'), jsonb_typeof(metadata->'after') FROM audit_log WHERE action='settings.audit_sink_change' AND target_id=$1 ORDER BY id DESC LIMIT 1`, created.Sink.ID).Scan(&action, &before, &after); err != nil {
		t.Fatal(err)
	}
	// The recorded action ends with the route (today it is the method and then
	// the route pattern, which names the method again).
	if !strings.HasSuffix(action, "DELETE "+base+"/{id}") || before != "object" || after != "null" {
		t.Errorf("delete audit row: action %q, before %s, after %s", action, before, after)
	}
	if n := sinkChanges(); n != 3 {
		t.Errorf("after the delete: %d audit rows, want 3", n)
	}
}
