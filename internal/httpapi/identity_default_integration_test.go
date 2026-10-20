package httpapi_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Decision 64: "Send identity token" defaults to off for a server with no
// authentication on a public host, and stays on for the company's own hosts
// and for the other modes. An explicit value is always kept.

// defaultsEnv is a registry outside development mode where
// mcp.deepwiki.example.com resolves to a public address, mcp.corp.example.com
// to 10.20.0.5 and anything else not at all; nothing is ever dialled.
func defaultsEnv(t *testing.T) *registryEnv {
	return newRegistryEnvWith(t, func(d *httpapi.Deps, _ *testutil.FakeMCP) {
		c := d.Registry.Client()
		c.AllowPrivate = false
		c.Lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
			switch strings.TrimSuffix(strings.ToLower(host), ".") {
			case "mcp.deepwiki.example.com":
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			case "mcp.corp.example.com":
				return []netip.Addr{netip.MustParseAddr("10.20.0.5")}, nil
			}
			return nil, errors.New("no such host")
		}
		c.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("no network in tests") }
	})
}

func TestSendIdentityDefaultFollowsTheHost(t *testing.T) {
	e := defaultsEnv(t)
	e.setNetworks(entry("host", "mcp.corp.example.com", false), entry("cidr", "10.30.0.0/16", false))
	n := 0
	create := func(url string, extra map[string]any) apitypes.McpServer {
		t.Helper()
		n++
		body := map[string]any{"slug": "s" + string(rune('a'+n)), "name": "S", "url": url}
		for k, v := range extra {
			body[k] = v
		}
		return e.create(body).Server
	}
	sends := func(s apitypes.McpServer) string {
		t.Helper()
		if s.SendIdentity == nil {
			return "absent"
		}
		if *s.SendIdentity {
			return "on"
		}
		return "off"
	}
	for _, c := range []struct {
		name, url string
		extra     map[string]any
		want      string
	}{
		{"public host, no auth", "https://mcp.deepwiki.example.com/mcp", nil, "off"},
		{"public host, authMode none", "https://mcp.deepwiki.example.com/mcp", map[string]any{"authMode": "none"}, "off"},
		{"public literal, no auth", "https://93.184.216.34/mcp", nil, "off"},
		{"unresolvable name, no auth", "https://nowhere.example.com/mcp", nil, "off"},
		{"allow-listed host, no auth", "https://mcp.corp.example.com/mcp", nil, "on"},
		{"allow-listed network, no auth", "https://10.30.1.2/mcp", nil, "on"},
		{"public host, static header", "https://mcp.deepwiki.example.com/mcp", map[string]any{"authHeaderName": "X-Api-Key", "authValue": "key-1234567890"}, "on"},
		{"public host, explicit on", "https://mcp.deepwiki.example.com/mcp", map[string]any{"sendIdentity": true}, "on"},
		{"public host, explicit off", "https://mcp.deepwiki.example.com/mcp", map[string]any{"sendIdentity": false}, "off"},
		{"allow-listed host, explicit off", "https://mcp.corp.example.com/mcp", map[string]any{"sendIdentity": false}, "off"},
		{"unresolvable name, explicit on", "https://nowhere.example.com/mcp", map[string]any{"sendIdentity": true}, "on"},
	} {
		s := create(c.url, c.extra)
		if got := sends(s); got != c.want {
			t.Errorf("%s: sendIdentity = %s, want %s", c.name, got, c.want)
		}
		// What was stored is what the API says, and a later change of another
		// field keeps it.
		if got := sends(e.server(e.editor, s.Id.String())); got != c.want {
			t.Errorf("%s: read back %s, want %s", c.name, got, c.want)
		}
	}
	// The first public server's audit entry records the stored value.
	var after string
	if err := e.app.Pool.QueryRow(context.Background(),
		`SELECT after_state::text FROM audit_log WHERE action = 'mcp_server.create' ORDER BY id LIMIT 1`).Scan(&after); err != nil || !strings.Contains(after, `"sendIdentity": false`) {
		t.Errorf("audit after = %s (%v)", after, err)
	}
	// A public no-auth server that was saved with the default and is then given a
	// header keeps what it had (only a person changes the switch).
	pub := create("https://mcp.deepwiki.example.com/mcp", nil)
	code, ec := e.editor.call("PATCH", toolsTeam+"/mcp-servers/"+pub.Id.String(), map[string]any{"description": "changed"}, nil, ifMatch(pub.Revision))
	mustCode(t, "patch", code, ec, 200, "")
	if got := sends(e.server(e.editor, pub.Id.String())); got != "off" {
		t.Errorf("after an unrelated edit = %s", got)
	}
}

// The add form asks which default applies before saving.
func TestIdentityDefaultEndpoint(t *testing.T) {
	e := defaultsEnv(t)
	e.setNetworks(entry("host", "mcp.corp.example.com", false))
	ask := func(s *session, url string) (int, string, apitypes.IdentityDefault) {
		t.Helper()
		var out apitypes.IdentityDefault
		code, ec := s.call("POST", toolsTeam+"/mcp-servers/identity-default", map[string]any{"url": url}, &out, nil)
		return code, ec, out
	}
	for _, c := range []struct {
		url   string
		basis apitypes.IdentityDefaultBasis
		send  bool
	}{
		{"https://mcp.deepwiki.example.com/mcp", "public_host", false},
		{"https://mcp.corp.example.com/mcp", "internal_host", true},
		{"https://nowhere.example.com/mcp", "unresolved_host", false},
	} {
		code, ec, got := ask(e.editor, c.url)
		mustCode(t, c.url, code, ec, 200, "")
		if got.Basis != c.basis || got.SendIdentity != c.send {
			t.Errorf("%s = %+v, want %s and %v", c.url, got, c.basis, c.send)
		}
	}
	code, ec, _ := ask(e.editor, "http://mcp.deepwiki.example.com/mcp")
	mustCode(t, "http", code, ec, 422, "url_not_allowed")
	code, ec, _ = ask(e.member, "https://mcp.deepwiki.example.com/mcp")
	mustCode(t, "member", code, ec, 403, "forbidden")
	code, ec, _ = ask(e.outsider, "https://mcp.deepwiki.example.com/mcp")
	mustCode(t, "outsider", code, ec, 404, "")
	// Nothing was saved or audited.
	var servers int
	if err := e.app.Pool.QueryRow(context.Background(), `SELECT count(*) FROM mcp_servers`).Scan(&servers); err != nil || servers != 0 {
		t.Errorf("servers = %d (%v)", servers, err)
	}
}

// The call record says whether the identity token went to the server
// (identitySent): true when sent, false when the switch was off, absent for a
// call that was not forwarded and for one recorded before the field existed;
// ?identitySent= keeps either kind.
func TestCallRecordsIdentitySent(t *testing.T) {
	e := newGwEnv(t, nil)
	quiet := testutil.NewFakeMCP(t)
	quiet.EnableGatewayTools()
	noID := e.createServer(e.owner, "tools", "quiet", quiet.URL(), map[string]any{"sendIdentity": false})
	gw := e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	gwPath := toolsTeam + "/gateways/" + gw.Id.String()
	e.mustSetCaps(e.owner, gwPath, sel(
		e.capID(e.owner, e.server, "tool", "whoami"), e.capID(e.owner, noID, "tool", "whoami"),
		e.capID(e.owner, e.server, "tool", "check_outage")+":admin"))
	key := newKey(t, e.member, "laptop")
	cs := connect(t, e.app, "support", key.Secret)
	call := func(name string) *mcp.CallToolResult {
		t.Helper()
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name})
		if err != nil {
			return nil // refused as an error
		}
		return res
	}
	if res := call("status__whoami"); res == nil || res.IsError {
		t.Fatalf("status__whoami = %+v", res)
	}
	if res := call("quiet__whoami"); res == nil || res.IsError {
		t.Fatalf("quiet__whoami = %+v", res)
	}
	call("status__check_outage") // needs admin: denied, never forwarded
	toolNames(t, cs)             // a list: served by the portal

	// A call recorded by the previous release: no value.
	e.scalar(`INSERT INTO mcp_calls (method, exposed_name, gateway_id, gateway_slug, gateway_name, gateway_team_id, user_id, outcome)
		SELECT 'tools/call', 'old__tool', $1::uuid, 'support', 'Support', (SELECT id FROM teams WHERE slug = 'tools'), id, 'ok'
		FROM users WHERE email = 'blair@localhost' RETURNING id::text`, gw.Id.String())

	list := func(s *session, path string) map[string]*bool {
		t.Helper()
		var page apitypes.McpCallPage
		if code := s.get(path, &page); code != 200 {
			t.Fatalf("%s = %d", path, code)
		}
		out := map[string]*bool{}
		for _, it := range page.Items {
			name := it.Method + " " + string(it.Outcome)
			if it.ExposedName != nil {
				name += " " + *it.ExposedName
			}
			out[name] = it.IdentitySent
		}
		return out
	}
	state := func(b *bool) string {
		switch {
		case b == nil:
			return "none"
		case *b:
			return "true"
		}
		return "false"
	}
	all := list(e.owner, toolsTeam+"/calls?limit=50")
	want := map[string]string{
		"tools/call ok status__whoami":           "true",
		"tools/call ok quiet__whoami":            "false",
		"tools/call denied status__check_outage": "none",
		"tools/list ok":                          "none",
		"tools/call ok old__tool":                "none",
	}
	for k, v := range want {
		if got, ok := all[k]; !ok || state(got) != v {
			t.Errorf("%s: identitySent = %v (listed %v), want %s", k, state(all[k]), ok, v)
		}
	}
	if len(all) != len(want) {
		t.Errorf("calls = %d, want %d: %v", len(all), len(want), all)
	}

	// The filter, for the team and for platform staff.
	for _, base := range []struct {
		s    *session
		path string
	}{{e.owner, toolsTeam + "/calls"}, {e.admin, "/v1/admin/calls"}} {
		sent := list(base.s, base.path+"?identitySent=true&limit=50")
		if len(sent) != 1 || sent["tools/call ok status__whoami"] == nil || !*sent["tools/call ok status__whoami"] {
			t.Errorf("%s identitySent=true = %v", base.path, sent)
		}
		notSent := list(base.s, base.path+"?identitySent=false&limit=50")
		if len(notSent) != 1 || notSent["tools/call ok quiet__whoami"] == nil || *notSent["tools/call ok quiet__whoami"] {
			t.Errorf("%s identitySent=false = %v", base.path, notSent)
		}
	}
	if code := e.owner.get(toolsTeam+"/calls?identitySent=maybe", nil); code != 400 {
		t.Errorf("identitySent=maybe = %d, want 400", code)
	}
	// One call's detail carries it too.
	var one apitypes.McpCall
	id := e.scalar(`SELECT id::text FROM mcp_calls WHERE exposed_name = 'quiet__whoami'`)
	if code := e.owner.get(toolsTeam+"/calls/"+id, &one); code != 200 || one.IdentitySent == nil || *one.IdentitySent {
		t.Errorf("call detail = %d %+v", code, one.IdentitySent)
	}
}
