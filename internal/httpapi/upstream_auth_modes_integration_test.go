package httpapi_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// The v0.3.2 upstream auth features together (decisions 72, 73 and 74): a
// server can be in any of the modes none, static_header, person_secret and
// machine_oauth (oauth needs a sign-in and is covered by its own tests) while
// also behind a private CA that requires a client certificate. These tests
// run every mode against a server like that and check what the features
// promise one another: every mode is created, tested, refreshed and called;
// a switch of mode leaves no secret of the old one behind; another origin
// never keeps any kind of secret; a changed CA sends every mode back to
// review; automation tokens set none of it; relayed calls apply the right
// credential; and no secret of any kind leaks.
//
// Limit, as documented (docs/registry.md, docs/machine-oauth.md): the TLS
// settings are for the MCP server's own URL. The OAuth metadata and token
// endpoints a machine_oauth or oauth server uses are reached with the system
// roots and no client certificate, so a server's token endpoint can't be
// behind its private CA.

const (
	modeStaticKey = "static-key-SENTINEL-0007"
	modeKeyOwner  = "person-key-SENTINEL-0008"
	modeKeyBlair  = "person-key-SENTINEL-0009"
	portalCN      = "omp-portal"
)

// modeSrv is one server behind the private CA, in one mode.
type modeSrv struct {
	mode, slug string
	fake       *testutil.MTLSFake
	srv        apitypes.McpServer
}

func (m *modeSrv) tool() string { return m.slug + "__whoami" }

type modesEnv struct {
	*gwEnv
	logs *syncBuffer
	reg  *registry.Service
	as   *testutil.FakeOAuth
	// ca signs the servers' certificates and the client certificate.
	ca, client *testutil.Cert
	servers    map[string]*modeSrv
	// seen is every response body the test made.
	seen []string
	// gwPath is the team's gateway "support"; ownerMCP and blairMCP are their MCP keys for it.
	gwPath             string
	ownerMCP, blairMCP string
}

func newModesEnv(t *testing.T) *modesEnv {
	t.Helper()
	logs := &syncBuffer{}
	e := &modesEnv{logs: logs, servers: map[string]*modeSrv{}}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e.gwEnv = newGwEnvHook(t, log, func(d *httpapi.Deps) { e.reg = d.Registry })
	e.as = testutil.NewFakeOAuth(t)
	e.as.Set(func(f *testutil.FakeOAuth) {
		f.ClientSecret, f.EnforceExpiry, f.MachineScopes = machineSecret, true, []string{"read", "write"}
	})
	e.ca = testutil.NewCA(t, "Internal CA")
	e.client = e.ca.Issue(t, testutil.IssueOptions{CommonName: portalCN, Client: true, NotAfter: time.Now().Add(90 * 24 * time.Hour)})
	return e
}

// startMTLS starts a server that requires client certificates signed by the
// CA, with the tools every test uses (and the one that echoes credentials).
func (e *modesEnv) startMTLS() *testutil.MTLSFake {
	e.t.Helper()
	f := testutil.StartMTLSFake(e.t, testutil.MTLSOptions{
		Server:    e.ca.Issue(e.t, testutil.IssueOptions{Server: true, IPs: []net.IP{net.ParseIP("127.0.0.1")}}),
		ClientCAs: []*testutil.Cert{e.ca},
	})
	f.EnableGatewayTools()
	f.EnableEchoSecrets()
	return f
}

func (e *modesEnv) tlsBody() map[string]any {
	return map[string]any{"caPem": e.ca.CertPEM, "clientCertPem": e.client.CertPEM, "clientKeyPem": e.client.KeyPEM}
}

func (e *modesEnv) machineBody(f *testutil.MTLSFake, extra map[string]any) map[string]any {
	m := map[string]any{"tokenUrl": e.as.URL + "/token", "clientId": e.as.ClientID, "clientSecret": machineSecret,
		"scopes": []string{"read"}, "resource": f.URL()}
	for k, v := range extra {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

// protect makes f an OAuth resource server for the fake authorization server.
func (e *modesEnv) protect(f *testutil.MTLSFake) {
	f.Protect(testutil.Protection{Issuer: e.as.Issuer(), Resource: f.URL(),
		Introspect: func(_ context.Context, tok string) testutil.Introspection { return e.as.Introspect(tok) }})
}

func (e *modesEnv) staticBody() []any {
	return []any{map[string]any{"kind": "header", "name": "X-Api-Key", "value": modeStaticKey}}
}

// body is the create body of a server in mode on f, with the TLS settings.
func (e *modesEnv) body(mode, slug string, f *testutil.MTLSFake) map[string]any {
	b := map[string]any{"slug": slug, "name": strings.ToUpper(slug), "url": f.URL(), "tls": e.tlsBody()}
	switch mode {
	case "static_header":
		f.RequireHeader("X-Api-Key", modeStaticKey)
		b["authMode"], b["credentials"] = "static_header", e.staticBody()
	case "machine_oauth":
		e.protect(f)
		b["authMode"], b["machineOAuth"] = "machine_oauth", e.machineBody(f, nil)
	case "person_secret":
		b["authMode"], b["personSecret"] = "person_secret", secretConfig("header", "X-Api-Key", "")
	}
	return b
}

func (e *modesEnv) post(path string, body any) (int, []byte) {
	e.t.Helper()
	code, raw := e.owner.raw("POST", path, body, nil)
	e.seen = append(e.seen, string(raw))
	return code, raw
}

// add creates a server in mode behind its own private-CA server and, for
// person_secret, enters the owner's key as the setup key.
func (e *modesEnv) add(mode string) *modeSrv {
	e.t.Helper()
	m := &modeSrv{mode: mode, slug: strings.ReplaceAll(mode, "_", "-"), fake: e.startMTLS()}
	code, raw := e.post(toolsTeam+"/mcp-servers", e.body(mode, m.slug, m.fake))
	if code != 201 {
		e.t.Fatalf("create %s = %d %s", mode, code, raw)
	}
	var created struct{ Data apitypes.McpServerCreated }
	_ = json.Unmarshal(raw, &created)
	if created.Data.RefreshError != nil {
		e.t.Fatalf("discovery of %s failed: %+v", mode, created.Data.RefreshError)
	}
	m.srv = created.Data.Server
	if mode == "person_secret" {
		if created.Data.SetupRequired == nil || !*created.Data.SetupRequired {
			e.t.Fatalf("a new person_secret server should need setup: %+v", created.Data)
		}
		e.putSecret(e.owner, m, modeKeyOwner, map[string]any{"useForSetup": true}, 200)
	}
	e.servers[mode] = m
	return m
}

func (e *modesEnv) path(m *modeSrv) string { return toolsTeam + "/mcp-servers/" + m.srv.Id.String() }

func (e *modesEnv) get(s *session, m *modeSrv) apitypes.McpServer {
	e.t.Helper()
	var sv apitypes.McpServer
	if code := s.get(e.path(m), &sv); code != 200 {
		e.t.Fatalf("get %s = %d", m.slug, code)
	}
	return sv
}

func (e *modesEnv) patch(s *session, m *modeSrv, body map[string]any) (int, []byte) {
	e.t.Helper()
	code, raw := s.raw("PATCH", e.path(m), body, ifMatch(e.get(s, m).Revision))
	e.seen = append(e.seen, string(raw))
	return code, raw
}

func (e *modesEnv) mustPatch(s *session, m *modeSrv, body map[string]any) apitypes.McpServer {
	e.t.Helper()
	code, raw := e.patch(s, m, body)
	if code != 200 {
		e.t.Fatalf("patch %s %v = %d %s", m.slug, keysOf(body), code, raw)
	}
	var out struct{ Data apitypes.McpServer }
	_ = json.Unmarshal(raw, &out)
	return out.Data
}

func (e *modesEnv) putSecret(s *session, m *modeSrv, value string, extra map[string]any, want int) []byte {
	e.t.Helper()
	body := map[string]any{"origin": registry.OriginOf(m.fake.URL())}
	if value != "" {
		body["value"] = value
	}
	for k, v := range extra {
		body[k] = v
	}
	code, raw := s.raw("PUT", "/v1/me/server-secrets/"+m.srv.Id.String(), body, nil)
	e.seen = append(e.seen, string(raw))
	if code != want {
		e.t.Fatalf("PUT the key of %s = %d %s, want %d", m.slug, code, raw, want)
	}
	return raw
}

// setupGateway offers every added server's whoami tool in the team's gateway
// "support" and gives the owner and Blair an MCP key each.
func (e *modesEnv) setupGateway() {
	e.t.Helper()
	gw := e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	e.gwPath = toolsTeam + "/gateways/" + gw.Id.String()
	var ids []string
	for _, m := range e.servers {
		ids = append(ids, e.capID(e.owner, m.srv, "tool", "whoami"), e.capID(e.owner, m.srv, "tool", "echo_secrets"))
	}
	e.mustSetCaps(e.owner, e.gwPath, sel(ids...))
	e.ownerMCP, e.blairMCP = newKey(e.t, e.owner, "laptop").Secret, newKey(e.t, e.member, "laptop").Secret
}

func (e *modesEnv) call(key, tool string) (int, map[string]any) {
	e.t.Helper()
	code, _, out := rawMCP(e.t, e.app, "POST", "support", key, rpc(1, "tools/call", map[string]any{"name": tool, "arguments": map[string]any{}}), nil)
	b, _ := json.Marshal(out)
	e.seen = append(e.seen, string(b))
	return code, out
}

// requestsSince are the HTTP requests m's server received after the first n.
func requestsSince(m *modeSrv, n int) []testutil.HTTPRequest { return m.fake.HTTPRequests()[n:] }

// wantTLSIdentity checks that every request m's server received came over TLS
// 1.2 or newer with the portal's client certificate.
func (e *modesEnv) wantTLSIdentity(m *modeSrv) {
	e.t.Helper()
	seen := m.fake.Seen()
	if len(seen) == 0 {
		e.t.Fatalf("%s: no request reached the server", m.slug)
	}
	for _, s := range seen {
		if s.ClientCN != portalCN || s.Version < tls.VersionTLS12 {
			e.t.Errorf("%s: a request came with client %q over TLS %x", m.slug, s.ClientCN, s.Version)
		}
	}
}

// wantCredential checks the credential every request of m's server since n
// carried: the one of its mode (key: the person's own for person_secret) and,
// when identity, the portal's signed identity token (Test and calls send one;
// discovery and scheduled checks send nobody's). The identity token travels in
// Authorization: Bearer, except where that header is the mode's own (the
// machine token), when it moves to MCP-Gateway-Identity.
func (e *modesEnv) wantCredential(m *modeSrv, n int, key string, identity bool) {
	e.t.Helper()
	reqs := requestsSince(m, n)
	if len(reqs) == 0 {
		e.t.Fatalf("%s: no request since %d", m.slug, n)
	}
	issued := e.as.Issued()
	for _, r := range reqs {
		auth, id, apikey := r.Header.Get("Authorization"), r.Header.Get("MCP-Gateway-Identity"), r.Header.Get("X-Api-Key")
		isJWT := strings.HasPrefix(auth, "Bearer ") && strings.Count(auth, ".") == 2
		switch m.mode {
		case "machine_oauth":
			if !strings.HasPrefix(auth, "Bearer ") || !slices.Contains(issued, strings.TrimPrefix(auth, "Bearer ")) || apikey != "" || (id != "") != identity {
				e.t.Errorf("machine_oauth: Authorization %.20q (an issued token: %v), identity header %v, want identity %v",
					auth, slices.Contains(issued, strings.TrimPrefix(auth, "Bearer ")), id != "", identity)
			}
			continue
		case "static_header":
			if apikey != modeStaticKey {
				e.t.Errorf("static_header: X-Api-Key %q", apikey)
			}
		case "person_secret":
			if apikey != key && !(key == "" && apikey == "") {
				e.t.Errorf("person_secret: X-Api-Key %q, want %q", apikey, key)
			}
		default:
			if apikey != "" {
				e.t.Errorf("none: X-Api-Key %q", apikey)
			}
		}
		if id != "" || isJWT != identity {
			e.t.Errorf("%s: identity token in Authorization %v (want %v), MCP-Gateway-Identity %q", m.mode, isJWT, identity, id)
		}
	}
}

// Every mode works behind a private CA that requires a client certificate: the
// server is created and read, tested, refreshed, health-checked, edited and
// called by a person, each time over mTLS and with the credential of its mode.
func TestEveryAuthModeWorksBehindAPrivateCAAndMTLS(t *testing.T) {
	e := newModesEnv(t)
	ctx := context.Background()
	for _, mode := range []string{"none", "static_header", "machine_oauth", "person_secret"} {
		e.add(mode)
	}
	e.setupGateway()
	e.putSecret(e.member, e.servers["person_secret"], modeKeyBlair, nil, 200)

	for _, mode := range []string{"none", "static_header", "machine_oauth", "person_secret"} {
		m := e.servers[mode]
		t.Run(mode, func(t *testing.T) {
			sv := e.get(e.owner, m)
			if sv.AuthMode == nil || string(*sv.AuthMode) != mode || sv.Tls == nil || sv.Tls.Client == nil || sv.Tls.Ca == nil || sv.Tls.Client.HasKey != true || sv.Counts.Tools == 0 {
				t.Fatalf("%s as created = %+v tls %+v", mode, sv, sv.Tls)
			}
			switch mode {
			case "machine_oauth":
				if sv.MachineOAuth == nil || sv.PersonSecret != nil {
					t.Fatalf("machine view = %+v %+v", sv.MachineOAuth, sv.PersonSecret)
				}
			case "person_secret":
				if sv.PersonSecret == nil || sv.MachineOAuth != nil || sv.PersonSecret.People != 2 {
					t.Fatalf("person_secret view = %+v %+v", sv.MachineOAuth, sv.PersonSecret)
				}
			default:
				if sv.PersonSecret != nil || sv.MachineOAuth != nil {
					t.Fatalf("%s shows another mode's settings: %+v %+v", mode, sv.PersonSecret, sv.MachineOAuth)
				}
			}

			// Test connection (the editor's own key, for person_secret, was
			// chosen as the setup key; the identity token is the editor's).
			mark := len(m.fake.HTTPRequests())
			code, raw := e.owner.raw("POST", e.path(m)+"/test", nil, nil)
			e.seen = append(e.seen, string(raw))
			if code != 200 || !strings.Contains(string(raw), `"ok":true`) {
				t.Fatalf("test = %d %s", code, raw)
			}
			e.wantCredential(m, mark, modeKeyOwner, true)

			// Refresh reads the capabilities again.
			mark = len(m.fake.HTTPRequests())
			if code, raw := e.owner.raw("POST", e.path(m)+"/refresh", nil, nil); code != 200 {
				t.Fatalf("refresh = %d %s", code, raw)
			} else {
				e.seen = append(e.seen, string(raw))
			}
			e.wantCredential(m, mark, modeKeyOwner, false)

			// An edit that touches no credential keeps the mode, the secrets and the TLS settings.
			e.mustPatch(e.owner, m, map[string]any{"description": "edited"})
			after := e.get(e.owner, m)
			if after.Description != "edited" || string(*after.AuthMode) != mode || after.Tls == nil || after.Tls.Client == nil ||
				after.Tls.Client.Certificate.Sha256 != sv.Tls.Client.Certificate.Sha256 {
				t.Fatalf("after an edit: %+v tls %+v", after, after.Tls)
			}

			// A scheduled health check: with the credential of its mode, or none
			// for person_secret (it sends nobody's key, and the server's 401 is healthy).
			if _, err := e.app.Pool.Exec(ctx, `DELETE FROM mcp_health_checks WHERE server_id = $1`, m.srv.Id); err != nil {
				t.Fatal(err)
			}
			mark = len(m.fake.HTTPRequests())
			if _, err := e.reg.RunHealthChecks(ctx, time.Minute); err != nil {
				t.Fatal(err)
			}
			if h := e.get(e.owner, m).Health; h.Status != "healthy" {
				t.Fatalf("health = %+v", h)
			}
			if mode == "person_secret" {
				for _, r := range requestsSince(m, mark) {
					if r.Header.Get("X-Api-Key") != "" {
						t.Errorf("a scheduled check carried a key")
					}
				}
			} else {
				e.wantCredential(m, mark, "", false)
			}

			// Calls by two people through the gateway.
			for who, key := range map[string]string{"owner": e.ownerMCP, "blair": e.blairMCP} {
				mark = len(m.fake.HTTPRequests())
				code, out := e.call(key, m.tool())
				if code != 200 {
					t.Fatalf("%s's call = %d %v", who, code, out)
				}
				if text, isErr := toolText(t, out); isErr {
					t.Fatalf("%s's call failed: %s", who, text)
				}
				want := modeKeyOwner
				if who == "blair" {
					want = modeKeyBlair
				}
				e.wantCredential(m, mark, want, true)
			}
			e.wantTLSIdentity(m)
		})
	}
	// The call records say each call worked, and the keys are not in them.
	if n := e.scalar(`SELECT count(*)::text FROM mcp_calls WHERE outcome = 'ok'`); n != "8" {
		t.Errorf("%s successful calls recorded, want 8", n)
	}
}

// count is how many rows of table (keyed by server_id) the server has.
func (e *modesEnv) count(table string, m *modeSrv) string {
	return e.scalar(`SELECT count(*)::text FROM `+table+` WHERE server_id = $1`, m.srv.Id)
}

// audited counts the audit entries of action whose metadata has key = value.
func (e *modesEnv) audited(action, key, value string) string {
	return e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = $1 AND metadata->>$2 = $3`, action, key, value)
}

// wantTLSKept checks the server's TLS settings (and the sealed key) are the
// ones it was created with: a change of mode never touches them.
func (e *modesEnv) wantTLSKept(m *modeSrv, fingerprint string) {
	e.t.Helper()
	sv := e.get(e.owner, m)
	if sv.Tls == nil || sv.Tls.Client == nil || sv.Tls.Ca == nil || sv.Tls.Client.Certificate.Sha256 != fingerprint ||
		e.scalar(`SELECT (client_key_cipher IS NOT NULL)::text FROM mcp_server_tls WHERE server_id = $1`, m.srv.Id) != "true" {
		e.t.Fatalf("the TLS settings changed: %+v", sv.Tls)
	}
}

// Switching a server between modes leaves nothing of the old one behind: a
// person's keys are deleted when the mode changes away from person_secret
// (and audited), the machine client and its secret when it changes away from
// machine_oauth, whichever mode it goes to; the static credential and the TLS
// settings are not the old mode's and stay.
func TestSwitchingAuthModeCleansUpEverySecret(t *testing.T) {
	e := newModesEnv(t)
	m := e.add("none")
	e.setupGateway()
	fingerprint := e.get(e.owner, m).Tls.Client.Certificate.Sha256
	personCfg := secretConfig("header", "X-Person-Key", "")
	people := func() string { return e.count("person_secrets", m) }
	machines := func() string { return e.count("mcp_server_machine_oauth", m) }
	enterKeys := func() {
		e.putSecret(e.owner, m, modeKeyOwner, map[string]any{"useForSetup": true}, 200)
		e.putSecret(e.member, m, modeKeyBlair, nil, 200)
		if people() != "2" {
			t.Fatalf("%s keys after entering two", people())
		}
	}
	apiKey := func(who string) string {
		t.Helper()
		mark := len(m.fake.HTTPRequests())
		key := e.blairMCP
		if who == "owner" {
			key = e.ownerMCP
		}
		if code, out := e.call(key, m.tool()); code != 200 {
			t.Fatalf("call = %d %v", code, out)
		} else if text, isErr := toolText(t, out); isErr {
			t.Fatalf("call failed: %s", text)
		}
		reqs := requestsSince(m, mark)
		return reqs[len(reqs)-1].Header.Get("X-Person-Key") + "|" + reqs[len(reqs)-1].Header.Get("X-Api-Key") + "|" + strings.TrimPrefix(reqs[len(reqs)-1].Header.Get("Authorization"), "Bearer ")
	}
	isToken := func(auth string) bool { return slices.Contains(e.as.Issued(), auth) }

	// none -> person_secret: Blair's own key is sent, in the header the team chose.
	e.mustPatch(e.owner, m, map[string]any{"authMode": "person_secret", "personSecret": personCfg})
	enterKeys()
	if got := strings.SplitN(apiKey("blair"), "|", 3); got[0] != modeKeyBlair || got[1] != "" || isToken(got[2]) {
		t.Fatalf("person_secret call sent %q", got)
	}

	// person_secret -> machine_oauth: everyone's keys are deleted, the client is stored.
	e.mustPatch(e.owner, m, map[string]any{"authMode": "machine_oauth", "machineOAuth": e.machineBody(m.fake, nil)})
	if people() != "0" || machines() != "1" || e.audited("mcp_server.person_secrets_reset", "reason", "mode_changed") != "1" ||
		e.scalar(`SELECT (secret_placement IS NULL)::text FROM mcp_servers WHERE id = $1`, m.srv.Id) != "true" {
		t.Fatalf("after person_secret -> machine_oauth: %s keys, %s clients", people(), machines())
	}
	if got := strings.SplitN(apiKey("blair"), "|", 3); got[0] != "" || !isToken(got[2]) {
		t.Fatalf("machine_oauth call sent %q: the portal's own token must replace the person's key", got)
	}
	issued := len(e.as.Issued())

	// machine_oauth -> static_header: the client and its secret are discarded, the
	// cached token is not sent any more, and the static credential is.
	e.mustPatch(e.owner, m, map[string]any{"authMode": "static_header", "credentials": e.staticBody()})
	if machines() != "0" || e.audited("mcp_server.auth_update", "machineOAuthRemoved", "true") != "1" {
		t.Fatalf("after machine_oauth -> static_header: %s clients", machines())
	}
	if got := strings.SplitN(apiKey("owner"), "|", 3); got[1] != modeStaticKey || isToken(got[2]) || len(e.as.Issued()) != issued {
		t.Fatalf("static call sent %q (tokens issued %d, was %d)", got, len(e.as.Issued()), issued)
	}

	// static_header -> person_secret: the static credential stays beside each
	// person's key; keys are entered again.
	e.mustPatch(e.owner, m, map[string]any{"authMode": "person_secret", "personSecret": personCfg})
	enterKeys()
	if got := strings.SplitN(apiKey("owner"), "|", 3); got[0] != modeKeyOwner || got[1] != modeStaticKey {
		t.Fatalf("person_secret with a static part sent %q", got)
	}
	// person_secret -> machine_oauth: keys deleted again, the static part still goes.
	e.mustPatch(e.owner, m, map[string]any{"authMode": "machine_oauth", "machineOAuth": e.machineBody(m.fake, nil)})
	if people() != "0" || machines() != "1" || e.audited("mcp_server.person_secrets_reset", "reason", "mode_changed") != "2" {
		t.Fatalf("after the second switch: %s keys, %s clients", people(), machines())
	}
	if got := strings.SplitN(apiKey("owner"), "|", 3); got[0] != "" || got[1] != modeStaticKey || !isToken(got[2]) {
		t.Fatalf("machine_oauth with a static part sent %q", got)
	}
	// machine_oauth -> person_secret directly: the client goes, keys start empty.
	e.mustPatch(e.owner, m, map[string]any{"authMode": "person_secret", "personSecret": personCfg})
	if machines() != "0" || people() != "0" {
		t.Fatalf("after machine_oauth -> person_secret: %s clients, %s keys", machines(), people())
	}
	enterKeys()
	// person_secret -> none: keys deleted, nothing of either mode is left.
	e.mustPatch(e.owner, m, map[string]any{"authMode": "none"})
	if people() != "0" || machines() != "0" || e.audited("mcp_server.person_secrets_reset", "reason", "mode_changed") != "3" ||
		e.count("secret_requests", m) != "0" {
		t.Fatalf("after person_secret -> none: %s keys, %s clients", people(), machines())
	}
	if got := strings.SplitN(apiKey("owner"), "|", 3); got[0] != "" || isToken(got[2]) || !strings.Contains(got[2], ".") {
		t.Fatalf("a server in none sent %q", got)
	}
	// None of it touched the TLS settings, and the key of none of it is in the audit log.
	e.wantTLSKept(m, fingerprint)
	e.wantTLSIdentity(m)
	audit := e.scalar(`SELECT coalesce(string_agg(coalesce(before_state::text, '') || coalesce(after_state::text, '') || coalesce(metadata::text, ''), ' '), '') FROM audit_log`)
	for _, secret := range append([]string{modeKeyOwner, modeKeyBlair, modeStaticKey, machineSecret}, e.as.Issued()...) {
		if strings.Contains(audit, secret) {
			t.Errorf("the audit log holds %q", secret)
		}
	}
}

// errorOf reads the code and details of an error answer.
func errorOf(raw []byte) (code, field, reason string) {
	var env struct {
		Error struct {
			Code    string
			Details struct{ Field, Reason string }
		}
	}
	_ = json.Unmarshal(raw, &env)
	return env.Error.Code, env.Error.Details.Field, env.Error.Details.Reason
}

// The F-1 origin rule covers every kind of secret a server holds: a URL on
// another origin never carries the static credential's values, the machine
// client secret or the TLS client key (each refused, with nothing sent to the
// new host, unless the same request replaces it), and a server's person
// secrets are deleted. A secret entered again goes to the new origin; the old
// one's never does.
func TestAnotherOriginDiscardsEverySecretUnlessReplaced(t *testing.T) {
	e := newModesEnv(t)
	statics := e.add("static_header")
	machines := e.add("machine_oauth")
	people := e.add("person_secret")
	e.setupGateway()
	e.putSecret(e.member, people, modeKeyBlair, nil, 200)

	newHost := func(m *modeSrv) *testutil.MTLSFake {
		f := e.startMTLS()
		switch m.mode {
		case "static_header":
			f.RequireHeader("X-Api-Key", modeStaticKey)
		case "machine_oauth":
			e.protect(f)
		}
		return f
	}
	// move sends the update to f's URL with the pieces a refusal asked for, one
	// refusal at a time, and returns the refusals in the order they came.
	move := func(m *modeSrv, f *testutil.MTLSFake, extra map[string]any, replace func(refusal string, body map[string]any)) []string {
		t.Helper()
		body := map[string]any{"url": f.URL()}
		for k, v := range extra {
			body[k] = v
		}
		var refusals []string
		for range 6 {
			code, raw := e.patch(e.owner, m, body)
			if code == 200 {
				return refusals
			}
			c, _, _ := errorOf(raw)
			if code != 422 || c == "" {
				t.Fatalf("%s: move = %d %s", m.slug, code, raw)
			}
			if f.Requests() != 0 {
				t.Fatalf("%s: %s was refused but the new host got %d requests", m.slug, c, f.Requests())
			}
			refusals = append(refusals, c)
			replace(c, body)
		}
		t.Fatalf("%s: still refused after %v", m.slug, refusals)
		return nil
	}
	withTLS := func(body map[string]any) { body["tls"] = e.tlsBody() }

	// Static credential and TLS key: both must be entered again.
	f := newHost(statics)
	oldStatic := statics.fake
	refusals := move(statics, f, nil, func(c string, body map[string]any) {
		switch c {
		case "auth_value_required":
			body["credentials"] = e.staticBody()
		case "tls_key_required":
			withTLS(body)
		default:
			t.Fatalf("static: unexpected refusal %s", c)
		}
	})
	if !slices.Equal(refusals, []string{"auth_value_required", "tls_key_required"}) {
		t.Errorf("static refusals = %v", refusals)
	}
	if got := e.get(e.owner, statics); got.Url != f.URL() || f.Requests() == 0 {
		t.Errorf("the static server didn't move: %s", got.Url)
	}
	e.wantCredential(&modeSrv{mode: "static_header", slug: "static-new", fake: f}, 0, "", false)
	if oldStatic.Requests() == 0 {
		t.Error("the old host saw nothing before the move")
	}

	// Machine client secret and TLS key.
	f = newHost(machines)
	refusals = move(machines, f, nil, func(c string, body map[string]any) {
		switch c {
		case "tls_key_required":
			withTLS(body)
		case "client_secret_required":
			body["machineOAuth"] = map[string]any{"clientSecret": machineSecret, "resource": f.URL()}
		default:
			t.Fatalf("machine: unexpected refusal %s", c)
		}
	})
	slices.Sort(refusals)
	if !slices.Equal(refusals, []string{"client_secret_required", "tls_key_required"}) {
		t.Errorf("machine refusals = %v", refusals)
	}
	if n := len(e.as.ClientCredentialsRequests()); n == 0 {
		t.Error("no token was ever requested")
	}
	for _, r := range e.as.ClientCredentialsRequests() {
		if r.Resource == f.URL() && r.ClientSecret != machineSecret {
			t.Errorf("the token request for the new origin carried %q", r.ClientSecret)
		}
	}
	e.wantCredential(&modeSrv{mode: "machine_oauth", slug: "machine-new", fake: f}, 0, "", false)

	// Person secrets: they are deleted on the move (nothing to enter again here
	// but the TLS key, which the request clears instead of replacing).
	if e.count("person_secrets", people) != "2" {
		t.Fatalf("%s person secrets before the move", e.count("person_secrets", people))
	}
	f = newHost(people)
	refusals = move(people, f, nil, func(c string, body map[string]any) {
		if c != "tls_key_required" {
			t.Fatalf("person_secret: unexpected refusal %s", c)
		}
		body["tls"] = map[string]any{"clear": true}
	})
	if !slices.Equal(refusals, []string{"tls_key_required"}) {
		t.Errorf("person_secret refusals = %v", refusals)
	}
	if e.count("person_secrets", people) != "0" || e.audited("mcp_server.person_secrets_reset", "reason", "origin_changed") != "1" ||
		e.count("mcp_server_tls", people) != "0" {
		t.Errorf("after the move: %s keys, %s TLS rows", e.count("person_secrets", people), e.count("mcp_server_tls", people))
	}
	// The server asks for a new key at the new origin: one entered for the old origin is refused.
	if code, raw := e.owner.raw("PUT", "/v1/me/server-secrets/"+people.srv.Id.String(),
		map[string]any{"origin": registry.OriginOf(people.fake.URL()), "value": modeKeyOwner}, nil); code != 409 {
		t.Errorf("a key entered for the old origin = %d %s, want 409", code, raw)
	}

	// Nothing of the old origins' secrets is anywhere any more: the sealed
	// client key is the replaced one (same PEM here, a new ciphertext) and the
	// static and machine servers kept exactly one row each.
	if e.count("mcp_server_tls", statics) != "1" || e.count("mcp_server_tls", machines) != "1" || e.count("mcp_server_machine_oauth", machines) != "1" {
		t.Error("a moved server lost or duplicated its settings")
	}
}

// A published server goes back to review when what the reviewer approved
// changes, in every mode: a changed or removed CA (decision 74), and the mode's
// own settings (where each person's key goes, the machine client's endpoint).
// A new client certificate, or a new machine secret, does not, but the digest
// the approval names moves with the certificate, so an earlier look is stale.
func TestAChangedCAOrModeSettingSendsEveryModeBackToReview(t *testing.T) {
	e := newModesEnv(t)
	for _, mode := range []string{"none", "static_header", "machine_oauth", "person_secret"} {
		e.add(mode)
	}
	approve := func(m *modeSrv) {
		t.Helper()
		id := m.srv.Id.String()
		if code, ec := e.admin.call("POST", "/v1/admin/mcp-servers/"+id+"/review", approveBody(t, e.admin, id), nil, nil); code != 200 {
			t.Fatalf("approve %s = %d %s", m.slug, code, ec)
		}
	}
	reason := func() string {
		return e.scalar(`SELECT coalesce(metadata->>'reason', '') FROM audit_log WHERE action = 'mcp_server.publish_request' ORDER BY id DESC LIMIT 1`)
	}
	other := testutil.NewCA(t, "Another CA")
	for _, mode := range []string{"none", "static_header", "machine_oauth", "person_secret"} {
		m := e.servers[mode]
		t.Run(mode, func(t *testing.T) {
			e.publish(e.owner, e.get(e.owner, m))
			published := e.get(e.owner, m)
			if published.PublishState != "published" {
				t.Fatalf("published = %s", published.PublishState)
			}
			// A new client certificate: still published, the digest moves.
			second := e.ca.Issue(t, testutil.IssueOptions{CommonName: "second-" + m.slug, Client: true})
			e.mustPatch(e.owner, m, map[string]any{"tls": map[string]any{"clientCertPem": second.CertPEM, "clientKeyPem": second.KeyPEM}})
			afterCert := e.get(e.owner, m)
			if afterCert.PublishState != "published" || *afterCert.ReviewDigest == *published.ReviewDigest {
				t.Fatalf("a new client certificate: %s, digest moved %v", afterCert.PublishState, *afterCert.ReviewDigest != *published.ReviewDigest)
			}
			// A changed CA: pending, reason upstream_tls_changed, and the earlier digest is stale.
			e.mustPatch(e.owner, m, map[string]any{"tls": map[string]any{"caPem": e.ca.CertPEM + other.CertPEM}})
			if got := e.get(e.owner, m); got.PublishState != "pending" || reason() != "upstream_tls_changed" {
				t.Fatalf("a changed CA: %s (%s)", got.PublishState, reason())
			}
			id := m.srv.Id.String()
			if code, ec := e.admin.call("POST", "/v1/admin/mcp-servers/"+id+"/review",
				map[string]any{"decision": "approve", "expectedDigest": *afterCert.ReviewDigest}, nil, nil); code != 409 || ec != "changed_since_review" {
				t.Fatalf("approve on a stale digest = %d %s", code, ec)
			}
			approve(m)
			// The mode's own setting.
			switch mode {
			case "machine_oauth":
				// A new secret alone is not a review trigger; another token endpoint is.
				e.mustPatch(e.owner, m, map[string]any{"machineOAuth": map[string]any{"clientSecret": machineSecret}})
				if got := e.get(e.owner, m).PublishState; got != "published" {
					t.Fatalf("a new client secret sent the server to %s", got)
				}
				e.mustPatch(e.owner, m, map[string]any{"machineOAuth": map[string]any{"tokenUrl": e.as.URL + "/token2", "clientSecret": machineSecret}})
				if got := e.get(e.owner, m).PublishState; got != "pending" || reason() != "upstream_auth_changed" {
					t.Fatalf("another token endpoint: %s (%s)", got, reason())
				}
			case "person_secret":
				e.mustPatch(e.owner, m, map[string]any{"personSecret": secretConfig("query", "key", "")})
				if got := e.get(e.owner, m).PublishState; got != "pending" || reason() != "upstream_auth_changed" {
					t.Fatalf("another placement: %s (%s)", got, reason())
				}
			}
		})
	}
}

// A call an agent platform relays for a person (decisions 65 to 68) applies
// the credential of the server's mode: the portal's own for static_header and
// machine_oauth, whoever calls (the relay's service account alone included),
// and a person's own key only when that person allowed agents to use it. All
// of it over the server's mTLS.
func TestRelayedCallsApplyEveryAuthMode(t *testing.T) {
	e := newModesEnv(t)
	for _, mode := range []string{"none", "static_header", "machine_oauth", "person_secret"} {
		e.add(mode)
	}
	e.setupGateway()
	fx := setupRelay(t, e.gwEnv)
	agent := agentSpec{Email: "blair@localhost"}
	relay := func(m *modeSrv, who any) (map[string]any, []testutil.HTTPRequest) {
		t.Helper()
		mark := len(m.fake.HTTPRequests())
		_, out := fx.callTool(who, m.tool(), nil)
		return out, requestsSince(m, mark)
	}
	ok := func(m *modeSrv, who any, key string) {
		t.Helper()
		out, reqs := relay(m, who)
		if text, isErr := toolText(t, out); isErr {
			t.Fatalf("%s: the relayed call failed: %s", m.mode, text)
		}
		if len(reqs) == 0 {
			t.Fatalf("%s: nothing reached the server", m.mode)
		}
		_ = key
	}

	// none, static and machine: the agent's call is the person's call and carries the
	// server's own credential; no switch of the person's is involved.
	for _, mode := range []string{"none", "static_header", "machine_oauth"} {
		m := e.servers[mode]
		mark := len(m.fake.HTTPRequests())
		ok(m, agent, "")
		e.wantCredential(m, mark, "", true)
		// The identity token is the person's, with the agent that acted for them.
		who := whoamiOf(t, mustToolCall(t, fx, agent, m.tool()))
		if who.Claims["email"] != "blair@localhost" || who.Act == nil {
			t.Errorf("%s: the identity token a relayed call carried = %+v", mode, who)
		}
		// The relay's own account, with nobody behind it, is a service account's
		// call: the server's own credential applies to it as to anyone.
		mark = len(m.fake.HTTPRequests())
		ok(m, "", "")
		e.wantCredential(m, mark, "", true)
		if sa := whoamiOf(t, mustToolCall(t, fx, agentSpec{}, m.tool())); sa.Claims["principal_type"] != "service_account" {
			t.Errorf("%s: a service account's call carried %+v", mode, sa.Claims)
		}
	}

	// person_secret: nothing without a key, nothing without the switch, the
	// person's own key with it, and never anyone else's; a service account has
	// no key at all.
	ps := e.servers["person_secret"]
	if out, reqs := relay(ps, ""); len(reqs) != 0 {
		t.Fatalf("person_secret: a service account's call reached the server: %v", out)
	} else if c, _, data := rpcErr(out); c != -32010 || data["reason"] != "service_account" {
		t.Fatalf("person_secret: a service account's call = %v", out)
	}
	e.putSecret(e.member, ps, modeKeyBlair, nil, 200)
	mark := len(ps.fake.HTTPRequests())
	out, _ := relay(ps, agent)
	if text, isErr := toolText(t, out); !isErr || !strings.Contains(text, "allowed agents") || len(requestsSince(ps, mark)) != 0 {
		t.Fatalf("person_secret, agents not allowed: %v", out)
	}
	e.putSecret(e.member, ps, "", map[string]any{"allowAgents": true}, 200)
	mark = len(ps.fake.HTTPRequests())
	ok(ps, agent, modeKeyBlair)
	e.wantCredential(ps, mark, modeKeyBlair, true)
	// The owner has a key (the setup key) but hasn't allowed agents.
	mark = len(ps.fake.HTTPRequests())
	out, _ = relay(ps, agentSpec{Email: "user@localhost"})
	if text, isErr := toolText(t, out); !isErr || !strings.Contains(text, "allowed agents") || len(requestsSince(ps, mark)) != 0 {
		t.Fatalf("the owner's agent used a key the owner hadn't allowed: %v", out)
	}
	e.wantTLSIdentity(ps)
	for _, m := range e.servers {
		e.wantTLSIdentity(m)
	}
	// Nothing of any key or token is in the call records, the audit log or what the relay answered.
	secrets := append([]string{modeStaticKey, modeKeyOwner, modeKeyBlair, machineSecret}, e.as.Issued()...)
	fx.noSecrets(e.logs, secrets...)
}

// mustToolCall makes a relayed call and returns the answer (it must have succeeded).
func mustToolCall(t *testing.T, fx *relayFx, who agentSpec, tool string) map[string]any {
	t.Helper()
	_, out := fx.callTool(who, tool, nil)
	return out
}

// One of every secret at once (a static key, two people's keys, a machine
// client secret and the tokens it buys, and a TLS client key), servers that
// echo what they receive, calls that fail in every way, a server whose CA
// isn't the one that signed it, and recorded payloads: none of them is in any
// response, log, audit entry, call record, recorded payload, health message,
// stored error, span or sealed column in the clear.
func TestEverySecretKindNeverLeaksAnywhere(t *testing.T) {
	sr := tracingOn(t)
	e := newModesEnv(t)
	for _, mode := range []string{"none", "static_header", "machine_oauth", "person_secret"} {
		e.add(mode)
	}
	e.setupGateway()
	e.putSecret(e.member, e.servers["person_secret"], modeKeyBlair, map[string]any{"allowAgents": true}, 200)
	// Record the contents of calls.
	g := e.gateway(e.owner, e.gwPath)
	if code, ec := e.owner.call("PATCH", e.gwPath, map[string]any{"capturePayloads": true}, nil, ifMatch(g.Revision)); code != 200 {
		t.Fatalf("capture: %d %s", code, ec)
	}

	// Calls that echo every credential they got, by both people. What a server
	// echoes back to the caller is scrubbed of the person's key, the machine
	// token and the identity token; a team's static credential is not (decision
	// 70 redacts it from logs, messages and recorded payloads, not from a result
	// the caller is meant to get), so it is the one value left out of this check.
	for _, m := range e.servers {
		for _, key := range []string{e.ownerMCP, e.blairMCP} {
			code, _, out := rawMCP(e.t, e.app, "POST", "support", key, rpc(1, "tools/call", map[string]any{"name": m.slug + "__echo_secrets", "arguments": map[string]any{}}), nil)
			if code != 200 || out["error"] != nil {
				t.Fatalf("%s echo = %d %v", m.slug, code, out)
			}
			text, _ := toolText(t, out)
			for _, s := range e.sentinels() {
				if strings.Contains(text, s) && !strings.Contains(modeStaticKey, s) {
					t.Errorf("%s: the client was given %q by an echoing server", m.slug, s)
				}
			}
		}
	}
	// A test and a refresh of each, and the views.
	for _, m := range e.servers {
		for _, op := range []string{"test", "refresh"} {
			_, raw := e.owner.raw("POST", e.path(m)+"/"+op, nil, nil)
			e.seen = append(e.seen, string(raw))
		}
	}
	// Failures: the static server stops accepting its key, the person's key is
	// refused, the machine token is refused once and renewed, and the server
	// with no TLS settings that match its CA fails the handshake.
	e.servers["static_header"].fake.RequireHeader("X-Api-Key", "another-static-0123")
	e.servers["person_secret"].fake.RequireHeader("X-Api-Key", "another-person-0123")
	for _, token := range e.as.Issued() {
		e.as.Invalidate(token)
	}
	for _, m := range e.servers {
		for _, key := range []string{e.ownerMCP, e.blairMCP} {
			e.call(key, m.tool())
		}
	}
	e.mustPatch(e.owner, e.servers["none"], map[string]any{"tls": map[string]any{"caPem": testutil.NewCA(t, "Not the CA").CertPEM}})
	_, raw := e.owner.raw("POST", e.path(e.servers["none"])+"/refresh", nil, nil)
	e.seen = append(e.seen, string(raw))
	if !strings.Contains(string(raw), `"tls"`) {
		t.Errorf("the handshake failure isn't class tls: %s", raw)
	}
	for _, m := range e.servers {
		for _, p := range []string{e.path(m), e.path(m) + "/health", e.path(m) + "/capabilities"} {
			_, raw := e.admin.raw("GET", p, nil, nil)
			e.seen = append(e.seen, string(raw))
		}
	}
	for _, p := range []string{toolsTeam + "/mcp-servers", "/v1/admin/mcp-servers", "/v1/me/server-secrets", toolsTeam + "/calls?limit=100",
		"/v1/admin/audit?limit=500", "/v1/admin/users/" + e.userID("blair@localhost") + "/server-secrets", "/v1/admin/overview"} {
		_, raw := e.admin.raw("GET", p, nil, nil)
		e.seen = append(e.seen, string(raw))
	}
	time.Sleep(300 * time.Millisecond) // calls are recorded after the answer
	ids := e.scalar(`SELECT coalesce(string_agg(call_id::text, ','), '') FROM mcp_call_payloads`)
	if ids == "" {
		t.Fatal("no payload was captured, so the check proves nothing")
	}
	redacted := false
	for _, id := range strings.Split(ids, ",") {
		_, raw := e.admin.raw("GET", "/v1/admin/calls/"+id+"/payload", nil, nil)
		e.seen = append(e.seen, string(raw))
		redacted = redacted || strings.Contains(string(raw), "REDACTED")
	}
	if !redacted {
		t.Error("no payload shows a redaction, so the check proves little")
	}

	where := map[string]string{
		"responses":       strings.Join(e.seen, "\n"),
		"logs":            e.logs.String(),
		"the audit log":   e.scalar(`SELECT coalesce(string_agg(coalesce(before_state::text, '') || coalesce(after_state::text, '') || coalesce(metadata::text, ''), E'\n'), '') FROM audit_log`),
		"call records":    e.scalar(`SELECT coalesce(string_agg(to_jsonb(c)::text, E'\n'), '') FROM mcp_calls c`),
		"payload rows":    e.scalar(`SELECT coalesce(string_agg(to_jsonb(p)::text || encode(arguments_cipher, 'escape') || encode(result_cipher, 'escape'), E'\n'), '') FROM mcp_call_payloads p`),
		"health checks":   e.scalar(`SELECT coalesce(string_agg(to_jsonb(h)::text, E'\n'), '') FROM mcp_health_checks h`),
		"server rows":     e.scalar(`SELECT coalesce(string_agg(to_jsonb(s)::text, E'\n'), '') FROM mcp_servers s`),
		"person secrets":  e.scalar(`SELECT coalesce(string_agg(to_jsonb(p)::text || encode(secret_cipher, 'escape'), E'\n'), '') FROM person_secrets p`),
		"secret requests": e.scalar(`SELECT coalesce(string_agg(to_jsonb(r)::text, E'\n'), '') FROM secret_requests r`),
		"machine clients": e.scalar(`SELECT coalesce(string_agg(to_jsonb(m)::text || encode(client_secret_cipher, 'escape'), E'\n'), '') FROM mcp_server_machine_oauth m`),
		"TLS rows":        e.scalar(`SELECT coalesce(string_agg(to_jsonb(t)::text || encode(client_key_cipher, 'escape'), E'\n'), '') FROM mcp_server_tls t`),
	}
	allowed := map[string]bool{}
	for _, k := range observability.AllowedAttributeKeys() {
		allowed[k] = true
	}
	var spans []string
	for _, sp := range sr.Ended() {
		spans = append(spans, sp.Name(), sp.Status().Description)
		for _, a := range sp.Attributes() {
			if !allowed[string(a.Key)] {
				t.Errorf("span %s carries the attribute %s", sp.Name(), a.Key)
			}
			spans = append(spans, a.Value.Emit())
		}
	}
	where["spans"] = strings.Join(spans, "\n")
	for place, text := range where {
		for _, s := range e.sentinels() {
			if s != "" && strings.Contains(text, s) {
				t.Errorf("%s contains %.40q", place, s)
			}
		}
		if place != "TLS rows" && strings.Contains(text, "PRIVATE KEY") {
			t.Errorf("%s contains private key material", place)
		}
	}
	if len(e.as.Issued()) == 0 {
		t.Error("no machine token was issued, so the check proves little")
	}
}

// sentinels are every form of every secret a leak could take: the keys, the
// machine secret (also as the client sent it) and every token the authorization
// server issued, and the client key's PEM, its base64 body and a slice of it.
func (e *modesEnv) sentinels() []string {
	basic := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(e.as.ClientID) + ":" + url.QueryEscape(machineSecret)))
	out := []string{modeStaticKey, modeKeyOwner, modeKeyBlair, machineSecret, basic, "SENTINEL-0001", "SENTINEL-0007", "SENTINEL-0008", "SENTINEL-0009"}
	for _, f := range keyForms(e.client) {
		if f != "PRIVATE KEY" {
			out = append(out, f)
		}
	}
	return append(out, e.as.Issued()...)
}
