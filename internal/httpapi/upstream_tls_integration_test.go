package httpapi_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/notify"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// mTLS client certificates and a per-server CA (roadmap #25, decision 74): a
// server behind a private CA that requires a client certificate can be
// registered, discovered, health-checked and called; the private key is
// sealed and never returned, logged, audited or captured; the CA replaces the
// system roots for that server only; the key and CA never follow a URL to
// another origin; and a changed CA is a trust change that sends a published
// server back to review.

type tlsEnv struct {
	*rtEnv
	logs   *syncBuffer
	reg    *registry.Service
	notify *notify.Service
	// mtls is the server behind the private CA; ca signed its certificate and
	// the client certificate, which has key material `client`.
	mtls   *testutil.MTLSFake
	ca     *testutil.Cert
	client *testutil.Cert
	// seen is every response body the test made.
	seen []string
}

func newTLSEnv(t *testing.T) *tlsEnv {
	t.Helper()
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e := &tlsEnv{logs: logs}
	e.rtEnv = newRuntimeEnvHook(t, log, func(d *httpapi.Deps) { e.reg, e.notify = d.Registry, d.Notify })
	e.ca = testutil.NewCA(t, "Internal CA")
	e.client = e.ca.Issue(t, testutil.IssueOptions{CommonName: "omp-portal", Client: true, NotAfter: time.Now().Add(90 * 24 * time.Hour)})
	e.mtls = e.startMTLS(e.ca)
	return e
}

// startMTLS starts a server that requires client certificates signed by ca,
// with a certificate for 127.0.0.1 signed by ca.
func (e *tlsEnv) startMTLS(ca *testutil.Cert) *testutil.MTLSFake {
	e.t.Helper()
	f := testutil.StartMTLSFake(e.t, testutil.MTLSOptions{
		Server:    ca.Issue(e.t, testutil.IssueOptions{Server: true, IPs: []net.IP{net.ParseIP("127.0.0.1")}}),
		ClientCAs: []*testutil.Cert{ca},
	})
	f.EnableGatewayTools()
	return f
}

func (e *tlsEnv) tlsBody(ca *testutil.Cert, client *testutil.Cert) map[string]any {
	out := map[string]any{}
	if ca != nil {
		out["caPem"] = ca.CertPEM
	}
	if client != nil {
		out["clientCertPem"], out["clientKeyPem"] = client.CertPEM, client.KeyPEM
	}
	return out
}

func (e *tlsEnv) path(id string) string { return toolsTeam + "/mcp-servers/" + id }

func (e *tlsEnv) create(body map[string]any) (int, []byte) {
	e.t.Helper()
	code, raw := e.owner.raw("POST", toolsTeam+"/mcp-servers", body, nil)
	e.seen = append(e.seen, string(raw))
	return code, raw
}

func (e *tlsEnv) get(s *session, id string) apitypes.McpServer {
	e.t.Helper()
	var sv apitypes.McpServer
	if code := s.get(e.path(id), &sv); code != 200 {
		e.t.Fatalf("get server = %d", code)
	}
	return sv
}

func (e *tlsEnv) patch(id string, body map[string]any) (int, []byte) {
	e.t.Helper()
	code, raw := e.owner.raw("PATCH", e.path(id), body, ifMatch(e.get(e.owner, id).Revision))
	e.seen = append(e.seen, string(raw))
	return code, raw
}

func (e *tlsEnv) post(id, op string) (int, []byte) {
	e.t.Helper()
	code, raw := e.owner.raw("POST", e.path(id)+"/"+op, nil, nil)
	e.seen = append(e.seen, string(raw))
	return code, raw
}

// keyForms are every form of a private key a leak could take.
func keyForms(c *testutil.Cert) []string {
	b, _ := pem.Decode([]byte(c.KeyPEM))
	body := base64.StdEncoding.EncodeToString(b.Bytes)
	return []string{c.KeyPEM, strings.TrimSpace(c.KeyPEM), body, body[10:60], "PRIVATE KEY"}
}

func (e *tlsEnv) assertNoKey(what, text string, certs ...*testutil.Cert) {
	e.t.Helper()
	for _, c := range certs {
		for _, f := range keyForms(c) {
			if strings.Contains(text, f) {
				e.t.Errorf("%s contains key material (%.30q)", what, f)
			}
		}
	}
}

// everything the test could have leaked into: responses, logs, the audit
// log, stored errors and health messages, and the call history.
func (e *tlsEnv) everywhere() map[string]string {
	return map[string]string{
		"responses":     strings.Join(e.seen, "\n"),
		"logs":          e.logs.String(),
		"the audit log": e.scalar(`SELECT coalesce(string_agg(coalesce(before_state::text, '') || coalesce(after_state::text, '') || coalesce(metadata::text, ''), E'\n'), '') FROM audit_log`),
		"stored errors": e.scalar(`SELECT coalesce(string_agg(coalesce(last_refresh_error, ''), '|'), '') || (SELECT coalesce(string_agg(message, '|'), '') FROM mcp_health_checks) FROM mcp_servers`),
		"call history":  e.scalar(`SELECT coalesce(string_agg(coalesce(error_class, ''), '|'), '') FROM mcp_calls`),
		"the TLS row":   e.scalar(`SELECT coalesce(string_agg(encode(client_key_cipher, 'escape'), '|'), '') FROM mcp_server_tls`),
	}
}

func TestUpstreamTLSEndToEnd(t *testing.T) {
	e := newTLSEnv(t)
	ctx := context.Background()

	// Without the private CA the server can be registered but not read: class
	// tls (not unavailable), with words that say what to do.
	code, raw := e.create(map[string]any{"slug": "secure", "name": "Secure", "url": e.mtls.URL()})
	if code != 201 {
		t.Fatalf("create = %d %s", code, raw)
	}
	var created struct{ Data apitypes.McpServerCreated }
	_ = json.Unmarshal(raw, &created)
	id := created.Data.Server.Id.String()
	if created.Data.RefreshError == nil || created.Data.RefreshError.ErrorClass == nil || *created.Data.RefreshError.ErrorClass != "tls" ||
		created.Data.RefreshError.Message == nil || !strings.Contains(*created.Data.RefreshError.Message, "private CA") {
		t.Fatalf("refreshError = %+v", created.Data.RefreshError)
	}
	if created.Data.Server.Tls != nil {
		t.Fatalf("a server without TLS settings shows %+v", created.Data.Server.Tls)
	}

	// The CA alone isn't enough: the server wants a client certificate.
	code, raw = e.patch(id, map[string]any{"tls": e.tlsBody(e.ca, nil)})
	if code != 200 {
		t.Fatalf("set the CA = %d %s", code, raw)
	}
	sv := e.get(e.owner, id)
	if sv.Health.Status != "failing" || sv.Health.ErrorClass == nil || *sv.Health.ErrorClass != "tls" || sv.Health.Message == nil ||
		!strings.Contains(*sv.Health.Message, "client certificate") {
		t.Fatalf("CA only: health = %+v, class %v, message %q", sv.Health, sv.Health.ErrorClass, strings.TrimSpace(fmt.Sprint(*sv.Health.Message)))
	}

	// The certificate and key: discovered at once (the update reads the
	// capabilities again), and Test, Refresh and the scheduled check all work.
	code, raw = e.patch(id, map[string]any{"tls": e.tlsBody(nil, e.client)})
	if code != 200 {
		t.Fatalf("set the client certificate = %d %s", code, raw)
	}
	sv = e.get(e.owner, id)
	if sv.Health.Status != "healthy" || sv.RefreshedAt == nil || sv.Counts.Tools < 3 || sv.Tls == nil || sv.Tls.Ca == nil || sv.Tls.Client == nil {
		t.Fatalf("after setting it: health %+v, tools %d, tls %+v", sv.Health, sv.Counts.Tools, sv.Tls)
	}
	// Metadata only: fingerprint, subject, issuer, expiry; the key is a bool.
	c := sv.Tls.Client
	if !c.HasKey || c.Status != "valid" || len(c.Certificate.Sha256) != 64 || !strings.Contains(c.Certificate.Subject, "omp-portal") ||
		!strings.Contains(c.Certificate.Issuer, "Internal CA") || c.Certificate.NotAfter.Before(time.Now()) || c.ChainLength != 1 {
		t.Fatalf("client = %+v", c)
	}
	if len(sv.Tls.Ca.Certificates) != 1 || len(sv.Tls.Ca.Sha256) != 64 || !strings.Contains(sv.Tls.Ca.Certificates[0].Subject, "Internal CA") {
		t.Fatalf("ca = %+v", sv.Tls.Ca)
	}
	if code, raw := e.post(id, "test"); code != 200 || !strings.Contains(string(raw), `"ok":true`) {
		t.Fatalf("test = %d %s", code, raw)
	}
	if code, raw := e.post(id, "refresh"); code != 200 {
		t.Fatalf("refresh = %d %s", code, raw)
	}
	if _, err := e.app.Pool.Exec(ctx, `DELETE FROM mcp_health_checks`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.RunHealthChecks(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	if e.get(e.owner, id).Health.Status != "healthy" || !strings.Contains(e.healthChecks(id), "scheduled:true") {
		t.Fatalf("scheduled health = %s", e.healthChecks(id))
	}

	// A call through a gateway (publish, select the tool, call it).
	e.publish(e.owner, sv)
	whoami := e.capID(e.owner, sv, "tool", "whoami")
	e.mustSetCaps(e.owner, e.supportTeamPath, sel(whoami))
	code, _, out := rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(1, "tools/call", map[string]any{"name": "secure__whoami", "arguments": map[string]any{}}), nil)
	if code != 200 || out["error"] != nil {
		t.Fatalf("call = %d %v", code, out)
	}
	seen := e.mtls.Seen()
	if len(seen) == 0 {
		t.Fatal("the server saw nothing")
	}
	for _, s := range seen[len(seen)-1:] {
		if s.ClientCN != "omp-portal" || s.Version < tls.VersionTLS12 || s.ProtoMajor != 2 {
			t.Fatalf("the last request arrived as %+v", s)
		}
	}

	// Key hygiene: the sealed key is in the table and nowhere else; no response,
	// log, audit entry, stored error or call record has any of it, nor does the
	// public catalog show TLS settings or warnings.
	if got := e.scalar(`SELECT (client_key_cipher IS NOT NULL AND length(client_key_cipher) > 30)::text FROM mcp_server_tls`); got != "true" {
		t.Fatalf("the key isn't stored sealed: %s", got)
	}
	for _, s := range []*session{e.owner, e.admin, e.member} {
		path := e.path(id)
		if s == e.admin {
			path = "/v1/admin/mcp-servers/" + id
		}
		var anything json.RawMessage
		if c := s.get(path, &anything); c == 200 || c == 403 || c == 404 {
			e.seen = append(e.seen, string(anything))
		}
	}
	_, catalog := e.admin.raw("GET", "/v1/catalog/servers/"+id, nil, nil)
	if strings.Contains(string(catalog), "omp-portal") || strings.Contains(string(catalog), `"tls"`) || strings.Contains(string(catalog), "warnings") {
		t.Errorf("the catalog shows TLS facts: %s", catalog)
	}
	for what, text := range e.everywhere() {
		e.assertNoKey(what, text, e.client)
		if what != "responses" && strings.Contains(text, e.client.CertPEM) && what != "the TLS row" {
			t.Errorf("%s holds the certificate PEM", what)
		}
	}
	// The audit entries carry fingerprints and what changed.
	au := e.scalar(`SELECT coalesce(string_agg(after_state::text || metadata::text, E'\n' ORDER BY id), '') FROM audit_log WHERE action = 'mcp_server.update'`)
	if !strings.Contains(au, `"hasClientKey": true`) || !strings.Contains(au, c.Certificate.Sha256) || !strings.Contains(au, "tlsClientCertChanged") ||
		!strings.Contains(au, sv.Tls.Ca.Sha256) {
		t.Errorf("the audit entries don't show what changed: %s", au)
	}

	// A different CA for this server doesn't touch the others: the plain server
	// registered beside it still works, and removing the client certificate
	// brings the failure back.
	if code, raw := e.patch(id, map[string]any{"tls": map[string]any{"clientCertPem": ""}}); code != 200 {
		t.Fatalf("remove the client certificate = %d %s", code, raw)
	}
	if got := e.get(e.owner, id); got.Tls == nil || got.Tls.Client != nil || got.Tls.Ca == nil || got.Health.Status != "failing" {
		t.Fatalf("after removing it: %+v %+v", got.Tls, got.Health)
	}
	if got := e.scalar(`SELECT (client_key_cipher IS NULL AND client_cert_pem IS NULL)::text FROM mcp_server_tls`); got != "true" {
		t.Fatalf("the key outlived its certificate: %s", got)
	}
	if code, raw := e.patch(id, map[string]any{"tls": map[string]any{"clear": true}}); code != 200 {
		t.Fatalf("clear = %d %s", code, raw)
	}
	if got := e.scalar(`SELECT count(*)::text FROM mcp_server_tls`); got != "0" || e.get(e.owner, id).Tls != nil {
		t.Fatalf("clear left a row: %s", got)
	}
	e.refresh(e.owner, e.server) // the plain server is untouched
	for what, text := range e.everywhere() {
		e.assertNoKey(what, text, e.client)
	}
}

// Input is validated when saved, and nothing of it is quoted back.
func TestUpstreamTLSInputValidation(t *testing.T) {
	e := newTLSEnv(t)
	code, raw := e.create(map[string]any{"slug": "secure", "name": "Secure", "url": e.mtls.URL()})
	if code != 201 {
		t.Fatal(code, string(raw))
	}
	id := serverIDOf(t, raw)
	now := time.Now()
	other := e.ca.Issue(t, testutil.IssueOptions{Client: true})
	expired := e.ca.Issue(t, testutil.IssueOptions{Client: true, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour)})
	weak := e.ca.Issue(t, testutil.IssueOptions{Client: true, Key: testutil.KeyRSA1024})
	encrypted := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nQUFBQUFBQUFBQUFBQUFBQUFBQUE=\n-----END ENCRYPTED PRIVATE KEY-----\n"
	for name, c := range map[string]struct {
		tls    map[string]any
		field  string
		reason string
	}{
		"a key that isn't the certificate's": {map[string]any{"clientCertPem": e.client.CertPEM, "clientKeyPem": other.KeyPEM}, "tls.clientKeyPem", "key_mismatch"},
		"an encrypted key":                   {map[string]any{"clientCertPem": e.client.CertPEM, "clientKeyPem": encrypted}, "tls.clientKeyPem", "encrypted_key"},
		"an expired certificate":             {map[string]any{"clientCertPem": expired.CertPEM, "clientKeyPem": expired.KeyPEM}, "tls.clientCertPem", "expired"},
		"a weak key":                         {map[string]any{"clientCertPem": weak.CertPEM, "clientKeyPem": weak.KeyPEM}, "tls.clientCertPem", "weak_key"},
		"a key without its certificate":      {map[string]any{"clientKeyPem": e.client.KeyPEM}, "tls.clientCertPem", "key_without_certificate"},
		"a certificate without a stored key": {map[string]any{"clientCertPem": e.client.CertPEM}, "tls.clientKeyPem", "key_required"},
		"a private key as the CA":            {map[string]any{"caPem": e.ca.CertPEM + e.client.KeyPEM}, "tls.caPem", "private_key_in_certificate_field"},
		"text as the CA":                     {map[string]any{"caPem": "not a certificate"}, "tls.caPem", "not_pem"},
		"too many CAs":                       {map[string]any{"caPem": strings.Repeat(e.ca.CertPEM, 11)}, "tls.caPem", "too_many_certificates"},
		"an oversized CA":                    {map[string]any{"caPem": strings.Repeat("A", 70000)}, "tls.caPem", "too_large"},
		"clear with other fields":            {map[string]any{"clear": true, "caPem": e.ca.CertPEM}, "tls", "clear_with_other_fields"},
	} {
		code, raw := e.patch(id, map[string]any{"tls": c.tls})
		det := errorDetails(raw)
		if code != 422 || errorCode(raw) != "invalid_tls" || det["field"] != c.field || det["reason"] != c.reason {
			t.Errorf("%s: %d %s", name, code, raw)
		}
		e.assertNoKey("the error for "+name, string(raw), e.client, other, expired, weak)
		if strings.Contains(string(raw), "QUFBQUFB") || strings.Contains(string(raw), "BEGIN CERTIFICATE") {
			t.Errorf("%s: the error quotes the input: %s", name, raw)
		}
	}
	if got := e.scalar(`SELECT count(*)::text FROM mcp_server_tls`); got != "0" {
		t.Fatalf("a refused request stored something: %s", got)
	}
	// The same checks on create: nothing is created.
	code, raw = e.create(map[string]any{"slug": "bad", "name": "Bad", "url": e.mtls.URL(),
		"tls": map[string]any{"clientCertPem": expired.CertPEM, "clientKeyPem": expired.KeyPEM}})
	if code != 422 || errorCode(raw) != "invalid_tls" || e.scalar(`SELECT count(*)::text FROM mcp_servers WHERE slug = 'bad'`) != "0" {
		t.Errorf("create with an expired certificate: %d %s", code, raw)
	}
	// A renewal: a new certificate for the stored key needs no key in the request.
	if code, raw := e.patch(id, map[string]any{"tls": e.tlsBody(e.ca, e.client)}); code != 200 {
		t.Fatalf("set = %d %s", code, raw)
	}
	renewed := reissue(t, e.ca, e.client, "omp-portal-renewed")
	if code, raw := e.patch(id, map[string]any{"tls": map[string]any{"clientCertPem": renewed}}); code != 200 {
		t.Fatalf("renewal = %d %s", code, raw)
	}
	if got := e.get(e.owner, id); got.Tls == nil || got.Tls.Client == nil || !strings.Contains(got.Tls.Client.Certificate.Subject, "renewed") || !got.Tls.Client.HasKey {
		t.Fatalf("after a renewal: %+v", got.Tls)
	}
	if code, raw := e.patch(id, map[string]any{"tls": map[string]any{"clientCertPem": other.CertPEM}}); code != 422 || det(raw)["reason"] != "key_mismatch" {
		t.Fatalf("a certificate that isn't for the stored key = %d %s", code, raw)
	}
	// Resending what is stored changes nothing (no revision, no audit entry).
	before := e.get(e.owner, id)
	audits := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'mcp_server.update'`)
	if code, raw := e.patch(id, map[string]any{"tls": map[string]any{"caPem": e.ca.CertPEM}}); code != 200 {
		t.Fatalf("same CA = %d %s", code, raw)
	}
	if after := e.get(e.owner, id); after.Revision != before.Revision || e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'mcp_server.update'`) != audits {
		t.Fatalf("an unchanged request wrote something: %d -> %d", before.Revision, after.Revision)
	}
}

func det(raw []byte) map[string]any { return errorDetails(raw) }

// reissue makes a new certificate with the same key as client (a renewal), as
// PEM.
func reissue(t *testing.T, ca, client *testutil.Cert, cn string) string {
	t.Helper()
	return ca.IssueFor(t, client.Key, testutil.IssueOptions{CommonName: cn, Client: true}).CertPEM
}

// F-1: the stored client key and CA belong to the origin they were entered
// for, and never follow the URL to another.
func TestUpstreamTLSKeyDoesNotFollowOriginChange(t *testing.T) {
	e := newTLSEnv(t)
	code, raw := e.create(map[string]any{"slug": "secure", "name": "Secure", "url": e.mtls.URL(), "tls": e.tlsBody(e.ca, e.client)})
	if code != 201 {
		t.Fatalf("create = %d %s", code, raw)
	}
	id := serverIDOf(t, raw)
	if e.get(e.owner, id).Health.Status != "healthy" {
		t.Fatalf("created unhealthy: %s", raw)
	}
	cipher := func() string { return e.scalar(`SELECT encode(client_key_cipher, 'hex') FROM mcp_server_tls`) }
	before, cipherBefore := e.get(e.owner, id), cipher()
	audits := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'mcp_server.update'`)

	// A host the editor controls that would accept the portal's client certificate
	// if it were sent: it never is. (It trusts the same CA, so a handshake would
	// succeed and show the certificate.)
	evil := e.startMTLS(e.ca)
	_, port, _ := net.SplitHostPort(e.mtls.Addr())
	for name, body := range map[string]map[string]any{
		"the URL only":                      {"url": evil.URL()},
		"the URL and a CA":                  {"url": evil.URL(), "tls": map[string]any{"caPem": e.ca.CertPEM}},
		"the URL and a certificate, no key": {"url": evil.URL(), "tls": map[string]any{"clientCertPem": e.client.CertPEM}},
		"the URL and the same pair kept":    {"url": evil.URL(), "name": "Other"},
		"the URL and an empty tls":          {"url": evil.URL(), "tls": map[string]any{}},
		"the URL and a CA removal":          {"url": evil.URL(), "tls": map[string]any{"caPem": ""}},
		"another host, the same port":       {"url": "https://localhost:" + port + "/mcp"},
		"another scheme":                    {"url": "http://" + e.mtls.Addr() + "/mcp"},
	} {
		code, raw := e.patch(id, body)
		if code != 422 || errorCode(raw) != "tls_key_required" || errorDetails(raw)["field"] != "tls.clientKeyPem" {
			t.Errorf("%s = %d %s", name, code, raw)
		}
		e.assertNoKey(name, string(raw), e.client)
	}
	after := e.get(e.owner, id)
	if len(evil.Seen()) != 0 || evil.Conns() != 0 || after.Url != before.Url || after.Revision != before.Revision || cipher() != cipherBefore ||
		e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'mcp_server.update'`) != audits {
		t.Fatalf("a refused update changed something: %d requests to the other host, %+v", len(evil.Seen()), after)
	}

	// The same origin keeps the pair: a path change, a different case and an
	// explicit default are the same origin.
	if code, raw := e.patch(id, map[string]any{"url": e.mtls.URL() + "x"}); code != 200 {
		t.Fatalf("a path change = %d %s", code, raw)
	}
	if cipher() != cipherBefore || e.get(e.owner, id).Tls.Client == nil {
		t.Fatal("a path change dropped the key")
	}
	if code, raw := e.patch(id, map[string]any{"url": e.mtls.URL()}); code != 200 {
		t.Fatalf("back = %d %s", code, raw)
	}

	// Another origin with a new pair works, and discovery uses it; the old key
	// is gone (replaced, sealed again under the same server and field).
	fresh := e.ca.Issue(t, testutil.IssueOptions{CommonName: "second-client", Client: true})
	if code, raw := e.patch(id, map[string]any{"url": evil.URL(), "tls": e.tlsBody(e.ca, fresh)}); code != 200 {
		t.Fatalf("move with a new pair = %d %s", code, raw)
	}
	moved := e.get(e.owner, id)
	if moved.Url != evil.URL() || moved.Tls == nil || moved.Tls.Client == nil || !strings.Contains(moved.Tls.Client.Certificate.Subject, "second-client") ||
		moved.Health.Status != "healthy" {
		t.Fatalf("moved = %+v", moved)
	}
	if cipher() == cipherBefore {
		t.Fatal("the old key is still stored")
	}
	for _, s := range evil.Seen() {
		if s.ClientCN == "omp-portal" {
			t.Fatal("the old certificate reached the new host")
		}
	}
	// Moving back removes the settings with an explicit clear...
	if code, raw := e.patch(id, map[string]any{"url": e.mtls.URL(), "tls": map[string]any{"clear": true}}); code != 200 {
		t.Fatalf("move and clear = %d %s", code, raw)
	}
	if e.scalar(`SELECT count(*)::text FROM mcp_server_tls`) != "0" {
		t.Fatal("clear kept a row")
	}
	// ... and a stored CA alone (no key) is dropped with the origin, audited.
	if code, raw := e.patch(id, map[string]any{"tls": map[string]any{"caPem": e.ca.CertPEM}}); code != 200 {
		t.Fatalf("CA only = %d %s", code, raw)
	}
	if code, raw := e.patch(id, map[string]any{"url": evil.URL()}); code != 200 {
		t.Fatalf("move with only a CA stored = %d %s", code, raw)
	}
	if e.scalar(`SELECT count(*)::text FROM mcp_server_tls`) != "0" {
		t.Fatal("a CA followed the URL to another origin")
	}
	if meta := e.scalar(`SELECT metadata::text FROM audit_log WHERE action = 'mcp_server.update' ORDER BY id DESC LIMIT 1`); !strings.Contains(meta, "tlsDroppedForOrigin") ||
		!strings.Contains(meta, "oldOrigin") {
		t.Errorf("the audit entry doesn't say the TLS settings were dropped: %s", meta)
	}
	for what, text := range e.everywhere() {
		e.assertNoKey(what, text, e.client, fresh)
	}
}

// A changed CA is a trust change: a published server goes back to review under
// approval_required. A new client certificate is not, and both change the
// digest a reviewer approves.
func TestUpstreamTLSChangedCASendsPublishedServerBackToReview(t *testing.T) {
	e := newTLSEnv(t)
	code, raw := e.create(map[string]any{"slug": "secure", "name": "Secure", "url": e.mtls.URL(), "tls": e.tlsBody(e.ca, e.client)})
	if code != 201 {
		t.Fatalf("create = %d %s", code, raw)
	}
	id := serverIDOf(t, raw)
	sv := e.get(e.owner, id)
	e.publish(e.owner, sv)
	published := e.get(e.owner, id)
	if published.PublishState != "published" || published.ReviewDigest == nil {
		t.Fatalf("published = %+v", published)
	}

	// A new client certificate (same CA): stays published; the digest moves.
	second := e.ca.Issue(t, testutil.IssueOptions{CommonName: "second-client", Client: true})
	if code, raw := e.patch(id, map[string]any{"tls": e.tlsBody(nil, second)}); code != 200 {
		t.Fatalf("new certificate = %d %s", code, raw)
	}
	afterCert := e.get(e.owner, id)
	if afterCert.PublishState != "published" || *afterCert.ReviewDigest == *published.ReviewDigest {
		t.Fatalf("a new client certificate: state %s, digest unchanged = %v", afterCert.PublishState, *afterCert.ReviewDigest == *published.ReviewDigest)
	}
	if e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'mcp_server.publish_request' AND metadata->>'reason' IS NOT NULL`) != "0" {
		t.Fatal("a client certificate sent the server back to review")
	}

	// A different CA (the server's certificate is signed by the original one,
	// so this fails to read it, but that is not what is checked here): back to
	// pending, reason upstream_tls_changed, and the old digest is stale.
	otherCA := testutil.NewCA(t, "Another CA")
	if code, raw := e.patch(id, map[string]any{"tls": map[string]any{"caPem": e.ca.CertPEM + otherCA.CertPEM}}); code != 200 {
		t.Fatalf("new CA = %d %s", code, raw)
	}
	pending := e.get(e.owner, id)
	if pending.PublishState != "pending" || *pending.ReviewDigest == *afterCert.ReviewDigest {
		t.Fatalf("a changed CA: state %s", pending.PublishState)
	}
	if reason := e.scalar(`SELECT metadata->>'reason' FROM audit_log WHERE action = 'mcp_server.publish_request' ORDER BY id DESC LIMIT 1`); reason != "upstream_tls_changed" {
		t.Fatalf("review reason = %q", reason)
	}
	if ev := e.scalar(`SELECT coalesce(string_agg(payload->>'reason', ','), '') FROM notification_events WHERE event = 'publish.requested'`); !strings.Contains(ev, "upstream_tls_changed") {
		t.Fatalf("the platform admins weren't told why: %q", ev)
	}
	// An approval made on the digest of an earlier look is refused.
	stale := map[string]any{"decision": "approve", "expectedDigest": *afterCert.ReviewDigest}
	if code, ec := e.admin.call("POST", "/v1/admin/mcp-servers/"+id+"/review", stale, nil, nil); code != 409 || ec != "changed_since_review" {
		t.Fatalf("approve on a stale digest = %d %s", code, ec)
	}
	if code, ec := e.admin.call("POST", "/v1/admin/mcp-servers/"+id+"/review", approveBody(t, e.admin, id), nil, nil); code != 200 {
		t.Fatalf("approve on the current digest = %d %s", code, ec)
	}
	// Removing the CA is a change of trust too.
	if code, raw := e.patch(id, map[string]any{"tls": map[string]any{"caPem": ""}}); code != 200 {
		t.Fatalf("remove the CA = %d %s", code, raw)
	}
	if got := e.get(e.owner, id).PublishState; got != "pending" {
		t.Fatalf("removing the CA left the server %s", got)
	}
	// The same CA again is no change at all.
	e.admin.call("POST", "/v1/admin/mcp-servers/"+id+"/review", approveBody(t, e.admin, id), nil, nil)
	if code, raw := e.patch(id, map[string]any{"tls": map[string]any{"caPem": ""}}); code != 200 || e.get(e.owner, id).PublishState != "published" {
		t.Fatalf("an unchanged CA: %d %s", code, raw)
	}
}

// A client certificate that is about to expire shows as a warning in the
// server's health, in the admin overview and the team's attention, and is told
// to the team's editors by the hourly scan; an expired one is critical.
func TestUpstreamTLSExpiryWarnings(t *testing.T) {
	e := newTLSEnv(t)
	soon := e.ca.Issue(t, testutil.IssueOptions{CommonName: "soon", Client: true, NotAfter: time.Now().Add(5 * 24 * time.Hour)})
	code, raw := e.create(map[string]any{"slug": "secure", "name": "Secure", "url": e.mtls.URL(), "tls": e.tlsBody(e.ca, soon)})
	if code != 201 {
		t.Fatalf("create = %d %s", code, raw)
	}
	id := serverIDOf(t, raw)
	sv := e.get(e.owner, id)
	if sv.Health.Status != "healthy" || sv.Tls.Client.Status != "expiring" || sv.Tls.Client.DaysLeft < 4 || sv.Tls.Client.DaysLeft > 5 ||
		sv.Health.Warnings == nil || len(*sv.Health.Warnings) != 1 || (*sv.Health.Warnings)[0].Code != "tls_certificate_expiring" {
		t.Fatalf("health = %+v, client = %+v", sv.Health, sv.Tls.Client)
	}
	e.publish(e.owner, sv)

	var ov apitypes.AdminOverview
	if c := e.admin.get("/v1/admin/overview", &ov); c != 200 {
		t.Fatalf("overview = %d", c)
	}
	var item *apitypes.AttentionItem
	for i, it := range ov.Attention {
		if it.Kind == "server_certificate_expiring" {
			item = &ov.Attention[i]
		}
	}
	if item == nil || item.Severity != "info" || item.Subject == nil || item.Subject.Id != id || item.At == nil || !strings.Contains(item.Summary, "client certificate") {
		t.Fatalf("overview attention = %+v", ov.Attention)
	}
	var team apitypes.TeamAttention
	if c := e.owner.get(toolsTeam+"/attention", &team); c != 200 {
		t.Fatalf("team attention = %d", c)
	}
	found := false
	for _, it := range team.Attention {
		found = found || it.Kind == "server_certificate_expiring"
	}
	if !found {
		t.Fatalf("team attention = %+v", team.Attention)
	}

	// The hourly scan tells the team's owners, admins and editors once.
	n, err := e.notify.ScanKeys(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("scan = %d %v", n, err)
	}
	if again, _ := e.notify.ScanKeys(context.Background()); again != 0 {
		t.Fatalf("the scan isn't idempotent: %d", again)
	}
	payload := e.scalar(`SELECT payload::text FROM notification_events WHERE event = 'key.expiring' AND dedup_key LIKE 'key.expiring:server_certificate:%'`)
	if !strings.Contains(payload, `"keyKind": "server_certificate"`) || !strings.Contains(payload, `"slug": "secure"`) || strings.Contains(payload, "PRIVATE") {
		t.Fatalf("event payload = %s", payload)
	}
	e.assertNoKey("the event", payload, soon)

	// Expired (the server's clock moved on; the portal still presents it, and the
	// attention item is critical).
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE mcp_server_tls SET client_not_after = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	sv = e.get(e.owner, id)
	if sv.Tls.Client.Status != "expired" || sv.Health.Warnings == nil || (*sv.Health.Warnings)[0].Code != "tls_certificate_expired" {
		t.Fatalf("expired: %+v", sv.Tls.Client)
	}
	if c := e.admin.get("/v1/admin/overview", &ov); c != 200 {
		t.Fatal(c)
	}
	item = nil
	for i, it := range ov.Attention {
		if it.Kind == "server_certificate_expiring" {
			item = &ov.Attention[i]
		}
	}
	if item == nil || item.Severity != "critical" {
		t.Fatalf("an expired certificate: %+v", item)
	}
	// An expired certificate isn't announced as expiring.
	if n, _ := e.notify.ScanKeys(context.Background()); n != 0 {
		t.Fatalf("scan after expiry = %d", n)
	}
}
