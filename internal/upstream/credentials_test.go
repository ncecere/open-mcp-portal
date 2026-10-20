package upstream

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestMergeQuery(t *testing.T) {
	key := func(name, value string) Credential { return Credential{Kind: CredQuery, Name: name, Value: value} }
	for _, c := range []struct {
		name, raw string
		parts     []Credential
		want      string
	}{
		{"no query", "", []Credential{key("api_key", "k-1")}, "api_key=k-1"},
		{"an existing query stays as it is", "a=1&b=two%20words", []Credential{key("api_key", "k-1")}, "a=1&b=two%20words&api_key=k-1"},
		{"a parameter of the same name is replaced", "api_key=old&a=1", []Credential{key("api_key", "new")}, "a=1&api_key=new"},
		{"values are encoded", "", []Credential{key("k", "a b&c=d/é+")}, "k=a+b%26c%3Dd%2F%C3%A9%2B"},
		{"two parts, in order", "x=1", []Credential{key("t", "1"), key("u", "2")}, "x=1&t=1&u=2"},
		{"an encoded name matches", "api%5Fkey=old", []Credential{key("api_key", "new")}, "api_key=new"},
		{"empty pieces are dropped", "&a=1&&", []Credential{key("k", "v")}, "a=1&k=v"},
	} {
		if got := MergeQuery(c.raw, c.parts); got != c.want {
			t.Errorf("%s: MergeQuery(%q) = %q, want %q", c.name, c.raw, got, c.want)
		}
		// What the server parses is what was meant.
		got, _ := url.ParseQuery(MergeQuery(c.raw, c.parts))
		for _, p := range c.parts {
			if got.Get(p.Name) != p.Value {
				t.Errorf("%s: %s parses as %q, want %q", c.name, p.Name, got.Get(p.Name), p.Value)
			}
		}
	}
}

// recorder is a RoundTripper that keeps the request it was given.
type recorder struct{ req *http.Request }

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.req = req
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
}

func roundTrip(t *testing.T, creds []Credential, identity, identityValue, rawURL string) (*http.Request, *http.Response, *http.Request) {
	t.Helper()
	rec := &recorder{}
	tr := &headerTransport{next: rec, creds: creds, identity: identity, identityValue: identityValue, maxResponse: 1 << 20, ex: &exchange{}}
	req := httptest.NewRequest(http.MethodPost, rawURL, strings.NewReader("{}"))
	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	return rec.req, res, req
}

// Every part reaches the request: headers, Bearer, Basic and query values,
// merged into a query the request has; the caller's request is not changed and
// the response doesn't carry the query.
func TestTransportAppliesEveryPart(t *testing.T) {
	creds := []Credential{
		{Kind: CredHeader, Name: "X-Tenant", Value: "acme"},
		{Kind: CredHeader, Name: "X-API-Key", Value: "k-1234567890"},
		{Kind: CredQuery, Name: "api_key", Value: "q-sentinel 12&34"},
		{Kind: CredBasic, Value: "alice", Secondary: "p:ss word"},
	}
	sent, res, orig := roundTrip(t, creds, "", "", "http://upstream.example/mcp?page=2")
	if sent.Header.Get("X-Tenant") != "acme" || sent.Header.Get("X-API-Key") != "k-1234567890" {
		t.Errorf("headers = %v", sent.Header)
	}
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:p:ss word")); sent.Header.Get("Authorization") != want {
		t.Errorf("Authorization = %q, want %q", sent.Header.Get("Authorization"), want)
	}
	if user, pass, ok := sent.BasicAuth(); !ok || user != "alice" || pass != "p:ss word" {
		t.Errorf("BasicAuth = %q %q %v", user, pass, ok)
	}
	q := sent.URL.Query()
	if q.Get("page") != "2" || q.Get("api_key") != "q-sentinel 12&34" || sent.URL.Path != "/mcp" {
		t.Errorf("sent URL = %s", sent.URL)
	}
	if orig.URL.RawQuery != "page=2" || orig.Header.Get("X-Tenant") != "" || orig.Header.Get("Authorization") != "" {
		t.Errorf("the caller's request changed: %s %v", orig.URL, orig.Header)
	}
	// Nothing the SDK or an error message prints from the response can show the query.
	if res.Request != orig || strings.Contains(res.Request.URL.String(), "sentinel") {
		t.Errorf("the response's request = %s", res.Request.URL)
	}
}

func TestTransportBearerAndIdentity(t *testing.T) {
	sent, _, _ := roundTrip(t, []Credential{{Kind: CredBearer, Value: "tok-123456"}}, "MCP-Gateway-Identity", "jwt-1", "http://upstream.example/mcp")
	if sent.Header.Get("Authorization") != "Bearer tok-123456" || sent.Header.Get("MCP-Gateway-Identity") != "jwt-1" {
		t.Errorf("headers = %v", sent.Header)
	}
	// The identity token never replaces a credential part, even if a caller
	// asked for the same header.
	sent, _, _ = roundTrip(t, []Credential{{Kind: CredBasic, Value: "u", Secondary: "p"}}, "Authorization", "Bearer jwt-1", "http://upstream.example/mcp")
	if !strings.HasPrefix(sent.Header.Get("Authorization"), "Basic ") {
		t.Errorf("the identity replaced the Basic part: %q", sent.Header.Get("Authorization"))
	}
	sent, _, _ = roundTrip(t, []Credential{{Kind: CredHeader, Name: "authorization", Value: "Token abc"}}, "Authorization", "Bearer jwt-1", "http://upstream.example/mcp")
	if sent.Header.Get("Authorization") != "Token abc" {
		t.Errorf("the identity replaced the Authorization header: %q", sent.Header.Get("Authorization"))
	}
}

func TestAuthorizationHeaderOfTarget(t *testing.T) {
	for _, c := range []struct {
		name  string
		creds []Credential
		want  string
	}{
		{"none", nil, ""},
		{"other header", []Credential{{Kind: CredHeader, Name: "X-API-Key", Value: "v"}}, ""},
		{"query", []Credential{{Kind: CredQuery, Name: "k", Value: "v"}}, ""},
		{"Authorization header", []Credential{{Kind: CredHeader, Name: "authorization", Value: "v"}}, "Authorization"},
		{"bearer", []Credential{{Kind: CredHeader, Name: "X-A", Value: "v"}, {Kind: CredBearer, Value: "v"}}, "Authorization"},
		{"basic", []Credential{{Kind: CredBasic, Value: "u", Secondary: "p"}}, "Authorization"},
	} {
		if got := (Target{Credentials: c.creds}).AuthorizationHeader(); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// SafeMessage takes a list, and redacts the encoded forms of a value and the
// base64 string of a Basic part.
func TestSafeMessageRedactsEveryPart(t *testing.T) {
	tgt := Target{Credentials: []Credential{
		{Kind: CredHeader, Name: "X-Tenant", Value: "tenant-sentinel-1"},
		{Kind: CredQuery, Name: "key", Value: "q sentinel&2"},
		{Kind: CredBasic, Value: "alice", Secondary: "pa55-sentinel-3"},
	}, IdentityValue: "identity-sentinel-4"}
	basic := base64.StdEncoding.EncodeToString([]byte("alice:pa55-sentinel-3"))
	msg := "bad GET /mcp?key=q+sentinel%262 and key=q%20sentinel%262; tenant-sentinel-1; Basic " + basic + "; pa55-sentinel-3 for alice; " +
		"identity-sentinel-4 raw q sentinel&2"
	got := tgt.safe(msg)
	for _, secret := range []string{"tenant-sentinel-1", "sentinel%262", "sentinel+", "q sentinel", basic, "pa55-sentinel-3", "identity-sentinel-4"} {
		if strings.Contains(got, secret) {
			t.Errorf("%q survived: %s", secret, got)
		}
	}
	if !strings.Contains(got, "alice") && !strings.Contains(got, "[redacted]") {
		t.Errorf("message = %s", got)
	}
	// The plain helper takes a list too, and skips empty values.
	if got := SafeMessage("a b-sentinel c", "", "b-sentinel"); strings.Contains(got, "sentinel") {
		t.Errorf("SafeMessage = %s", got)
	}
	// A Basic user name too short to redact without wrecking ordinary words is
	// left to the base64 string.
	if s := (Target{Credentials: []Credential{{Kind: CredBasic, Value: "bo", Secondary: "longpassword"}}}).Secrets(); strings.Contains(strings.Join(s, "|"), "|bo|") {
		t.Errorf("secrets = %v", s)
	}
}

// Whatever goes wrong, the error and the log line built from it show no query
// value: the request the SDK and net/http know carries no query (the part is
// added on a copy), a dial error names only an address, and a server that
// repeats its request line is redacted.
func TestQueryPartNeverInErrorsOrLogs(t *testing.T) {
	const value = "qv-sentinel-0042"
	creds := []Credential{{Kind: CredQuery, Name: "sig", Value: value}}
	var logs strings.Builder
	client := &Client{AllowPrivate: true, Log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	ctx := context.Background()

	// Nothing listens.
	_, err := client.Discover(ctx, Target{URL: "http://127.0.0.1:1/mcp", Credentials: creds, Timeout: 3 * time.Second})
	if err == nil || strings.Contains(err.Error(), value) {
		t.Fatalf("dial error = %v", err)
	}
	// A server that fails and repeats the request line, in a few shapes.
	for name, body := range map[string]func(r *http.Request) string{
		"plain":   func(r *http.Request) string { return "failed: " + r.URL.RequestURI() },
		"json":    func(r *http.Request) string { return `{"error":"bad request ` + r.URL.String() + `"}` },
		"escaped": func(r *http.Request) string { return "failed: " + url.QueryEscape(r.URL.Query().Get("sig")) },
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, body(r), http.StatusInternalServerError)
		}))
		_, err := client.Discover(ctx, Target{URL: srv.URL + "/mcp", Credentials: creds, Timeout: 3 * time.Second})
		srv.Close()
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		if strings.Contains(err.Error(), value) {
			t.Errorf("%s: the error shows the query value: %v", name, err)
		}
		var ue *Error
		if errors.As(err, &ue) && strings.Contains(ue.Message, value) {
			t.Errorf("%s: the message shows the query value: %s", name, ue.Message)
		}
	}
	if strings.Contains(logs.String(), value) {
		t.Errorf("the log shows the query value: %s", logs.String())
	}
}
