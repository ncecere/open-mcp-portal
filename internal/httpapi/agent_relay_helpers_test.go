package httpapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// An agent platform for the tests (decisions 65 and 66): a fake issuer that
// signs tokens with a P-256 key and serves its JWKS from a loopback TLS server
// (the keys address is https always, L-1; newTestAppDeps makes the app trust
// the test servers' certificate, which every httptest TLS server shares),
// a trusted-platform entry for it, and a team service account marked as its
// relay.

var relayJTI atomic.Int64

// relayIssuer is the fake platform.
type relayIssuer struct {
	t       *testing.T
	srv     *httptest.Server
	key     *ecdsa.PrivateKey
	kid     string
	issuer  string
	fetches atomic.Int64
	mu      sync.Mutex
	keys    map[string]*ecdsa.PrivateKey
	minted  []string
}

func newRelayIssuer(t *testing.T, issuer string) *relayIssuer {
	t.Helper()
	ri := &relayIssuer{t: t, issuer: issuer, keys: map[string]*ecdsa.PrivateKey{}}
	ri.kid = "key-" + issuer[len(issuer)-4:]
	ri.key = ri.addKey(ri.kid)
	ri.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ri.fetches.Add(1)
		ri.mu.Lock()
		defer ri.mu.Unlock()
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
		for kid, k := range ri.keys {
			set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"})
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(ri.srv.Close)
	return ri
}

func (ri *relayIssuer) addKey(kid string) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		ri.t.Fatal(err)
	}
	ri.mu.Lock()
	ri.keys[kid] = k
	ri.mu.Unlock()
	return k
}

func (ri *relayIssuer) jwksURL() string { return ri.srv.URL + "/jwks" }

// agentSpec describes the agent behind a token.
type agentSpec struct {
	// Person is the user the agent acts for ("" email: none): the sign-in
	// subject is looked up from the database.
	Email string
	// Subject overrides the person's subject (a person unknown to the portal).
	Subject string
	// Absent: the person is not present.
	Absent bool
	Agent  string
	Name   string
	// Tool is the token's tool claim: the tool the call is for. PDP sets it
	// on a tools/call and on nothing else (M-1), so a token for any other
	// method leaves it empty (no claim).
	Tool string
	// Mutate edits the claims before signing.
	Mutate func(map[string]any)
}

// mint signs a token for a portal at aud (its URL).
func (ri *relayIssuer) mint(aud string, subject func(email string) string, s agentSpec) string {
	ri.t.Helper()
	now := time.Now()
	agent, name := s.Agent, s.Name
	if agent == "" {
		agent = "0e6a3d4c-5f1b-4f0e-9b8e-2d7c1a9f3b21"
	}
	if name == "" {
		name = "Mail assistant"
	}
	c := map[string]any{
		"iss": ri.issuer, "aud": aud, "sub": agent, "principal_type": "agent", "name": name,
		"team":              map[string]any{"id": "6f1c0000", "slug": "personal-1a2b3c4d5e6f", "kind": "personal"},
		"thread_visibility": "private", "person_present": !s.Absent,
		"jti": fmt.Sprintf("jti-%d-%d", now.UnixNano(), relayJTI.Add(1)),
		"iat": now.Unix(), "nbf": now.Add(-30 * time.Second).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	if s.Tool != "" {
		c["tool"] = s.Tool
	}
	if s.Email != "" || s.Subject != "" {
		sub := s.Subject
		if sub == "" {
			sub = subject(s.Email)
		}
		c["person"] = map[string]any{"iss": auth.DevIssuer, "sub": sub, "email": s.Email}
	} else {
		c["person_present"] = false
	}
	if s.Mutate != nil {
		s.Mutate(c)
	}
	return ri.sign(c, ri.kid, ri.key)
}

func (ri *relayIssuer) sign(claims map[string]any, kid string, key *ecdsa.PrivateKey) string {
	ri.t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid)
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		ri.t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := sg.Sign(payload)
	if err != nil {
		ri.t.Fatal(err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		ri.t.Fatal(err)
	}
	ri.mu.Lock()
	ri.minted = append(ri.minted, s)
	ri.mu.Unlock()
	return s
}

// relayFx is the platform and its relay service account in one app.
type relayFx struct {
	t          *testing.T
	e          *gwEnv
	ri         *relayIssuer
	platformID string
	account    apitypes.ServiceAccount
	key        string
	responses  []string
}

const relayIssuerURL = "https://agents.example.test"

// setupRelay trusts a fake platform, makes a service account of the tools
// team (role editor) and marks it as the platform's relay.
func setupRelay(t *testing.T, e *gwEnv) *relayFx {
	t.Helper()
	fx := &relayFx{t: t, e: e, ri: newRelayIssuer(t, relayIssuerURL)}
	fx.platformID = fx.addPlatform("Pi Durable Platform", fx.ri)
	fx.account = createSA(t, e.owner, map[string]any{"name": "pdp-relay", "role": "editor"})
	fx.key = createSAKey(t, e.owner, fx.account.Id.String(), map[string]any{"name": "pdp", "expiresInDays": 30}).Secret
	fx.mark(fx.platformID, fx.account.Id.String())
	return fx
}

// addPlatform trusts a fake issuer and returns the platform's ID.
func (fx *relayFx) addPlatform(name string, ri *relayIssuer) string {
	fx.t.Helper()
	var out apitypes.AgentPlatform
	code, ec := fx.e.admin.call("POST", "/v1/admin/agent-platforms", map[string]any{"name": name, "issuer": ri.issuer, "jwksUrl": ri.jwksURL()}, &out, nil)
	mustCode(fx.t, "trust "+name, code, ec, 201, "")
	if out.Audience != fx.e.app.URL {
		fx.t.Fatalf("the default audience is %q, want the portal's URL", out.Audience)
	}
	return out.Id.String()
}

func (fx *relayFx) mark(platformID, accountID string) {
	fx.t.Helper()
	code, ec := fx.e.admin.call("PUT", "/v1/admin/agent-platforms/"+platformID+"/relays/"+accountID, nil, nil, nil)
	mustCode(fx.t, "mark relay", code, ec, 200, "")
}

// subject is a person's sign-in subject at the portal's identity provider.
func (fx *relayFx) subject(email string) string {
	fx.t.Helper()
	return fx.e.scalar(`SELECT oidc_subject FROM users WHERE email = $1`, email)
}

// token mints a token of the platform for this portal.
func (fx *relayFx) token(s agentSpec) string {
	fx.t.Helper()
	return fx.ri.mint(fx.e.app.URL, fx.subject, s)
}

// toolToken mints a token for a tools/call of the tool (the name the client
// calls, as the portal exposes it).
func (fx *relayFx) toolToken(s agentSpec, tool string) string {
	fx.t.Helper()
	s.Tool = tool
	return fx.token(s)
}

// post sends a JSON-RPC request to the gateway with a credential and an
// optional token (header MCP-Gateway-Identity).
func (fx *relayFx) post(key, token, slug string, body map[string]any) (int, map[string]any) {
	fx.t.Helper()
	var headers map[string]string
	if token != "" {
		headers = map[string]string{"MCP-Gateway-Identity": token}
	}
	code, _, out := rawMCP(fx.t, fx.e.app, "POST", slug, key, body, headers)
	b, _ := json.Marshal(out)
	fx.responses = append(fx.responses, string(b))
	return code, out
}

// callTool is a tools/call through the gateway "support" with the relay's
// key and a token. who is an agentSpec (a token for exactly this tool is
// minted), or a token string to send as it is ("": none).
func (fx *relayFx) callTool(who any, name string, args map[string]any) (int, map[string]any) {
	fx.t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	var token string
	switch w := who.(type) {
	case agentSpec:
		token = fx.toolToken(w, name)
	case string:
		token = w
	default:
		fx.t.Fatalf("callTool: %T", who)
	}
	return fx.post(fx.key, token, "support", rpc(7, "tools/call", map[string]any{"name": name, "arguments": args}))
}

// lastCallID is the newest call record's ID.
func (fx *relayFx) lastCallID() int64 {
	var id int64
	_ = fx.e.app.Pool.QueryRow(context.Background(), `SELECT coalesce(max(id), 0) FROM mcp_calls`).Scan(&id)
	return id
}

// callRecord is what a call record says about who called.
type callRecord struct {
	ID                                  int64
	Outcome, Class, Provider, Kind      string
	User, Agent, AgentName, Platform    string
	PersonPresent, ServiceAccount, Name string
}

// recordAfter waits for the call recorded after id (calls are recorded
// after the answer is written).
func (fx *relayFx) recordAfter(id int64) callRecord {
	fx.t.Helper()
	for range 150 {
		var r callRecord
		err := fx.e.app.Pool.QueryRow(context.Background(), `SELECT id, outcome, coalesce(error_class, ''), coalesce(provider_slug, ''), principal_kind,
			coalesce(user_id::text, ''), coalesce(agent_id, ''), coalesce(agent_name, ''), coalesce(via_platform_name, ''), coalesce(person_present::text, ''),
			coalesce(service_account_id::text, ''), coalesce(exposed_name, '')
			FROM mcp_calls WHERE id > $1 ORDER BY id DESC LIMIT 1`, id).Scan(&r.ID, &r.Outcome, &r.Class, &r.Provider, &r.Kind, &r.User, &r.Agent, &r.AgentName,
			&r.Platform, &r.PersonPresent, &r.ServiceAccount, &r.Name)
		if err == nil {
			return r
		}
		time.Sleep(20 * time.Millisecond)
	}
	fx.t.Fatal("no call was recorded")
	return callRecord{}
}

// tokenCount reads omp_agent_token_total{result}.
func tokenCount(result string) float64 {
	return promtest.ToFloat64(observability.AgentTokens.WithLabelValues(result))
}

// whoamiClaims reads the identity token claims the fake server saw.
func whoamiClaims(t *testing.T, out map[string]any) testutil.WhoamiResult {
	t.Helper()
	return whoamiOf(t, out)
}

// toolText is the text of a tool result, and whether it was an error.
func toolText(t *testing.T, out map[string]any) (text string, isError bool) {
	t.Helper()
	res, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in %v", out)
	}
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content in %v", out)
	}
	text, _ = content[0].(map[string]any)["text"].(string)
	isError, _ = res["isError"].(bool)
	return text, isError
}

// noSecrets checks that no token or key reached the logs, the audit log, the
// call records or what the API answered.
func (fx *relayFx) noSecrets(logs *syncBuffer, extra ...string) {
	fx.t.Helper()
	dump := fx.e.scalar(`SELECT coalesce(string_agg(row_to_json(a)::text, ' '), '') FROM audit_log a`) +
		fx.e.scalar(`SELECT coalesce(string_agg(row_to_json(c)::text, ' '), '') FROM mcp_calls c`) +
		fx.e.scalar(`SELECT coalesce(string_agg(row_to_json(p)::text, ' '), '') FROM agent_platforms p`) +
		fx.e.scalar(`SELECT coalesce(string_agg(row_to_json(j)::text, ' '), '') FROM agent_token_jtis j`) +
		strings.Join(fx.responses, " ")
	if logs != nil {
		dump += logs.String()
	}
	for _, p := range []string{"/v1/admin/agent-platforms", "/v1/admin/agent-platforms/" + fx.platformID + "/relays", "/v1/admin/audit?limit=200",
		"/v1/teams/tools/calls?limit=100", "/v1/admin/service-accounts"} {
		_, raw := fx.e.admin.raw("GET", p, nil, nil)
		dump += string(raw)
	}
	secrets := append([]string{fx.key}, extra...)
	fx.ri.mu.Lock()
	secrets = append(secrets, fx.ri.minted...)
	fx.ri.mu.Unlock()
	for _, s := range secrets {
		if s != "" && strings.Contains(dump, s) {
			fx.t.Fatalf("a token or key leaked (%d chars): %.12s...", len(s), s)
		}
	}
}

// signUnpublished signs claims with a key the issuer never published.
func (ri *relayIssuer) signUnpublished(claims map[string]any) string {
	ri.t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		ri.t.Fatal(err)
	}
	return ri.sign(claims, "ghost", k)
}

// nowMinus is the Unix time sec seconds ago.
func nowMinus(sec int64) int64 { return time.Now().Unix() - sec }

// rawMCPMulti posts a request with several MCP-Gateway-Identity headers.
func rawMCPMulti(t *testing.T, app *testApp, slug, key string, body any, tokens []string) (int, http.Header, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", app.URL+"/mcp/"+slug, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	for _, tok := range tokens {
		req.Header.Add("MCP-Gateway-Identity", tok)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, res.Header, out
}
