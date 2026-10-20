package httpapi_test

import (
	"encoding/json"
	"strings"
	"testing"
)

// An automation token sets none of the v0.3.2 upstream auth settings: not a
// person's secret configuration (decision 72), not a machine client (decision
// 73), not a CA or client key (decision 74), and not a switch into any of the
// secret modes, on create or update, even on a server with nothing to steal
// yet. Once a server is in one of the modes (or holds a client key), a token
// can't re-point or switch it either; harmless fields still work. The
// per-feature rules are tested with each feature; this is all of them together
// on servers in every state, with nothing stored by a refused request.
func TestAutomationTokensSetNoSecretTLSOrModeChange(t *testing.T) {
	e := newMatrixEnv(t)
	var pub tokenCred
	for _, c := range e.tokenCreds() {
		if c.name == "publisher-write" {
			pub = c
		}
	}
	const sentinel = "token-sentinel-secret-0042"
	secretCfg := map[string]any{"placement": "header", "name": "X-Key", "label": "Key"}
	machine := map[string]any{"tokenUrl": "https://idp.example.com/token", "clientId": "c", "clientSecret": sentinel}
	tlsIn := map[string]any{"caPem": "x", "clientCertPem": "y", "clientKeyPem": sentinel}
	fieldOf := func(code int, body []byte) string {
		var env struct {
			Error struct {
				Code    string
				Details struct{ Field string }
			}
		}
		_ = json.Unmarshal(body, &env)
		if code == 200 || code == 201 {
			return "ok"
		}
		if code != 403 || env.Error.Code != "token_not_allowed" {
			return "unexpected " + env.Error.Code
		}
		return env.Error.Details.Field
	}
	// Create: each of these alone, and together with the others.
	create := func(extra map[string]any) string {
		b := map[string]any{"slug": "from-ci", "name": "From CI", "url": e.fakeURL}
		for k, v := range extra {
			b[k] = v
		}
		code, _, body := e.bearer(pub.secret, post("/v1/teams/bravo/mcp-servers", b))
		if strings.Contains(string(body), sentinel) {
			t.Errorf("create %v echoed a secret: %s", keysOf(extra), body)
		}
		return fieldOf(code, body)
	}
	for name, c := range map[string]struct {
		extra map[string]any
		want  string
	}{
		"personSecret with the mode": {map[string]any{"authMode": "person_secret", "personSecret": secretCfg}, "personSecret"},
		"personSecret alone":         {map[string]any{"personSecret": secretCfg}, "personSecret"},
		"the person_secret mode":     {map[string]any{"authMode": "person_secret"}, "authMode"},
		"machineOAuth with the mode": {map[string]any{"authMode": "machine_oauth", "machineOAuth": machine}, "machineOAuth"},
		"machineOAuth alone":         {map[string]any{"machineOAuth": machine}, "machineOAuth"},
		"the machine_oauth mode":     {map[string]any{"authMode": "machine_oauth"}, "authMode"},
		"tls":                        {map[string]any{"tls": tlsIn}, "tls"},
		"tls with a secret mode":     {map[string]any{"tls": tlsIn, "authMode": "machine_oauth", "machineOAuth": machine}, "tls"},
		"every secret at once":       {map[string]any{"tls": tlsIn, "personSecret": secretCfg, "machineOAuth": machine}, "tls"},
		"an empty tls":               {map[string]any{"tls": map[string]any{}}, "tls"},
	} {
		if got := create(c.extra); got != c.want {
			t.Errorf("create with %s: %q, want %q", name, got, c.want)
		}
	}
	if n := e.exec(`SELECT count(*)::text FROM mcp_servers WHERE slug = 'from-ci'`); n != "0" {
		t.Errorf("a refused create stored %s servers", n)
	}
	for _, table := range []string{"mcp_server_tls", "mcp_server_machine_oauth", "person_secrets"} {
		if n := e.exec(`SELECT count(*)::text FROM ` + table); n != "0" {
			t.Errorf("a refused request left %s rows in %s", n, table)
		}
	}

	// Update: on a server with nothing to steal, and on one in each state.
	update := func(srv string, body map[string]any) string {
		t.Helper()
		path := "/v1/teams/bravo/mcp-servers/" + srv
		rev := map[string]string{"If-Match": `"` + e.exec(`SELECT revision::text FROM mcp_servers WHERE id = $1`, srv) + `"`}
		code, _, raw := e.bearer(pub.secret, patch(path, body).h(rev))
		if strings.Contains(string(raw), sentinel) {
			t.Errorf("update %v echoed a secret: %s", keysOf(body), raw)
		}
		return fieldOf(code, raw)
	}
	changes := map[string]struct {
		body map[string]any
		want string
	}{
		"personSecret":           {map[string]any{"personSecret": secretCfg}, "personSecret"},
		"personSecret and mode":  {map[string]any{"authMode": "person_secret", "personSecret": secretCfg}, "authMode"},
		"the person_secret mode": {map[string]any{"authMode": "person_secret"}, "authMode"},
		"machineOAuth":           {map[string]any{"machineOAuth": machine}, "machineOAuth"},
		"machineOAuth and mode":  {map[string]any{"authMode": "machine_oauth", "machineOAuth": machine}, "machineOAuth"},
		"the machine_oauth mode": {map[string]any{"authMode": "machine_oauth"}, "authMode"},
		"tls":                    {map[string]any{"tls": tlsIn}, "tls"},
		"tls clear":              {map[string]any{"tls": map[string]any{"clear": true}}, "tls"},
	}
	plain := e.newServer(e.b, "private")
	for name, c := range changes {
		if got := update(plain, c.body); got != c.want {
			t.Errorf("update of a server with nothing to steal: %s = %q, want %q", name, got, c.want)
		}
	}
	for table, n := range map[string]string{"mcp_server_tls": "0", "mcp_server_machine_oauth": "0"} {
		if got := e.exec(`SELECT count(*)::text FROM ` + table); got != n {
			t.Errorf("%s has %s rows after refused updates", table, got)
		}
	}

	states := map[string]func(srv string){
		"person_secret": func(srv string) {
			e.run(`UPDATE mcp_servers SET auth_mode = 'person_secret', secret_placement = 'header', secret_name = 'X-K' WHERE id = $1`, srv)
		},
		"machine_oauth": func(srv string) {
			e.run(`UPDATE mcp_servers SET auth_mode = 'machine_oauth' WHERE id = $1`, srv)
			e.run(`INSERT INTO mcp_server_machine_oauth (server_id, token_url, client_id, client_secret_cipher) VALUES ($1, 'https://idp.example.com/token', 'c', '\x00')`, srv)
		},
		"a client key": func(srv string) {
			e.run(`INSERT INTO mcp_server_tls (server_id, client_cert_pem, client_key_cipher, client_cert_sha256, client_not_after)
				VALUES ($1, 'x', '\x00', repeat('a', 64), now() + interval '90 days')`, srv)
		},
	}
	for state, set := range states {
		srv := e.newServer(e.b, "private")
		set(srv)
		for name, c := range changes {
			// Which field a refusal names first is the server's business; that it
			// is a refusal of this kind is not.
			if got := update(srv, c.body); got == "ok" || strings.HasPrefix(got, "unexpected") {
				t.Errorf("update of a server in %s: %s = %q, want a token_not_allowed refusal", state, name, got)
			}
		}
		for name, body := range map[string]map[string]any{
			"the url":      {"url": "https://attacker.example.com/mcp"},
			"sendIdentity": {"sendIdentity": false},
			"the mode":     {"authMode": "none"},
		} {
			if state == "a client key" && name != "the url" {
				continue // a server holding only a client key has nothing else to steal
			}
			if got := update(srv, body); got == "ok" {
				t.Errorf("update of a server in %s: %s was accepted", state, name)
			}
		}
		if got := update(srv, map[string]any{"description": "still fine"}); got != "ok" {
			t.Errorf("a harmless field on a server in %s: %q", state, got)
		}
	}
	for _, table := range []string{"person_secrets", "secret_requests"} {
		if n := e.exec(`SELECT count(*)::text FROM ` + table); n != "0" {
			t.Errorf("%s has %s rows", table, n)
		}
	}
	if got := e.exec(`SELECT count(*)::text FROM mcp_server_machine_oauth WHERE token_url <> 'https://idp.example.com/token' OR client_id <> 'c'`); got != "0" {
		t.Errorf("a token changed a machine client")
	}
}
