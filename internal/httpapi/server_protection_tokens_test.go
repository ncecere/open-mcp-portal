package httpapi_test

import (
	"encoding/json"
	"testing"
)

func TestTokenServerProtectionFieldsNeverGainOwnerAuthority(t *testing.T) {
	e := newMatrixEnv(t)
	var pub tokenCred
	for _, c := range e.tokenCreds() {
		if c.name == "publisher-write" {
			pub = c
		}
	}
	srv := e.newServer(e.b, "private")
	path := "/v1/teams/bravo/mcp-servers/" + srv
	rev := map[string]string{"If-Match": `"` + e.exec(`SELECT revision::text FROM mcp_servers WHERE id=$1`, srv) + `"`}
	for _, field := range []string{"rateLimitPerMinute", "maxConcurrent"} {
		for _, value := range []any{1, nil} {
			code, _, body := e.bearer(pub.secret, patch(path, map[string]any{field: value}).h(rev))
			var env struct {
				Error struct {
					Code    string
					Details struct{ Field string }
				}
			}
			_ = json.Unmarshal(body, &env)
			if code != 403 || env.Error.Code != "token_not_allowed" || env.Error.Details.Field != field {
				t.Fatalf("token %s=%v: %d %s", field, value, code, body)
			}
		}
		code, _, body := e.bearer(pub.secret, post("/v1/teams/bravo/mcp-servers", map[string]any{"slug": "new-protection", "name": "Never created", "url": e.fakeURL, field: 1}))
		var env struct {
			Error struct {
				Code    string
				Details struct{ Field string }
			}
		}
		_ = json.Unmarshal(body, &env)
		if code != 403 || env.Error.Code != "token_not_allowed" || env.Error.Details.Field != field {
			t.Fatalf("token creates %s: %d %s", field, code, body)
		}
	}
	if got := e.exec(`SELECT (rate_limit_per_minute IS NULL AND max_concurrent IS NULL)::text FROM mcp_servers WHERE id=$1`, srv); got != "true" {
		t.Fatal("token changed operational fields")
	}
}
