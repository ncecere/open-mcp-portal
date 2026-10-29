package httpapi_test

import (
	"encoding/json"
	"testing"
)

func TestServerEndpointsAutomationFieldBoundaries(t *testing.T) {
	e := newMatrixEnv(t)
	var publisher tokenCred
	for _, c := range e.tokenCreds() {
		if c.name == "publisher-write" {
			publisher = c
		}
	}
	srv := e.newServer(e.b, "private")
	path := "/v1/teams/bravo/mcp-servers/" + srv
	revision := map[string]string{"If-Match": `"` + e.exec(`SELECT revision::text FROM mcp_servers WHERE id=$1`, srv) + `"`}
	for _, value := range []any{nil, []any{}, []any{map[string]any{"url": e.fakeURL + "/replica"}}} {
		for _, req := range []request{patch(path, map[string]any{"endpoints": value}).h(revision), post("/v1/teams/bravo/mcp-servers", map[string]any{"slug": "forbidden-endpoint", "name": "Forbidden", "url": e.fakeURL, "endpoints": value})} {
			code, _, raw := e.bearer(publisher.secret, req)
			var body struct {
				Error struct {
					Code    string
					Details struct{ Field string }
				}
			}
			_ = json.Unmarshal(raw, &body)
			if code != 403 || body.Error.Code != "token_not_allowed" || body.Error.Details.Field != "endpoints" {
				t.Fatalf("token endpoint mutation: %d %s", code, raw)
			}
		}
	}
}
