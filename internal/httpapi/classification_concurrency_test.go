package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

func classifyHTTP(t *testing.T, s *session, path string, body any, revision int64) (int, http.Header, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("PUT", s.app.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", s.app.URL)
	req.Header.Set("X-CSRF-Token", s.csrf)
	for k, v := range ifMatch(revision) {
		req.Header.Set(k, v)
	}
	res, err := s.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, res.Header, out
}

func TestToolClassificationETagAndConcurrentBatch(t *testing.T) {
	e := newRegistryEnv(t)
	sv := e.create(map[string]any{"slug": "status", "name": "Status", "url": e.fake.URL()}).Server
	id := sv.Id.String()
	base := toolsTeam + "/mcp-servers/" + id + "/capabilities"
	caps := e.capabilities(e.owner, id)
	code, h, raw := classifyHTTP(t, e.owner, base+"/"+caps["check_outage"].Id.String()+"/class", map[string]any{"toolClass": "read"}, sv.Revision)
	if code != 200 || h.Get("ETag") != ifMatch(sv.Revision + 1)["If-Match"] {
		t.Fatalf("single ETag: %d %v %s", code, h, raw)
	}
	sv = e.server(e.owner, id)
	body := map[string]any{"items": []any{map[string]any{"capabilityId": caps["check_outage"].Id, "toolClass": "write"}, map[string]any{"capabilityId": caps["create_ticket"].Id, "toolClass": "destructive"}}}
	type result struct {
		status int
		h      http.Header
		raw    []byte
	}
	ch := make(chan result, 2)
	for range 2 {
		go func() {
			code, h, raw := classifyHTTP(t, e.owner, base+"/classes", body, sv.Revision)
			ch <- result{code, h, raw}
		}()
	}
	statuses := []int{}
	for range 2 {
		r := <-ch
		statuses = append(statuses, r.status)
		if r.status == 200 {
			var out struct{ Data []apitypes.McpCapability }
			if err := json.Unmarshal(r.raw, &out); err != nil || len(out.Data) != 2 || r.h.Get("ETag") != ifMatch(sv.Revision + 1)["If-Match"] {
				t.Fatalf("bulk ETag %v %s", r.h, r.raw)
			}
		}
	}
	sort.Ints(statuses)
	if statuses[0] != 200 || statuses[1] != 412 || e.server(e.owner, id).Revision != sv.Revision+1 {
		t.Fatalf("concurrent statuses %v", statuses)
	}
}
