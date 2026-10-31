package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	serverID = "11111111-1111-4111-8111-111111111111"
	teamID   = "22222222-2222-4222-8222-222222222222"
	secret   = "UPSTREAM_SECRET_SENTINEL_47"
)

func token(platform bool) string {
	if platform {
		return "ompadm_" + strings.Repeat("a", 43)
	}
	return "omppub_" + strings.Repeat("b", 43)
}
func serverFixture() map[string]any {
	return map[string]any{"id": serverID, "teamId": teamID, "teamSlug": "bravo", "slug": "status", "name": "Status", "enabled": false, "revision": int64(1), "counts": map[string]any{"tools": int64(0), "prompts": int64(0), "resources": int64(0), "resourceTemplates": int64(0)}, "authValueHint": secret, "credentials": []any{map[string]any{"value": secret}}, "governance": map[string]any{"oncallContact": secret}, "oauth": map[string]any{"claims": secret}}
}
func reply(w http.ResponseWriter, data any) {
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}
func TestURLAndTokenValidation(t *testing.T) {
	for _, u := range []string{"", "://", "http://example.org", "https://user:pass@example.org", "https://example.org/?x=1", "https://example.org/?", "https://example.org/#", "https://example.org/#x", "ftp://localhost", "https://example.org/%2f"} {
		if _, err := newReader(u, token(false)); err == nil {
			t.Errorf("accepted unsafe URL %q", u)
		}
	}
	for _, u := range []string{"https://example.org", "http://localhost:9999", "http://127.0.0.1:9999", "http://[::1]:9999"} {
		if _, err := newReader(u, token(false)); err != nil {
			t.Errorf("rejected URL: %v", err)
		}
	}
	for _, v := range []string{"", "omp_abc", token(false) + "x", "omppub_" + strings.Repeat("\n", 43)} {
		if _, err := newReader("https://example.org", v); err == nil {
			t.Fatal("accepted bad token")
		}
	}
}
func TestReadsAndRefresh(t *testing.T) {
	m := serverFixture()
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" {
			t.Error("mutation")
		}
		if r.Header.Get("Authorization") != "Bearer "+token(false) {
			t.Error("missing auth")
		}
		switch r.URL.Path {
		case "/v1/teams/bravo/mcp-servers":
			reply(w, map[string]any{"items": []any{m}})
		case "/v1/teams/bravo/mcp-servers/" + serverID:
			reply(w, m)
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	c, _ := newReader(ts.URL, token(false))
	first, err := c.server(context.Background(), "bravo", "status")
	if err != nil || *first.Enabled || *first.Counts.Tools != 0 || first.SupportsTasks != nil {
		t.Fatalf("read: %v", err)
	}
	m["name"] = "Edited outside Terraform"
	m["revision"] = int64(2)
	m["supportsTasks"] = false
	second, err := c.server(context.Background(), "bravo", serverID)
	if err != nil || *second.Name == *first.Name || second.SupportsTasks == nil || *second.SupportsTasks {
		t.Fatalf("refresh: %v", err)
	}
	_, err = c.server(context.Background(), "bravo", "absent")
	if err != notFound {
		t.Fatalf("not found: %v", err)
	}
	before := calls
	c.kind = "platform_admin"
	if _, err = c.server(context.Background(), "bravo", "status"); err == nil || calls != before {
		t.Fatal("platform reached team route")
	}
}
func TestStrictMetadata(t *testing.T) {
	for _, field := range []string{"id", "slug", "teamId", "teamSlug", "name", "enabled", "revision", "counts"} {
		t.Run("missing-"+field, func(t *testing.T) {
			m := serverFixture()
			delete(m, field)
			checkMalformed(t, m)
		})
	}
	for field, value := range map[string]any{"id": "bad", "teamId": "00000000-0000-0000-0000-000000000000", "teamSlug": "foreign", "revision": 0, "enabled": "false", "counts": map[string]any{"tools": -1, "prompts": 0, "resources": 0, "resourceTemplates": 0}, "supportsTasks": "true"} {
		t.Run("invalid-"+field, func(t *testing.T) { m := serverFixture(); m[field] = value; checkMalformed(t, m) })
	}
	m := serverFixture()
	m["counts"] = map[string]any{"tools": 1.1, "prompts": 0, "resources": 0, "resourceTemplates": 0}
	checkMalformed(t, m)
}
func checkMalformed(t *testing.T, m any) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reply(w, m) }))
	defer ts.Close()
	c, _ := newReader(ts.URL, token(false))
	_, err := c.server(context.Background(), "bravo", serverID)
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), token(false)) {
		t.Fatalf("unsafe result: %v", err)
	}
}
func TestStatusErrorsAndTransport(t *testing.T) {
	for _, status := range []int{401, 403, 404, 429, 500, 302} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(secret + token(false)))
			}))
			defer ts.Close()
			c, _ := newReader(ts.URL, token(false))
			_, err := c.server(context.Background(), "bravo", serverID)
			if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), token(false)) {
				t.Fatal("unsafe diagnostic")
			}
		})
	}
	targetCalls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls++ }))
	defer target.Close()
	for _, cross := range []bool{false, true} {
		redirectCalls := 0
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			redirectCalls++
			destination := "/elsewhere"
			if cross {
				destination = target.URL
			}
			http.Redirect(w, r, destination, 302)
		}))
		c, _ := newReader(ts.URL, token(false))
		_, err := c.server(context.Background(), "bravo", serverID)
		ts.Close()
		if err == nil || targetCalls != 0 || redirectCalls != 1 {
			t.Fatal("redirect followed")
		}
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS reached handler") }))
	defer tlsServer.Close()
	c, _ := newReader(tlsServer.URL, token(false))
	if _, err := c.server(context.Background(), "bravo", serverID); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	c, _ = newReader(slow.URL, token(false))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.server(ctx, "bravo", serverID)
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("cancellation unbounded")
	}
}
func TestTeamRead(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/admin/teams/bravo" {
			t.Error("unexpected route")
		}
		reply(w, map[string]any{"team": map[string]any{"id": teamID, "slug": "bravo", "name": "Bravo", "status": "active", "revision": 1, "description": secret}, "ownerInvites": 99})
	}))
	defer ts.Close()
	c, _ := newReader(ts.URL, token(true))
	m, err := c.team(context.Background(), "bravo")
	if err != nil || *m.ID != teamID {
		t.Fatalf("team: %v", err)
	}
	c.kind = "team_publisher"
	if _, err := c.team(context.Background(), "bravo"); err == nil {
		t.Fatal("publisher team read")
	}
}

func TestPaginationAndMalformedResponses(t *testing.T) {
	for _, mode := range []string{"second-page", "cycle", "duplicate", "missing-items", "null-data", "wrong-id", "token-echo", "huge-body"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if mode == "huge-body" {
					_, _ = w.Write([]byte(strings.Repeat(" ", 4*1024*1024+1)))
					return
				}
				if mode == "token-echo" {
					reply(w, map[string]any{"unknown": token(false)})
					return
				}
				if mode == "null-data" {
					reply(w, nil)
					return
				}
				m := serverFixture()
				if mode == "wrong-id" {
					m["id"] = teamID
					reply(w, m)
					return
				}
				if mode == "missing-items" {
					reply(w, map[string]any{})
					return
				}
				if strings.HasSuffix(r.URL.Path, serverID) {
					reply(w, m)
					return
				}
				if mode == "duplicate" {
					reply(w, map[string]any{"items": []any{m, m}})
					return
				}
				if mode == "cycle" {
					reply(w, map[string]any{"items": []any{}, "nextCursor": "repeat"})
					return
				}
				if r.URL.Query().Get("cursor") == "" {
					reply(w, map[string]any{"items": []any{}, "nextCursor": "second"})
					return
				}
				reply(w, map[string]any{"items": []any{m}})
			}))
			defer ts.Close()
			c, _ := newReader(ts.URL, token(false))
			key := "status"
			if mode == "wrong-id" {
				key = serverID
			}
			_, err := c.server(context.Background(), "bravo", key)
			if mode == "second-page" {
				if err != nil || calls != 3 {
					t.Fatalf("pagination: %d %v", calls, err)
				}
			} else if err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
}
