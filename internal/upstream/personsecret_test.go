package upstream

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A person's own secret travels as one more credential part (decision 72):
// where the server's team chose, with the prefix, and the identity token moves
// out of Authorization when the secret takes it.
func TestWithPersonSecretPlacements(t *testing.T) {
	const secret = "s3cret value&+/0001"
	cases := []struct {
		name, placement, field, prefix string
		check                          func(t *testing.T, req *http.Request)
		authz                          string
	}{
		{"header", PlaceHeader, "X-Api-Key", "Token ", func(t *testing.T, req *http.Request) {
			if got := req.Header.Get("X-Api-Key"); got != "Token "+secret {
				t.Errorf("X-Api-Key = %q", got)
			}
		}, ""},
		{"authorization header", PlaceHeader, "Authorization", "Key ", func(t *testing.T, req *http.Request) {
			if got := req.Header.Get("Authorization"); got != "Key "+secret {
				t.Errorf("Authorization = %q", got)
			}
		}, "Authorization"},
		{"bearer", PlaceBearer, "", "", func(t *testing.T, req *http.Request) {
			if got := req.Header.Get("Authorization"); got != "Bearer "+secret {
				t.Errorf("Authorization = %q", got)
			}
		}, "Authorization"},
		{"query", PlaceQuery, "api_key", "", func(t *testing.T, req *http.Request) {
			if got := req.URL.Query().Get("api_key"); got != secret {
				t.Errorf("api_key = %q (raw %q)", got, req.URL.RawQuery)
			}
			if req.Header.Get("Authorization") != "" {
				t.Error("a query secret set Authorization")
			}
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var target Target
			target.Credentials = []Credential{{Kind: CredHeader, Name: "X-Tenant", Value: "t-1"}}
			if !target.WithPersonSecret(tc.placement, tc.field, tc.prefix, secret) {
				t.Fatal("not added")
			}
			if len(target.Credentials) != 2 || target.Credentials[0].Name != "X-Tenant" {
				t.Fatalf("credentials = %+v", target.Credentials)
			}
			req, _ := http.NewRequest("POST", "https://x.example/mcp?keep=1", nil)
			applyCredentials(req, target.Credentials)
			tc.check(t, req)
			if req.Header.Get("X-Tenant") != "t-1" || req.URL.Query().Get("keep") != "1" {
				t.Error("the server's own parts were lost")
			}
			if got := target.AuthorizationHeader(); got != tc.authz {
				t.Errorf("AuthorizationHeader = %q, want %q", got, tc.authz)
			}
			// Redaction covers the bare secret, the value with its prefix and the encodings.
			msg := SafeMessage(strings.Join([]string{"a", tc.prefix + secret, secret, url.QueryEscape(secret), url.PathEscape(tc.prefix + secret), "z"}, " | "), target.Secrets()...)
			for _, bad := range []string{"s3cret", url.QueryEscape(secret), "0001"} {
				if strings.Contains(msg, bad) {
					t.Errorf("message still has %q: %s", bad, msg)
				}
			}
		})
	}
	var t0 Target
	if t0.WithPersonSecret("cookie", "x", "", secret) || len(t0.Credentials) != 0 || t0.PersonSecret != "" {
		t.Error("an unknown placement added a credential")
	}
	// A secret never mutates the slice its target shared with another call.
	shared := []Credential{{Kind: CredHeader, Name: "X-Tenant", Value: "t"}}
	a, b := Target{Credentials: shared}, Target{Credentials: shared}
	a.WithPersonSecret(PlaceHeader, "X-Key", "", "aaaaaaaa")
	b.WithPersonSecret(PlaceHeader, "X-Key", "", "bbbbbbbb")
	if a.Credentials[1].Value != "aaaaaaaa" || b.Credentials[1].Value != "bbbbbbbb" || len(shared) != 1 {
		t.Errorf("targets share state: %+v %+v %+v", a.Credentials, b.Credentials, shared)
	}
}
