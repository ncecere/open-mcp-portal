package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"slices"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

// This is the existing OIDC snapshot contract, not SCIM interoperability:
// changing an IdP's claims alone cannot notify the portal. A later interactive
// login updates the shared user row, including access seen by older sessions.
func TestOIDCGroupSnapshotChangesOnLoginForAllSessions(t *testing.T) {
	app, provider := oidcApp(t, nil)
	ctx := context.Background()
	const slug = "oidc-group-snapshot"
	var gatewayID string
	if err := app.Pool.QueryRow(ctx, `INSERT INTO gateways (slug, name, owner_kind)
		VALUES ($1, 'OIDC group snapshot', 'platform') RETURNING id`, slug).Scan(&gatewayID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Pool.Exec(ctx, `INSERT INTO gateway_grants (gateway_id, subject_kind, group_name)
		VALUES ($1, 'group', 'omp-test-allow')`, gatewayID); err != nil {
		t.Fatal(err)
	}
	setGroups := func(groups ...string) {
		t.Helper()
		claims := map[string]any{"sub": "group-snapshot-user", "email": "group-snapshot@example.com", "email_verified": true}
		if groups != nil {
			claims["groups"] = groups
		}
		provider.SetClaims(claims)
	}
	login := func() {
		t.Helper()
		res, err := app.Client.Get(app.URL + "/auth/login")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK || res.Request.URL.Path != "/" {
			t.Fatalf("OIDC login status=%d path=%s", res.StatusCode, res.Request.URL.Path)
		}
	}
	assertSnapshot := func(client *http.Client, groups []string, allowed bool) apitypes.Me {
		t.Helper()
		current := app.Client
		app.Client = client
		defer func() { app.Client = current }()
		code, me := app.me()
		if code != http.StatusOK || !slices.Equal(me.Groups, groups) {
			t.Fatalf("group snapshot status=%d groups=%v, want %v", code, me.Groups, groups)
		}
		if me.Capabilities.PlatformAdmin || len(me.Teams) != 0 {
			t.Fatal("group login unexpectedly granted a platform role or team membership")
		}
		code, body := app.do(http.MethodGet, "/v1/me/gateways", nil, nil)
		if code != http.StatusOK {
			t.Fatalf("gateway list status=%d", code)
		}
		var reply struct {
			Data []apitypes.MyGateway `json:"data"`
		}
		if err := json.Unmarshal(body, &reply); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, gateway := range reply.Data {
			if gateway.Slug == slug {
				found = true
				if access(gateway) != "group_grant" || gateway.Groups == nil || !slices.Equal(*gateway.Groups, []string{"omp-test-allow"}) {
					t.Fatalf("unexpected grant provenance: access=%s groups=%v", access(gateway), gateway.Groups)
				}
			}
		}
		if found != allowed {
			t.Fatalf("gateway visible=%t, want %t", found, allowed)
		}
		return me
	}

	setGroups("omp-test-allow")
	login()
	originalSession := app.Client
	first := assertSnapshot(originalSession, []string{"omp-test-allow"}, true)

	// No callback, webhook or provisioning push occurred. The existing session
	// still uses the last verified groups stored by an interactive sign-in.
	setGroups("omp-test-deny")
	assertSnapshot(originalSession, []string{"omp-test-allow"}, true)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	app.Client = &http.Client{Jar: jar}
	login()
	fresh := assertSnapshot(app.Client, []string{"omp-test-deny"}, false)
	if fresh.User.Id != first.User.Id {
		t.Fatal("a group change replaced the issuer/subject identity")
	}
	assertSnapshot(originalSession, []string{"omp-test-deny"}, false)

	// An absent groups claim must clear the old snapshot, not preserve grants.
	setGroups()
	login()
	assertSnapshot(app.Client, nil, false)
	assertSnapshot(originalSession, nil, false)

	// A later verified group addition is ordinary OIDC authority; this does not
	// stand in for SCIM reactivation or restoring consumed credentials.
	setGroups("omp-test-allow")
	login()
	assertSnapshot(app.Client, []string{"omp-test-allow"}, true)
	assertSnapshot(originalSession, []string{"omp-test-allow"}, true)
	var users int
	if err := app.Pool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&users); err != nil || users != 1 {
		t.Fatalf("identity count=%d, error=%v", users, err)
	}
}
