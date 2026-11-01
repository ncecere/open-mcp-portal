package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/scim"
)

// SCIM provisioning end to end (decision 92, docs/scim.md). The directory is
// bound to the development sign-in issuer, so enrollment, fencing, deletion
// and re-enrollment go through the real sign-in transaction.

type scimEnv struct {
	t     *testing.T
	app   *testApp
	svc   *scim.Service
	admin *session
	token string
}

func newSCIMEnv(t *testing.T, enrollment string) *scimEnv {
	t.Helper()
	var svc *scim.Service
	app := newTestAppDeps(t, nil, nil, func(d *httpapi.Deps) {
		d.SCIM.Issuer = auth.DevIssuer
		svc = d.SCIM
	})
	e := &scimEnv{t: t, app: app, svc: svc, admin: app.signIn("admin")}
	var dir apitypes.ProvisioningDirectory
	code, ec := e.admin.call("POST", "/v1/admin/provisioning", map[string]any{"enabled": true, "enrollment": enrollment}, &dir, nil)
	mustCode(t, "create directory", code, ec, 201, "")
	if !dir.IssuerMatches || dir.Issuer != auth.DevIssuer || !strings.HasSuffix(dir.ScimBaseUrl, "/scim/v2") {
		t.Fatalf("directory = %+v", dir)
	}
	var tok apitypes.ProvisioningTokenCreated
	code, ec = e.admin.call("POST", "/v1/admin/provisioning/tokens", map[string]any{"name": "idp"}, &tok, nil)
	mustCode(t, "create token", code, ec, 201, "")
	if !strings.HasPrefix(tok.Secret, "ompscim_") || tok.Status != "active" {
		t.Fatalf("token = %+v", tok)
	}
	e.token = tok.Secret
	return e
}

// scim sends a SCIM request with the directory token (or token override).
func (e *scimEnv) scim(method, path string, body any, headers map[string]string) (int, map[string]any, http.Header) {
	e.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.app.URL+"/scim/v2"+path, rdr)
	req.Header.Set("Authorization", "Bearer "+e.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			e.t.Fatalf("%s %s: not JSON: %s", method, path, raw)
		}
		if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/scim+json") {
			e.t.Fatalf("%s %s content type %q", method, path, ct)
		}
	}
	return res.StatusCode, out, res.Header
}

func (e *scimEnv) mustSCIM(want int, method, path string, body any) map[string]any {
	e.t.Helper()
	code, out, _ := e.scim(method, path, body, nil)
	if code != want {
		e.t.Fatalf("%s %s = %d (want %d): %v", method, path, code, want, out)
	}
	return out
}

func (e *scimEnv) createUser(userName, externalID string, active bool) string {
	e.t.Helper()
	out := e.mustSCIM(201, "POST", "/Users", map[string]any{"schemas": []string{scim.SchemaUser}, "userName": userName, "externalId": externalID,
		"active": active, "name": map[string]any{"givenName": "Given", "familyName": "Family"}, "emails": []any{map[string]any{"value": userName, "primary": true}}})
	return out["id"].(string)
}

func (e *scimEnv) patchUser(id string, ops ...map[string]any) {
	e.t.Helper()
	e.mustSCIM(200, "PATCH", "/Users/"+id, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": ops})
}

func (e *scimEnv) scalar(query string, args ...any) string {
	e.t.Helper()
	var s string
	if err := e.app.Pool.QueryRow(context.Background(), query, args...).Scan(&s); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
	return s
}

func (e *scimEnv) standing(email string) (status, manual, directory string) {
	e.t.Helper()
	if err := e.app.Pool.QueryRow(context.Background(), `SELECT status, manual_status, directory_standing FROM users WHERE email=$1`, email).Scan(&status, &manual, &directory); err != nil {
		e.t.Fatalf("standing of %s: %v", email, err)
	}
	return
}

func trySignIn(app *testApp, account string) (int, *session) {
	jar, _ := cookiejar.New(nil)
	s := &session{t: app.t, app: app, client: &http.Client{Jar: jar}}
	code, _ := s.raw("POST", "/auth/dev", map[string]string{"account": account}, nil)
	if code == 200 {
		s.refresh()
	}
	return code, s
}

func TestSCIMProtocolSurfaceAndCredentialIsolation(t *testing.T) {
	e := newSCIMEnv(t, scim.EnrollmentOptional)
	for _, path := range []string{"/ServiceProviderConfig", "/ResourceTypes", "/ResourceTypes/User", "/Schemas", "/Schemas/" + scim.SchemaGroup} {
		e.mustSCIM(200, "GET", path, nil)
	}
	spc := e.mustSCIM(200, "GET", "/ServiceProviderConfig", nil)
	if spc["bulk"].(map[string]any)["supported"] != false || spc["patch"].(map[string]any)["supported"] != true {
		t.Fatalf("service provider config = %v", spc)
	}
	// Only a directory token authenticates /scim/v2.
	for _, tok := range []string{"", "ompadm_" + strings.Repeat("a", 43), "ompscim_" + strings.Repeat("b", 43), "omp_" + strings.Repeat("c", 43)} {
		saved := e.token
		e.token = tok
		code, out, h := e.scim("GET", "/Users", nil, nil)
		e.token = saved
		if code != 401 || out["status"] != "401" || !strings.HasPrefix(h.Get("WWW-Authenticate"), "Bearer") {
			t.Fatalf("token %q: %d %v", tok[:min(len(tok), 9)], code, out)
		}
	}
	// The directory token never authenticates /v1 or /mcp.
	req, _ := http.NewRequest("GET", e.app.URL+"/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+e.token)
	if res, err := http.DefaultClient.Do(req); err != nil || res.StatusCode != 401 {
		t.Fatalf("/v1 with a SCIM token: %v %v", res.StatusCode, err)
	}
	req, _ = http.NewRequest("POST", e.app.URL+"/mcp/anything", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+e.token)
	if res, err := http.DefaultClient.Do(req); err != nil || res.StatusCode == 200 {
		t.Fatalf("/mcp with a SCIM token: %v %v", res.StatusCode, err)
	}

	id := e.createUser("Pat@Example.test", "pat-subject", true)
	code, out, _ := e.scim("POST", "/Users", map[string]any{"userName": "pat@example.TEST"}, nil)
	if code != 409 || out["scimType"] != "uniqueness" {
		t.Fatalf("case-insensitive userName uniqueness: %d %v", code, out)
	}
	list := e.mustSCIM(200, "GET", `/Users?filter=userName%20eq%20%22PAT@example.test%22`, nil)
	if list["totalResults"].(float64) != 1 {
		t.Fatalf("userName filter = %v", list)
	}
	list = e.mustSCIM(200, "GET", `/Users?filter=externalId%20eq%20%22PAT-subject%22`, nil)
	if list["totalResults"].(float64) != 0 {
		t.Fatal("externalId must compare case-exact")
	}
	if code, out, _ := e.scim("GET", `/Users?filter=name.familyName%20co%20%22x%22`, nil, nil); code != 400 || out["scimType"] != "invalidFilter" {
		t.Fatalf("unsupported filter: %d %v", code, out)
	}
	page := e.mustSCIM(200, "GET", "/Users?startIndex=0&count=-5", nil)
	if page["startIndex"].(float64) != 1 || page["itemsPerPage"].(float64) != 0 || page["totalResults"].(float64) != 1 {
		t.Fatalf("pagination normalisation = %v", page)
	}
	code, got, h := e.scim("GET", "/Users/"+id, nil, nil)
	if code != 200 || h.Get("ETag") != `W/"1"` || got["meta"].(map[string]any)["version"] != `W/"1"` {
		t.Fatalf("get user = %d %v %q", code, got, h.Get("ETag"))
	}
	if code, _, _ := e.scim("PATCH", "/Users/"+id, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{"op": "replace", "path": "displayName", "value": "x"}}}, map[string]string{"If-Match": `W/"7"`}); code != 412 {
		t.Fatalf("stale If-Match = %d", code)
	}
	// Atomic PATCH: a bad later operation leaves the earlier one unapplied.
	if code, _, _ := e.scim("PATCH", "/Users/"+id, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{"op": "replace", "path": "displayName", "value": "Changed"}, map[string]any{"op": "remove", "path": "userName"}}}, nil); code != 400 {
		t.Fatalf("invalid PATCH = %d", code)
	}
	if got := e.mustSCIM(200, "GET", "/Users/"+id, nil); got["displayName"] != nil && got["displayName"] != "" {
		t.Fatalf("partial PATCH applied: %v", got["displayName"])
	}
	// Entra-style capitalised op, string boolean, filtered email path, ignored extension.
	e.patchUser(id, map[string]any{"op": "Replace", "path": "emails[type eq \"work\"].value", "value": "pat2@example.test"},
		map[string]any{"op": "Add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "value": "x"},
		map[string]any{"op": "replace", "path": "active", "value": "False"})
	got = e.mustSCIM(200, "GET", "/Users/"+id, nil)
	if got["active"] != false || got["emails"].([]any)[0].(map[string]any)["value"] != "pat2@example.test" {
		t.Fatalf("patched user = %v", got)
	}
	// Groups: members must exist; member-filter removal; excludedAttributes.
	if code, out, _ := e.scim("POST", "/Groups", map[string]any{"displayName": "eng", "members": []any{map[string]any{"value": "00000000-0000-0000-0000-000000000001"}}}, nil); code != 400 {
		t.Fatalf("unknown member = %d %v", code, out)
	}
	g := e.mustSCIM(201, "POST", "/Groups", map[string]any{"displayName": "eng", "members": []any{map[string]any{"value": id}}})
	gid := g["id"].(string)
	// displayName is unique per directory, ignoring case: a repeated or
	// concurrent create (seen from authentik) gets 409, never a twin group.
	if code, out, _ := e.scim("POST", "/Groups", map[string]any{"displayName": "ENG"}, nil); code != 409 || out["scimType"] != "uniqueness" {
		t.Fatalf("duplicate group = %d %v", code, out)
	}
	codes := make(chan int, 2)
	for range 2 {
		go func() {
			c, _, _ := e.scim("POST", "/Groups", map[string]any{"displayName": "racing", "externalId": "same"}, nil)
			codes <- c
		}()
	}
	if a, b := <-codes, <-codes; a+b != 201+409 {
		t.Fatalf("concurrent duplicate creates = %d, %d", a, b)
	}
	if list := e.mustSCIM(200, "GET", `/Groups?filter=displayName%20eq%20%22racing%22`, nil); list["totalResults"].(float64) != 1 {
		t.Fatalf("concurrent creates left %v groups", list["totalResults"])
	}
	if code, out, _ := e.scim("PATCH", "/Groups/"+gid, map[string]any{"Operations": []any{map[string]any{"op": "replace", "path": "displayName", "value": "Racing"}}}, nil); code != 409 || out["scimType"] != "uniqueness" {
		t.Fatalf("rename onto an existing group = %d %v", code, out)
	}
	if len(g["members"].([]any)) != 1 {
		t.Fatalf("group = %v", g)
	}
	if lean := e.mustSCIM(200, "GET", "/Groups/"+gid+"?excludedAttributes=members", nil); lean["members"] != nil {
		t.Fatal("excludedAttributes=members still returned members")
	}
	e.mustSCIM(200, "PATCH", "/Groups/"+gid, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{"op": "remove", "path": `members[value eq "` + id + `"]`}, map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": id}}},
			map[string]any{"op": "remove", "path": "members", "value": []any{map[string]any{"value": id}}}}})
	// An empty group still returns "members": [] (authentik needs it to
	// compute additions); excludedAttributes alone omits it.
	if g := e.mustSCIM(200, "GET", "/Groups/"+gid, nil); g["members"] == nil || len(g["members"].([]any)) != 0 {
		t.Fatalf("ordered member operations ended with %v", g["members"])
	}
	// authentik 2025.8's attribute update: no top-level schemas, path-less
	// replace carrying id/schemas in the value (observed against a real
	// authentik push).
	e.mustSCIM(200, "PATCH", "/Groups/"+gid, map[string]any{"Operations": []any{map[string]any{"op": "replace",
		"value": map[string]any{"id": gid, "displayName": "eng-renamed", "schemas": []string{scim.SchemaGroup}, "externalId": "ak-pk"}}}})
	if g := e.mustSCIM(200, "GET", "/Groups/"+gid, nil); g["displayName"] != "eng-renamed" || g["externalId"] != "ak-pk" {
		t.Fatalf("authentik-style replace = %v", g)
	}
	e.mustSCIM(204, "DELETE", "/Groups/"+gid, nil)
	e.mustSCIM(404, "GET", "/Groups/"+gid, nil)
	e.mustSCIM(204, "DELETE", "/Users/"+id, nil)
	e.mustSCIM(404, "GET", "/Users/"+id, nil)
	// Revoking the token takes effect at once.
	var toks []apitypes.ProvisioningToken
	e.admin.get("/v1/admin/provisioning/tokens", &toks)
	code, ec := e.admin.call("DELETE", "/v1/admin/provisioning/tokens/"+toks[0].Id.String(), nil, nil, nil)
	mustCode(t, "revoke token", code, ec, 200, "")
	if code, _, _ := e.scim("GET", "/Users", nil, nil); code != 401 {
		t.Fatalf("revoked token = %d", code)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action LIKE 'scim.%' AND metadata::text LIKE '%ompscim_%' || 'xxxxxxxxxxxxxxxx%'`); n != "0" {
		t.Fatal("a token secret reached the audit log")
	}
}

func TestSCIMLifecycleEnrollmentFenceDeletionAndReenrollment(t *testing.T) {
	e := newSCIMEnv(t, scim.EnrollmentOptional)
	createTeam(t, e.admin, "tools", "user@localhost")
	owner := e.app.signIn("user")
	// alex is a manual member before provisioning; the directory never changes it.
	alex0 := e.app.signIn("alex")
	code, ec := owner.call("POST", toolsTeam+"/members", map[string]any{"email": "alex@localhost", "role": "member"}, nil, nil)
	mustCode(t, "manual member", code, ec, 201, "")

	blairRes := e.createUser("blair@localhost", "blair", true)
	alexRes := e.createUser("alex@localhost", "alex", true)
	// blair enrolls on first sign-in (new identity, active resource).
	code, blair := trySignIn(e.app, "blair")
	if code != 200 {
		t.Fatalf("enrolling sign-in = %d", code)
	}
	if st, manual, dir := e.standing("blair@localhost"); st != "active" || manual != "active" || dir != "active" {
		t.Fatalf("enrolled standing = %s/%s/%s", st, manual, dir)
	}
	// alex existed unmanaged: not linked until an admin adopts.
	if _, _, dir := e.standing("alex@localhost"); dir != "none" {
		t.Fatal("an existing person was linked without adoption")
	}
	code, ec = e.admin.call("POST", "/v1/admin/provisioning/users/"+alexRes+"/adopt", nil, nil, nil)
	mustCode(t, "adopt alex", code, ec, 200, "")

	// Group mapping grants roles only where no manual membership exists.
	g := e.mustSCIM(201, "POST", "/Groups", map[string]any{"displayName": "Engineering", "members": []any{map[string]any{"value": blairRes}, map[string]any{"value": alexRes}}})
	var teamView apitypes.TeamView
	e.admin.get("/v1/teams/tools", &teamView)
	var mapping apitypes.ProvisioningMapping
	code, ec = e.admin.call("POST", "/v1/admin/provisioning/mappings", map[string]any{"groupId": g["id"], "teamId": teamView.Team.Id, "role": "editor"}, &mapping, nil)
	mustCode(t, "map group", code, ec, 201, "")
	role := func(email string) string {
		return e.scalar(`SELECT coalesce((SELECT m.role FROM team_members m JOIN users u ON u.id=m.user_id JOIN teams t ON t.id=m.team_id WHERE t.slug='tools' AND u.email=$1),'none')`, email)
	}
	if role("blair@localhost") != "editor" || role("alex@localhost") != "member" {
		t.Fatalf("mapped roles blair=%s alex=%s", role("blair@localhost"), role("alex@localhost"))
	}
	if code, ec = e.admin.call("POST", "/v1/admin/provisioning/mappings", map[string]any{"groupId": g["id"], "teamId": teamView.Team.Id, "role": "owner"}, nil, nil); code != 400 {
		t.Fatalf("owner mapping = %d %s", code, ec)
	}
	// Directory-managed people can't become owners or platform admins.
	code, ec = owner.call("PATCH", toolsTeam+"/members/"+blair.me.User.Id.String(), map[string]any{"role": "owner"}, nil, ifMatch(1))
	mustCode(t, "promote managed to owner", code, ec, 409, "protected_principal")
	var blairDetail apitypes.UserDetail
	e.admin.get("/v1/admin/users/"+blair.me.User.Id.String(), &blairDetail)
	code, ec = e.admin.call("PATCH", "/v1/admin/users/"+blair.me.User.Id.String(), map[string]any{"platformRole": "platform_admin"}, nil, ifMatch(blairDetail.User.Revision))
	mustCode(t, "promote managed to admin", code, ec, 409, "protected_principal")
	// Protected principals can't be adopted.
	ownerRes := e.createUser("user@localhost", "user", true)
	code, ec = e.admin.call("POST", "/v1/admin/provisioning/users/"+ownerRes+"/adopt", nil, nil, nil)
	mustCode(t, "adopt team owner", code, ec, 409, "protected_principal")

	key := newKey(t, blair, "laptop")
	// Removing blair from the group removes only the directory membership.
	e.mustSCIM(200, "PATCH", "/Groups/"+g["id"].(string), map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{"op": "remove", "path": `members[value eq "` + blairRes + `"]`}}})
	if role("blair@localhost") != "none" || role("alex@localhost") != "member" {
		t.Fatalf("after removal blair=%s alex=%s", role("blair@localhost"), role("alex@localhost"))
	}

	// Directory deactivation is a short fence: the retained cookie ends.
	sessionsBefore := e.scalar(`SELECT count(*)::text FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.email='blair@localhost'`)
	e.patchUser(blairRes, map[string]any{"op": "replace", "path": "active", "value": false})
	// While inactive the retained cookie gets the existing suspended refusal;
	// after reactivation its ended generation makes it 401 (below).
	if code := blair.get("/v1/me", nil); code != 403 {
		t.Fatalf("deactivated cookie = %d", code)
	}
	if after := e.scalar(`SELECT count(*)::text FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.email='blair@localhost'`); after != sessionsBefore {
		t.Fatal("deactivation deleted sessions instead of fencing them")
	}
	if st, manual, dir := e.standing("blair@localhost"); st != "suspended" || manual != "active" || dir != "inactive" {
		t.Fatalf("deactivated standing = %s/%s/%s", st, manual, dir)
	}
	if code, _ := trySignIn(e.app, "blair"); code != 403 {
		t.Fatalf("sign-in while directory-inactive = %d", code)
	}
	// Neither a manual reactivation nor a previous binary's status write lifts it.
	e.admin.get("/v1/admin/users/"+blair.me.User.Id.String(), &blairDetail)
	code, ec = e.admin.call("PATCH", "/v1/admin/users/"+blair.me.User.Id.String(), map[string]any{"status": "active"}, nil, ifMatch(blairDetail.User.Revision))
	mustCode(t, "manual reactivation is manual only", code, ec, 200, "")
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE users SET status='active' WHERE email='blair@localhost'`); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := e.standing("blair@localhost"); st != "suspended" {
		t.Fatal("a status-only write lifted the directory restriction")
	}
	// Reactivation: fresh sign-in works, the old cookie stays ended, and the
	// unrevoked key is preserved for fresh requests.
	e.patchUser(blairRes, map[string]any{"op": "replace", "path": "active", "value": true})
	if code := blair.get("/v1/me", nil); code != 401 {
		t.Fatal("reactivation revived the fenced cookie")
	}
	code, blair = trySignIn(e.app, "blair")
	if code != 200 {
		t.Fatalf("fresh sign-in after reactivation = %d", code)
	}
	if n := e.scalar(`SELECT count(*)::text FROM api_keys WHERE id=$1 AND revoked_at IS NULL`, key.Key.Id); n != "1" {
		t.Fatal("reversible deactivation revoked the key")
	}
	pendingStates := e.scalar(`SELECT count(*)::text FROM directory_cleanup_jobs`)
	if pendingStates != "0" {
		t.Fatal("deactivation created clean-up")
	}

	// Deletion ends the directory life; clean-up removes personal credentials.
	e.mustSCIM(204, "DELETE", "/Users/"+blairRes, nil)
	if code := blair.get("/v1/me", nil); code != 403 {
		t.Fatalf("deleted person's cookie = %d", code)
	}
	if st, _, dir := e.standing("blair@localhost"); st != "suspended" || dir != "deleted" {
		t.Fatalf("deleted standing = %s/%s", st, dir)
	}
	// A new resource can't re-enroll before clean-up completes.
	blairRes2 := e.createUser("blair@localhost", "blair", true)
	code, ec = e.admin.call("POST", "/v1/admin/provisioning/users/"+blairRes2+"/adopt", nil, nil, nil)
	mustCode(t, "re-enroll before clean-up", code, ec, 409, "cleanup_pending")
	if code, _ := trySignIn(e.app, "blair"); code != 403 {
		t.Fatal("a deleted life signed in through a new resource")
	}
	res, err := e.svc.Cleanup(context.Background())
	if err != nil || res.Completed != 1 {
		t.Fatalf("clean-up = %+v %v", res, err)
	}
	for _, q := range []string{
		`SELECT count(*)::text FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.email='blair@localhost'`,
		`SELECT count(*)::text FROM api_keys k JOIN users u ON u.id=k.user_id WHERE u.email='blair@localhost' AND k.revoked_at IS NULL`,
		`SELECT count(*)::text FROM team_members m JOIN users u ON u.id=m.user_id WHERE u.email='blair@localhost'`,
	} {
		if n := e.scalar(q); n != "0" {
			t.Fatalf("clean-up left %s: %s", n, q)
		}
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action='scim.user_cleanup'`); n != "1" {
		t.Fatal("clean-up not audited")
	}
	code, ec = e.admin.call("POST", "/v1/admin/provisioning/users/"+blairRes2+"/adopt", nil, nil, nil)
	mustCode(t, "re-enroll after clean-up", code, ec, 200, "")
	if code, _ := trySignIn(e.app, "blair"); code != 200 {
		t.Fatal("re-enrolled person cannot sign in")
	}
	_ = alex0
}

func TestSCIMRequiredEnrollmentRefusesBeforeAnyWrite(t *testing.T) {
	e := newSCIMEnv(t, scim.EnrollmentRequired)
	before := e.scalar(`SELECT count(*)::text FROM users`)
	if code, _ := trySignIn(e.app, "casey"); code != 403 {
		t.Fatalf("unprovisioned sign-in = %d", code)
	}
	e.createUser("casey@localhost", "casey", false)
	if code, _ := trySignIn(e.app, "casey"); code != 403 {
		t.Fatalf("inactive resource sign-in = %d", code)
	}
	if after := e.scalar(`SELECT count(*)::text FROM users`); after != before {
		t.Fatal("a refused sign-in created a user")
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action='auth.login_denied'`); n != "2" {
		t.Fatalf("refusals audited %s times", n)
	}
	// Existing unmanaged people (the admin) keep signing in.
	if code, _ := trySignIn(e.app, "admin"); code != 200 {
		t.Fatal("required enrollment locked out an existing unmanaged admin")
	}
	// Duplicate candidates are ambiguous: refused, never the first one.
	e.createUser("blair@localhost", "blair", true)
	e.createUser("blair2@localhost", "blair", true)
	if code, _ := trySignIn(e.app, "blair"); code != 403 {
		t.Fatal("an ambiguous externalId enrolled")
	}
}

// A deactivation that commits while an enrolling sign-in waits on the same
// resource wins: the sign-in is refused and creates nothing.
func TestSCIMEnrollmentSerialisesWithDeactivation(t *testing.T) {
	e := newSCIMEnv(t, scim.EnrollmentRequired)
	res := e.createUser("casey@localhost", "casey", true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tx, err := e.app.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var holder int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid() FROM scim_users WHERE id=$1 FOR UPDATE`, res).Scan(&holder); err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() {
		code, _ := trySignIn(e.app, "casey")
		done <- code
	}()
	for {
		var waiting bool
		if err := e.app.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database()
			AND position('LockEnrollmentCandidates' IN a.query)>0 AND $1::integer=ANY(pg_blocking_pids(a.pid)))`, holder).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("sign-in never waited on the resource")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE scim_users SET active=false WHERE id=$1`, res); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if code := <-done; code != 403 {
		t.Fatalf("sign-in after concurrent deactivation = %d", code)
	}
	if n := e.scalar(`SELECT count(*)::text FROM users WHERE email='casey@localhost'`); n != "0" {
		t.Fatal("refused enrollment created the user")
	}
}

// A clean-up pass that meets a locked artifact stays incomplete and retries;
// it never reports completion while the artifact remains.
func TestSCIMCleanupIsIncompleteUnderContention(t *testing.T) {
	e := newSCIMEnv(t, scim.EnrollmentOptional)
	res := e.createUser("blair@localhost", "blair", true)
	code, blair := trySignIn(e.app, "blair")
	if code != 200 {
		t.Fatal("enroll")
	}
	key := newKey(t, blair, "laptop")
	e.mustSCIM(204, "DELETE", "/Users/"+res, nil)
	ctx := context.Background()
	tx, err := e.app.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM api_keys WHERE id=$1 FOR UPDATE`, key.Key.Id); err != nil {
		t.Fatal(err)
	}
	r, err := e.svc.Cleanup(ctx)
	if err != nil || r.Completed != 0 || r.Incomplete != 1 {
		t.Fatalf("contended clean-up = %+v %v", r, err)
	}
	if n := e.scalar(`SELECT count(*)::text FROM directory_cleanup_jobs WHERE completed_at IS NULL AND attempts=1 AND last_error='sqlstate_55P03'`); n != "1" {
		t.Fatal("contended clean-up not recorded as incomplete")
	}
	_ = tx.Rollback(ctx)
	if r, err = e.svc.Cleanup(ctx); err != nil || r.Completed != 1 {
		t.Fatalf("retried clean-up = %+v %v", r, err)
	}
	if n := e.scalar(`SELECT count(*)::text FROM api_keys WHERE id=$1 AND revoked_at IS NOT NULL`, key.Key.Id); n != "1" {
		t.Fatal("clean-up did not revoke the key")
	}
}
