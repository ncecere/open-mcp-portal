package httpapi_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Search shares the catalog list's authorization and eligibility query. It
// returns servers, never capability definitions, snippets or pre-filter totals.
func TestCatalogApprovedCapabilitySearch(t *testing.T) {
	e := newRegistryEnv(t)
	e.fake.SetDescription("check_outage", `Distinctive Needle 100%_\ <script>alert(1)</script>`)
	ids := []string{}
	for _, name := range []string{"Alpha", "Beta"} {
		id := e.create(map[string]any{"slug": strings.ToLower(name), "name": name, "description": "ServerMetadataUnique", "url": e.fake.URL()}).Server.Id.String()
		ids = append(ids, id)
		code, ec := e.owner.call("POST", toolsTeam+"/mcp-servers/"+id+"/publish", nil, nil, nil)
		mustCode(t, "request", code, ec, 200, "")
		code, ec = e.admin.call("POST", "/v1/admin/mcp-servers/"+id+"/review", approveBody(t, e.admin, id), nil, nil)
		mustCode(t, "approve", code, ec, 200, "")
	}
	// A private server with identical capabilities never contributes a hit.
	e.create(map[string]any{"slug": "private", "name": "Private", "url": e.fake.URL()})
	search := func(q string, want int) apitypes.CatalogServerPage {
		t.Helper()
		var out apitypes.CatalogServerPage
		code := e.outsider.get("/v1/catalog/servers?q="+url.QueryEscape(q), &out)
		if code != 200 || len(out.Items) != want {
			t.Fatalf("q=%q: code=%d page=%+v", q, code, out)
		}
		if want == 0 && out.NextCursor != nil {
			t.Fatal("hidden hit leaked through cursor")
		}
		return out
	}
	for _, q := range []string{"check_outage", "Check outage", "Searches open support tickets.", "DISTINCTIVE needle", `100%_\`, "<script>", "tools", "ServerMetadataUnique", "  Needle  "} {
		search(q, 2)
	}
	// Every capability visible on detail is discoverable, across kinds.
	if code, detail := e.catalog(e.outsider, ids[0]); code != 200 {
		t.Fatalf("detail: %d", code)
	} else {
		for _, capability := range detail.Capabilities {
			search(capability.Name, 2)
		}
	}
	for _, q := range []string{"100xx", "Al%ha", "Al_ha", `Al\pha`, "missing", "' OR 1=1 --", strings.Repeat("x", 200)} {
		search(q, 0)
	}
	code, ec := e.outsider.call("GET", "/v1/catalog/servers?q="+strings.Repeat("x", 201), nil, nil, nil)
	mustCode(t, "long query", code, ec, 400, "invalid_search")
	code, ec = e.outsider.call("GET", "/v1/catalog/servers?q="+url.QueryEscape(strings.Repeat("é", 101)), nil, nil, nil)
	mustCode(t, "UTF-8 byte bound", code, ec, 400, "invalid_search")
	for _, limit := range []string{"0", "201"} {
		code, _ := e.outsider.raw("GET", "/v1/catalog/servers?q=Needle&limit="+limit, nil, nil)
		if code != 400 {
			t.Fatalf("limit %s = %d", limit, code)
		}
	}
	var first, second apitypes.CatalogServerPage
	if code := e.outsider.get("/v1/catalog/servers?q=Needle&limit=1", &first); code != 200 || len(first.Items) != 1 || first.Items[0].Name != "Alpha" || first.NextCursor == nil {
		t.Fatalf("first: %d %+v", code, first)
	}
	if code := e.outsider.get("/v1/catalog/servers?q=Needle&limit=1&cursor="+url.QueryEscape(*first.NextCursor), &second); code != 200 || len(second.Items) != 1 || second.Items[0].Name != "Beta" || second.NextCursor != nil {
		t.Fatalf("second: %d %+v", code, second)
	}
	// Removing a hit between pages cannot leak it through the old cursor.
	pool := testutil.OwnerPool(t, e.app.Pool)
	if _, err := pool.Exec(context.Background(), `UPDATE mcp_servers SET enabled=false WHERE id=$1`, ids[1]); err != nil {
		t.Fatal(err)
	}
	var withdrawn apitypes.CatalogServerPage
	if code := e.outsider.get("/v1/catalog/servers?q=Needle&limit=1&cursor="+url.QueryEscape(*first.NextCursor), &withdrawn); code != 200 || len(withdrawn.Items) != 0 || withdrawn.NextCursor != nil {
		t.Fatalf("withdrawn page: %d %+v", code, withdrawn)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE mcp_servers SET enabled=true WHERE id=$1`, ids[1]); err != nil {
		t.Fatal(err)
	}
	// Changed definitions retain a stale approved fingerprint, but neither the
	// old name nor the new candidate's description can produce a hit.
	e.fake.SetDescription("check_outage", "ChangedSecret")
	e.fake.AddTool("UnapprovedSecret")
	for _, id := range ids {
		e.refresh(id)
	}
	for _, q := range []string{"%", `\`, "Distinctive", "ChangedSecret", "UnapprovedSecret", "check_outage"} {
		search(q, 0)
	}
	if items := search("create_ticket", 2).Items; items[0].Counts.Tools != 2 {
		t.Fatalf("counts include unapproved capabilities: %+v", items[0].Counts)
	}
	// Definition-only fields are never searched (even on an approved row).
	if _, err := pool.Exec(context.Background(), `UPDATE mcp_capabilities SET definition = definition || '{"hidden":"RawDefinitionSecret"}'::jsonb WHERE name='search_tickets'`); err != nil {
		t.Fatal(err)
	}
	search("RawDefinitionSecret", 0)
	// Gone rows are excluded after the server no longer lists a capability.
	if _, err := pool.Exec(context.Background(), `UPDATE mcp_capabilities SET gone_at=now(), approved_fingerprint=NULL, approved_at=NULL, approved_by=NULL WHERE name='search_tickets'`); err != nil {
		t.Fatal(err)
	}
	search("search_tickets", 0)
	if items := search("create_ticket", 2).Items; items[0].Counts.Tools != 1 {
		t.Fatalf("counts include gone capabilities: %+v", items[0].Counts)
	}
	// Live standing/publishing filters run before keyset pagination.
	for _, update := range []string{
		`UPDATE mcp_servers SET enabled=false WHERE publish_state='published'`,
		`UPDATE mcp_servers SET enabled=true, publish_state='private', published_at=NULL`,
		`UPDATE mcp_servers SET publish_state='published', published_at=now(); UPDATE teams SET status='archived' WHERE slug='tools'`,
	} {
		if _, err := pool.Exec(context.Background(), update); err != nil {
			t.Fatal(err)
		}
		search("create_ticket", 0)
		search("Alpha", 0)
	}
}
