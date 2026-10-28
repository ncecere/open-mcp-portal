package httpapi_test

import (
	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"net/url"
	"testing"
)

func TestServiceConnectionAdminPaginationAndStrictUpdates(t *testing.T) {
	e := newProvEnv(t)
	for _, name := range []string{"one", "two", "three"} {
		connectShared(t, e.owner, e.provider.Id, name)
	}
	var first, second apitypes.ServiceConnectionPage
	if code := e.auditor.get("/v1/admin/service-connections?limit=1", &first); code != 200 || len(first.Items) != 1 || first.NextCursor == nil {
		t.Fatalf("first page = %d %+v", code, first)
	}
	if code := e.auditor.get("/v1/admin/service-connections?limit=1&cursor="+url.QueryEscape(*first.NextCursor), &second); code != 200 || len(second.Items) != 1 || second.Items[0].Id == first.Items[0].Id {
		t.Fatalf("next page = %d %+v", code, second)
	}
	c := sharedByName(t, e.owner, "one")
	path := sharedBase + "/" + c.Id.String()
	code, ec := e.owner.call("PUT", path, map[string]any{"accounts": []any{}, "servers": []any{}}, nil, nil)
	mustCode(t, "required If-Match", code, ec, 428, "")
	for _, body := range []map[string]any{{}, {"accounts": nil, "servers": nil}, {"accounts": []any{}}} {
		code, ec = e.owner.call("PUT", path, body, nil, ifMatch(c.Revision))
		mustCode(t, "required array fields", code, ec, 400, "invalid_assignment")
	}
	ids := make([]uuid.UUID, 501)
	for i := range ids {
		ids[i] = uuid.New()
	}
	code, ec = e.owner.call("PUT", path, map[string]any{"accounts": ids, "servers": []any{}}, nil, ifMatch(c.Revision))
	mustCode(t, "bounded assignments", code, ec, 400, "invalid_assignment")
	foreign := e.scalar(`INSERT INTO service_connections(team_id,provider_id,name) SELECT id,$1,'foreign' FROM teams WHERE slug='other' RETURNING id::text`, e.provider.Id)
	code, ec = e.owner.call("PUT", sharedBase+"/"+foreign, map[string]any{"accounts": []any{}, "servers": []any{}}, nil, ifMatch(1))
	mustCode(t, "foreign connection ID", code, ec, 404, "connection_not_found")
}
