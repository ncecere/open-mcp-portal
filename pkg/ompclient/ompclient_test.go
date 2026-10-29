package ompclient_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

// The client covers exactly the operations that accept automation tokens
// (the x-omp-token-scopes table the server enforces): no more, so no
// session-only operation becomes public API, and no fewer.
func TestClientCoversExactlyTheTokenOperations(t *testing.T) {
	want := map[string]bool{}
	for _, op := range apitypes.TokenOperations {
		want[op.OperationID] = true
	}
	got := map[string]bool{}
	typ := reflect.TypeOf((*ompclient.ClientInterface)(nil)).Elem()
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		name = strings.TrimSuffix(name, "WithBody")
		got[strings.ToLower(name[:1])+name[1:]] = true
	}
	for id := range want {
		if !got[id] {
			t.Errorf("operation %s accepts tokens but has no client method", id)
		}
	}
	for id := range got {
		if !want[id] {
			t.Errorf("client method for %s, which does not accept tokens", id)
		}
	}
	if len(want) == 0 {
		t.Fatal("no token operations")
	}
}

func TestWithBearerToken(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"11111111-1111-1111-1111-111111111111","kind":"team_publisher","name":"ci","prefix":"omppub_abcdefgh","scopes":["servers:read"],"status":"active","team":null,"createdAt":"2026-01-01T00:00:00Z","expiresAt":"2026-02-01T00:00:00Z"}}`))
	}))
	defer srv.Close()
	c, err := ompclient.NewClientWithResponses(srv.URL, ompclient.WithBearerToken("omppub_x"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.GetTokenWithResponse(context.Background())
	if err != nil || res.JSON200 == nil || res.JSON200.Data.Name != "ci" {
		t.Fatalf("%v %+v", err, res)
	}
	if auth != "Bearer omppub_x" {
		t.Fatalf("Authorization = %q", auth)
	}
}
