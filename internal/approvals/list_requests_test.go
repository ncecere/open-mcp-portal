package approvals

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/authz"
)

func TestQueueCursorValidation(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.New()
	raw := encodeQueueCursor("requested", at, id)
	c, err := parseQueueCursor(raw, "requested")
	if err != nil || c.ID != id || !c.CreatedAt.Equal(at) {
		t.Fatalf("round trip: %+v %v", c, err)
	}
	for _, bad := range []string{"!", strings.Repeat("x", 513), raw, base64.RawURLEncoding.EncodeToString([]byte(`{"view":"actionable","createdAt":"not-a-time","id":"` + id.String() + `"}`)), encodeQueueCursor("actionable", time.Time{}, id), encodeQueueCursor("actionable", at, uuid.Nil)} {
		if _, err := parseQueueCursor(bad, "actionable"); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestQueueInputBoundsAndBrowserActor(t *testing.T) {
	s := &Service{} // Rejections must happen before even acquiring a connection.
	a := authz.Actor{UserID: uuid.New()}
	for _, limit := range []int32{-1, 0, 201} {
		_, _, err := s.ListRequestsPage(context.Background(), a, "requested", "", limit)
		requireCode(t, err, "invalid_pagination")
	}
	for _, bad := range []authz.Actor{{}, {Kind: authz.KindAutomationToken, UserID: a.UserID}, {Kind: "service_account", UserID: a.UserID}} {
		_, _, err := s.ListRequestsPage(context.Background(), bad, "requested", "", 1)
		requireCode(t, err, "forbidden")
	}
	_, _, err := s.ListRequestsPage(context.Background(), a, "wrong", "", 1)
	requireCode(t, err, "invalid_view")
}
