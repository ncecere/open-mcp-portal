package limits

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func TestServerEffectiveAndAttemptAccounting(t *testing.T) {
	s := New(nil, nil)
	settings := decodeSettings(dbgen.LimitSetting{Items: []byte(`{"server_per_minute":{"default":2,"ceiling":5}}`)})
	s.set(settings)
	for name, tc := range map[string]struct {
		own  *int64
		team Overrides
		want *int64
	}{
		"default": {nil, nil, n(2)}, "team": {nil, Overrides{ServerPerMinute: 3}, n(3)},
		"own": {n(4), Overrides{ServerPerMinute: 3}, n(4)}, "cap existing value": {n(7), nil, n(5)},
	} {
		if got := settings.ServerEffective(tc.own, tc.team); !eq(got, tc.want) {
			t.Errorf("%s: got %v want %v", name, got, tc.want)
		}
	}
	at := time.Unix(1_800_000_000, 0).Truncate(time.Minute).Add(10 * time.Second)
	store := ratelimit.NewWithClock(func() time.Time { return at })
	team := dbgen.Team{ID: uuid.New(), LimitOverrides: []byte(`{"server_per_minute":3}`)}
	sv := dbgen.McpServer{ID: uuid.New(), TeamID: team.ID}
	for i := 0; i < 4; i++ {
		d, err := s.CheckServer(context.Background(), store, sv, team)
		if err != nil || d.Own != nil {
			t.Fatalf("server exposed caller usage or failed: %+v %v", d, err)
		}
		if i < 3 && d.Exceeded != "" {
			t.Fatal("early quota refusal")
		}
		if i == 3 && (d.Exceeded != ServerPerMinute || d.LimitPerMinute != 3 || d.Reset != 50*time.Second) {
			t.Fatalf("last attempt: %+v", d)
		}
	}
	sv.ID = uuid.New()
	if d, err := s.CheckServer(context.Background(), store, sv, team); err != nil || d.Exceeded != "" {
		t.Fatalf("other server shared counter: %+v %v", d, err)
	}
	team.ID = uuid.New()
	if _, err := s.CheckServer(context.Background(), store, sv, team); err == nil {
		t.Fatal("wrong owning team accepted")
	}
}
