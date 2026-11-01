package auth

import (
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func TestIdentityActorCapturesRequestEpochSnapshot(t *testing.T) {
	id := Identity{User: dbgen.User{ID: uuid.New(), PlatformRole: authz.PlatformNone, RequestEpoch: 17}}
	actor := id.Actor("epoch-admission", "127.0.0.1")
	id.User.RequestEpoch = 18
	if actor.UserID != id.User.ID || actor.RequestEpoch != 17 || actor.PlatformRole != authz.PlatformNone || actor.RequestID != "epoch-admission" || actor.ClientIP != "127.0.0.1" {
		t.Fatal("actor did not retain its original authenticated admission snapshot")
	}
	if fresh := id.Actor("new-admission", ""); fresh.RequestEpoch != 18 {
		t.Fatal("fresh actor did not capture current authenticated epoch")
	}
}
