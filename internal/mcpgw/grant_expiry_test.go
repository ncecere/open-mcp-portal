package mcpgw

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

func TestGrantExpiryGuardRefusesEveryExchangeKind(t *testing.T) {
	for _, tool := range []bool{false, true} {
		t.Run(map[bool]string{false: "protocol_prompt_or_resource", true: "actual_tool"}[tool], func(t *testing.T) {
			past := time.Now().Add(-time.Hour)
			rc := &request{caller: gateways.Caller{ExpiresAt: &past}}
			calls := 0
			target := upstream.Target{BeforeTransport: func(context.Context, bool) error { calls++; return nil }}
			rc.guardGrantExpiry(&target)
			if err := target.BeforeTransport(context.Background(), tool); !errors.Is(err, errGrantExpired) {
				t.Fatalf("guard = %v", err)
			}
			if calls != 0 {
				t.Fatal("expired authority reached later transport work")
			}
		})
	}
}

func TestGrantExpiryGuardPreservesPriorAndFreezesSnapshot(t *testing.T) {
	future := time.Now().Add(time.Hour)
	want := errors.New("prior refusal")
	check := func(context.Context, time.Time) (bool, error) { return true, nil }
	guard := grantExpiryGuard(future, time.Now, check, func(context.Context, bool) error { return want })
	if err := guard(context.Background(), false); !errors.Is(err, want) {
		t.Fatalf("lost prior refusal: %v", err)
	}
	past := time.Now().Add(-time.Hour)
	rc := &request{caller: gateways.Caller{ExpiresAt: &past}}
	target := upstream.Target{}
	rc.guardGrantExpiry(&target)
	rc.caller.ExpiresAt = &future
	if err := target.BeforeTransport(context.Background(), true); !errors.Is(err, errGrantExpired) {
		t.Fatalf("expired snapshot widened: %v", err)
	}
}

func TestGrantExpiryGuardDatabaseClockAndPostCommitCheck(t *testing.T) {
	base := time.Now()
	deadline := base.Add(time.Hour)
	for _, mode := range []string{"database_ahead", "database_error", "unavailable_clock", "expires_during_commit"} {
		t.Run(mode, func(t *testing.T) {
			checks, priorCalls := 0, 0
			var check grantClockCheck = func(context.Context, time.Time) (bool, error) {
				checks++
				if mode == "database_error" {
					return false, errors.New("database unavailable")
				}
				return mode == "expires_during_commit" && checks == 1, nil
			}
			if mode == "unavailable_clock" {
				check = nil
			}
			// Local time remains before the deadline in every case. SQL time,
			// including the post-commit recheck, must still refuse dispatch.
			guard := grantExpiryGuard(deadline, func() time.Time { return base }, check, func(context.Context, bool) error { priorCalls++; return nil })
			if err := guard(context.Background(), true); !errors.Is(err, errGrantExpired) {
				t.Fatalf("deadline/error fell back to local time: %v", err)
			}
			if mode == "expires_during_commit" {
				if checks != 2 || priorCalls != 1 {
					t.Fatalf("post-commit check missing: clock=%d commit=%d", checks, priorCalls)
				}
			} else if priorCalls != 0 {
				t.Fatal("invalid pre-commit deadline reached consumption")
			}
		})
	}
}

func TestApprovalInputUsesEarlierGrantAndCredentialDeadline(t *testing.T) {
	early, late := time.Now().Add(time.Minute), time.Now().Add(time.Hour)
	for _, tt := range []struct {
		credential, grant *time.Time
		want              time.Time
	}{
		{&early, &late, early}, {&late, &early, early}, {nil, &early, early}, {&late, nil, late},
	} {
		rc := &request{principal: principal{expiresAt: tt.credential}, caller: gateways.Caller{ExpiresAt: tt.grant}}
		in := rc.approvalInput(gateways.Offer{}, nil, nil)
		if !in.CredentialExpiresAt.Equal(tt.want) {
			t.Fatalf("deadline=%v want %v", in.CredentialExpiresAt, tt.want)
		}
	}
}
