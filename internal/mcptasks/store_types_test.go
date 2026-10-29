package mcptasks

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestTaskCapacityKeyScopesPrincipalNotCredentialOrGateway(t *testing.T) {
	r := Root{PrincipalKind: PrincipalUser, PrincipalID: uuid.MustParse("b9bfa561-e632-4ddd-a302-08e8807c3752"),
		CredentialKind: CredentialAPIKey, CredentialID: uuid.New(), GatewayID: uuid.New()}
	key := capacityKey(r)
	other := r
	other.CredentialID, other.GatewayID = uuid.New(), uuid.New()
	other.CredentialKind = CredentialOAuthGrant
	if capacityKey(other) != key {
		t.Fatal("credential/gateway variation split principal capacity")
	}
	other.PrincipalKind, other.CredentialKind = PrincipalServiceAccount, CredentialServiceKey
	if capacityKey(other) == key {
		t.Fatal("principal kind omitted from capacity namespace")
	}
	other = r
	other.PrincipalID = uuid.MustParse("f7597c5d-aa93-442f-a3fc-17a46e3dd820")
	if capacityKey(other) == key {
		t.Fatal("principal ID omitted from capacity namespace")
	}
}

func TestTaskStoreErrorsDoNotEchoWrappedPrivateDetail(t *testing.T) {
	for _, base := range []error{context.Canceled, context.DeadlineExceeded} {
		err := storeError(fmt.Errorf("private SQL/server/credential sentinel: %w", base))
		if err != base {
			t.Fatal("context error retained private wrapper detail")
		}
	}
	if storeError(errors.New("private upstream ID")) != ErrUnavailable {
		t.Fatal("unclassified store error was not generic")
	}
}
