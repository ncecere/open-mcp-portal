package scim

import (
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/apikeys"
	"github.com/ncecere/open-mcp-portal/internal/credentials"
)

// Provisioning tokens use the same digest and pepper ID as the other
// credentials, so API_KEY_PEPPER rotation treats them alike.
func TestDigestMatchesSharedCredentialConstruction(t *testing.T) {
	pepper := []byte("owned-test-pepper-0123456789abcdef")
	secret := credentials.SCIMPrefix + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	if Digest(pepper, secret) != apikeys.Digest(pepper, secret) {
		t.Fatal("provisioning digest diverged from the shared construction")
	}
	if string(pepperID(pepper)) != string(apikeys.PepperID(pepper)) {
		t.Fatal("pepper ID diverged")
	}
	if credentials.Classify(secret) != credentials.SCIMToken || credentials.Classify(secret).IsAutomationToken() {
		t.Fatal("classification")
	}
	if credentials.Classify(secret[:20]) == credentials.SCIMToken {
		t.Fatal("a truncated token classified as a provisioning token")
	}
}
