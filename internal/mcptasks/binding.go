package mcptasks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	PrincipalUser           = "user"
	PrincipalServiceAccount = "service_account"
	CredentialAPIKey        = "api_key"
	CredentialOAuthGrant    = "oauth"
	CredentialServiceKey    = "service_account"
	MaxArgumentsBytes       = 1 << 20
)

// Binding is a snapshot identity, NOT authorization. Each lifecycle operation
// must independently resolve the current principal/credential/offer/dependencies
// and no-rule policy, compare its binding, and recheck live deadlines/transport
// guards. Epoch and access-token value are deliberately not durable identities.
type Binding struct {
	PrincipalKind         string    `json:"principalKind"`
	PrincipalID           uuid.UUID `json:"principalId"`
	CredentialKind        string    `json:"credentialKind"`
	CredentialID          uuid.UUID `json:"credentialId"` // OAuth grant, not short-lived token
	GatewayID             uuid.UUID `json:"gatewayId"`
	ServerID              uuid.UUID `json:"serverId"`
	CapabilityID          uuid.UUID `json:"capabilityId"`
	ExposedName           string    `json:"exposedName"`
	ServerURL             string    `json:"serverUrl"` // full actual primary URL, not only origin
	ServerRevision        int64     `json:"serverRevision"`
	ToolClass             string    `json:"toolClass"` // empty is unclassified
	DefinitionFingerprint string    `json:"definitionFingerprint"`
	CurationDigest        string    `json:"curationDigest"`
	ArgumentsDigest       string    `json:"argumentsDigest"`
	DependencyDigest      string    `json:"dependencyDigest"`
}

func (b Binding) valid() bool {
	switch b.PrincipalKind {
	case PrincipalUser:
		if b.CredentialKind != CredentialAPIKey && b.CredentialKind != CredentialOAuthGrant {
			return false
		}
	case PrincipalServiceAccount:
		if b.CredentialKind != CredentialServiceKey {
			return false
		}
	default:
		return false
	}
	if b.PrincipalID == uuid.Nil || b.CredentialID == uuid.Nil || b.GatewayID == uuid.Nil || b.ServerID == uuid.Nil || b.CapabilityID == uuid.Nil || b.ServerRevision <= 0 {
		return false
	}
	if b.ExposedName == "" || len(b.ExposedName) > 512 || !utf8.ValidString(b.ExposedName) || strings.ContainsFunc(b.ExposedName, control) {
		return false
	}
	switch b.ToolClass {
	case "", "read", "write", "destructive":
	default:
		return false
	}
	if !taskDestination(b.ServerURL) {
		return false
	}
	return validDigest(b.DefinitionFingerprint) && validDigest(b.CurationDigest) && validDigest(b.ArgumentsDigest) && validDigest(b.DependencyDigest)
}

func control(r rune) bool { return r < 0x20 || r == 0x7f }

// This is a pure shape/binding check. Live SSRF policy and canonicalization
// belong to the existing registry/transport, never to a crypto helper.
func taskDestination(raw string) bool {
	if raw == "" || len(raw) > 500 || !utf8.ValidString(raw) || strings.TrimSpace(raw) != raw || strings.ContainsFunc(raw, control) {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.Opaque == "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.Contains(raw, "#")
}

func validDigest(raw string) bool {
	if len(raw) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(raw)
	return err == nil && hex.EncodeToString(decoded) == raw
}

// DigestBinding gives a deterministic identity for comparison/sealing. It
// carries no policy verdict: a digest cannot grant permission or extend expiry.
func DigestBinding(b Binding) (string, error) {
	if !b.valid() {
		return "", ErrUnavailable
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return "", ErrUnavailable
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// DigestArguments binds the exact validated effective argument object while
// ignoring insignificant whitespace. It does not re-merge curation or accept
// new arguments on a lifecycle request. Caller policy validation remains prior.
func DigestArguments(raw json.RawMessage) (string, error) {
	if len(raw) > MaxArgumentsBytes || !utf8.Valid(raw) {
		return "", ErrUnavailable
	}
	v := bytes.TrimSpace(raw)
	if len(v) == 0 || v[0] != '{' {
		return "", ErrUnavailable
	}
	var compact bytes.Buffer
	if json.Compact(&compact, v) != nil {
		return "", ErrUnavailable
	}
	sum := sha256.Sum256(compact.Bytes())
	return hex.EncodeToString(sum[:]), nil
}
