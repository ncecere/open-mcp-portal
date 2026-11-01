// Package credentials classifies a bearer credential by its shape, before
// any lookup (docs/automation-tokens.md, "Authentication"). One classifier is
// shared by /v1 (which takes browser sessions and automation tokens, and
// refuses MCP credentials) and /mcp (which takes MCP credentials and never
// an automation token), so the two sides can't drift apart.
package credentials

import "strings"

// Kind is what a credential looks like.
type Kind int

const (
	// Unknown is anything that is not one of ours.
	Unknown Kind = iota
	// PlatformToken: ompadm_ and 43 characters (platform-admin token).
	PlatformToken
	// PublisherToken: omppub_ and 43 characters (team publisher token).
	PublisherToken
	// MCPCredential: a personal key (omp_), a service account key (omp_sa_),
	// an OAuth access token (ompat_) or a refresh token or authorization code
	// (omprt_, ompac_): accepted by /mcp only.
	MCPCredential
	// SCIMToken: ompscim_ and 43 characters (directory provisioning token,
	// decision 92): accepted by /scim/v2 only, never /v1 or /mcp.
	SCIMToken
)

// Prefixes.
const (
	PlatformPrefix  = "ompadm_"
	PublisherPrefix = "omppub_"
	SCIMPrefix      = "ompscim_"
	// TokenBodyLen is the length of the random part of an automation token.
	TokenBodyLen = 43
	// StoredPrefixLen is how much of a token is stored in the clear to
	// recognise it: the prefix and 8 characters.
	StoredPrefixLen = len(PlatformPrefix) + 8
)

// mcpPrefixes are the MCP credentials' prefixes (decision 46).
var mcpPrefixes = []string{"omp_sa_", "omp_", "ompat_", "omprt_", "ompac_"}

// Classify reports what s looks like. It never looks anything up.
func Classify(s string) Kind {
	for _, t := range []struct {
		prefix string
		kind   Kind
	}{{PlatformPrefix, PlatformToken}, {PublisherPrefix, PublisherToken}, {SCIMPrefix, SCIMToken}} {
		if strings.HasPrefix(s, t.prefix) {
			if len(s) == len(t.prefix)+TokenBodyLen && urlSafe(s[len(t.prefix):]) {
				return t.kind
			}
			return Unknown
		}
	}
	for _, p := range mcpPrefixes {
		if strings.HasPrefix(s, p) {
			return MCPCredential
		}
	}
	return Unknown
}

// IsAutomationToken reports whether k is one of the two token kinds.
func (k Kind) IsAutomationToken() bool { return k == PlatformToken || k == PublisherToken }

func urlSafe(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
