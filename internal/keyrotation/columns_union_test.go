package keyrotation_test

import (
	"slices"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/keyrotation"
)

// Columns is the union of what every v0.3.2 feature seals: a person's own
// secret and the link that asks for one (decision 72), a machine OAuth client
// secret (decision 73) and an mTLS client key (decision 74), next to
// everything sealed before. The seeding test below inserts one row for each
// entry and counts exactly len(Columns) re-sealed values, so a feature missing
// here (or listed twice) fails there; this names them so that dropping one in
// a merge fails with its name.
func TestColumnsIncludeEveryFeaturesSealedValues(t *testing.T) {
	var have []string
	for _, c := range keyrotation.Columns {
		have = append(have, c.Name())
	}
	for _, want := range []string{
		"mcp_servers.auth_value_cipher", "mcp_server_credentials.value_cipher", "mcp_server_credentials.secondary_cipher", // static credentials (70)
		"mcp_server_endpoints.credentials_cipher",                   // independent extra-endpoint envelope (85)
		"person_secrets.secret_cipher", "secret_requests.id_cipher", // person secrets (72)
		"mcp_server_machine_oauth.client_secret_cipher", // machine OAuth (73)
		"mcp_server_tls.client_key_cipher",              // mTLS (74)
		"auth_providers.client_secret_cipher", "provider_connections.access_token_cipher", "mcp_call_payloads.result_cipher",
		"approval_requests.preview_cipher",                     // sensitive-call review preview (82)
		"omp_private.approval_binding_keys.binding_key_cipher", // stable approval HMAC root
	} {
		if !slices.Contains(have, want) {
			t.Errorf("keyrotation.Columns lacks %s", want)
		}
	}
	seen := map[string]bool{}
	for _, name := range have {
		if seen[name] {
			t.Errorf("%s is listed twice", name)
		}
		seen[name] = true
	}
}
