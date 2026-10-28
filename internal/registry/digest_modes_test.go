package registry

import (
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// One review digest covers every mode's settings and the TLS settings together
// (decisions 72, 73 and 74; omp-review-v4): each piece moves the digest, none of
// them is mistaken for another, and a server in one mode never has another
// mode's settings in its digest.
func TestReviewDigestCoversEveryModeAndTLSTogether(t *testing.T) {
	caps := []CapabilityRef{{Kind: "tool", Name: "a", Fingerprint: "f1"}}
	ca, cert, other := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	machine := &MachineOAuthView{TokenURL: "https://idp.example/token", ClientID: "client", TokenAuthMethod: MachineAuthBasic, Scopes: []string{"read"}}
	person := func(placement, name string) dbgen.McpServer {
		sv := dbgen.McpServer{URL: "https://a.example/mcp", AuthMode: AuthPersonSecret, SecretPlacement: &placement}
		if name != "" {
			sv.SecretName = &name
		}
		return sv
	}
	machineSV := dbgen.McpServer{URL: "https://a.example/mcp", AuthMode: AuthMachineOAuth}
	staticSV := dbgen.McpServer{URL: "https://a.example/mcp", AuthMode: AuthStaticHeader}
	noneSV := dbgen.McpServer{URL: "https://a.example/mcp", AuthMode: AuthNone}
	noTLS, withCA, withBoth := tlsDigest{}, tlsDigest{CASHA: ca}, tlsDigest{CASHA: ca, ClientSHA: cert}

	digests := map[string]string{
		"none":                     reviewDigest(noneSV, caps, nil, noTLS, nil),
		"none + CA":                reviewDigest(noneSV, caps, nil, withCA, nil),
		"none + CA and client":     reviewDigest(noneSV, caps, nil, withBoth, nil),
		"none + another CA":        reviewDigest(noneSV, caps, nil, tlsDigest{CASHA: other, ClientSHA: cert}, nil),
		"static":                   reviewDigest(staticSV, caps, nil, noTLS, nil),
		"static + CA":              reviewDigest(staticSV, caps, nil, withCA, nil),
		"person header":            reviewDigest(person("header", "X-K"), caps, nil, noTLS, nil),
		"person header + CA":       reviewDigest(person("header", "X-K"), caps, nil, withCA, nil),
		"person query":             reviewDigest(person("query", "k"), caps, nil, noTLS, nil),
		"person query + CA":        reviewDigest(person("query", "k"), caps, nil, withCA, nil),
		"machine":                  reviewDigest(machineSV, caps, machine, noTLS, nil),
		"machine + CA":             reviewDigest(machineSV, caps, machine, withCA, nil),
		"machine + CA and client":  reviewDigest(machineSV, caps, machine, withBoth, nil),
		"machine without a client": reviewDigest(machineSV, caps, nil, noTLS, nil),
	}
	seen := map[string]string{}
	for name, d := range digests {
		if prev, dup := seen[d]; dup {
			t.Errorf("%s and %s have the same digest", name, prev)
		}
		seen[d] = name
	}
	// The public entry points are the combined digest with nothing else set.
	if ReviewDigest(noneSV, caps) != digests["none"] || ReviewDigestMachine(machineSV, caps, machine) != digests["machine"] {
		t.Error("ReviewDigest and ReviewDigestMachine disagree with the combined digest")
	}
	// One mode's settings never reach another mode's digest.
	if reviewDigest(noneSV, caps, machine, noTLS, nil) != digests["none"] {
		t.Error("a machine client is in the digest of a server in none mode")
	}
	if reviewDigest(staticSV, caps, machine, withCA, nil) != digests["static + CA"] {
		t.Error("a machine client is in the digest of a static server")
	}
	stray := person("header", "X-K")
	stray.AuthMode = AuthMachineOAuth
	if reviewDigest(stray, caps, machine, noTLS, nil) != reviewDigest(machineSV, caps, machine, noTLS, nil) {
		t.Error("a person secret placement is in the digest of a machine server")
	}
	// A secret never is: the machine view's hint is not part of it.
	hinted := *machine
	hinted.SecretHint = "9999"
	if reviewDigest(machineSV, caps, &hinted, noTLS, nil) != digests["machine"] {
		t.Error("the machine secret's hint is in the digest")
	}
	if digestVersion != "omp-review-v4" {
		t.Errorf("digest version %s: one version covers the settings of all three features", digestVersion)
	}
}
