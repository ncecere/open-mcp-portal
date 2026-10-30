package ompcli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vectorFile struct {
	KeyPlaceholder string `json:"keyPlaceholder"`
	VSCodeInputID  string `json:"vscodeInputId"`
	Clients        []struct {
		ID       string `json:"id"`
		Label    string `json:"label"`
		Language string `json:"language"`
		File     string `json:"file"`
		OAuth    bool   `json:"oauth"`
	} `json:"clients"`
	Snippets []struct {
		Client string `json:"client"`
		Name   string `json:"name"`
		URL    string `json:"url"`
		Auth   string `json:"auth"`
		Secret string `json:"secret"`
		Want   string `json:"want"`
	} `json:"snippets"`
	ClientNames []struct {
		Input    string `json:"input"`
		Fallback string `json:"fallback"`
		Want     string `json:"want"`
	} `json:"clientNames"`
	AuthFor []struct {
		Client string `json:"client"`
		Auth   string `json:"auth"`
		Want   string `json:"want"`
	} `json:"authFor"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "connect-snippet-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// The same vectors are checked by web/src/test/gateway-helpers.test.ts against
// the TypeScript snippets: the two cannot drift without a test failing.
func TestSnippetsMatchTheSharedVectors(t *testing.T) {
	v := loadVectors(t)
	if v.KeyPlaceholder != KeyPlaceholder || v.VSCodeInputID != VSCodeInputID {
		t.Fatalf("constants differ: %q %q", v.KeyPlaceholder, v.VSCodeInputID)
	}
	if len(v.Clients) != len(SnippetClients) {
		t.Fatalf("clients: %d vs %d", len(v.Clients), len(SnippetClients))
	}
	for i, c := range v.Clients {
		g := SnippetClients[i]
		if c.ID != string(g.ID) || c.Label != g.Label || c.Language != g.Language || c.File != g.File || c.OAuth != g.OAuth {
			t.Errorf("client %d: %+v vs %+v", i, c, g)
		}
	}
	if len(v.Snippets) < 20 {
		t.Fatalf("only %d snippet vectors", len(v.Snippets))
	}
	for _, s := range v.Snippets {
		got, err := Snippet(SnippetClient(s.Client), SnippetInput{Name: s.Name, URL: s.URL, Secret: s.Secret, Auth: Auth(s.Auth)})
		if err != nil {
			t.Fatal(err)
		}
		if got != s.Want {
			t.Errorf("%s auth=%q secret=%q:\n got: %q\nwant: %q", s.Client, s.Auth, s.Secret, got, s.Want)
		}
	}
	for _, n := range v.ClientNames {
		if got := ClientName(n.Input, n.Fallback); got != n.Want {
			t.Errorf("ClientName(%q, %q) = %q, want %q", n.Input, n.Fallback, got, n.Want)
		}
	}
	for _, a := range v.AuthFor {
		if got := AuthFor(SnippetClient(a.Client), Auth(a.Auth)); string(got) != a.Want {
			t.Errorf("AuthFor(%s, %s) = %s, want %s", a.Client, a.Auth, got, a.Want)
		}
	}
}

// omp connect prints the vector's snippet for the gateway's endpoint.
func TestConnectPrintsTheSharedSnippets(t *testing.T) {
	v := loadVectors(t)
	h := newHarness(t)
	checked := 0
	for _, s := range v.Snippets {
		if s.Secret != "" || !strings.HasSuffix(s.URL, "/mcp/support-tools") || s.Name != "support-tools" {
			continue // the CLI never writes a key into a snippet
		}
		auth := s.Auth
		if auth == "" {
			auth = "oauth"
		}
		code, out, errOut := h.run("connect", s.URL, "--client", s.Client, "--auth", auth)
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", s.Client, code, errOut)
		}
		if strings.TrimSuffix(out, "\n") != s.Want {
			t.Errorf("%s/%s: output differs from the vector:\n%s\nwant:\n%s", s.Client, auth, out, s.Want)
		}
		checked++
	}
	if checked < 6 {
		t.Fatalf("only %d vectors exercised", checked)
	}
}
