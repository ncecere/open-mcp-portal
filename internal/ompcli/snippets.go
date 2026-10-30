package ompcli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// The connect snippets are a port of web/src/components/gateways/connect-snippets.ts.
// Both are tested against the same vectors (api/connect-snippet-vectors.json),
// so a change to one without the other fails a test in each suite.

// KeyPlaceholder is what the snippets show instead of a key.
const KeyPlaceholder = "<YOUR_API_KEY>"

// VSCodeInputID is the VS Code input that prompts for the key.
const VSCodeInputID = "omp-key"

// SnippetClient is an MCP client a snippet is written for.
type SnippetClient string

// The clients, in the order the web UI lists them.
const (
	ClientClaude SnippetClient = "claude"
	ClientVSCode SnippetClient = "vscode"
	ClientCursor SnippetClient = "cursor"
	ClientCurl   SnippetClient = "curl"
)

// Auth is how the client proves who it is: OAuth sign-in in the browser, or
// an API key in a header.
type Auth string

// The two ways to authenticate.
const (
	AuthOAuth Auth = "oauth"
	AuthKey   Auth = "key"
)

// ClientInfo describes a client for output.
type ClientInfo struct {
	ID       SnippetClient
	Label    string
	Language string
	File     string // where the snippet goes, when it is a file
	OAuth    bool   // the client can sign in with OAuth
}

// SnippetClients lists the clients like the web UI's snippetClients.
var SnippetClients = []ClientInfo{
	{ClientClaude, "Claude Code", "bash", "", true},
	{ClientVSCode, "VS Code", "json", ".vscode/mcp.json", true},
	{ClientCursor, "Cursor", "json", "~/.cursor/mcp.json", true},
	{ClientCurl, "curl", "bash", "", false},
}

// ClientByID finds a client.
func ClientByID(id string) (ClientInfo, bool) {
	for _, c := range SnippetClients {
		if string(c.ID) == id {
			return c, true
		}
	}
	return ClientInfo{}, false
}

// AuthFor is the way a client connects: OAuth unless a key was chosen, or the
// client cannot sign in (curl).
func AuthFor(client SnippetClient, auth Auth) Auth {
	if c, ok := ClientByID(string(client)); ok && c.OAuth {
		return auth
	}
	return AuthKey
}

var (
	unsafeName = regexp.MustCompile(`[^A-Za-z0-9_-]+`)
	edgeDashes = regexp.MustCompile(`^-+|-+$`)
)

// ClientName is a name clients accept: letters, digits, hyphens and
// underscores ("Support tools!" becomes "Support-tools").
func ClientName(name, fallback string) string {
	clean := unsafeName.ReplaceAllString(strings.TrimSpace(name), "-")
	clean = edgeDashes.ReplaceAllString(clean, "")
	if len(clean) > 64 {
		clean = clean[:64]
	}
	if clean == "" {
		return fallback
	}
	return clean
}

// SnippetInput is what a snippet is made from. Secret is a key to write into
// the snippet; empty means the placeholder. The CLI never sets it.
type SnippetInput struct {
	Name   string
	URL    string
	Secret string
	Auth   Auth // empty means OAuth
}

// Snippet is one client's snippet (OAuth by default; AuthKey for the API-key
// variant). The output has no trailing newline, like the web's.
func Snippet(client SnippetClient, in SnippetInput) (string, error) {
	key := in.Secret
	if key == "" {
		key = KeyPlaceholder
	}
	auth := in.Auth
	if auth == "" {
		auth = AuthOAuth
	}
	withKey := AuthFor(client, auth) == AuthKey
	switch client {
	case ClientClaude:
		if withKey {
			return fmt.Sprintf(`claude mcp add --transport http %s %s --header "Authorization: Bearer %s"`, in.Name, in.URL, key), nil
		}
		return fmt.Sprintf("claude mcp add --transport http %s %s", in.Name, in.URL), nil
	case ClientVSCode:
		type server struct {
			Type    string            `json:"type"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers,omitempty"`
		}
		if !withKey {
			return stringify(struct {
				Servers map[string]server `json:"servers"`
			}{map[string]server{in.Name: {Type: "http", URL: in.URL}}})
		}
		// VS Code asks for the key once and keeps it in its secret storage:
		// never written into the file.
		type input struct {
			Type        string `json:"type"`
			ID          string `json:"id"`
			Description string `json:"description"`
			Password    bool   `json:"password"`
		}
		return stringify(struct {
			Inputs  []input           `json:"inputs"`
			Servers map[string]server `json:"servers"`
		}{
			[]input{{"promptString", VSCodeInputID, "Open MCP Portal API key", true}},
			map[string]server{in.Name: {Type: "http", URL: in.URL, Headers: map[string]string{"Authorization": "Bearer ${input:" + VSCodeInputID + "}"}}},
		})
	case ClientCursor:
		type server struct {
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers,omitempty"`
		}
		s := server{URL: in.URL}
		if withKey {
			s.Headers = map[string]string{"Authorization": "Bearer " + key}
		}
		return stringify(struct {
			McpServers map[string]server `json:"mcpServers"`
		}{map[string]server{in.Name: s}})
	case ClientCurl:
		return strings.Join([]string{
			fmt.Sprintf("curl -X POST %s \\", in.URL),
			fmt.Sprintf(`  -H "Authorization: Bearer %s" \`, key),
			`  -H "Content-Type: application/json" \`,
			`  -H "Accept: application/json, text/event-stream" \`,
			`  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`,
		}, "\n"), nil
	}
	return "", fmt.Errorf("unknown client %q", client)
}

// stringify is JSON.stringify(v, null, 2): two-space indent, no HTML escaping.
func stringify(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}
