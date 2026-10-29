// Package ompcli is the omp command line (cmd/omp): connect snippets, a view
// of the caller's automation token, server registration and publishing for CI,
// and declarative export and import. It talks to the portal only through
// pkg/ompclient, with an automation token (docs/cli.md, decision 89).
package ompcli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

// App is one run of the CLI. cmd/omp fills it from the process; tests fill it
// with fakes.
type App struct {
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Getenv  func(string) string
	HomeDir func() (string, error)
	Version string
	Commit  string

	// GOOS lets tests exercise the platform-specific file checks; empty is runtime.GOOS.
	GOOS string

	// httpClient replaces the default client in tests (an httptest TLS server's
	// client). Production code never sets it, so TLS verification is always on.
	httpClient *http.Client

	secrets  []string // values scrubbed from every line of output
	jsonMode bool
}

// NewApp is an App wired to the process.
func NewApp(version, commit string) *App {
	return &App{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		Getenv: os.Getenv, HomeDir: os.UserHomeDir,
		Version: version, Commit: commit,
	}
}

func (a *App) goos() string {
	if a.GOOS != "" {
		return a.GOOS
	}
	return runtime.GOOS
}

// addSecret registers a value that must never appear in output.
func (a *App) addSecret(v string) {
	if len(v) >= 6 {
		a.secrets = append(a.secrets, v)
	}
}

func (a *App) scrub(b []byte) []byte {
	for _, s := range a.secrets {
		if bytes.Contains(b, []byte(s)) {
			b = bytes.ReplaceAll(b, []byte(s), []byte("[redacted]"))
		}
	}
	return b
}

// write is the only way output leaves the program, so a secret that reached a
// message by accident is replaced on the way out.
func (a *App) write(w io.Writer, b []byte) {
	_, _ = w.Write(a.scrub(b))
}

func (a *App) outf(format string, args ...any) {
	a.write(a.Stdout, []byte(fmt.Sprintf(format, args...)))
}

func (a *App) errf(format string, args ...any) {
	a.write(a.Stderr, []byte(fmt.Sprintf(format, args...)))
}

// printJSON writes v as indented JSON to stdout.
func (a *App) printJSON(v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	a.write(a.Stdout, buf.Bytes())
	return nil
}

const usageText = `omp: the Open MCP Portal command line

Usage: omp [--json] [--portal URL] <command> [arguments]

Commands:
  whoami                           show the automation token in use (kind, scopes, team, expiry)
  connect <gateway> --client C     print the snippet that connects a client (claude, vscode, cursor, curl)
  servers list|get|register|test|refresh|publish|unpublish
                                   manage a team's MCP servers (team publisher token)
  export                           write the portal's configuration as an omp/v1 file
  import -f FILE [--plan]          apply an omp/v1 file; --plan only shows the changes
  configure                        store the portal URL and token in the config file (mode 0600)
  version                          print the version

Global flags:
  --json            print JSON (errors too, on stderr)
  --portal URL      the portal's URL (default: OMP_URL, then the config file)
  --timeout 60s     time limit for the whole command

Configuration: OMP_URL and OMP_TOKEN, or ~/.config/omp/config.yaml (mode 0600).
Exit codes: 0 ok, 1 internal error, 2 usage, 3 configuration, 4 authentication, 5 forbidden,
6 not found, 7 conflict, 8 rejected, 9 unavailable, 10 changes found, 11 check failed.
Run "omp <command> --help" for a command's flags. Full reference: docs/cli.md
`

// Run executes one command line and returns the process exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	for _, arg := range args {
		if arg == "--json" || arg == "-json" || arg == "--json=true" || arg == "-json=true" {
			a.jsonMode = true
		}
	}
	err := a.run(ctx, args)
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, errHelp) {
		return ExitOK
	}
	e := asError(err)
	a.printError(e)
	return e.Exit
}

func (a *App) printError(e *Error) {
	if a.jsonMode {
		obj := map[string]any{"code": e.Code, "message": e.Message, "exitCode": e.Exit}
		if e.Status != 0 {
			obj["status"] = e.Status
		}
		if len(e.Details) > 0 {
			obj["details"] = e.Details
		}
		b, _ := json.MarshalIndent(map[string]any{"error": obj}, "", "  ")
		a.write(a.Stderr, append(b, '\n'))
		return
	}
	a.errf("omp: error: %s: %s\n", e.Code, e.Message)
	if e.Status != 0 {
		if field, ok := e.Details["field"].(string); ok {
			a.errf("  field: %s\n", field)
		}
		if req, ok := e.Details["requiredScopes"]; ok {
			a.errf("  required scopes: %s (token has: %s)\n", joinAny(req), joinAny(e.Details["tokenScopes"]))
		}
	}
}

func joinAny(v any) string {
	list, ok := v.([]any)
	if !ok {
		return fmt.Sprint(v)
	}
	parts := make([]string, 0, len(list))
	for _, x := range list {
		parts = append(parts, fmt.Sprint(x))
	}
	return strings.Join(parts, ", ")
}

func (a *App) run(ctx context.Context, args []string) error {
	cmd, rest := splitGlobals(args)
	if cmd == "" {
		for _, r := range rest {
			if r == "-h" || r == "--help" || r == "-help" {
				a.outf("%s", usageText)
				return nil
			}
		}
		if len(rest) == 0 {
			a.errf("%s", usageText)
			return usageErr("no command given")
		}
		return usageErr("no command given")
	}
	switch cmd {
	case "help":
		a.outf("%s", usageText)
		return nil
	case "version":
		return a.cmdVersion(rest)
	case "whoami":
		return a.cmdWhoami(ctx, rest)
	case "connect":
		return a.cmdConnect(ctx, rest)
	case "servers":
		return a.cmdServers(ctx, rest)
	case "export":
		return a.cmdExport(ctx, rest)
	case "import":
		return a.cmdImport(ctx, rest)
	case "configure":
		return a.cmdConfigure(ctx, rest)
	case "keys":
		return usageErr("omp has no keys command: it authenticates with an automation token only. Create API keys in the browser (Account > API keys); see docs/cli.md")
	}
	return usageErr("unknown command %q (run omp help)", cmd)
}

// api is an authenticated client for the configured portal.
type api struct {
	*ompclient.ClientWithResponses
	cfg *Config
}

// newAPI loads the configuration and builds the client. Redirects are never
// followed (a redirect could carry the token to another host), TLS
// verification is always on, and nothing here can turn either off.
func (a *App) newAPI(g *global) (*api, error) {
	cfg, err := a.loadConfig(g, true)
	if err != nil {
		return nil, err
	}
	hc := a.httpClient
	if hc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		hc = &http.Client{Transport: tr}
	} else {
		c := *hc
		hc = &c
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ua := "omp/" + a.Version
	cl, err := ompclient.NewClientWithResponses(cfg.URL,
		ompclient.WithHTTPClient(hc),
		ompclient.WithBearerToken(cfg.Token),
		ompclient.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
			r.Header.Set("User-Agent", ua)
			return nil
		}))
	if err != nil {
		return nil, configErr("cannot build the client: %v", err)
	}
	return &api{ClientWithResponses: cl, cfg: cfg}, nil
}

func (a *App) cmdVersion(args []string) error {
	g := &global{}
	fs := newFlagSet("version", g)
	pos, err := a.parseFlags(fs, args, "omp version")
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return usageErr("usage: omp version")
	}
	if g.json {
		return a.printJSON(map[string]string{"version": a.Version, "commit": a.Commit})
	}
	a.outf("omp %s (%s)\n", a.Version, a.Commit)
	return nil
}

// parseFlags parses a command's flags and positional arguments. --help prints
// the usage line and the flags and returns errHelp.
func (a *App) parseFlags(fs *flag.FlagSet, args []string, usage string) ([]string, error) {
	pos, err := parseArgs(fs, args)
	if errors.Is(err, errHelp) {
		var buf bytes.Buffer
		fs.SetOutput(&buf)
		fs.PrintDefaults()
		a.outf("usage: %s\n\nflags:\n%s", usage, buf.String())
		return nil, errHelp
	}
	return pos, err
}

// timeout bounds a command by its --timeout.
func (a *App) timeout(ctx context.Context, g *global) (context.Context, context.CancelFunc) {
	if g.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, g.timeout)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
