package ompcli

import (
	"bufio"
	"context"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ---- whoami ------------------------------------------------------------------

func (a *App) cmdWhoami(ctx context.Context, args []string) error {
	g := &global{}
	fs := newFlagSet("whoami", g)
	pos, err := a.parseFlags(fs, args, "omp whoami [--json]")
	if err != nil {
		return err
	}
	if err := needArgs(pos, 0, "omp whoami [--json]"); err != nil {
		return err
	}
	ctx, cancel := a.timeout(ctx, g)
	defer cancel()
	c, err := a.newAPI(g)
	if err != nil {
		return err
	}
	res, err := check(c.GetTokenWithResponse(ctx))
	if err != nil {
		return err
	}
	t := res.JSON200.Data
	if g.json {
		return a.printJSON(map[string]any{"url": c.cfg.URL, "token": t})
	}
	a.outf("Portal:   %s\n", c.cfg.URL)
	a.outf("Token:    %s (%s, %s)\n", t.Name, t.Kind, t.Prefix)
	if t.Team != nil {
		a.outf("Team:     %s\n", t.Team.Slug)
	}
	scopes := make([]string, len(t.Scopes))
	for i, s := range t.Scopes {
		scopes[i] = string(s)
	}
	a.outf("Scopes:   %s\n", strings.Join(scopes, " "))
	a.outf("Status:   %s\n", t.Status)
	a.outf("Expires:  %s\n", t.ExpiresAt.UTC().Format(time.RFC3339))
	return nil
}

// tokenTeam is the slug of the publisher token's team ("" for a platform token).
func tokenTeam(ctx context.Context, c *api) (string, error) {
	res, err := check(c.GetTokenWithResponse(ctx))
	if err != nil {
		return "", err
	}
	if t := res.JSON200.Data.Team; t != nil {
		return t.Slug, nil
	}
	return "", nil
}

// ---- configure ---------------------------------------------------------------

func (a *App) cmdConfigure(ctx context.Context, args []string) error {
	_ = ctx
	g := &global{}
	fs := newFlagSet("configure", g)
	tokenStdin := fs.Bool("token-stdin", false, "read the token from the first line of standard input")
	tokenEnv := fs.String("token-env", "", "read the token from this environment variable")
	usage := "omp configure --portal URL [--token-stdin | --token-env NAME]"
	pos, err := a.parseFlags(fs, args, usage)
	if err != nil {
		return err
	}
	if err := needArgs(pos, 0, usage); err != nil {
		return err
	}
	if *tokenStdin && *tokenEnv != "" {
		return usageErr("use either --token-stdin or --token-env, not both")
	}
	path, err := a.configPath()
	if err != nil {
		return err
	}
	fc, _, err := a.readConfigFile(path)
	if err != nil {
		return err
	}
	if g.url != "" {
		u, err := ValidateURL(g.url)
		if err != nil {
			return err
		}
		fc.URL = u
	}
	var token string
	switch {
	case *tokenStdin:
		line, _ := bufio.NewReader(a.Stdin).ReadString('\n')
		token = strings.TrimSpace(line)
	case *tokenEnv != "":
		token = strings.TrimSpace(a.Getenv(*tokenEnv))
		if token == "" {
			return usageErr("the environment variable %s is empty or not set", *tokenEnv)
		}
	}
	if token != "" {
		a.addSecret(token)
		if err := ValidateToken(token); err != nil {
			return err
		}
		fc.Token = token
	} else if *tokenStdin {
		return usageErr("no token on standard input")
	}
	if fc.URL == "" && fc.Token == "" {
		return usageErr("usage: %s", usage)
	}
	if err := writeConfigFile(path, fc); err != nil {
		return &Error{Exit: ExitFailure, Code: "config_write", Message: err.Error()}
	}
	if g.json {
		return a.printJSON(map[string]any{"path": path, "url": fc.URL, "tokenStored": fc.Token != ""})
	}
	a.outf("wrote %s (mode 0600)\n", path)
	return nil
}

// ---- connect -----------------------------------------------------------------

var gatewaySlug = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func (a *App) cmdConnect(ctx context.Context, args []string) error {
	_ = ctx
	g := &global{}
	fs := newFlagSet("connect", g)
	client := fs.String("client", "", "claude, vscode, cursor or curl")
	authFlag := fs.String("auth", "oauth", "oauth (sign in with the browser) or key (API-key variant, with a placeholder)")
	nameFlag := fs.String("name", "", "the name the client shows (default: the gateway's slug)")
	usage := "omp connect <gateway-slug-or-url> --client claude|vscode|cursor|curl [--auth oauth|key] [--name NAME]"
	pos, err := a.parseFlags(fs, args, usage)
	if err != nil {
		return err
	}
	if err := needArgs(pos, 1, usage); err != nil {
		return err
	}
	info, ok := ClientByID(*client)
	if !ok {
		return usageErr("--client must be one of claude, vscode, cursor, curl (got %q)", *client)
	}
	if *authFlag != "oauth" && *authFlag != "key" {
		return usageErr("--auth must be oauth or key (got %q)", *authFlag)
	}
	gwURL, slug, err := a.gatewayEndpoint(g, pos[0])
	if err != nil {
		return err
	}
	name := ClientName(*nameFlag, ClientName(slug, "omp"))
	auth := AuthFor(info.ID, Auth(*authFlag))
	text, err := Snippet(info.ID, SnippetInput{Name: name, URL: gwURL, Auth: Auth(*authFlag)})
	if err != nil {
		return err
	}
	if g.json {
		out := map[string]any{"client": string(info.ID), "label": info.Label, "auth": string(auth), "name": name, "url": gwURL, "language": info.Language, "snippet": text}
		if info.File != "" {
			out["file"] = info.File
		}
		return a.printJSON(out)
	}
	a.outf("%s\n", text)
	if auth == AuthKey {
		a.errf("note: replace %s with an API key from Account > API keys (automation tokens do not work on /mcp)\n", KeyPlaceholder)
	}
	return nil
}

// gatewayEndpoint resolves the argument to the gateway's MCP endpoint and slug:
// a full https://portal/mcp/<slug> URL, or a slug on the configured portal.
// No network and no token are involved.
func (a *App) gatewayEndpoint(g *global, arg string) (endpoint, slug string, err error) {
	if strings.Contains(arg, "://") {
		clean, err := ValidateURL(arg)
		if err != nil {
			return "", "", err
		}
		u, _ := url.Parse(clean)
		idx := strings.LastIndex(u.Path, "/mcp/")
		if idx < 0 || !gatewaySlug.MatchString(u.Path[idx+len("/mcp/"):]) {
			return "", "", usageErr("a gateway URL looks like https://portal.example.com/mcp/<slug>")
		}
		return clean, u.Path[idx+len("/mcp/"):], nil
	}
	if !gatewaySlug.MatchString(arg) {
		return "", "", usageErr("%q is not a gateway slug", arg)
	}
	cfg, err := a.loadConfig(g, false)
	if err != nil {
		return "", "", err
	}
	return cfg.URL + "/mcp/" + arg, arg, nil
}
