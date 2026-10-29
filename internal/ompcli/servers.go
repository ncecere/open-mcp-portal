package ompcli

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

// dataOf returns the "data" of a decoded 2xx response, or an error when the
// portal answered 2xx without the JSON the contract promises.
func dataOf[T any](p *struct {
	Data T `json:"data"`
}) (T, error) {
	if p == nil {
		var zero T
		return zero, &Error{Exit: ExitFailure, Code: "bad_response", Message: "the portal's reply was not the expected JSON"}
	}
	return p.Data, nil
}

const serversUsage = `omp servers <list|get|register|test|refresh|publish|unpublish> [flags]

  list                       the team's servers
  get <slug>                 one server
  register --slug S --url U  register a server and read its capabilities
  test <slug>                connect and list capabilities without saving them
  refresh <slug>             read the capabilities again
  publish <slug>             request publication to the catalog (publishes at once under self_publish)
  unpublish <slug>           withdraw a request or remove it from the catalog

Every subcommand takes --team SLUG (default: the team of a publisher token), --json and --portal.
`

func (a *App) cmdServers(ctx context.Context, args []string) error {
	sub, rest := splitGlobals(args)
	if sub == "" {
		for _, r := range rest {
			if r == "-h" || r == "--help" {
				a.outf("%s", serversUsage)
				return nil
			}
		}
		return usageErr("usage: %s", strings.SplitN(serversUsage, "\n", 2)[0])
	}
	switch sub {
	case "list":
		return a.cmdServersList(ctx, rest)
	case "get":
		return a.cmdServersGet(ctx, rest)
	case "register":
		return a.cmdServersRegister(ctx, rest)
	case "test":
		return a.cmdServersTest(ctx, rest)
	case "refresh":
		return a.cmdServersRefresh(ctx, rest)
	case "publish":
		return a.cmdServersPublish(ctx, rest, true)
	case "unpublish":
		return a.cmdServersPublish(ctx, rest, false)
	}
	return usageErr("unknown servers subcommand %q (list, get, register, test, refresh, publish, unpublish)", sub)
}

// serverCmd is the setup every servers subcommand shares.
type serverCmd struct {
	g    *global
	fs   *flag.FlagSet
	team *string
}

func newServerCmd(name string) *serverCmd {
	g := &global{}
	fs := newFlagSet(name, g)
	return &serverCmd{g: g, fs: fs, team: fs.String("team", "", "team slug (default: the team of the publisher token)")}
}

// open parses the flags and returns the client and the team.
func (a *App) openServerCmd(ctx context.Context, s *serverCmd, args []string, usage string, positional int, validate func() error) (*api, string, []string, context.Context, context.CancelFunc, error) {
	pos, err := a.parseFlags(s.fs, args, usage)
	if err != nil {
		return nil, "", nil, ctx, nil, err
	}
	if err := needArgs(pos, positional, usage); err != nil {
		return nil, "", nil, ctx, nil, err
	}
	if validate != nil {
		if err := validate(); err != nil {
			return nil, "", nil, ctx, nil, err
		}
	}
	ctx, cancel := a.timeout(ctx, s.g)
	c, err := a.newAPI(s.g)
	if err != nil {
		cancel()
		return nil, "", nil, ctx, nil, err
	}
	team := *s.team
	if team == "" {
		team, err = tokenTeam(ctx, c)
		if err != nil {
			cancel()
			return nil, "", nil, ctx, nil, err
		}
		if team == "" {
			cancel()
			return nil, "", nil, ctx, nil, usageErr("--team is required: this is a platform token, and platform tokens cannot manage servers (use a team publisher token)")
		}
	}
	return c, team, pos, ctx, cancel, nil
}

// listServers reads every page of a team's servers (q filters by substring).
func listServers(ctx context.Context, c *api, team, q string) ([]ompclient.McpServer, error) {
	var all []ompclient.McpServer
	var cursor *string
	limit := 200
	for {
		p := &ompclient.ListTeamMcpServersParams{Cursor: cursor, Limit: &limit}
		if q != "" {
			p.Q = &q
		}
		res, err := check(c.ListTeamMcpServersWithResponse(ctx, team, p))
		if err != nil {
			return nil, err
		}
		page, err := dataOf(res.JSON200)
		if err != nil {
			return nil, err
		}
		all = append(all, page.Items...)
		if page.NextCursor == nil || *page.NextCursor == "" {
			return all, nil
		}
		cursor = page.NextCursor
	}
}

// findServer resolves a slug (the natural key) or an ID to a server.
func findServer(ctx context.Context, c *api, team, ref string) (*ompclient.McpServer, error) {
	if id, err := uuid.Parse(ref); err == nil {
		res, err := check(c.GetTeamMcpServerWithResponse(ctx, team, id))
		if err != nil {
			return nil, err
		}
		s, err := dataOf(res.JSON200)
		return &s, err
	}
	servers, err := listServers(ctx, c, team, ref)
	if err != nil {
		return nil, err
	}
	for i := range servers {
		if servers[i].Slug == ref {
			return &servers[i], nil
		}
	}
	return nil, &Error{Exit: ExitNotFound, Code: "server_not_found", Message: fmt.Sprintf("team %s has no server with slug %q", team, ref), Status: 404}
}

func (a *App) cmdServersList(ctx context.Context, args []string) error {
	s := newServerCmd("servers list")
	search := s.fs.String("search", "", "only servers whose name or slug contains this")
	usage := "omp servers list [--team SLUG] [--search TEXT] [--json]"
	c, team, _, ctx, cancel, err := a.openServerCmd(ctx, s, args, usage, 0, nil)
	if err != nil {
		return err
	}
	defer cancel()
	servers, err := listServers(ctx, c, team, *search)
	if err != nil {
		return err
	}
	if s.g.json {
		return a.printJSON(map[string]any{"team": team, "items": servers})
	}
	tw := tabwriter.NewWriter(a.scrubbed(a.Stdout), 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SLUG\tNAME\tPUBLISH\tHEALTH\tENABLED\tURL")
	for _, sv := range servers {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%v\t%s\n", sv.Slug, sv.Name, sv.PublishState, sv.Health.Status, sv.Enabled, sv.Url)
	}
	return tw.Flush()
}

func (a *App) cmdServersGet(ctx context.Context, args []string) error {
	s := newServerCmd("servers get")
	usage := "omp servers get <slug|id> [--team SLUG] [--json]"
	c, team, pos, ctx, cancel, err := a.openServerCmd(ctx, s, args, usage, 1, nil)
	if err != nil {
		return err
	}
	defer cancel()
	sv, err := findServer(ctx, c, team, pos[0])
	if err != nil {
		return err
	}
	if s.g.json {
		return a.printJSON(sv)
	}
	a.printServer(sv)
	return nil
}

func (a *App) printServer(sv *ompclient.McpServer) {
	a.outf("Slug:      %s\n", sv.Slug)
	a.outf("Name:      %s\n", sv.Name)
	a.outf("ID:        %s\n", sv.Id)
	a.outf("Team:      %s\n", sv.TeamSlug)
	a.outf("URL:       %s\n", sv.Url)
	mode := "none"
	if sv.AuthMode != nil {
		mode = string(*sv.AuthMode)
	}
	a.outf("Auth:      %s\n", mode)
	a.outf("Enabled:   %v\n", sv.Enabled)
	a.outf("Publish:   %s\n", sv.PublishState)
	a.outf("Health:    %s\n", sv.Health.Status)
	a.outf("Revision:  %d\n", sv.Revision)
	a.outf("Tools:     %d, prompts %d, resources %d, templates %d\n", sv.Counts.Tools, sv.Counts.Prompts, sv.Counts.Resources, sv.Counts.ResourceTemplates)
	if sv.PendingChanges > 0 {
		a.outf("Pending:   %d changed capabilities wait for approval\n", sv.PendingChanges)
	}
	if sv.LastRefreshError != nil && *sv.LastRefreshError != "" {
		a.outf("Last refresh error: %s\n", *sv.LastRefreshError)
	}
}

// scrubbed wraps a writer so text/tabwriter output goes through the scrubber.
func (a *App) scrubbed(w interface{ Write([]byte) (int, error) }) *scrubWriter {
	return &scrubWriter{a: a, w: w}
}

type scrubWriter struct {
	a *App
	w interface{ Write([]byte) (int, error) }
}

func (s *scrubWriter) Write(p []byte) (int, error) {
	if _, err := s.w.Write(s.a.scrub(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (a *App) cmdServersRegister(ctx context.Context, args []string) error {
	s := newServerCmd("servers register")
	slug := s.fs.String("slug", "", "the server's slug: unique on the portal, immutable (required)")
	name := s.fs.String("name", "", "display name (default: the slug)")
	urlFlag := s.fs.String("url", "", "the server's Streamable HTTP endpoint (required)")
	desc := s.fs.String("description", "", "description")
	auth := s.fs.String("auth", "none", "none or static_header")
	header := s.fs.String("auth-header", "", "header name for static_header, e.g. Authorization or X-API-Key")
	valueEnv := s.fs.String("auth-value-env", "", "environment variable holding the header value (never taken from a flag)")
	timeoutSec := s.fs.Int("timeout-seconds", 0, "per-call timeout of the server (default: the portal's)")
	disabled := s.fs.Bool("disabled", false, "register it turned off")
	usage := "omp servers register --slug S --url U [--name N] [--auth static_header --auth-header H --auth-value-env VAR] [--team SLUG]"
	var body ompclient.McpServerCreate
	// Everything that can be refused is refused before the first request.
	validate := func() error {
		if *slug == "" || *urlFlag == "" {
			return usageErr("usage: %s", usage)
		}
		body = ompclient.McpServerCreate{Slug: *slug, Name: *name, Url: *urlFlag}
		if body.Name == "" {
			body.Name = *slug
		}
		if *desc != "" {
			body.Description = desc
		}
		if *disabled {
			f := false
			body.Enabled = &f
		}
		if *timeoutSec != 0 {
			v := int32(*timeoutSec)
			body.TimeoutSeconds = &v
		}
		switch *auth {
		case "none":
			if *header != "" || *valueEnv != "" {
				return usageErr("--auth-header and --auth-value-env need --auth static_header")
			}
		case "static_header":
			if *header == "" || *valueEnv == "" {
				return usageErr("--auth static_header needs --auth-header and --auth-value-env")
			}
			val, err := a.secretFromEnv(*valueEnv)
			if err != nil {
				return err
			}
			mode := ompclient.McpServerAuthModeStaticHeader
			body.AuthMode, body.AuthHeaderName, body.AuthValue = &mode, header, &val
		default:
			return usageErr("--auth must be none or static_header: other modes need a browser session")
		}
		return nil
	}
	c, team, _, ctx, cancel, err := a.openServerCmd(ctx, s, args, usage, 0, validate)
	if err != nil {
		return err
	}
	defer cancel()
	res, err := check(c.CreateTeamMcpServerWithResponse(ctx, team, body))
	if err != nil {
		return err
	}
	created, err := dataOf(res.JSON201)
	if err != nil {
		return err
	}
	if s.g.json {
		if err := a.printJSON(created); err != nil {
			return err
		}
	} else {
		sv := created.Server
		a.outf("registered %s (%s) in team %s\n", sv.Slug, sv.Id, sv.TeamSlug)
		switch {
		case created.RefreshError != nil:
			a.outf("discovery failed: %s\n", deref(created.RefreshError.Message))
		case created.Refresh != nil:
			a.outf("discovery: %d capabilities (%d tools)\n", created.Refresh.Listed, sv.Counts.Tools)
		}
	}
	if created.RefreshError != nil {
		return &Error{Exit: ExitCheckFailed, Code: "discovery_failed", Message: "the server was registered but its capabilities could not be read: " + deref(created.RefreshError.Message)}
	}
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// secretFromEnv reads a secret from a named environment variable and
// registers it with the output scrubber.
func (a *App) secretFromEnv(name string) (string, error) {
	v := a.Getenv(name)
	if v == "" {
		return "", usageErr("the environment variable %s is empty or not set", name)
	}
	a.addSecret(v)
	return v, nil
}

func (a *App) cmdServersTest(ctx context.Context, args []string) error {
	s := newServerCmd("servers test")
	usage := "omp servers test <slug|id> [--team SLUG] [--json]"
	c, team, pos, ctx, cancel, err := a.openServerCmd(ctx, s, args, usage, 1, nil)
	if err != nil {
		return err
	}
	defer cancel()
	sv, err := findServer(ctx, c, team, pos[0])
	if err != nil {
		return err
	}
	res, err := check(c.TestTeamMcpServerWithResponse(ctx, team, sv.Id))
	if err != nil {
		return err
	}
	r, err := dataOf(res.JSON200)
	if err != nil {
		return err
	}
	if s.g.json {
		if err := a.printJSON(r); err != nil {
			return err
		}
	} else {
		status := "ok"
		if !r.Ok {
			status = "FAILED"
		}
		a.outf("%s: %s in %d ms\n", sv.Slug, status, r.LatencyMs)
		if r.Counts != nil {
			a.outf("capabilities: %d tools, %d prompts, %d resources, %d templates\n", r.Counts.Tools, r.Counts.Prompts, r.Counts.Resources, r.Counts.ResourceTemplates)
		}
		if r.ErrorClass != nil {
			a.outf("error class: %s\n", *r.ErrorClass)
		}
		if m := deref(r.Message); m != "" {
			a.outf("message: %s\n", m)
		}
	}
	if !r.Ok {
		return &Error{Exit: ExitCheckFailed, Code: "test_failed", Message: fmt.Sprintf("the test of %s failed: %s", sv.Slug, deref(r.Message))}
	}
	return nil
}

func (a *App) cmdServersRefresh(ctx context.Context, args []string) error {
	s := newServerCmd("servers refresh")
	failOnChanges := s.fs.Bool("fail-on-changes", false, "exit 10 when capabilities changed (they stay out of the catalog until approved)")
	usage := "omp servers refresh <slug|id> [--team SLUG] [--fail-on-changes] [--json]"
	c, team, pos, ctx, cancel, err := a.openServerCmd(ctx, s, args, usage, 1, nil)
	if err != nil {
		return err
	}
	defer cancel()
	sv, err := findServer(ctx, c, team, pos[0])
	if err != nil {
		return err
	}
	res, err := check(c.RefreshTeamMcpServerWithResponse(ctx, team, sv.Id))
	if err != nil {
		return err
	}
	r, err := dataOf(res.JSON200)
	if err != nil {
		return err
	}
	if s.g.json {
		if err := a.printJSON(map[string]any{"server": sv.Slug, "added": r.Added, "changed": r.Changed, "gone": r.Gone, "listed": r.Listed}); err != nil {
			return err
		}
	} else {
		a.outf("%s: %d listed, %d added, %d changed, %d gone\n", sv.Slug, r.Listed, r.Added, r.Changed, r.Gone)
		if r.Changed > 0 {
			a.outf("changed capabilities wait for approval before they reach the catalog (review queue)\n")
		}
	}
	if *failOnChanges && r.Changed > 0 {
		return &Error{Exit: ExitChanges, Code: "capabilities_changed", Message: fmt.Sprintf("%d capabilities of %s changed and need approval", r.Changed, sv.Slug)}
	}
	return nil
}

func (a *App) cmdServersPublish(ctx context.Context, args []string, publish bool) error {
	name := "servers unpublish"
	usage := "omp servers unpublish <slug|id> [--team SLUG] [--json]"
	if publish {
		name = "servers publish"
		usage = "omp servers publish <slug|id> [--team SLUG] [--note TEXT] [--expected-digest D] [--json]"
	}
	s := newServerCmd(name)
	var note, digest *string
	if publish {
		note = s.fs.String("note", "", "a note for the reviewer")
		digest = s.fs.String("expected-digest", "", "the server's reviewDigest as you saw it; 409 changed_since_review when it moved")
	}
	c, team, pos, ctx, cancel, err := a.openServerCmd(ctx, s, args, usage, 1, nil)
	if err != nil {
		return err
	}
	defer cancel()
	sv, err := findServer(ctx, c, team, pos[0])
	if err != nil {
		return err
	}
	var out ompclient.McpServer
	if publish {
		body := ompclient.McpPublishRequest{}
		if *note != "" {
			body.Note = note
		}
		if *digest != "" {
			body.ExpectedDigest = digest
		}
		res, err := check(c.PublishTeamMcpServerWithResponse(ctx, team, sv.Id, body))
		if err != nil {
			return err
		}
		if out, err = dataOf(res.JSON200); err != nil {
			return err
		}
	} else {
		res, err := check(c.UnpublishTeamMcpServerWithResponse(ctx, team, sv.Id))
		if err != nil {
			return err
		}
		if out, err = dataOf(res.JSON200); err != nil {
			return err
		}
	}
	if s.g.json {
		return a.printJSON(out)
	}
	a.outf("%s: %s\n", out.Slug, out.PublishState)
	return nil
}
