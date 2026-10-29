package ompcli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

const exportHeader = `# Exported by omp (schema omp/v1). Secrets are never exported: a server with a static
# header names an environment variable in authValueEnv, which "omp import" reads.
# Set it before an import that creates the server or replaces its secret.
`

func checkOnly(only string) error {
	switch only {
	case "", "servers", "platform":
		return nil
	}
	return usageErr("--only must be servers or platform (got %q)", only)
}

// whoamiData reads the token's own description, which decides what a file may
// contain.
func whoamiData(ctx context.Context, c *api) (ompclient.AutomationToken, error) {
	res, err := check(c.GetTokenWithResponse(ctx))
	if err != nil {
		return ompclient.AutomationToken{}, err
	}
	return dataOf(res.JSON200)
}

// ---- export ------------------------------------------------------------------

func (a *App) cmdExport(ctx context.Context, args []string) error {
	g := &global{}
	fs := newFlagSet("export", g)
	only := fs.String("only", "", "servers or platform (default: everything this token can read)")
	out := fs.String("o", "", "write to this file instead of standard output")
	usage := "omp export [--only servers|platform] [-o FILE] [--json]"
	pos, err := a.parseFlags(fs, args, usage)
	if err != nil {
		return err
	}
	if err := needArgs(pos, 0, usage); err != nil {
		return err
	}
	if err := checkOnly(*only); err != nil {
		return err
	}
	ctx, cancel := a.timeout(ctx, g)
	defer cancel()
	c, err := a.newAPI(g)
	if err != nil {
		return err
	}
	tok, err := whoamiData(ctx, c)
	if err != nil {
		return err
	}
	f := &File{Schema: SchemaID}
	var warnings []string
	switch tok.Kind {
	case ompclient.AutomationTokenKindTeamPublisher:
		if *only == "platform" {
			return usageErr("this is a team publisher token: it cannot read platform objects")
		}
		if err := exportServers(ctx, c, tok.Team.Slug, f, &warnings); err != nil {
			return err
		}
	default:
		if *only == "servers" {
			return usageErr("this is a platform token: platform tokens cannot read team servers through the team routes; use a team publisher token for --only servers")
		}
		if err := exportPlatform(ctx, c, f); err != nil {
			return err
		}
	}
	f.Sort()
	for _, w := range warnings {
		a.errf("warning: %s\n", w)
	}
	var data []byte
	if g.json {
		b, err := marshalJSON(f)
		if err != nil {
			return err
		}
		data = b
	} else {
		b, err := f.Marshal()
		if err != nil {
			return err
		}
		data = append([]byte(exportHeader), b...)
	}
	if *out != "" {
		if err := os.WriteFile(*out, a.scrub(data), 0o644); err != nil { //nolint:gosec // no secrets in the file
			return &Error{Exit: ExitFailure, Code: "write_failed", Message: err.Error()}
		}
		a.outf("wrote %s\n", *out)
		return nil
	}
	a.write(a.Stdout, data)
	return nil
}

func suggestEnv(slug string) string {
	return "OMP_" + strings.ToUpper(strings.NewReplacer("-", "_").Replace(slug)) + "_AUTH_VALUE"
}

func exportServers(ctx context.Context, c *api, team string, f *File, warnings *[]string) error {
	servers, err := listServers(ctx, c, team, "")
	if err != nil {
		return err
	}
	for i := range servers {
		sv := &servers[i]
		if why := manageable(sv); why != "" {
			*warnings = append(*warnings, fmt.Sprintf("skipped server %s: it %s", sv.Slug, why))
			continue
		}
		desc, enabled, timeout := sv.Description, sv.Enabled, sv.TimeoutSeconds
		s := Server{Team: sv.TeamSlug, Slug: sv.Slug, Name: sv.Name, Description: &desc, URL: sv.Url, Enabled: &enabled, TimeoutSeconds: &timeout, AuthMode: serverMode(sv)}
		if s.AuthMode == "static_header" {
			s.AuthHeaderName = deref(sv.AuthHeaderName)
			s.AuthValueEnv = suggestEnv(sv.Slug)
		}
		s.Publish = "none"
		if sv.PublishState == ompclient.PublishStatePending || sv.PublishState == ompclient.PublishStatePublished {
			s.Publish = "request"
		}
		f.Servers = append(f.Servers, s)
	}
	return nil
}

func exportPlatform(ctx context.Context, c *api, f *File) error {
	teams, err := listTeams(ctx, c)
	if err != nil {
		return err
	}
	for _, t := range teams {
		desc := t.Description
		et := Team{Slug: t.Slug, Name: t.Name, Description: &desc, Status: string(t.Status)}
		limits, err := getTeamLimits(ctx, c, t.Slug)
		if err != nil {
			return err
		}
		for k, v := range limits {
			if v != nil {
				if et.Limits == nil {
					et.Limits = map[string]*int64{}
				}
				et.Limits[k] = v
			}
		}
		f.Teams = append(f.Teams, et)
	}
	gateways, err := listPlatformGateways(ctx, c)
	if err != nil {
		return err
	}
	for _, gw := range gateways {
		desc, enabled := gw.Description, gw.Enabled
		eg := Gateway{Slug: gw.Slug, Name: gw.Name, Description: &desc, Enabled: &enabled}
		caps, err := getGatewayCapabilities(ctx, c, gw.Id)
		if err != nil {
			return err
		}
		refs := []CapabilityRef{}
		for _, cp := range caps.Items {
			refs = append(refs, capFrom(cp))
		}
		grants, err := getGatewayGrants(ctx, c, gw.Id)
		if err != nil {
			return err
		}
		gl := []Grant{}
		for _, gr := range grants {
			gl = append(gl, grantFrom(gr))
		}
		eg.Capabilities, eg.Grants = &refs, &gl
		f.Gateways = append(f.Gateways, eg)
	}
	limits, err := getPlatformLimits(ctx, c)
	if err != nil {
		return err
	}
	f.Limits = map[string]PlatformLimit{}
	for _, it := range limits.Items {
		f.Limits[string(it.Key)] = PlatformLimit{Default: it.Default, Ceiling: it.Ceiling}
	}
	return nil
}

// ---- import ------------------------------------------------------------------

func (a *App) cmdImport(ctx context.Context, args []string) error {
	g := &global{}
	fs := newFlagSet("import", g)
	file := fs.String("f", "", "the omp/v1 file to apply (- for standard input)")
	fs.StringVar(file, "file", "", "same as -f")
	plan := fs.Bool("plan", false, "only show the changes; exit 10 when there are any")
	only := fs.String("only", "", "servers or platform: apply only that part of the file")
	refresh := fs.Bool("refresh", false, "after applying, refresh every declared server (not part of --plan)")
	failOnChanges := fs.Bool("fail-on-changes", false, "with --refresh: exit 10 when a refresh found changed capabilities")
	replaceSecrets := fs.Bool("replace-secrets", false, "send each authValueEnv's value again even when nothing else changed")
	usage := "omp import -f FILE [--plan] [--only servers|platform] [--refresh [--fail-on-changes]] [--replace-secrets] [--json]"
	pos, err := a.parseFlags(fs, args, usage)
	if err != nil {
		return err
	}
	if err := needArgs(pos, 0, usage); err != nil {
		return err
	}
	if *file == "" {
		return usageErr("usage: %s", usage)
	}
	if err := checkOnly(*only); err != nil {
		return err
	}
	if *plan && (*refresh || *failOnChanges) {
		return usageErr("--refresh and --fail-on-changes apply to a real import, not --plan")
	}
	if *failOnChanges && !*refresh {
		return usageErr("--fail-on-changes needs --refresh")
	}
	var raw []byte
	if *file == "-" {
		raw, err = io.ReadAll(io.LimitReader(a.Stdin, 8<<20))
	} else {
		raw, err = os.ReadFile(*file)
	}
	if err != nil {
		return usageErr("cannot read %s: %v", *file, err)
	}
	f, err := ParseFile(raw)
	if err != nil {
		return err
	}
	ctx, cancel := a.timeout(ctx, g)
	defer cancel()
	c, err := a.newAPI(g)
	if err != nil {
		return err
	}
	tok, err := whoamiData(ctx, c)
	if err != nil {
		return err
	}
	pl := &planner{a: a, c: c, token: tok, opts: importOpts{apply: !*plan, replaceSecrets: *replaceSecrets, refresh: *refresh, only: *only}}
	if err := pl.build(ctx, f); err != nil {
		return err
	}
	result := pl.plan()
	if *plan {
		if err := a.printPlan(g, result); err != nil {
			return err
		}
		if result.Drift() {
			return &Error{Exit: ExitChanges, Code: "changes_found", Message: fmt.Sprintf("%d object(s) differ from the file", len(result.Changes))}
		}
		return nil
	}
	return a.applyPlan(ctx, g, pl, result, *failOnChanges)
}

func (a *App) applyPlan(ctx context.Context, g *global, pl *planner, result *Plan, failOnChanges bool) error {
	// Everything that can be checked before the first call is, so a missing
	// secret does not leave a half-applied file.
	var missing []string
	for _, st := range pl.steps {
		for _, env := range st.needsEnv {
			if a.Getenv(env) == "" {
				missing = append(missing, env)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return usageErr("these environment variables are not set (they hold secrets named by authValueEnv): %s", strings.Join(missing, ", "))
	}
	for _, st := range pl.steps {
		for _, env := range st.needsEnv {
			a.addSecret(a.Getenv(env))
		}
	}
	rr := &runResult{}
	var applied []Change
	for _, st := range pl.steps {
		if err := st.run(ctx, rr); err != nil {
			e := asError(err)
			c := *e
			c.Message = fmt.Sprintf("%s %s %s: %s (%d applied before this)", st.Action, st.Kind, st.Key, e.Message, len(applied))
			return &c
		}
		if st.Action != "refresh" {
			applied = append(applied, st.Change)
		}
		if !g.json {
			if st.Action == "refresh" {
				continue
			}
			a.outf("applied: %s\n", changeHeadline(st.Change))
		}
	}
	if g.json {
		if err := a.printJSON(map[string]any{"applied": nonNil(applied), "warnings": result.Warnings, "notes": rr.notes}); err != nil {
			return err
		}
	} else {
		for _, n := range rr.notes {
			a.outf("%s\n", n)
		}
		for _, w := range result.Warnings {
			a.errf("warning: %s\n", w)
		}
		if len(applied) == 0 {
			a.outf("No changes: the portal already matches the file.\n")
		}
	}
	if len(rr.failures) > 0 {
		return rr.failures[0]
	}
	if failOnChanges && rr.changed > 0 {
		return &Error{Exit: ExitChanges, Code: "capabilities_changed", Message: fmt.Sprintf("%d capabilities changed on refresh and need approval", rr.changed)}
	}
	return nil
}

func nonNil(c []Change) []Change {
	if c == nil {
		return []Change{}
	}
	return c
}

func changeHeadline(c Change) string {
	sign := map[string]string{"create": "+", "update": "~"}[c.Action]
	return fmt.Sprintf("%s %s %s", sign, c.Kind, c.Key)
}

// printPlan writes a plan as text, or as JSON with --json.
func (a *App) printPlan(g *global, p *Plan) error {
	if g.json {
		return a.printJSON(map[string]any{"schema": SchemaID, "drift": p.Drift(), "changes": nonNil(p.Changes), "warnings": nonNilS(p.Warnings)})
	}
	a.write(a.Stdout, []byte(RenderPlan(p)))
	for _, w := range p.Warnings {
		a.errf("warning: %s\n", w)
	}
	return nil
}

func nonNilS(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// RenderPlan is the text form of a plan (golden-tested).
func RenderPlan(p *Plan) string {
	if len(p.Changes) == 0 {
		return "No changes: the portal matches the file.\n"
	}
	var b strings.Builder
	creates, updates := 0, 0
	for _, c := range p.Changes {
		fmt.Fprintf(&b, "%s\n", changeHeadline(c))
		if c.Action == "create" {
			creates++
		} else {
			updates++
		}
		for _, f := range c.Fields {
			switch {
			case c.Action == "create":
				fmt.Fprintf(&b, "    %s: %s%s\n", f.Field, jsonVal(f.To), note(f))
			case f.From == nil:
				fmt.Fprintf(&b, "    %s: (none) -> %s%s\n", f.Field, jsonVal(f.To), note(f))
			case f.To == nil:
				fmt.Fprintf(&b, "    %s: %s -> (none)\n", f.Field, jsonVal(f.From))
			default:
				fmt.Fprintf(&b, "    %s: %s -> %s%s\n", f.Field, jsonVal(f.From), jsonVal(f.To), note(f))
			}
		}
	}
	fmt.Fprintf(&b, "Plan: %d to create, %d to update.\n", creates, updates)
	return b.String()
}

func note(f FieldChange) string {
	if f.Note == "" {
		return ""
	}
	return " (" + f.Note + ")"
}
