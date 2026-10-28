// Package doctor implements `open-mcp-portal doctor`: the configuration and
// production safety checks, then PostgreSQL connectivity and the migration
// state, with timings, then key rotation: sealed values still on
// ENCRYPTION_KEY_PREVIOUS or on neither key, and keys still on another API
// key pepper. It changes nothing.
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/buildinfo"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/keyrotation"
	"github.com/ncecere/open-mcp-portal/internal/notify"
	"github.com/ncecere/open-mcp-portal/internal/oauth"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Status of one check.
type Status string

const (
	OK   Status = "ok"
	Info Status = "info" // worth knowing
	Fail Status = "fail" // broken: doctor exits non-zero
)

// Check is one line of the report.
type Check struct {
	Group      string  `json:"group"` // configuration, safety, postgres, keys
	Name       string  `json:"name"`
	Status     Status  `json:"status"`
	Detail     string  `json:"detail"`
	Fix        string  `json:"fix,omitempty"`
	DurationMs float64 `json:"durationMs,omitempty"`
}

// Report is the outcome of a run. OK is false when any check failed.
type Report struct {
	Version string  `json:"version"`
	Mode    string  `json:"mode"`
	OK      bool    `json:"ok"`
	Checks  []Check `json:"checks"`
}

// Options select what a run checks.
type Options struct {
	// Mode is the process mode whose configuration is validated: serve
	// (default) or migrate.
	Mode string
	// Timeout bounds each check (default 10s).
	Timeout time.Duration
}

type runner struct {
	cfg    config.Config
	opts   Options
	checks []Check
}

func (r *runner) add(c Check) { r.checks = append(r.checks, c) }

// Run performs every check.
func Run(ctx context.Context, cfg config.Config, opts Options) Report {
	if opts.Mode == "" {
		opts.Mode = "serve"
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	r := &runner{cfg: cfg, opts: opts}
	r.configuration()
	r.notifications(ctx)
	if pool := r.postgres(ctx); pool != nil {
		pool.Close()
	}
	return r.report()
}

// ConfigLoadFailed is the report when the configuration cannot even be
// loaded (an invalid value or an unreadable *_FILE).
func ConfigLoadFailed(mode string, err error) Report {
	r := &runner{opts: Options{Mode: mode}}
	for _, e := range splitErrors(err) {
		r.add(Check{Group: "configuration", Name: "load", Status: Fail, Detail: e.Error()})
	}
	return r.report()
}

func (r *runner) report() Report {
	rep := Report{Version: buildinfo.String(), Mode: r.opts.Mode, OK: true, Checks: r.checks}
	for _, c := range r.checks {
		if c.Status == Fail {
			rep.OK = false
		}
	}
	return rep
}

// configuration reports the production safety checks, then the rest of
// the validation of the mode's configuration.
func (r *runner) configuration() {
	safety := r.cfg.SafetyErrors(r.opts.Mode)
	seen := map[string]bool{}
	for _, e := range safety {
		seen[e.Error()] = true
		r.add(Check{Group: "safety", Name: "production", Status: Fail, Detail: e.Error()})
	}
	var other []error
	for _, e := range splitErrors(r.cfg.Validate(r.opts.Mode)) {
		if !seen[e.Error()] {
			other = append(other, e)
		}
	}
	for _, e := range other {
		r.add(Check{Group: "configuration", Name: r.opts.Mode, Status: Fail, Detail: e.Error()})
	}
	switch {
	case len(safety) == 0 && r.cfg.LoopbackAppURL():
		r.add(Check{Group: "safety", Name: "production", Status: Info,
			Detail: "APP_URL is loopback (" + r.cfg.AppURL + "): development install, production checks not applied"})
	case len(safety) == 0:
		r.add(Check{Group: "safety", Name: "production", Status: OK, Detail: "DEV_AUTH off, APP_URL is https"})
	}
	if len(other) == 0 {
		r.add(Check{Group: "configuration", Name: r.opts.Mode, Status: OK, Detail: "valid for open-mcp-portal " + r.opts.Mode})
	}
	r.proxies()
	r.tracing()
}

// tracing reports the span exporter (group configuration, check tracing):
// off is info; on, the collector's host (never its path, headers or
// credentials) and the sampler. The collector is not contacted: spans are
// exported in the background and a collector that is down loses spans, not
// requests.
func (r *runner) tracing() {
	if r.opts.Mode != "serve" {
		return
	}
	t := r.cfg.Tracing
	if !t.Enabled() {
		r.add(Check{Group: "configuration", Name: "tracing", Status: Info,
			Detail: "tracing is off (no OTEL_EXPORTER_OTLP_ENDPOINT): no spans are created or sent"})
		return
	}
	sampler := t.Sampler
	if sampler == "" {
		sampler = config.DefaultTracesSampler
	}
	detail := fmt.Sprintf("OTLP/HTTP to %s, sampler %s", t.Host(), sampler)
	if strings.Contains(sampler, "ratio") {
		detail += fmt.Sprintf(" (%g)", t.SamplerArg)
	}
	if sampler == "always_on" || sampler == "parentbased_always_on" {
		detail += ": every request is traced"
	}
	if t.Headers != "" {
		detail += ", with export headers"
	}
	r.add(Check{Group: "configuration", Name: "tracing", Status: OK, Detail: detail})
}

// proxies hints at TRUSTED_PROXIES. The portal serves plain http and an https
// APP_URL means TLS ends at a proxy, so with TRUSTED_PROXIES empty every
// request appears to come from that proxy: rate limits and audit addresses
// are the proxy's. Doctor cannot see traffic; the running portal logs a
// warning once a minute when requests actually carry X-Forwarded-For.
func (r *runner) proxies() {
	if r.opts.Mode != "serve" || !r.cfg.SecureCookies() || len(r.cfg.TrustedProxies) > 0 {
		return
	}
	r.add(Check{Group: "configuration", Name: "trusted proxies", Status: Info,
		Detail: "APP_URL is https and TRUSTED_PROXIES is empty: behind an ingress, client addresses in rate limits, audit entries and logs are the ingress's",
		Fix:    "Set TRUSTED_PROXIES to the ingress controller's network (docs/deploy.md), or ignore this when nothing sits in front of the portal"})
}

// postgres connects, reports the server version and the migration state.
// It returns the pool (nil when unavailable).
func (r *runner) postgres(ctx context.Context) *pgxpool.Pool {
	if r.cfg.DatabaseURL == "" {
		r.add(Check{Group: "postgres", Name: "connect", Status: Fail, Detail: "DATABASE_URL is not set"})
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()
	start := time.Now()
	pool, err := store.Open(cctx, r.cfg.DatabaseURL)
	if err != nil {
		r.add(Check{Group: "postgres", Name: "connect", Status: Fail, Detail: err.Error(), DurationMs: millis(time.Since(start)),
			Fix: "Start PostgreSQL (make deps-up) and check DATABASE_URL"})
		return nil
	}
	var version string
	err = pool.QueryRow(cctx, "SHOW server_version").Scan(&version)
	c := Check{Group: "postgres", Name: "connect", Status: OK, Detail: "PostgreSQL " + version, DurationMs: millis(time.Since(start))}
	if err != nil {
		c.Status, c.Detail = Fail, "server version: "+err.Error()
	}
	r.add(c)
	if r.migrations(cctx, pool) {
		safety, err := store.InspectRoles(cctx, pool, "", true)
		c := Check{Group: "postgres", Name: "roles", Status: OK, Detail: safety.Detail()}
		if err != nil {
			c.Status, c.Detail = Fail, "cannot inspect database roles: "+err.Error()
		} else if !safety.Safe() {
			c.Status = Info
			if r.cfg.DBRequireSplitRoles {
				c.Status = Fail
			}
			c.Fix = "Use distinct owner/runtime logins; see docs/database-roles.md"
		}
		r.add(c)
		r.keys(cctx, pool)
		r.oauthRegistration(cctx, pool)
	}
	return pool
}

// keys reports sealed values by key and keys by pepper.
func (r *runner) keys(ctx context.Context, pool *pgxpool.Pool) {
	cur, err := secrets.ParseKey(r.cfg.EncryptionKey)
	if err != nil {
		return // reported by the configuration checks
	}
	var prev []byte
	if r.cfg.EncryptionKeyPrevious != "" {
		if p, err := secrets.ParseKey(r.cfg.EncryptionKeyPrevious); err == nil {
			prev = secrets.KeyID(p)
		}
	}
	start := time.Now()
	counts, err := keyrotation.Count(ctx, pool, secrets.KeyID(cur), prev)
	c := Check{Group: "keys", Name: "encryption", Status: OK}
	var onPrev, others int64
	var where []string
	for _, k := range counts {
		onPrev += k.Previous
		others += k.Others
		if k.Previous > 0 || k.Others > 0 {
			where = append(where, fmt.Sprintf("%s: %d previous, %d undecryptable", k.Column, k.Previous, k.Others))
		}
	}
	switch {
	case err != nil:
		c.Status, c.Detail = Fail, err.Error()
	case others > 0:
		c.Status = Fail
		c.Detail = fmt.Sprintf("%d sealed value(s) carry neither ENCRYPTION_KEY nor ENCRYPTION_KEY_PREVIOUS (%s)", others, strings.Join(where, "; "))
		c.Fix = "Set the key they were sealed with as ENCRYPTION_KEY_PREVIOUS, then run open-mcp-portal rotate-keys"
	case onPrev > 0:
		c.Status = Info
		c.Detail = fmt.Sprintf("%d sealed value(s) still on ENCRYPTION_KEY_PREVIOUS (%s)", onPrev, strings.Join(where, "; "))
		c.Fix = "Run open-mcp-portal rotate-keys, then remove ENCRYPTION_KEY_PREVIOUS"
	case prev != nil:
		c.Status = Info
		c.Detail = "every sealed value is on ENCRYPTION_KEY: ENCRYPTION_KEY_PREVIOUS can be removed"
	default:
		c.Detail = "every sealed value is on ENCRYPTION_KEY"
	}
	c.DurationMs = millis(time.Since(start))
	r.add(c)

	pepper, err := secrets.ParseKey(r.cfg.APIKeyPepper)
	if err != nil {
		return
	}
	p := keyrotation.Peppers{Current: pepper}
	if r.cfg.APIKeyPepperPrevious != "" {
		if pp, err := secrets.ParseKey(r.cfg.APIKeyPepperPrevious); err == nil {
			p.Previous = pp
		}
	}
	keys, tokens, err := keyrotation.PepperReport(ctx, dbgen.New(pool), p)
	pc := Check{Group: "keys", Name: "pepper", Status: OK}
	var previous, retired int
	for _, k := range keys {
		if k.State == keyrotation.PepperPrevious {
			previous++
		} else {
			retired++
		}
	}
	switch {
	case err != nil:
		pc.Status, pc.Detail = Fail, err.Error()
	case previous+retired > 0 || tokens > 0:
		pc.Status = Info
		pc.Detail = fmt.Sprintf("%d usable key(s) on API_KEY_PEPPER_PREVIOUS, %d on a pepper no longer configured, %d connected-app token(s) on another pepper",
			previous, retired, tokens)
		pc.Fix = "Keys move to API_KEY_PEPPER when used; open-mcp-portal rotate-keys --dry-run lists them. Revoke keys on a retired pepper"
	case p.Previous != nil:
		pc.Status = Info
		pc.Detail = "every usable key is on API_KEY_PEPPER: API_KEY_PEPPER_PREVIOUS can be removed"
	default:
		pc.Detail = "every usable key is on API_KEY_PEPPER"
	}
	r.add(pc)
}

// oauthRegistration says whether open client registration is on and how many
// registered clients are live against the cap (info: nothing to fix).
func (r *runner) oauthRegistration(ctx context.Context, pool *pgxpool.Pool) {
	start := time.Now()
	live, open, err := oauth.RegistrationStatus(ctx, dbgen.New(pool), time.Now())
	c := Check{Group: "oauth", Name: "registration", Status: Info, DurationMs: millis(time.Since(start))}
	capText := "no cap (OAUTH_MAX_REGISTERED_CLIENTS=0)"
	if n := r.cfg.OAuthMaxRegisteredClients; n > 0 {
		capText = fmt.Sprintf("cap %d (OAUTH_MAX_REGISTERED_CLIENTS)", n)
	}
	switch {
	case err != nil:
		c.Status, c.Detail = Fail, err.Error()
	case !open:
		c.Detail = fmt.Sprintf("open client registration is off (Admin, Trusted clients); %d registered client(s) still live", live)
	default:
		c.Detail = fmt.Sprintf("open client registration is on; %d registered client(s) live, %s", live, capText)
	}
	r.add(c)
}

// migrations reports the migration state; ok when the schema is current.
func (r *runner) migrations(ctx context.Context, pool *pgxpool.Pool) bool {
	st, err := store.Migrations(ctx, pool)
	c := Check{Group: "postgres", Name: "migrations", Status: OK}
	switch {
	case err != nil:
		c.Status, c.Detail = Fail, err.Error()
	case st.Pending:
		c.Status = Fail
		c.Detail = fmt.Sprintf("pending: the database is at version %d, this binary has %d", st.Current, st.Latest)
		c.Fix = "Run open-mcp-portal migrate"
	case st.Current > st.Latest:
		c.Status = Info
		c.Detail = fmt.Sprintf("the database (version %d) is newer than this binary (%d): an older binary during a rollout?", st.Current, st.Latest)
	default:
		c.Detail = fmt.Sprintf("current (version %d)", st.Current)
	}
	r.add(c)
	return err == nil && !st.Pending && st.Current == st.Latest
}

// splitErrors lists the errors joined in err (errors.Join), one per check.
func splitErrors(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		var out []error
		for _, e := range j.Unwrap() {
			out = append(out, splitErrors(e)...)
		}
		return out
	}
	if err == nil {
		return nil
	}
	return []error{err}
}

func millis(d time.Duration) float64 {
	return float64(d.Round(10*time.Microsecond)) / float64(time.Millisecond)
}

var symbols = map[Status]string{OK: "ok  ", Info: "info", Fail: "FAIL"}

// WriteJSON writes the report as indented JSON.
func (rep Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// WriteText writes the report as a table: status, check, duration, detail,
// with fixes on indented lines below.
func (rep Report) WriteText(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "open-mcp-portal doctor (%s; configuration checked for %s)\n\n", rep.Version, rep.Mode)
	counts := map[Status]int{}
	for _, c := range rep.Checks {
		counts[c.Status]++
		dur := ""
		if c.DurationMs > 0 {
			dur = fmt.Sprintf("%.1fms", c.DurationMs)
		}
		fmt.Fprintf(&b, "%s  %-24s %9s  %s\n", symbols[c.Status], c.Group+" "+c.Name, dur, c.Detail)
		if c.Fix != "" && c.Status != OK {
			fmt.Fprintf(&b, "%39sfix: %s\n", "", c.Fix)
		}
	}
	verdict := "all checks passed"
	if !rep.OK {
		verdict = "FAILED"
	}
	fmt.Fprintf(&b, "\n%d checks: %d ok, %d info, %d failed. %s\n", len(rep.Checks), counts[OK], counts[Info], counts[Fail], verdict)
	_, err := io.WriteString(w, b.String())
	return err
}

// notifications reports email (group notifications, check email): off is
// info; configured, a connection with EHLO, TLS and AUTH within 5 s (no
// message is sent), never the username or password. Webhooks reach public
// addresses only unless the operator allowed networks.
func (r *runner) notifications(ctx context.Context) {
	if r.opts.Mode == "migrate" {
		return
	}
	smtp := r.cfg.SMTP
	c := Check{Group: "notifications", Name: "email"}
	if !smtp.Enabled() {
		c.Status, c.Detail = Info, "email is off (SMTP_HOST is not set): notifications go to the in-app inbox and webhooks only"
		r.add(c)
	} else {
		start := time.Now()
		merr := notify.Check(ctx, smtp)
		c.DurationMs = float64(time.Since(start).Microseconds()) / 1000
		desc := fmt.Sprintf("%s:%d, %s", smtp.Host, smtp.EffectivePort(), smtp.Mode())
		if smtp.Authenticates() {
			desc += ", authenticated"
		}
		switch {
		case merr != nil:
			c.Status, c.Detail = Fail, "could not use "+desc+": "+merr.Class
			c.Fix = "Check SMTP_HOST, SMTP_PORT, SMTP_TLS and the credentials; the server's certificate must verify (there is no insecure setting)"
		case smtp.Mode() == config.SMTPPlain:
			c.Status, c.Detail = Info, desc+" (unencrypted)"
		default:
			c.Status, c.Detail = OK, desc
		}
		r.add(c)
	}
	w := Check{Group: "notifications", Name: "webhooks", Status: OK, Detail: "webhook destinations reach public https addresses only"}
	if n := len(r.cfg.NotifyWebhookAllowedNetworks); n > 0 {
		w.Status, w.Detail = Info, fmt.Sprintf("webhook destinations may also reach %d internal network(s) or host(s) from NOTIFY_WEBHOOK_ALLOWED_NETWORKS", n)
	}
	r.add(w)
}
