// Package app wires dependencies together and runs one process mode.
package app

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/agentidentity"
	"github.com/ncecere/open-mcp-portal/internal/apikeys"
	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/automation"
	"github.com/ncecere/open-mcp-portal/internal/buildinfo"
	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/capture"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/identity"
	"github.com/ncecere/open-mcp-portal/internal/keyrotation"
	"github.com/ncecere/open-mcp-portal/internal/limits"
	"github.com/ncecere/open-mcp-portal/internal/mcpgw"
	"github.com/ncecere/open-mcp-portal/internal/notify"
	"github.com/ncecere/open-mcp-portal/internal/oauth"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/overview"
	"github.com/ncecere/open-mcp-portal/internal/personsecrets"
	"github.com/ncecere/open-mcp-portal/internal/platform"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/retention"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/serviceaccounts"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/teams"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
	"github.com/ncecere/open-mcp-portal/internal/usage"
	"github.com/ncecere/open-mcp-portal/web"
)

// Modes.
const (
	ModeServe   = "serve"   // HTTP API, embedded UI and background loops
	ModeMigrate = "migrate" // apply migrations and exit
)

// dbConnectWait is how long a process waits for Postgres at start-up.
const dbConnectWait = 3 * time.Minute

// cleanupInterval is how often expired sessions and abandoned sign-ins are
// deleted.
const cleanupInterval = 15 * time.Minute

// Run starts the given mode and blocks until ctx is cancelled (or the mode
// completes, for migrate). Shutdown is bounded by SHUTDOWN_TIMEOUT.
func Run(ctx context.Context, mode string, cfg config.Config, log *slog.Logger) error {
	if err := cfg.Validate(mode); err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	log = log.With("mode", mode)
	log.Info("starting", "version", buildinfo.Version, "commit", buildinfo.Commit)

	if mode == ModeMigrate || cfg.MigrateOnStart {
		owner, err := store.OpenWait(ctx, cfg.MigrationURL(), dbConnectWait, log)
		if err != nil {
			return err
		}
		err = store.Migrate(ctx, owner, log, cfg.DBRuntimeRole)
		owner.Close()
		if err != nil {
			return err
		}
		if mode == ModeMigrate {
			log.Info("migrations complete")
			return nil
		}
	}
	pool, err := store.OpenWait(ctx, cfg.DatabaseURL, dbConnectWait, log)
	if err != nil {
		return err
	}
	defer pool.Close()
	safety, err := store.InspectRoles(ctx, pool, "", true)
	if err != nil {
		return fmt.Errorf("postgres roles: %w", err)
	}
	if !safety.Safe() {
		if cfg.DBRequireSplitRoles {
			return fmt.Errorf("unsafe split database roles: %s", safety.Detail())
		}
		log.Warn("postgres roles: single-owner or unsafe runtime privileges", "detail", safety.Detail())
	}
	if st, err := store.Migrations(ctx, pool); err != nil {
		return fmt.Errorf("migration state: %w", err)
	} else if st.Pending {
		return fmt.Errorf("the database is at migration %d but this binary needs %d: run `open-mcp-portal migrate` (or set MIGRATE_ON_START=true)", st.Current, st.Latest)
	}

	stopTracing, err := startTracing(ctx, mode, cfg, log)
	if err != nil {
		return err
	}
	health := httpapi.NewHealth(map[string]func(context.Context) error{"postgres": pool.Ping})
	deps, err := NewDeps(cfg, pool, log)
	if err != nil {
		return err
	}
	if err := stampPeppers(ctx, cfg, pool, log); err != nil {
		return err
	}
	deps.Health = health
	deps.Web, deps.WebBuilt = web.Assets()
	if !deps.WebBuilt {
		log.Warn("web UI not built; run `make web` before building")
	}
	srv := newHTTPServer(ctx, cfg.ListenAddr, httpapi.NewAPIHandler(deps))
	loopCtx, stopLoops := context.WithCancel(ctx)
	defer stopLoops()
	go cleanupLoop(loopCtx, deps.Auth, deps.Providers, deps.Automation, log)
	go deps.Notify.Loop(loopCtx)
	go deps.Registry.HealthLoop(loopCtx, cfg.HealthCheckInterval, log)
	go deps.Providers.RefreshLoop(loopCtx, cfg.ProviderRefreshInterval, log)
	go deps.Identity.RotationLoop(loopCtx, log)
	go deps.Retention.Loop(loopCtx)
	go deps.Usage.Loop(loopCtx)
	go rateCounterLoop(loopCtx, deps.RateStore, log)
	servers := []*http.Server{srv}
	if cfg.MetricsAddr != "" {
		metrics := observability.NewMetrics(pool)
		observability.SetMaxObjects(cfg.MetricsMaxObjects)
		go metricsObjectsLoop(loopCtx, pool, log)
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", metrics.Handler())
		msrv := &http.Server{Addr: cfg.MetricsAddr, Handler: mux, ReadHeaderTimeout: readHeaderTimeout, IdleTimeout: idleTimeout,
			BaseContext: func(net.Listener) context.Context { return context.WithoutCancel(ctx) }}
		servers = append(servers, msrv)
		go func() {
			log.Info("metrics listening", "addr", msrv.Addr)
			if err := msrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics listener failed", "err", err)
			}
		}()
	}
	if err := serve(ctx, srv, log); err != nil {
		return err
	}
	stopLoops()
	err = shutdown(cfg, log, health, servers...)
	// Spans of the requests just drained are flushed last, within the same
	// bound as the drain.
	fctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if terr := stopTracing(fctx); terr != nil {
		log.Warn("tracing: spans could not be flushed", "err", terr)
	}
	return err
}

// startTracing turns tracing on when an OTLP endpoint is configured (serve
// mode only) and returns the function that flushes and stops it. Nothing is
// started, read or sent otherwise.
func startTracing(ctx context.Context, mode string, cfg config.Config, log *slog.Logger) (func(context.Context) error, error) {
	if mode != ModeServe || !cfg.Tracing.Enabled() {
		return func(context.Context) error { return nil }, nil
	}
	headers, err := cfg.Tracing.HeaderMap()
	if err != nil {
		return nil, err
	}
	stop, err := observability.InitTracing(ctx, observability.TracingOptions{
		Endpoint: cfg.Tracing.URL(), Headers: headers, ServiceName: cmp.Or(cfg.Tracing.ServiceName, config.DefaultTraceServiceName),
		Version: buildinfo.Version, Sampler: cfg.Tracing.Sampler, Arg: cfg.Tracing.SamplerArg,
	})
	if err != nil {
		return nil, fmt.Errorf("tracing: %w", err)
	}
	// The collector's host only: never its path, headers or credentials.
	log.Info("tracing on", "collector", cfg.Tracing.Host(), "sampler", cmp.Or(cfg.Tracing.Sampler, config.DefaultTracesSampler),
		"sampler_arg", cfg.Tracing.SamplerArg)
	return stop, nil
}

// Timeouts of the main listener. Slow request headers are cut after
// readHeaderTimeout and idle keep-alive connections after idleTimeout. There
// is deliberately no ReadTimeout or WriteTimeout: they bound the whole
// exchange, which would cut MCP responses that stream (SSE) and calls that
// run up to a server's timeout (120 s). Handlers bound their own work with
// contexts; bodies are capped at 1 MiB (httpx.Decode).
const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
)

// newHTTPServer is the main listener: see the timeouts above. Requests keep
// running through a shutdown signal (BaseContext without cancellation) so a
// drain can finish them.
func newHTTPServer(ctx context.Context, addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}
}

// stampPeppers records which pepper made key and token digests from before
// pepper IDs (docs/phase6-operations.md "Key rotation").
func stampPeppers(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, log *slog.Logger) error {
	p, err := peppers(cfg)
	if err != nil {
		return err
	}
	n, err := keyrotation.StampPeppers(ctx, pool, p)
	if err != nil {
		return fmt.Errorf("stamp key digests with their pepper: %w", err)
	}
	if n > 0 {
		log.Info("key digests stamped with their pepper", "rows", n)
	}
	return nil
}

func peppers(cfg config.Config) (keyrotation.Peppers, error) {
	var p keyrotation.Peppers
	var err error
	if p.Current, err = secrets.ParseKey(cfg.APIKeyPepper); err != nil {
		return p, fmt.Errorf("API_KEY_PEPPER: %w", err)
	}
	if cfg.APIKeyPepperPrevious != "" {
		if p.Previous, err = secrets.ParseKey(cfg.APIKeyPepperPrevious); err != nil {
			return p, fmt.Errorf("API_KEY_PEPPER_PREVIOUS: %w", err)
		}
	}
	return p, nil
}

// rateCounterLoop deletes old rate limit windows every minute (any replica;
// deletes are idempotent).
func rateCounterLoop(ctx context.Context, st ratelimit.Store, log *slog.Logger) {
	pg, ok := st.(*ratelimit.PostgresStore)
	if !ok {
		return
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, err := pg.Cleanup(ctx); err != nil && ctx.Err() == nil {
			log.Warn("rate limit counter clean-up failed", "err", err)
		}
	}
}

// metricsObjectsLoop keeps the gateway, server and provider slugs used as
// metric labels to existing objects.
func metricsObjectsLoop(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		if err := observability.SyncObjects(ctx, pool); err != nil && ctx.Err() == nil {
			log.Debug("metrics: reading object slugs failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// NewDeps builds the services the HTTP API needs (Health and Web are left
// to the caller). The configuration must be valid for serve.
func NewDeps(cfg config.Config, pool *pgxpool.Pool, log *slog.Logger) (httpapi.Deps, error) {
	box, err := secretBox(cfg)
	if err != nil {
		return httpapi.Deps{}, err
	}
	// The development allowance for MCP server addresses (DEV_AUTH on a
	// loopback APP_URL); in production internal networks are allowed only by
	// the allowlist (the deployment's entries plus the platform admins').
	nets := registry.NewNetworks(pool, cfg.UpstreamAllowedNetworks, log)
	client := &upstream.Client{AllowPrivate: cfg.AllowPrivateUpstreams(), Networks: nets, Log: log, Eras: upstream.NewEraCache()}
	pep, err := peppers(cfg)
	if err != nil {
		return httpapi.Deps{}, err
	}
	pepper := pep.Current
	// Rate limits are counted in PostgreSQL, shared by every replica.
	rates := ratelimit.NewPostgres(pool)
	lims := limits.New(pool, log)
	reg := registry.New(pool, box, client, log)
	gws := gateways.New(pool, cfg.AppURL, log)
	gws.Limits = lims
	keys := apikeys.New(pool, pepper, gws)
	sas := serviceaccounts.New(pool, pepper, gws)
	if pep.Previous != nil {
		keys.SetPreviousPepper(pep.Previous)
		sas.SetPreviousPepper(pep.Previous)
	}
	// Client metadata documents are fetched behind the same address guard
	// as MCP servers.
	as := oauth.New(pool, gws, oauth.Config{Issuer: cfg.AppURL, Pepper: pepper, PepperPrevious: pep.Previous, Upstream: client,
		MaxRegisteredClients: cfg.OAuthMaxRegisteredClients, MaxUnusedClientsPerAddress: cfg.OAuthMaxUnusedClientsPerAddress,
		RefreshAbsoluteTTL: cfg.OAuthRefreshAbsoluteTTL, Rates: rates})
	as.Log = log
	ids := identity.New(pool, box, cfg.AppURL, log)
	ids.Prepublish = cfg.SigningKeyPrepublish
	// A manual Test of an MCP server sends the editor's identity token.
	reg.SetIdentity(ids)
	// Provider endpoints are dialled behind the same address guard as MCP
	// servers.
	provs := providers.New(pool, box, client, cfg.AppURL, log)
	// Upstream OAuth (Phase 7): the registry reads oauth servers with the
	// setup connection and deletes their connections through providers,
	// which reads capabilities after a setup sign-in.
	reg.SetOAuth(registry.OAuthSettings{AppURL: cfg.AppURL, InstanceName: cfg.Instance.Name, Hooks: provs})
	provs.Registry = reg
	// A person allows a server from My connections (decision 68): the servers
	// they may use through a gateway are the ones offered.
	provs.Reachable = gws.ReachableServers
	// Per-person secrets (decision 72): people enter their own key for servers
	// in person_secret mode; the setup person's key reads the server's
	// capabilities through the registry.
	pers := personsecrets.New(pool, box, cfg.AppURL, log)
	pers.Reachable = gws.ReachableServers
	pers.Registry = reg
	// Trusted agent platforms (decisions 65 and 66): their keys are fetched
	// behind the same address guard as MCP servers; a person named in an
	// agent token must have signed in with this portal's own issuer.
	agents := agentidentity.New(pool, client, cfg.AppURL, personIssuer(cfg), log)
	// Automation tokens (docs/automation-tokens.md) and notifications
	// (docs/notifications.md). Webhook URLs get their own address guard,
	// never the MCP servers' internal-network allowlist.
	autoSvc := automation.New(pool, pepper)
	if pep.Previous != nil {
		autoSvc.SetPreviousPepper(pep.Previous)
	}
	autoSvc.Observe = func(result string) { observability.AutomationTokenAuth.WithLabelValues(result).Inc() }
	notifier := notify.New(pool, box, notify.NewWebhookClient(cfg.NotifyWebhookAllowedNetworks, log), notify.Config{
		SMTP: cfg.SMTP, AppURL: cfg.AppURL, InstanceName: cfg.Instance.Name, Interval: cfg.NotificationInterval, Version: buildinfo.Version}, log)
	notifier.Observe = func(channel, event, outcome string) {
		observability.NotificationDeliveries.WithLabelValues(channel, event, outcome).Inc()
	}
	notifier.ObserveLeader = func(leader bool) { observability.SetLeader("notifications", leader) }
	reg.SetNotifier(notifier)
	provs.Notify = notifier
	callSvc := calls.New(pool)
	ret := retention.New(pool, retention.Config{Interval: cfg.RetentionInterval, BatchSize: int32(cfg.RetentionBatchSize)}, log)
	ret.Hooks = []retention.Hook{provs.Cleanup, pers.Cleanup, rates.Cleanup, agents.Cleanup, func(ctx context.Context) (int64, error) {
		return notifier.Purge(ctx, int32(cfg.RetentionBatchSize), func(kind string, n int64) {
			observability.RetentionDeleted.WithLabelValues(kind).Add(float64(n))
		})
	}}
	ret.Observe = observeRetention
	capt := capture.New(pool, box, callSvc, ret, log)
	capt.Observe = capture.Observer{
		Captured: observability.PayloadCaptures.Inc,
		Redactions: func(rule string, n int) {
			observability.PayloadRedactions.WithLabelValues(redactionLabel(rule)).Add(float64(n))
		},
		Failed: observability.PayloadCaptureErrors.Inc,
	}
	use := usage.New(pool, log)
	use.Observe = func(leader bool, success time.Time) {
		observability.SetLeader("usage_rollup", leader)
		if leader {
			observability.UsageRollupLastSuccess.Set(float64(success.Unix()))
		}
	}
	authSvc := auth.NewService(cfg, pool, log)
	authSvc.SetRateStore(rates)
	return httpapi.Deps{
		Config:          cfg,
		Pool:            pool,
		Log:             log,
		Auth:            authSvc,
		Teams:           teams.NewService(pool),
		Platform:        platform.NewService(pool),
		Registry:        reg,
		Gateways:        gws,
		APIKeys:         keys,
		Identity:        ids,
		Calls:           callSvc,
		Limits:          lims,
		Capture:         capt,
		Retention:       ret,
		Usage:           use,
		RateStore:       rates,
		OAuth:           as,
		ServiceAccounts: sas,
		AgentPlatforms:  agents,
		Providers:       provs,
		PersonSecrets:   pers,
		Automation:      autoSvc,
		Notify:          notifier,
		Overview:        overview.New(pool),
		MCP: &mcpgw.Handler{Gateways: gws, Keys: keys, OAuth: as, ServiceAccounts: sas, Agents: agents, Identity: ids, Registry: reg, Providers: provs, PersonSecrets: pers, Secrets: box,
			Limits: lims, RateStore: rates, Capture: capt, Pool: pool, AppURL: cfg.AppURL, Log: log},
	}, nil
}

// personIssuer is the issuer people sign in with here: OIDC_ISSUER, or the
// development issuer when only DEV_AUTH is on. An agent token's person.iss
// must equal it (decision 65).
func personIssuer(cfg config.Config) string {
	if cfg.OIDC.Issuer != "" {
		return cfg.OIDC.Issuer
	}
	if cfg.DevAuth {
		return auth.DevIssuer
	}
	return ""
}

// observeRetention records a retention run's metrics.
func observeRetention(run retention.Run, leader bool) {
	observability.SetLeader("retention", leader)
	if !leader {
		return
	}
	for _, k := range retention.Kinds {
		if n := run.Deleted[k.Kind]; n > 0 {
			observability.RetentionDeleted.WithLabelValues(k.Kind).Add(float64(n))
		}
		if _, failed := run.Errors[k.Kind]; !failed {
			observability.RetentionLastSuccess.WithLabelValues(k.Kind).Set(float64(run.FinishedAt.Unix()))
		}
	}
}

// redactionLabel bounds the rule label: admin patterns are one label.
func redactionLabel(rule string) string {
	if len(rule) > 8 && rule[:8] == "pattern:" {
		return "pattern"
	}
	return rule
}

// secretBox opens ENCRYPTION_KEY (and ENCRYPTION_KEY_PREVIOUS).
func secretBox(cfg config.Config) (*secrets.Box, error) {
	key, err := secrets.ParseKey(cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("ENCRYPTION_KEY: %w", err)
	}
	var previous [][]byte
	if cfg.EncryptionKeyPrevious != "" {
		prev, err := secrets.ParseKey(cfg.EncryptionKeyPrevious)
		if err != nil {
			return nil, fmt.Errorf("ENCRYPTION_KEY_PREVIOUS: %w", err)
		}
		previous = append(previous, prev)
	}
	return secrets.New(key, previous...)
}

// cleanupLoop deletes expired sessions and sign-in states, and expired
// authorization states and consent links of delegated credentials. Deletes
// are idempotent, so every replica may run it; no leader election is needed.
func cleanupLoop(ctx context.Context, a *auth.Service, p *providers.Service, tokens *automation.Service, log *slog.Logger) {
	t := time.NewTicker(cleanupInterval)
	defer t.Stop()
	for {
		sessions, logins, err := a.Cleanup(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			log.Warn("session cleanup failed", "err", err)
		case sessions+logins > 0:
			log.Debug("expired sessions deleted", "sessions", sessions, "loginStates", logins)
		}
		if n, err := p.Cleanup(ctx); err != nil && ctx.Err() == nil {
			log.Warn("connect request cleanup failed", "err", err)
		} else if n > 0 {
			log.Debug("expired connect requests and states deleted", "count", n)
		}
		if n, err := tokens.Cleanup(ctx); err != nil && ctx.Err() == nil {
			log.Warn("automation token clean-up failed", "err", err)
		} else if n > 0 {
			log.Debug("old automation tokens deleted", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// serve runs srv until ctx is cancelled or the server fails.
func serve(ctx context.Context, srv *http.Server, log *slog.Logger) error {
	serveErr := make(chan error, 1)
	go func() {
		log.Info("http listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
		close(serveErr)
	}()
	select {
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
	case <-ctx.Done():
	}
	return nil
}

// shutdown drains traffic before stopping: readiness fails first so the load
// balancer removes the pod, then in-flight requests get SHUTDOWN_TIMEOUT to
// finish.
func shutdown(cfg config.Config, log *slog.Logger, health *httpapi.Health, servers ...*http.Server) error {
	log.Info("shutting down", "drain_delay", cfg.ShutdownDelay, "timeout", cfg.ShutdownTimeout)
	health.SetDraining()
	time.Sleep(cfg.ShutdownDelay)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	var errs []error
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("http shutdown (%s): %w", srv.Addr, err))
		}
	}
	if len(errs) == 0 {
		log.Info("shutdown complete")
	}
	return errors.Join(errs...)
}
