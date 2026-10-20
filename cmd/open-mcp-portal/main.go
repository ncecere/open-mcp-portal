// Command open-mcp-portal runs Open MCP Portal, a self-hosted portal that
// gives a company's people and agents governed access to its MCP servers.
//
//	open-mcp-portal serve     HTTP API, embedded UI and background loops
//	open-mcp-portal migrate   apply database migrations and exit
//	open-mcp-portal doctor    check the configuration, Postgres and migrations
//	open-mcp-portal rotate-keys  re-encrypt stored secrets with ENCRYPTION_KEY
//	open-mcp-portal version   print the version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/app"
	"github.com/ncecere/open-mcp-portal/internal/buildinfo"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/doctor"
	"github.com/ncecere/open-mcp-portal/internal/keyrotation"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store"
)

const usage = `usage: open-mcp-portal <command>

commands:
  serve     HTTP API, embedded UI and background loops
  migrate   apply database migrations and exit
  doctor    check the configuration, Postgres and migrations (--json, --help)
  rotate-keys
            re-encrypt stored secrets from ENCRYPTION_KEY_PREVIOUS to
            ENCRYPTION_KEY and list keys on an old API key pepper
            (--dry-run, --batch-size, --help)
  version   print the version

Configuration comes from environment variables and the optional YAML file
named by OMP_CONFIG_FILE. See .env.example.
`

// errChecksFailed makes `doctor` exit non-zero after printing its report.
var errChecksFailed = errors.New("some checks failed")

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "open-mcp-portal:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := app.ModeServe
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "version", "--version":
		fmt.Println(buildinfo.String())
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	case "doctor":
		return runDoctor(args[1:], os.Stdout)
	case "rotate-keys":
		return runRotateKeys(args[1:], os.Stdout)
	case app.ModeServe, app.ModeMigrate:
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration:\n%w", err)
	}
	log := newLogger(os.Stdout, cfg.LogLevel, cfg.LogFormat)
	// Packages that log through slog's package functions (httpx.Internal)
	// write in the same structured format as everything else.
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.Run(ctx, cmd, cfg, log)
}

func newLogger(w io.Writer, level, format string) *slog.Logger {
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(level))
	opts := &slog.HandlerOptions{Level: lvl}
	// Records logged with a traced request's context also carry trace_id and
	// span_id (beside request_id).
	if format == "text" {
		return slog.New(observability.NewTraceLogHandler(slog.NewTextHandler(w, opts)))
	}
	return slog.New(observability.NewTraceLogHandler(slog.NewJSONHandler(w, opts)))
}

// runDoctor implements `open-mcp-portal doctor [flags]`. It uses the same
// configuration as the other commands, so in a pod (the image has no shell):
// kubectl exec deploy/open-mcp-portal -- /open-mcp-portal doctor
func runDoctor(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the report as JSON")
	mode := fs.String("mode", "serve", "process mode whose configuration is validated: serve or migrate")
	timeout := fs.Duration("timeout", 10*time.Second, "time limit of each check")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "usage: open-mcp-portal doctor [--json] [--mode serve|migrate] [--timeout 10s]\n\n"+
			"Checks the configuration (including the production safety checks), then\n"+
			"PostgreSQL and the migration state. Exits 1 if any check fails.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}
	if *mode != app.ModeServe && *mode != app.ModeMigrate {
		return fmt.Errorf("--mode must be serve or migrate")
	}
	var rep doctor.Report
	if cfg, err := config.Load(); err != nil {
		rep = doctor.ConfigLoadFailed(*mode, err)
	} else {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		rep = doctor.Run(ctx, cfg, doctor.Options{Mode: *mode, Timeout: *timeout})
	}
	write := rep.WriteText
	if *asJSON {
		write = rep.WriteJSON
	}
	if err := write(stdout); err != nil {
		return err
	}
	if !rep.OK {
		return errChecksFailed
	}
	return nil
}

// runRotateKeys implements `open-mcp-portal rotate-keys [--dry-run]
// [--batch-size 100]` (docs/deploy.md "Key rotation"): it checks that every
// sealed value opens with ENCRYPTION_KEY or ENCRYPTION_KEY_PREVIOUS (and
// stops, naming table and row, if any doesn't), re-seals values still on
// the previous key, and lists keys still on another API key pepper.
// Idempotent and safe while the portal serves.
func runRotateKeys(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("rotate-keys", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "check and count; write nothing")
	batch := fs.Int("batch-size", keyrotation.DefaultBatchSize, "values re-encrypted per transaction (1-10000)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "usage: open-mcp-portal rotate-keys [--dry-run] [--batch-size 100]\n\n"+
			"Re-encrypts every stored secret (server header values, signing keys, auth\n"+
			"provider client secrets, connection tokens, PKCE verifiers, consent request\n"+
			"IDs, captured payloads) from ENCRYPTION_KEY_PREVIOUS to ENCRYPTION_KEY, and\n"+
			"lists keys still on API_KEY_PEPPER_PREVIOUS. Uses the same configuration as\n"+
			"serve. Safe to run while the portal serves and to run again.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}
	if *batch < 1 || *batch > 10_000 {
		return fmt.Errorf("--batch-size must be between 1 and 10000")
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration:\n%w", err)
	}
	if err := cfg.Validate(app.ModeServe); err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	key, err := secrets.ParseKey(cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("ENCRYPTION_KEY: %w", err)
	}
	var previous [][]byte
	if cfg.EncryptionKeyPrevious != "" {
		p, err := secrets.ParseKey(cfg.EncryptionKeyPrevious)
		if err != nil {
			return fmt.Errorf("ENCRYPTION_KEY_PREVIOUS: %w", err)
		}
		previous = append(previous, p)
	}
	box, err := secrets.New(key, previous...)
	if err != nil {
		return err
	}
	var peppers keyrotation.Peppers
	if peppers.Current, err = secrets.ParseKey(cfg.APIKeyPepper); err != nil {
		return fmt.Errorf("API_KEY_PEPPER: %w", err)
	}
	if cfg.APIKeyPepperPrevious != "" {
		if peppers.Previous, err = secrets.ParseKey(cfg.APIKeyPepperPrevious); err != nil {
			return fmt.Errorf("API_KEY_PEPPER_PREVIOUS: %w", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if st, err := store.Migrations(ctx, pool); err != nil {
		return fmt.Errorf("migration state: %w", err)
	} else if st.Pending {
		return fmt.Errorf("the database is at migration %d but this binary needs %d: run `open-mcp-portal migrate` first", st.Current, st.Latest)
	}
	sum, err := keyrotation.Run(ctx, pool, box, peppers, keyrotation.Options{DryRun: *dryRun, BatchSize: *batch, Out: stdout})
	if err != nil {
		return err
	}
	if !*dryRun {
		fmt.Fprintf(stdout, "\nDone: %d value(s) re-encrypted.\n", sum.Reencrypted())
	}
	return nil
}
