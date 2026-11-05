package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/auditstream"
	"github.com/ncecere/open-mcp-portal/internal/config"
)

func runAuditStream(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: audit-stream status|rebind|rebase [--resume-after-seq=N]")
	}
	fs := flag.NewFlagSet("audit-stream "+args[0], flag.ContinueOnError)
	resume := fs.Int64("resume-after-seq", -1, "declare a discontinuity through this sequence")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	specified := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "resume-after-seq" {
			specified = true
		}
	})
	if specified && (args[0] != "rebase" || *resume < 0) {
		return fmt.Errorf("--resume-after-seq requires rebase and a nonnegative sequence")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	url := cfg.DatabaseURL
	if args[0] != "status" {
		url = cfg.MigrationURL()
	}
	ctx := context.Background()
	p, err := pgxpool.New(ctx, url)
	if err != nil {
		return err
	}
	defer p.Close()
	s := auditstream.Sealer{Pool: p}
	switch args[0] {
	case "status":
		var raw []byte
		if err = p.QueryRow(ctx, `SELECT to_jsonb(s) FROM omp_audit.state s WHERE singleton`).Scan(&raw); err != nil {
			return err
		}
		var v any
		if err = json.Unmarshal(raw, &v); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(v)
	case "rebind":
		return s.Rebind(ctx)
	case "rebase":
		var n *int64
		if *resume >= 0 {
			n = resume
		}
		return s.Rebase(ctx, n)
	default:
		return fmt.Errorf("unknown audit-stream command %q", args[0])
	}
}
