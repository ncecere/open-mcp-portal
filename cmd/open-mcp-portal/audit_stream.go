package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/auditstream"
	"github.com/ncecere/open-mcp-portal/internal/buildinfo"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
)

func runAuditStream(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: audit-stream status|rebind|rebase|enable-checkpoints|enable-sinks|disable-sinks|rotate-checkpoint-key [--resume-after-seq=N]")
	}
	fs := flag.NewFlagSet("audit-stream "+args[0], flag.ContinueOnError)
	ack := fs.Bool("min-reader-version-ack", false, "acknowledge one-way minimum reader version transition")
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
	if *ack && args[0] != "enable-checkpoints" && args[0] != "enable-sinks" {
		return fmt.Errorf("--min-reader-version-ack requires enable-checkpoints or enable-sinks")
	}
	if args[0] == "enable-checkpoints" {
		fmt.Fprintln(out, "WARNING: enabling checkpoints is a one-way minimum-reader-version transition. Upgrade all replicas first; never roll back below the recorded version.")
		if !*ack {
			return fmt.Errorf("--min-reader-version-ack is required")
		}
		if err := checkpointReaderVersionOK(buildinfo.Version); err != nil {
			return err
		}
	}
	if args[0] == "enable-sinks" {
		fmt.Fprintln(out, "Enable sinks only after every replica runs this release. Before rollback: disable-sinks, then drain unfanned sink events with this release.")
		if !*ack {
			return fmt.Errorf("--min-reader-version-ack is required")
		}
		if err := sinkReaderVersionOK(buildinfo.Version); err != nil {
			return err
		}
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	url := cfg.DatabaseURL
	if args[0] == "rebind" || args[0] == "rebase" || args[0] == "enable-checkpoints" || args[0] == "enable-sinks" || args[0] == "disable-sinks" {
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
		if err = p.QueryRow(ctx, `SELECT to_jsonb(s)||jsonb_build_object('sink_settings',(SELECT to_jsonb(g) FROM omp_audit_ext.sink_settings g),'active_key_fingerprint',(SELECT translate(rtrim(encode(kid,'base64'),'='),'+/','-_') FROM omp_audit_ext.checkpoint_keys WHERE state='active')) FROM omp_audit.state s WHERE singleton`).Scan(&raw); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(json.RawMessage(raw))
	case "enable-sinks", "disable-sinks":
		return pgx.BeginFunc(ctx, p, func(tx pgx.Tx) error {
			enabled := args[0] == "enable-sinks"
			version := buildinfo.Version
			var recorded *string
			if err := tx.QueryRow(ctx, `SELECT min_reader_version FROM omp_audit_ext.sink_settings WHERE singleton`).Scan(&recorded); err != nil {
				return err
			}
			// Disabling a never-enabled installation is a no-op. Assigning a
			// development version here would poison the immutable gate version.
			if recorded == nil && !enabled {
				return nil
			}
			if recorded != nil {
				version = *recorded
			}
			if _, err := tx.Exec(ctx, `SELECT omp_audit_ext.set_sinks_enabled($1,$2)`, enabled, version); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO public.audit_log(actor_kind,action,target_type,target_id,metadata) VALUES('system','audit.sinks_gate','audit_stream','sinks',jsonb_build_object('enabled',$1::boolean,'min_reader_version',$2::text))`, enabled, version)
			return err
		})
	case "enable-checkpoints":
		return pgx.BeginFunc(ctx, p, func(tx pgx.Tx) error {
			if _, e := tx.Exec(ctx, `SELECT omp_audit_ext.enable_checkpoints($1)`, buildinfo.Version); e != nil {
				return fmt.Errorf("enable checkpoints: %w", e)
			}
			_, e := tx.Exec(ctx, `INSERT INTO public.audit_log(actor_kind,action,target_type,target_id,metadata) VALUES('system','audit.checkpoints_enabled','audit_stream','checkpoints',jsonb_build_object('min_reader_version',$1::text))`, buildinfo.Version)
			return e
		})
	case "rotate-checkpoint-key":
		key, e := secrets.ParseKey(cfg.EncryptionKey)
		if e != nil {
			return e
		}
		var previous [][]byte
		if cfg.EncryptionKeyPrevious != "" {
			k, e := secrets.ParseKey(cfg.EncryptionKeyPrevious)
			if e != nil {
				return e
			}
			previous = append(previous, k)
		}
		box, e := secrets.New(key, previous...)
		if e != nil {
			return e
		}
		seq, e := auditstream.RotateCheckpointKey(ctx, p, box)
		if e != nil {
			return fmt.Errorf("rotate checkpoint key: %w", e)
		}
		_, e = fmt.Fprintf(out, "Checkpoint key rotated at sequence %d\n", seq)
		return e
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

// lastNonCheckpointRelease is the newest release whose pull/verify code does not
// understand checkpoint records (it answers a partial 200 on them). The recorded
// minimum reader version must be a clean release above it, so a development build
// still reporting that release (or a describe/dev string) cannot enable checkpoints.
var lastNonCheckpointRelease = [3]int{0, 14, 0}

func checkpointReaderVersionOK(v string) error {
	var p [3]int
	if _, err := fmt.Sscanf(v, "%d.%d.%d", &p[0], &p[1], &p[2]); err != nil || fmt.Sprintf("%d.%d.%d", p[0], p[1], p[2]) != v {
		return fmt.Errorf("enable-checkpoints needs a released build (got version %q); run it from a checkpoint-capable release", v)
	}
	for i := range p {
		if p[i] != lastNonCheckpointRelease[i] {
			if p[i] > lastNonCheckpointRelease[i] {
				return nil
			}
			break
		}
	}
	return fmt.Errorf("enable-checkpoints needs a release newer than %d.%d.%d (got %s): older releases cannot read checkpoint records", lastNonCheckpointRelease[0], lastNonCheckpointRelease[1], lastNonCheckpointRelease[2], v)
}

// The most recent release without sink-aware notification dispatch is 0.14.0.
// Keep this boundary independent when checkpoint compatibility advances.
func sinkReaderVersionOK(v string) error {
	if err := checkpointReaderVersionOK(v); err != nil {
		return fmt.Errorf("enable-sinks requires a clean release newer than 0.14.0: older dispatchers discard sink events (got %q)", v)
	}
	return nil
}
