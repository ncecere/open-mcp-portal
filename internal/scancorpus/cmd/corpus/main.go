// corpus emits only bounded aggregate evidence. Public text is scratch-only.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/scancorpus"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	public := flag.Bool("public", false, "fetch the pinned reviewed public sample")
	flag.Parse()
	report := struct {
		Primitives  scancorpus.Report `json:"primitives"`
		Definitions scancorpus.Report `json:"definitions"`
	}{scancorpus.SyntheticReport(), scancorpus.DefinitionReport()}
	if *public {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		data, err := scancorpus.Download(ctx, scancorpus.PinnedManifest(), nil)
		if err != nil {
			return err
		}
		// Never write downloaded content in the checkout or report directories.
		dir, err := os.MkdirTemp("", "omp-public-corpus-")
		if err != nil {
			return fmt.Errorf("scratch_refused")
		}
		defer os.RemoveAll(dir)
		if err = os.WriteFile(dir+"/sample", data, 0600); err != nil {
			return fmt.Errorf("scratch_refused")
		}
		report.Primitives = scancorpus.PublicReport(string(data))
		report.Definitions = scancorpus.PublicDefinitionReport(string(data))
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}
