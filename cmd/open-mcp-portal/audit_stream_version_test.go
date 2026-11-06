package main

import (
	"bytes"
	"github.com/ncecere/open-mcp-portal/internal/buildinfo"
	"strings"
	"testing"
)

func TestCheckpointReaderVersionOK(t *testing.T) {
	for v, ok := range map[string]bool{
		"0.15.0": true, "1.0.0": true, "0.14.1": true,
		"0.14.0": false, "0.13.9": false, "0.9.99": false,
		"dev": false, "v0.15.0": false, "0.15.0-rc.1": false, "0.15.0-3-gabc": false, "": false,
	} {
		if got := checkpointReaderVersionOK(v) == nil; got != ok {
			t.Errorf("%q: ok=%v want %v", v, got, ok)
		}
	}
}

func TestSinkReaderVersionOK(t *testing.T) {
	for v, ok := range map[string]bool{"0.14.0": false, "0.15.0": true, "dev": false, "0.15.0-rc.1": false, "0.14.0-2-gabc": false} {
		if got := sinkReaderVersionOK(v) == nil; got != ok {
			t.Errorf("%s: %v", v, got)
		}
	}
}

func TestEnableSinksRefuses0140Build(t *testing.T) {
	old := buildinfo.Version
	buildinfo.Version = "0.14.0"
	defer func() { buildinfo.Version = old }()
	var out bytes.Buffer
	if err := runAuditStream([]string{"enable-sinks", "--min-reader-version-ack"}, &out); err == nil || !strings.Contains(err.Error(), "newer than 0.14.0") {
		t.Fatalf("old build accepted: %v", err)
	}
}
