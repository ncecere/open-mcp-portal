package main

import "testing"

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
