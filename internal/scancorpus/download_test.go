package scancorpus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func digest(s string) string                                              { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
func TestManifestRefusals(t *testing.T) {
	for _, change := range []func(*Manifest){
		func(m *Manifest) { m.License = "" }, func(m *Manifest) { m.DeclaredLicense = "Apache-2.0" }, func(m *Manifest) { m.Gated = true }, func(m *Manifest) { m.Revision = "main" }, func(m *Manifest) { m.TextFile.Path = "../file" }, func(m *Manifest) { m.TextFile.SHA256 = "" }, func(m *Manifest) { m.Repository = "other/source" }, func(m *Manifest) { m.LicenseFile.Path = "" },
	} {
		m := PinnedManifest()
		change(&m)
		called := false
		_, err := Download(context.Background(), m, transportFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, errors.New("private canary") }))
		if err == nil || called {
			t.Fatal("invalid manifest used network")
		}
	}
}
func TestDownloadOffline(t *testing.T) {
	license := "MIT License\nPermission is hereby granted, free of charge\nOriginal synthetic test licence stub."
	text := "Original synthetic corpus, not copied."
	for _, mode := range []string{"ok", "missing-license", "missing-text", "network", "read", "oversize", "empty", "hash", "license", "redirect", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			m := PinnedManifest()
			m.LicenseFile.SHA256 = digest(license)
			m.TextFile.SHA256 = digest(text)
			if mode == "license" {
				m.LicenseFile.SHA256 = digest("not MIT")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			calls := 0
			rt := transportFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Scheme != "https" || req.URL.Host != "raw.githubusercontent.com" || req.Header.Get("Authorization") != "" {
					t.Fatal("unexpected request")
				}
				if mode == "network" || req.Context().Err() != nil {
					return nil, errors.New(text)
				}
				body := text
				if strings.HasSuffix(req.URL.Path, "LICENSE") {
					body = license
				}
				status := 200
				switch mode {
				case "missing-license":
					if calls == 1 {
						status = 404
					}
				case "missing-text":
					if calls == 2 {
						status = 404
					}
				case "oversize":
					body = strings.Repeat("q", MaxDownloadBytes+1)
				case "empty":
					body = ""
				case "hash":
					body = text
				case "license":
					body = "not MIT"
				case "redirect":
					status = 302
				}
				var reader io.ReadCloser = io.NopCloser(strings.NewReader(body))
				if mode == "read" {
					reader = io.NopCloser(errorReader{})
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://example.invalid/"}}, Body: reader, Request: req}, nil
			})
			got, err := Download(ctx, m, rt)
			if mode == "ok" {
				if err != nil || string(got) != text {
					t.Fatal("valid corpus refused")
				}
			} else {
				expected := map[string]string{"missing-license": "status_refused", "missing-text": "status_refused", "network": "network_refused", "cancel": "network_refused", "read": "read_refused", "oversize": "size_refused", "empty": "size_refused", "hash": "hash_refused", "license": "license_refused", "redirect": "network_refused"}
				if err == nil || len(got) != 0 || err.Error() != expected[mode] {
					t.Fatal("refusal/privacy failed")
				}
			}
			if mode == "redirect" && calls != 1 {
				t.Fatal("redirect followed")
			}
		})
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("remote private text") }
