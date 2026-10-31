package scancorpus

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

//go:embed public.json
var manifestJSON []byte

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Repository      string `json:"repository"`
	Revision        string `json:"revision"`
	License         string `json:"license"`
	DeclaredLicense string `json:"declared_license"`
	Gated           bool   `json:"gated"`
	LicenseFile     File   `json:"license_file"`
	TextFile        File   `json:"text_file"`
}

func PinnedManifest() Manifest { var m Manifest; _ = json.Unmarshal(manifestJSON, &m); return m }

// Validate deliberately supports one reviewed public source, not arbitrary URLs.
// Any new source requires code review and a licence review at its pinned revision.
func (m Manifest) Validate() error {
	validHex := func(s string, n int) bool {
		b, e := hex.DecodeString(s)
		return e == nil && len(b) == n && s == strings.ToLower(s)
	}
	if m.Repository != "ethz-spylab/agentdojo" || !validHex(m.Revision, 20) || m.Gated || m.License != "MIT" || m.DeclaredLicense != m.License {
		return errors.New("manifest_refused")
	}
	for _, f := range []File{m.LicenseFile, m.TextFile} {
		if !validHex(f.SHA256, 32) || !regexp.MustCompile(`^[a-zA-Z0-9_./-]+$`).MatchString(f.Path) || strings.Contains(f.Path, "..") || strings.HasPrefix(f.Path, "/") {
			return errors.New("manifest_refused")
		}
	}
	if m.LicenseFile.Path != "LICENSE" || m.TextFile.Path != "src/agentdojo/attacks/baseline_attacks.py" {
		return errors.New("manifest_refused")
	}
	return nil
}

const MaxDownloadBytes = 1 << 20

// Download returns verified bytes only. Errors are fixed classes, never transport
// error bodies, URLs, remote text or snippets. No auth, proxy, redirects or cache.
func Download(ctx context.Context, m Manifest, transport http.RoundTripper) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if transport == nil {
		transport = &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	}
	c := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect_refused") }}
	fetch := func(f File) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://raw.githubusercontent.com/"+m.Repository+"/"+m.Revision+"/"+f.Path, nil)
		if err != nil {
			return nil, errors.New("request_refused")
		}
		res, err := c.Do(req)
		if err != nil {
			return nil, errors.New("network_refused")
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return nil, errors.New("status_refused")
		}
		b, err := io.ReadAll(io.LimitReader(res.Body, MaxDownloadBytes+1))
		if err != nil {
			return nil, errors.New("read_refused")
		}
		if len(b) == 0 || len(b) > MaxDownloadBytes {
			return nil, errors.New("size_refused")
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return nil, errors.New("hash_refused")
		}
		return b, nil
	}
	license, err := fetch(m.LicenseFile)
	if err != nil {
		return nil, err
	}
	// In addition to exact reviewed bytes, refuse a contradictory licence header.
	if !bytes.HasPrefix(license, []byte("MIT License\n")) || !bytes.Contains(license, []byte("Permission is hereby granted, free of charge")) {
		return nil, errors.New("license_refused")
	}
	return fetch(m.TextFile)
}
