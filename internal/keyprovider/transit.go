package keyprovider

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxContext    = 1024
	maxCiphertext = 4096
	maxResponse   = 16384
)

var segment = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// TokenSource is injected by the caller; no ambient authentication is discovered.
// It must honor cancellation and never log credentials. It is called once per
// valid operation, under the operation deadline. No authentication exchange occurs.
type TokenSource func(context.Context) (string, error)

// TransitConfig targets an existing, derived aes256-gcm96 Transit key. The
// operator must provision it separately; context is Transit derivation context,
// NOT portal row AAD. WriteVersion is explicit, never an implicit latest version.
type TransitConfig struct {
	Origin, Mount, Key string
	WriteVersion       uint32
	Token              TokenSource
	RootCAs            *x509.CertPool
	Timeout            time.Duration // default 5s, maximum 30s, including token acquisition
	AllowLoopbackHTTP  bool          // explicit development-only exception for literal IPs
}
type Transit struct {
	ref                Reference
	origin, mount, key string
	version            uint32
	token              TokenSource
	timeout            time.Duration
	client             *http.Client
}

var _ Provider = (*Transit)(nil)
var _ Rewrapper = (*Transit)(nil)

func NewTransit(c TransitConfig) (*Transit, error) {
	u, e := url.Parse(c.Origin)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" || u.Opaque != "" || strings.ContainsAny(c.Origin, "\\\r\n\t#?%") {
		return nil, fail(Invalid)
	}
	if u.Scheme != "https" {
		ip, e := netip.ParseAddr(u.Hostname())
		if u.Scheme != "http" || !c.AllowLoopbackHTTP || e != nil || !ip.IsLoopback() {
			return nil, fail(Invalid)
		}
	}
	if !segment.MatchString(c.Key) || len(c.Mount) > 512 || c.Token == nil || c.WriteVersion == 0 {
		return nil, fail(Invalid)
	}
	for _, s := range strings.Split(c.Mount, "/") {
		if !segment.MatchString(s) {
			return nil, fail(Invalid)
		}
	}
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}
	if c.Timeout < 0 || c.Timeout > 30*time.Second {
		return nil, fail(Invalid)
	}
	var roots *x509.CertPool
	if c.RootCAs != nil {
		roots = c.RootCAs.Clone()
	}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: c.Timeout}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: c.Timeout, ResponseHeaderTimeout: c.Timeout, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: maxResponse}
	return &Transit{ref: Reference{"transit", c.Origin + "/v1/" + c.Mount + "/keys/" + c.Key}, origin: c.Origin, mount: c.Mount, key: c.Key, version: c.WriteVersion, token: c.Token, timeout: c.Timeout, client: &http.Client{Transport: tr, Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (t *Transit) Reference() Reference { return t.ref }
func validContext(b []byte) bool        { return len(b) > 0 && len(b) <= maxContext }
func cipherVersion(s string) (uint32, bool) {
	if len(s) > maxCiphertext {
		return 0, false
	}
	p := strings.Split(s, ":")
	if len(p) != 3 || p[0] != "vault" || len(p[1]) < 2 || p[1][0] != 'v' {
		return 0, false
	}
	v, e := strconv.ParseUint(p[1][1:], 10, 32)
	if e != nil || v == 0 || p[1] != "v"+strconv.FormatUint(v, 10) {
		return 0, false
	}
	b, e := base64.StdEncoding.Strict().DecodeString(p[2])
	return uint32(v), e == nil && len(b) == 60 && base64.StdEncoding.EncodeToString(b) == p[2] // AES-GCM nonce + 32-byte DEK + tag
}
func (t *Transit) Wrap(ctx context.Context, key, binding []byte) (Wrapped, error) {
	if len(key) != 32 || !validContext(binding) {
		return Wrapped{}, fail(Invalid)
	}
	return t.write(ctx, "encrypt", map[string]any{"plaintext": base64.StdEncoding.EncodeToString(key), "context": base64.StdEncoding.EncodeToString(binding), "key_version": t.version})
}
func (t *Transit) validate(w Wrapped, b []byte) (uint32, error) {
	if w.Reference != t.ref {
		return 0, fail(Mismatch)
	}
	v, ok := cipherVersion(w.Ciphertext)
	if !ok || !validContext(b) {
		return 0, fail(Invalid)
	}
	return v, nil
}
func (t *Transit) Unwrap(ctx context.Context, w Wrapped, b []byte) ([]byte, error) {
	if _, e := t.validate(w, b); e != nil {
		return nil, e
	}
	d, e := t.call(ctx, "decrypt", map[string]any{"ciphertext": w.Ciphertext, "context": base64.StdEncoding.EncodeToString(b)})
	if e != nil {
		return nil, e
	}
	var s string
	if json.Unmarshal(d["plaintext"], &s) != nil || len(s) != 44 {
		return nil, fail(Protocol)
	}
	key, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != s {
		return nil, fail(Protocol)
	}
	return key, nil
}
func (t *Transit) Rewrap(ctx context.Context, w Wrapped, b []byte) (Wrapped, error) {
	v, e := t.validate(w, b)
	if e != nil {
		return Wrapped{}, e
	}
	if v > t.version {
		return Wrapped{}, fail(Mismatch)
	}
	return t.write(ctx, "rewrap", map[string]any{"ciphertext": w.Ciphertext, "context": base64.StdEncoding.EncodeToString(b), "key_version": t.version})
}
func (t *Transit) write(ctx context.Context, op string, p map[string]any) (Wrapped, error) {
	d, e := t.call(ctx, op, p)
	if e != nil {
		return Wrapped{}, e
	}
	var s string
	if json.Unmarshal(d["ciphertext"], &s) != nil {
		return Wrapped{}, fail(Protocol)
	}
	v, ok := cipherVersion(s)
	if !ok {
		return Wrapped{}, fail(Protocol)
	}
	if v != t.version {
		return Wrapped{}, fail(Mismatch)
	}
	if raw, ok := d["key_version"]; ok {
		var n uint32
		if json.Unmarshal(raw, &n) != nil || n != v {
			return Wrapped{}, fail(Protocol)
		}
	}
	return Wrapped{t.ref, s}, nil
}
func (t *Transit) call(parent context.Context, op string, p map[string]any) (map[string]json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(parent, t.timeout)
	defer cancel()
	if ctx.Err() != nil {
		return nil, fail(Cancelled)
	}
	token, e := t.token(ctx)
	if ctx.Err() != nil {
		return nil, fail(Cancelled)
	}
	if e != nil || len(token) == 0 || len(token) > 4096 {
		return nil, fail(Credential)
	}
	for _, c := range token {
		if c < 33 || c > 126 {
			return nil, fail(Credential)
		}
	}
	body, _ := json.Marshal(p)
	// No GetBody, idempotency header, redirect following, proxy discovery or retries.
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, t.origin+"/v1/"+t.mount+"/"+op+"/"+url.PathEscape(t.key), bytes.NewBuffer(body))
	if e != nil {
		return nil, fail(Invalid)
	}
	req.GetBody = nil
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, e := t.client.Do(req)
	if e != nil {
		var timeout net.Error
		if ctx.Err() != nil || (errors.As(e, &timeout) && timeout.Timeout()) {
			return nil, fail(Cancelled)
		}
		return nil, fail(Unavailable)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		k := Refused
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			k = Unauthorized
		}
		return nil, &Error{Kind: k, Status: resp.StatusCode}
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if ctx.Err() != nil {
		return nil, fail(Cancelled)
	}
	if e != nil || len(b) > maxResponse || !uniqueJSON(b) {
		return nil, fail(Protocol)
	}
	var envelope map[string]json.RawMessage
	var data map[string]json.RawMessage
	if json.Unmarshal(b, &envelope) != nil || json.Unmarshal(envelope["data"], &data) != nil || data == nil {
		return nil, fail(Protocol)
	}
	// Never accept a success/error hybrid or a response-wrapping envelope.
	if raw, ok := envelope["errors"]; ok && string(raw) != "null" && string(raw) != "[]" {
		return nil, fail(Protocol)
	}
	if raw, ok := envelope["wrap_info"]; ok && string(raw) != "null" {
		return nil, fail(Protocol)
	}
	if _, ok := data["error"]; ok {
		return nil, fail(Protocol)
	}
	return data, nil
}

// Reject duplicate members (including escaped aliases) at every nesting level,
// malformed/trailing JSON and excessive nesting, while allowing Vault metadata.
func uniqueJSON(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 32 {
			return false
		}
		tok, e := d.Token()
		if e != nil {
			return false
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return false
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return false
				}
				seen[s] = true
				if !value(depth + 1) {
					return false
				}
			}
			tok, e = d.Token()
			return e == nil && tok == json.Delim('}')
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			tok, e = d.Token()
			return e == nil && tok == json.Delim(']')
		}
		return false
	}
	if !value(0) {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}
