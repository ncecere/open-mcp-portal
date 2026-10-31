package keyprovider

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const tokenSentinel = "TEST-TOKEN-DO-NOT-DISCLOSE"

var plainSentinel = []byte("TEST-DEK-DO-NOT-DISCLOSE-1234567") // exactly 32 bytes
func checkError(t *testing.T, e error, k Kind) {
	t.Helper()
	var safe *Error
	if !errors.As(e, &safe) || safe.Kind != k {
		t.Fatalf("expected safe error kind %s", k)
	}
	for _, s := range []string{tokenSentinel, string(plainSentinel), base64.StdEncoding.EncodeToString(plainSentinel), "user:pass", "SERVICE-SENTINEL"} {
		if strings.Contains(fmt.Sprintf("%+v %#v", e, e), s) {
			t.Fatal("error leaked sentinel")
		}
	}
}
func config(s *httptest.Server) TransitConfig {
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	return TransitConfig{Origin: s.URL, Mount: "team/transit", Key: "dek-key", WriteVersion: 1, RootCAs: roots, Token: func(context.Context) (string, error) { return tokenSentinel, nil }}
}
func newAdapter(t *testing.T, c TransitConfig) *Transit {
	t.Helper()
	p, e := NewTransit(c)
	if e != nil {
		t.Fatal("valid config refused")
	}
	return p
}
func validCT(v int) string {
	return fmt.Sprintf("vault:v%d:%s", v, base64.StdEncoding.EncodeToString(make([]byte, 60)))
}

// The fake implements the documented JSON wire protocol, using locally owned
// AES-GCM keys and HKDF derivation; it is not evidence of a deployed Transit.
func fakeTransit(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	masters := map[int][]byte{}
	for _, v := range []int{1, 2} {
		k := make([]byte, 32)
		if _, e := rand.Read(k); e != nil {
			t.Fatal("fixture random failure")
		}
		masters[v] = k
	}
	attempts := &atomic.Int32{}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		if r.Method != "POST" || r.URL.RawQuery != "" || r.Header.Get("X-Vault-Token") != tokenSentinel || r.Header.Get("Content-Type") != "application/json" {
			t.Error("incorrect request metadata")
			w.WriteHeader(400)
			return
		}
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) != 6 || strings.Join(parts[:4], "/") != "/v1/team/transit" || parts[5] != "dek-key" {
			t.Error("incorrect key path")
			w.WriteHeader(400)
			return
		}
		var p struct {
			Plaintext  string `json:"plaintext"`
			Ciphertext string `json:"ciphertext"`
			Context    string `json:"context"`
			Version    int    `json:"key_version"`
		}
		if json.NewDecoder(r.Body).Decode(&p) != nil {
			w.WriteHeader(400)
			return
		}
		binding, e := base64.StdEncoding.DecodeString(p.Context)
		if e != nil || len(binding) == 0 {
			w.WriteHeader(400)
			return
		}
		aead := func(v int) cipher.AEAD {
			if masters[v] == nil {
				return nil
			}
			k, e := hkdf.Key(sha256.New, masters[v], nil, string(binding), 32)
			if e != nil {
				return nil
			}
			b, _ := aes.NewCipher(k)
			a, _ := cipher.NewGCM(b)
			return a
		}
		var plain []byte
		if parts[4] == "encrypt" {
			plain, e = base64.StdEncoding.DecodeString(p.Plaintext)
		} else {
			v, ok := cipherVersion(p.Ciphertext)
			if !ok || aead(int(v)) == nil {
				w.WriteHeader(400)
				return
			}
			b, _ := base64.StdEncoding.DecodeString(strings.Split(p.Ciphertext, ":")[2])
			a := aead(int(v))
			plain, e = a.Open(nil, b[:12], b[12:], nil)
		}
		if e != nil || len(plain) != 32 {
			w.WriteHeader(400)
			return
		}
		data := map[string]any{}
		if parts[4] == "decrypt" {
			data["plaintext"] = base64.StdEncoding.EncodeToString(plain)
		} else if parts[4] == "encrypt" || parts[4] == "rewrap" {
			a := aead(p.Version)
			if a == nil {
				w.WriteHeader(400)
				return
			}
			nonce := make([]byte, 12)
			if _, e := rand.Read(nonce); e != nil {
				w.WriteHeader(500)
				return
			}
			b := a.Seal(nonce, nonce, plain, nil)
			data["ciphertext"] = fmt.Sprintf("vault:v%d:%s", p.Version, base64.StdEncoding.EncodeToString(b))
			data["key_version"] = p.Version
		} else {
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "request_id": "fake"})
	}))
	t.Cleanup(s.Close)
	return s, attempts
}
func TestRoundTripRewrap(t *testing.T) {
	if len(plainSentinel) != 32 {
		t.Fatal("fixture length")
	}
	s, n := fakeTransit(t)
	c := config(s)
	p := newAdapter(t, c)
	ctx := context.Background()
	binding := []byte("owned-epoch-context")
	wrapped, e := p.Wrap(ctx, plainSentinel, binding)
	if e != nil {
		t.Fatal(e)
	}
	got, e := p.Unwrap(ctx, wrapped, binding)
	if e != nil || !bytes.Equal(got, plainSentinel) {
		t.Fatal("wrap round trip failed")
	}
	_, e = p.Unwrap(ctx, wrapped, []byte("wrong"))
	checkError(t, e, Refused)
	c.WriteVersion = 2
	p2 := newAdapter(t, c)
	if p.Reference() != p2.Reference() {
		t.Fatal("unstable identity")
	}
	next, e := p2.Rewrap(ctx, wrapped, binding)
	if e != nil || next.Ciphertext == wrapped.Ciphertext {
		t.Fatal("rewrap failed")
	}
	got, e = p.Unwrap(ctx, next, binding)
	if e != nil || !bytes.Equal(got, plainSentinel) {
		t.Fatal("rewrap round trip failed")
	}
	_, e = p.Rewrap(ctx, next, binding)
	checkError(t, e, Mismatch)
	wrong := wrapped
	wrong.Reference.Key += "other"
	_, e = p.Unwrap(ctx, wrong, binding)
	checkError(t, e, Mismatch)
	wrong = wrapped
	wrong.Ciphertext = strings.Replace(wrapped.Ciphertext, "vault:v1:", "vault:v9:", 1)
	_, e = p.Unwrap(ctx, wrong, binding)
	checkError(t, e, Refused)
	_, e = p2.Rewrap(ctx, wrapped, []byte("wrong"))
	checkError(t, e, Refused)
	if n.Load() != 7 {
		t.Fatalf("expected exactly 7 attempts, got %d", n.Load())
	}
}

func TestResponseRefusalsAndSentinels(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(old)
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldWriter)
	ct := validCT(1)
	cases := []struct {
		name, body string
		status     int
		kind       Kind
	}{
		{"truncated", `{"data":`, 200, Protocol},
		{"oversized", strings.Repeat(" ", maxResponse+1), 200, Protocol},
		{"missing", `{}`, 200, Protocol}, {"null", `{"data":null}`, 200, Protocol},
		{"wrong-data-type", `{"data":[]}`, 200, Protocol},
		{"wrong-field-type", `{"data":{"ciphertext":3}}`, 200, Protocol},
		{"duplicate-data", `{"data":{},"data":{"ciphertext":"` + ct + `"}}`, 200, Protocol},
		{"duplicate-field", `{"data":{"ciphertext":"bad","ciphertext":"` + ct + `"}}`, 200, Protocol},
		{"escaped-duplicate", `{"data":{"ciphertext":"` + ct + `","\u0063iphertext":"` + ct + `"}}`, 200, Protocol},
		{"trailing", `{"data":{}} {}`, 200, Protocol},
		{"deep", strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34), 200, Protocol},
		{"bad-shape", `{"data":{"ciphertext":"vault:v1:AAAA"}}`, 200, Protocol},
		{"bad-version", `{"data":{"ciphertext":"` + validCT(2) + `"}}`, 200, Mismatch},
		{"key-version-type", `{"data":{"ciphertext":"` + ct + `","key_version":"1"}}`, 200, Protocol},
		{"key-version-mismatch", `{"data":{"ciphertext":"` + ct + `","key_version":2}}`, 200, Protocol},
		{"error-hybrid", `{"data":{"ciphertext":"` + ct + `"},"errors":["SERVICE-SENTINEL"]}`, 200, Protocol},
		{"wrapping", `{"data":{"ciphertext":"` + ct + `"},"wrap_info":{}}`, 200, Protocol},
		{"data-error", `{"data":{"ciphertext":"` + ct + `","error":"SERVICE-SENTINEL"}}`, 200, Protocol},
		{"service", "SERVICE-SENTINEL" + tokenSentinel + string(plainSentinel), 500, Refused},
		{"unauthenticated", tokenSentinel, 401, Unauthorized}, {"forbidden", tokenSentinel, 403, Unauthorized},
		{"empty", ``, 204, Refused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var n atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n.Add(1)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer s.Close()
			p := newAdapter(t, config(s))
			_, e := p.Wrap(context.Background(), plainSentinel, []byte("context"))
			checkError(t, e, tc.kind)
			_, e = p.Rewrap(context.Background(), Wrapped{p.Reference(), validCT(1)}, []byte("context"))
			checkError(t, e, tc.kind)
			if n.Load() != 2 {
				t.Fatal("unexpected HTTP attempt count")
			}
		})
	}
	for _, s := range []string{tokenSentinel, string(plainSentinel), base64.StdEncoding.EncodeToString(plainSentinel), "SERVICE-SENTINEL"} {
		if strings.Contains(logs.String(), s) {
			t.Fatal("log leaked sentinel")
		}
	}
}
func TestUnwrapResponseValidation(t *testing.T) {
	for _, body := range []string{`{}`, `{"data":{"plaintext":null}}`, `{"data":{"plaintext":2}}`, `{"data":{"plaintext":"bad"}}`, `{"data":{"plaintext":"` + base64.StdEncoding.EncodeToString(make([]byte, 31)) + `"}}`, `{"data":{"plaintext":"` + base64.StdEncoding.EncodeToString(plainSentinel) + `","plaintext":"bad"}}`} {
		t.Run("invalid-plaintext", func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
			defer s.Close()
			p := newAdapter(t, config(s))
			_, e := p.Unwrap(context.Background(), Wrapped{p.Reference(), validCT(1)}, []byte("c"))
			checkError(t, e, Protocol)
		})
	}
}

func TestRedirectsNeverFollow(t *testing.T) {
	var cross atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cross.Add(1)
		t.Error("cross-origin request or credential forwarding")
	}))
	defer target.Close()
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, same := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", status, same), func(t *testing.T) {
				var n atomic.Int32
				s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					n.Add(1)
					location := target.URL + "/stolen"
					if same {
						location = "/other"
					}
					w.Header().Set("Location", location)
					w.WriteHeader(status)
				}))
				defer s.Close()
				p := newAdapter(t, config(s))
				_, e := p.Wrap(context.Background(), plainSentinel, []byte("c"))
				checkError(t, e, Refused)
				if n.Load() != 1 || cross.Load() != 0 {
					t.Fatal("redirect followed")
				}
			})
		}
	}
}
func TestTLSCancellationTimeoutAndTruncation(t *testing.T) {
	t.Run("untrusted-TLS", func(t *testing.T) {
		var n atomic.Int32
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1) }))
		defer s.Close()
		s.Config.ErrorLog = log.New(io.Discard, "", 0)
		c := config(s)
		c.RootCAs = nil
		p := newAdapter(t, c)
		_, e := p.Wrap(context.Background(), plainSentinel, []byte("c"))
		checkError(t, e, Unavailable)
		if n.Load() != 0 {
			t.Fatal("unverified request sent")
		}
	})
	for _, mode := range []string{"headers", "body", "cancel", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			var n atomic.Int32
			started := make(chan struct{})
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				close(started)
				if mode == "truncated" {
					w.Header().Set("Content-Length", "1000")
					_, _ = io.WriteString(w, `{"data":`)
					return
				}
				if mode == "body" {
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				}
				select {
				case <-r.Context().Done():
				case <-time.After(2 * time.Second):
				}
			}))
			defer s.Close()
			c := config(s)
			c.Timeout = 150 * time.Millisecond
			p := newAdapter(t, c)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				go func() { <-started; cancel() }()
			}
			_, e := p.Wrap(ctx, plainSentinel, []byte("c"))
			if mode == "truncated" {
				checkError(t, e, Protocol)
			} else {
				checkError(t, e, Cancelled)
			}
			if n.Load() != 1 {
				t.Fatal("unexpected attempt count")
			}
		})
	}
}

func TestValidationNoRequests(t *testing.T) {
	var n atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1) }))
	defer s.Close()
	c := config(s)
	for _, origin := range []string{"https://user:pass@example.com", "https://example.com/", "https://example.com/a", "https://example.com?token=SERVICE-SENTINEL", "https://example.com#frag", "http://example.com", "http://localhost:8200", "http://127.0.0.1.evil:8200", "http://0.0.0.0:8200", "https://example.com/%2e%2e", "https://example.com\\evil"} {
		bad := c
		bad.Origin = origin
		bad.AllowLoopbackHTTP = true
		_, e := NewTransit(bad)
		checkError(t, e, Invalid)
	}
	for _, s := range []string{"", "..", "a/b", "a?token=x", "a#b", "a%2fb", "a\\b", strings.Repeat("x", 129)} {
		bad := c
		bad.Key = s
		_, e := NewTransit(bad)
		checkError(t, e, Invalid)
	}
	for _, s := range []string{"", "/transit", "transit/", "a//b", "a/../b", "a/%2f", "a?b"} {
		bad := c
		bad.Mount = s
		_, e := NewTransit(bad)
		checkError(t, e, Invalid)
	}
	for _, mutate := range []func(*TransitConfig){func(c *TransitConfig) { c.WriteVersion = 0 }, func(c *TransitConfig) { c.Token = nil }, func(c *TransitConfig) { c.Timeout = -1 }, func(c *TransitConfig) { c.Timeout = 31 * time.Second }} {
		bad := c
		mutate(&bad)
		_, e := NewTransit(bad)
		checkError(t, e, Invalid)
	}
	p := newAdapter(t, c)
	ctx := context.Background()
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		_, e := p.Wrap(ctx, key, []byte("c"))
		checkError(t, e, Invalid)
	}
	for _, b := range [][]byte{nil, make([]byte, maxContext+1)} {
		_, e := p.Wrap(ctx, plainSentinel, b)
		checkError(t, e, Invalid)
	}
	for _, ct := range []string{"", "vault:v0:AAAA", "vault:v01:" + strings.Split(validCT(1), ":")[2], "vault:v4294967296:AAAA", "bao:v1:AAAA", strings.Repeat("x", maxCiphertext+1), strings.Replace(validCT(1), ":v1:", ":v+1:", 1), validCT(1) + "\n"} {
		_, e := p.Unwrap(ctx, Wrapped{p.Reference(), ct}, []byte("c"))
		checkError(t, e, Invalid)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, e := p.Wrap(cancelled, plainSentinel, []byte("c"))
	checkError(t, e, Cancelled)
	for _, token := range []string{"", "bad\r\nheader", strings.Repeat("x", 4097)} {
		bad := c
		bad.Token = func(context.Context) (string, error) { return token, nil }
		q := newAdapter(t, bad)
		_, e := q.Wrap(ctx, plainSentinel, []byte("c"))
		checkError(t, e, Credential)
	}
	bad := c
	bad.Token = func(context.Context) (string, error) { return "", fmt.Errorf("%s SERVICE-SENTINEL", tokenSentinel) }
	_, e = newAdapter(t, bad).Wrap(ctx, plainSentinel, []byte("c"))
	checkError(t, e, Credential)
	if n.Load() != 0 {
		t.Fatal("invalid inputs caused network request")
	}
}
func TestExplicitLoopbackHTTP(t *testing.T) {
	var n atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ciphertext": validCT(1)}})
	}))
	defer s.Close()
	c := TransitConfig{Origin: s.URL, Mount: "transit", Key: "key", WriteVersion: 1, Token: func(context.Context) (string, error) { return tokenSentinel, nil }}
	_, e := NewTransit(c)
	checkError(t, e, Invalid)
	c.AllowLoopbackHTTP = true
	p := newAdapter(t, c)
	_, e = p.Wrap(context.Background(), plainSentinel, []byte("c"))
	if e != nil || n.Load() != 1 {
		t.Fatal("explicit loopback fixture failed")
	}
	for _, origin := range []string{"http://[::1]:8200", "http://127.0.0.1:8200"} {
		c.Origin = origin
		if _, e := NewTransit(c); e != nil {
			t.Fatal("literal loopback refused")
		}
	}
}

func TestWrongMasterAndTampering(t *testing.T) {
	s, n := fakeTransit(t)
	p := newAdapter(t, config(s))
	binding := []byte("fixture-binding")
	w, e := p.Wrap(context.Background(), plainSentinel, binding)
	if e != nil {
		t.Fatal("fixture wrap failed")
	}
	other, attempts := fakeTransit(t)
	q := newAdapter(t, config(other))
	w.Reference = q.Reference() // routing metadata cannot defeat key authentication
	_, e = q.Unwrap(context.Background(), w, binding)
	checkError(t, e, Refused)
	w.Reference = p.Reference()
	pieces := strings.Split(w.Ciphertext, ":")
	blob, _ := base64.StdEncoding.DecodeString(pieces[2])
	blob[len(blob)-1] ^= 1
	w.Ciphertext = "vault:v1:" + base64.StdEncoding.EncodeToString(blob)
	_, e = p.Unwrap(context.Background(), w, binding)
	checkError(t, e, Refused)
	if n.Load() != 2 || attempts.Load() != 1 {
		t.Fatal("unexpected attempt count")
	}
}

func TestCredentialDeadline(t *testing.T) {
	var attempts atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { attempts.Add(1) }))
	defer s.Close()
	c := config(s)
	c.Timeout = 20 * time.Millisecond
	c.Token = func(ctx context.Context) (string, error) {
		<-ctx.Done()
		return tokenSentinel, fmt.Errorf("SERVICE-SENTINEL")
	}
	_, e := newAdapter(t, c).Wrap(context.Background(), plainSentinel, []byte("c"))
	checkError(t, e, Cancelled)
	if attempts.Load() != 0 {
		t.Fatal("expired credential source caused request")
	}
}

func TestTransportLimitsAndHostVerification(t *testing.T) {
	for _, mode := range []string{"headers-too-large", "hostname"} {
		t.Run(mode, func(t *testing.T) {
			var n atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n.Add(1)
				w.Header().Set("X-Oversized", strings.Repeat("x", maxResponse+1))
				_, _ = io.WriteString(w, `{"data":{}}`)
			}))
			defer s.Close()
			s.Config.ErrorLog = log.New(io.Discard, "", 0)
			c := config(s)
			if mode == "hostname" {
				c.Origin = strings.Replace(s.URL, "127.0.0.1", "localhost", 1)
			}
			_, e := newAdapter(t, c).Wrap(context.Background(), plainSentinel, []byte("c"))
			checkError(t, e, Unavailable)
			want := int32(1)
			if mode == "hostname" {
				want = 0
			}
			if n.Load() != want {
				t.Fatal("unexpected attempt count")
			}
		})
	}
}
