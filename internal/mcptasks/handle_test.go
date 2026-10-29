package mcptasks

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestHandleRoundTripUsesIndependentEntropyAndDigestOnly(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		token, digest, err := NewHandle()
		if err != nil || len(token) != handleLength || len(digest) != 64 || seen[token] || token == digest || strings.Contains(digest, HandlePrefix) {
			t.Fatalf("handle generation invariant failed: %v", err)
		}
		got, err := DigestHandle(token)
		if err != nil || got != digest {
			t.Fatal("handle digest did not round trip")
		}
		seen[token] = true
	}
}

func TestHandleCanonicalEncodingAndPrivateRefusal(t *testing.T) {
	token, digest, err := newHandle(bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	// Raw-base64's last character has two padding bits. B decodes to the same
	// zero byte as A with a permissive decoder; it is not a canonical handle.
	alias := token[:len(token)-1] + "B"
	for _, bad := range []string{"", "private-upstream-id", token + "=", " " + token, strings.ToUpper(token), alias,
		token[:len(token)-1], token + "A", HandlePrefix + strings.Repeat("-", 43), digest, token + "\n"} {
		got, err := DigestHandle(bad)
		if !errors.Is(err, ErrNotFound) || got != "" || strings.Contains(err.Error(), bad) && bad != "" {
			t.Fatal("invalid handle leaked or was accepted")
		}
	}
}

func TestHandleEntropyFailureReturnsNoPartialState(t *testing.T) {
	for _, r := range []io.Reader{bytes.NewReader(nil), bytes.NewReader(make([]byte, 31)), &failedReader{}} {
		token, digest, err := newHandle(r)
		if !errors.Is(err, ErrUnavailable) || token != "" || digest != "" || strings.Contains(err.Error(), "private-random-error") {
			t.Fatal("entropy failure exposed partial or diagnostic state")
		}
	}
}

type failedReader struct{}

func (*failedReader) Read([]byte) (int, error) { return 0, errors.New("private-random-error") }

func FuzzHandleParsing(f *testing.F) {
	token, _, err := newHandle(bytes.NewReader(make([]byte, 32)))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(token)
	f.Add("private-upstream-task-id")
	f.Fuzz(func(t *testing.T, token string) {
		digest, err := DigestHandle(token)
		if err == nil && (len(token) != handleLength || len(digest) != 64) {
			t.Fatal("unbounded successful handle parse")
		}
		if err != nil && (!errors.Is(err, ErrNotFound) || digest != "") {
			t.Fatal("nonuniform private refusal")
		}
	})
}
