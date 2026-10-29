// Package mcptasks holds durable task-relay state. A handle is a private lookup
// key, never an authentication credential or permission to bypass live policy.
package mcptasks

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

const (
	HandlePrefix = "omptask_"
	handleBytes  = 32
	handleLength = len(HandlePrefix) + 43 // raw URL-base64 encoding of 32 bytes
)

// ErrNotFound intentionally does not distinguish malformed, unknown, foreign,
// expired or currently unauthorized handles. Outer authentication stays separate.
var ErrNotFound = errors.New("Task not found")

var ErrUnavailable = errors.New("Task state is unavailable")

// NewHandle generates an independent random handle and its SHA-256 digest.
// Store the digest, not this plaintext token; do not put either in metrics or
// raw request URLs. The caller must reserve capacity before upstream dispatch
// and durably store the bound mapping before exposing the handle.
func NewHandle() (token, digest string, err error) {
	return newHandle(rand.Reader)
}

func newHandle(random io.Reader) (token, digest string, err error) {
	var raw [handleBytes]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		return "", "", ErrUnavailable
	}
	token = HandlePrefix + base64.RawURLEncoding.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

// DigestHandle accepts one canonical wire representation only. Alias encodings
// with nonzero trailing padding bits must not create multiple spellings of the
// same raw identifier. An error never echoes any supplied token.
func DigestHandle(token string) (string, error) {
	if len(token) != handleLength || !strings.HasPrefix(token, HandlePrefix) {
		return "", ErrNotFound
	}
	encoded := token[len(HandlePrefix):]
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != handleBytes || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return "", ErrNotFound
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]), nil
}
