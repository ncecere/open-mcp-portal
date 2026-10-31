// Package keyprovider wraps 32-byte data keys independently of secrets.Box.
// It does not define a storage envelope or any runtime availability policy.
package keyprovider

import "context"

// Reference is non-secret, stable across wrapping-key versions. It must identify
// the same provider origin, mount and key for the lifetime of a wrapped value.
type Reference struct{ Provider, Key string }

// Wrapped is not a portal ciphertext format. Callers must retain its reference.
type Wrapped struct {
	Reference  Reference
	Ciphertext string
}

// Provider binds keys to a nonempty caller context (not a row-AAD contract).
// Implementations must bound I/O and must not expose upstream error text.
type Provider interface {
	Reference() Reference
	Wrap(context.Context, []byte, []byte) (Wrapped, error)
	Unwrap(context.Context, Wrapped, []byte) ([]byte, error)
}

// Rewrapper is an optional capability; success must not return plaintext.
type Rewrapper interface {
	Rewrap(context.Context, Wrapped, []byte) (Wrapped, error)
}

type Kind string

const (
	Invalid      Kind = "invalid input or configuration"
	Mismatch     Kind = "key reference or version mismatch"
	Credential   Kind = "credential unavailable"
	Unauthorized Kind = "authorization refused"
	Refused      Kind = "service refused operation"
	Unavailable  Kind = "transport unavailable"
	Cancelled    Kind = "operation cancelled or timed out"
	Protocol     Kind = "invalid service response"
)

// Error contains only adapter-owned classifications and an optional HTTP status.
// It deliberately does not wrap service, credential-source or URL errors.
type Error struct {
	Kind   Kind
	Status int
}

func (e *Error) Error() string { return "keyprovider: " + string(e.Kind) }
func fail(k Kind) error        { return &Error{Kind: k} }
