package mcptasks

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
)

const (
	MaxPayloadBytes          = 2 << 20
	MaxUpstreamIDBytes       = 8 << 10
	MaxRedactionSecrets      = 64
	MaxRedactionSecretBytes  = 64 << 10
	MaxRedactionSecretsBytes = 128 << 10
)

// Payload is private data, never a wire response or an HTTP target. In
// particular RedactionOnly may contain obsolete upstream credentials solely to
// scrub echoes after rotation. Never populate it from capture.Secrets (which
// can include the downstream bearer), or use any retained value for dispatch.
type Payload struct {
	// Empty only for a pre-dispatch reservation. An active row's caller must
	// require the validated actual upstream ID before any lifecycle dispatch.
	UpstreamID    string          `json:"upstreamId"`
	Arguments     json.RawMessage `json:"arguments"`
	RedactionOnly []string        `json:"redactionOnly"`
	// Inputs is the bounded lifetime input-key ledger (see InputRecord).
	Inputs []InputRecord `json:"inputs,omitempty"`
}

type stateEnvelope struct {
	Version      int     `json:"version"`
	HandleDigest string  `json:"handleDigest"`
	Binding      Binding `json:"binding"`
	Payload      Payload `json:"payload"`
}

// StateAAD isolates each task row and field for key rotation. The sealed
// envelope additionally verifies the handle digest and complete association;
// changing public row metadata cannot silently rebind its private state.
func StateAAD(id uuid.UUID) []byte {
	return []byte("mcp_task:" + id.String() + ":state")
}

func validPayload(b Binding, p Payload) bool {
	if len(p.UpstreamID) > MaxUpstreamIDBytes || !utf8.ValidString(p.UpstreamID) || len(p.RedactionOnly) > MaxRedactionSecrets || !validLedger(p.Inputs) {
		return false
	}
	arguments, err := DigestArguments(p.Arguments)
	if err != nil || arguments != b.ArgumentsDigest {
		return false
	}
	total := 0
	for _, value := range p.RedactionOnly {
		if value == "" || len(value) > MaxRedactionSecretBytes || !utf8.ValidString(value) {
			return false
		}
		total += len(value)
		if total > MaxRedactionSecretsBytes {
			return false
		}
	}
	return true
}

// SealState validates local snapshot association and argument/secret bounds.
// This can seal a reservation before network; it cannot authorize a dispatch.
// The caller must validate/reserve before starting work, not discover a storage
// size/policy problem only after the upstream has already created a task.
func SealState(box *secrets.Box, id uuid.UUID, handleDigest string, binding Binding, payload Payload) ([]byte, error) {
	if box == nil || id == uuid.Nil || !validDigest(handleDigest) || !binding.valid() || !validPayload(binding, payload) {
		return nil, ErrUnavailable
	}
	env := stateEnvelope{Version: 1, HandleDigest: handleDigest, Binding: binding, Payload: payload}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // No unbounded HTML expansion of a validated argument snapshot.
	if enc.Encode(env) != nil || buf.Len() > MaxPayloadBytes {
		return nil, ErrUnavailable
	}
	cipher, err := box.Seal(buf.Bytes(), StateAAD(id))
	if err != nil {
		return nil, ErrUnavailable
	}
	return cipher, nil
}

// OpenState verifies association and format before returning any private
// payload. Expected values must be loaded from the bound row/current admission,
// never accepted from downstream task parameters. A success is not authority:
// current access/deadlines/no-rule and before-transport guards remain required.
func OpenState(box *secrets.Box, id uuid.UUID, handleDigest string, binding Binding, cipher []byte) (Payload, error) {
	fail := func() (Payload, error) { return Payload{}, ErrUnavailable }
	if box == nil || id == uuid.Nil || !validDigest(handleDigest) || !binding.valid() || len(cipher) > MaxPayloadBytes+1024 {
		return fail()
	}
	raw, err := box.Open(cipher, StateAAD(id))
	if err != nil || len(raw) > MaxPayloadBytes {
		return fail()
	}
	var env stateEnvelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&env) != nil || dec.Decode(new(any)) != io.EOF || env.Version != 1 {
		return fail()
	}
	if subtle.ConstantTimeCompare([]byte(env.HandleDigest), []byte(handleDigest)) != 1 || env.Binding != binding || !validPayload(binding, env.Payload) {
		return fail()
	}
	return env.Payload, nil
}
