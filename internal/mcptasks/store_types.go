package mcptasks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

var ErrCapacity = errors.New("Task capacity unavailable")

// Root must come from normal outer authentication, never task parameters.
// Association is not authorization: fresh scopes/grants/offer/dependency/no-rule
// and final deadline/transport checks remain mandatory in the serving layer.
type Root struct {
	PrincipalKind  string
	PrincipalID    uuid.UUID
	CredentialKind string
	CredentialID   uuid.UUID
	GatewayID      uuid.UUID
}

func (r Root) valid() bool {
	if r.PrincipalID == uuid.Nil || r.CredentialID == uuid.Nil || r.GatewayID == uuid.Nil {
		return false
	}
	return (r.PrincipalKind == PrincipalUser && (r.CredentialKind == CredentialAPIKey || r.CredentialKind == CredentialOAuthGrant)) ||
		(r.PrincipalKind == PrincipalServiceAccount && r.CredentialKind == CredentialServiceKey)
}

func rootOf(b Binding) Root {
	return Root{b.PrincipalKind, b.PrincipalID, b.CredentialKind, b.CredentialID, b.GatewayID}
}

// One stable key across every credential/gateway of a principal and every
// replica. A hash collision only over-serializes; it cannot bypass a count.
func capacityKey(r Root) int64 {
	sum := sha256.Sum256([]byte("mcp_task_capacity:v1:" + r.PrincipalKind + ":" + r.PrincipalID.String()))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

func rootParams(r Root) dbgen.MCPTaskRootBelongsToPrincipalParams {
	return dbgen.MCPTaskRootBelongsToPrincipalParams{Column1: r.PrincipalKind, Column2: r.PrincipalID,
		Column3: r.CredentialKind, Column4: r.CredentialID, Column5: r.GatewayID}
}

func rowRoot(r dbgen.McpTask) Root {
	out := Root{PrincipalKind: r.PrincipalKind, CredentialKind: r.CredentialKind, GatewayID: r.GatewayID}
	if r.PrincipalKind == PrincipalUser {
		out.PrincipalID = r.UserID.UUID
	} else {
		out.PrincipalID = r.ServiceAccountID.UUID
	}
	switch r.CredentialKind {
	case CredentialAPIKey:
		out.CredentialID = r.ApiKeyID.UUID
	case CredentialOAuthGrant:
		out.CredentialID = r.OauthGrantID.UUID
	case CredentialServiceKey:
		out.CredentialID = r.ServiceAccountKeyID.UUID
	}
	return out
}

func bindingOf(r dbgen.McpTask) (Binding, error) {
	var b Binding
	dec := json.NewDecoder(bytes.NewReader(r.Binding))
	dec.DisallowUnknownFields()
	if len(r.Binding) > 8192 || dec.Decode(&b) != nil || dec.Decode(new(any)) != io.EOF {
		return Binding{}, ErrNotFound
	}
	digest, err := DigestBinding(b)
	if err != nil || r.BindingDigest == nil || digest != *r.BindingDigest || rowRoot(r) != rootOf(b) ||
		r.ServerID != b.ServerID || r.CapabilityID != b.CapabilityID {
		return Binding{}, ErrNotFound
	}
	return b, nil
}

func storeError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ErrUnavailable // Never expose SQL, identity, IDs or sealed/plaintext state.
}

func clonePayload(p Payload) Payload {
	p.Arguments = bytes.Clone(p.Arguments)
	p.RedactionOnly = slices.Clone(p.RedactionOnly)
	return p
}

// Reservation cannot expose a handle. Activation must commit its durable
// mapping before returning one. Stringers prevent accidental formatted logging.
type Reservation struct {
	row     dbgen.McpTask
	handle  string
	binding Binding
}

func (r Reservation) Deadline() time.Time {
	if r.row.ReservationDeadline == nil {
		return time.Time{}
	}
	return *r.row.ReservationDeadline
}
func (Reservation) String() string   { return "private task reservation" }
func (Reservation) GoString() string { return "private task reservation" }

// Snapshot is private, decrypted data, NOT a permit to dispatch or reveal a
// result. The gateway must freshly resolve authority and compare Binding().
// No exported fields can accidentally become an encoded HTTP result.
type Snapshot struct {
	row     dbgen.McpTask
	binding Binding
	payload Payload
}

func (s Snapshot) Binding() Binding     { return s.binding }
func (s Snapshot) Payload() Payload     { return clonePayload(s.payload) }
func (s Snapshot) CreatedAt() time.Time { return s.row.CreatedAt }
func (s Snapshot) ExpiresAt() time.Time { return s.row.ExpiresAt }
func (s Snapshot) Status() string       { return s.row.Status }
func (s Snapshot) PollMillis() int64    { return int64(s.row.PollIntervalMs) }
func (Snapshot) String() string         { return "private task snapshot" }
func (Snapshot) GoString() string       { return "private task snapshot" }
