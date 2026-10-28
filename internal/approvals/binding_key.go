package approvals

import (
	"context"
	"crypto/rand"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// BindingKeyAAD binds the installation's immutable approval HMAC root to its
// dedicated storage slot. Encryption-key rotation rewraps, never replaces it.
func BindingKeyAAD() []byte { return []byte("approval_binding_key:v1") }

func loadBindingKey(pool *pgxpool.Pool, box *secrets.Box) ([]byte, error) {
	candidate := make([]byte, 32)
	if _, err := rand.Read(candidate); err != nil {
		return nil, ErrUnavailable
	}
	cipher, err := box.Seal(candidate, BindingKeyAAD())
	if err != nil {
		return nil, ErrUnavailable
	}
	// Startup-only I/O, never part of an approval transaction. The helper does
	// not overwrite an existing root and returns the concurrently stored winner.
	stored, err := dbgen.New(pool).EnsureApprovalBindingKey(context.Background(), cipher)
	if err != nil {
		return nil, ErrUnavailable
	}
	root, err := box.Open(stored, BindingKeyAAD())
	if err != nil || len(root) != 32 {
		return nil, ErrUnavailable
	}
	return root, nil
}
