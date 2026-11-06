package auditstream

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// CheckpointJWK publishes public verification material only. Publication is not
// receiver enrollment; receivers must authenticate their initial authority.
type CheckpointJWK struct {
	Kty           string `json:"kty"`
	Crv           string `json:"crv"`
	X             string `json:"x"`
	Kid           string `json:"kid"`
	ActiveFromSeq int64  `json:"active_from_seq"`
	RetiredAtSeq  *int64 `json:"retired_at_seq"`
}

func CheckpointKeys(ctx context.Context, tx pgx.Tx) ([]CheckpointJWK, map[CheckpointKID]CheckpointAuthority, error) {
	rows, err := tx.Query(ctx, `SELECT kid,public_key,active_from_seq,retired_at_seq FROM omp_audit_ext.checkpoint_keys ORDER BY active_from_seq,kid`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	keys := []CheckpointJWK{}
	authorities := map[CheckpointKID]CheckpointAuthority{}
	for rows.Next() {
		var kid, pub []byte
		var a CheckpointAuthority
		if err := rows.Scan(&kid, &pub, &a.ActiveFromSeq, &a.RetiredAtSeq); err != nil {
			return nil, nil, err
		}
		if len(kid) != 16 || len(pub) != 32 || CheckpointKeyID(ed25519.PublicKey(pub)) != CheckpointKID(kid) {
			return nil, nil, fmt.Errorf("invalid checkpoint public key")
		}
		a.Public = ed25519.PublicKey(pub)
		id := CheckpointKID(kid)
		keys = append(keys, CheckpointJWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub), Kid: id.String(), ActiveFromSeq: a.ActiveFromSeq, RetiredAtSeq: a.RetiredAtSeq})
		authorities[id] = a
	}
	return keys, authorities, rows.Err()
}
