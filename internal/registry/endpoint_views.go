package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func endpointViews(ctx context.Context, q *dbgen.Queries, servers []dbgen.McpServer) (map[uuid.UUID][]EndpointView, error) {
	ids := make([]uuid.UUID, len(servers))
	out := map[uuid.UUID][]EndpointView{}
	for i, s := range servers {
		ids[i] = s.ID
		out[s.ID] = []EndpointView{}
	}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.ListMCPServerEndpointsForServers(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		v, err := endpointRowView(row)
		if err != nil {
			return nil, err
		}
		out[row.ServerID] = append(out[row.ServerID], v)
	}
	return out, nil
}

// withEndpointDigest leaves servers without extras byte-for-byte compatible
// with existing review digests. Endpoints cover actual URLs/order/identity and
// placement, never plaintext, ciphertext or value hints.
func withEndpointDigest(base string, items []EndpointView) string {
	if len(items) == 0 {
		return base
	}
	type shape struct{ Kind, Name string }
	type endpoint struct {
		ID       uuid.UUID
		Position int32
		URL      string
		Enabled  bool
		AuthMode string
		Parts    []shape
	}
	out := make([]endpoint, len(items))
	for i, e := range items {
		parts := make([]shape, len(e.Credentials))
		for j, c := range e.Credentials {
			parts[j] = shape{c.Kind, c.Name}
		}
		out[i] = endpoint{e.ID, e.Position, e.URL, e.Enabled, e.AuthMode, parts}
	}
	raw, _ := json.Marshal(out) // Only fixed structs/scalars: marshal cannot fail.
	h := sha256.New()
	h.Write([]byte("omp-review-endpoints-v1\x00" + base + "\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

func withEndpointAudit(snap map[string]any, items []EndpointView) map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, e := range items {
		parts := make([]map[string]string, 0, len(e.Credentials))
		for _, c := range e.Credentials {
			parts = append(parts, map[string]string{"kind": c.Kind, "name": c.Name})
		}
		out = append(out, map[string]any{"id": e.ID, "position": e.Position, "origin": originOf(e.URL), "enabled": e.Enabled, "authMode": e.AuthMode, "credentials": parts})
	}
	snap["endpoints"] = out
	return snap
}
