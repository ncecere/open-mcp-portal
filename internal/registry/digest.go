package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// The review digest binds an approval to what the reviewer saw (docs/
// threat-model.md, F-2): a SHA-256 over the server's URL, auth mode and
// requirement (and its requires-a-present-person switch when on) and over every listed (not gone) capability's kind, name and
// fingerprint, sorted. A refresh that adds, drops or changes a definition, a
// new URL, another auth mode or another requirement changes it, so an
// approval made on the digest of an earlier look is refused (409
// changed_since_review) and approves nothing.

// digestVersion is hashed first so a future change of what is covered can't
// collide with this one.
const digestVersion = "omp-review-v1"

// CapabilityRef is one listed capability as the digest covers it.
type CapabilityRef struct{ Kind, Name, Fingerprint string }

// ReviewDigest is the digest of a server and its listed capabilities.
func ReviewDigest(sv dbgen.McpServer, caps []CapabilityRef) string {
	h := sha256.New()
	put := func(s string) {
		// Length-prefixed, so no field can run into the next.
		h.Write([]byte(strconv.Itoa(len(s)) + ":" + s + "\n"))
	}
	put(digestVersion)
	put(sv.URL)
	put(AuthModeOf(sv))
	if sv.AuthProviderID.Valid {
		put(sv.AuthProviderID.UUID.String())
		scopes := sorted(sv.AuthScopes)
		put(strconv.Itoa(len(scopes)))
		for _, s := range scopes {
			put(s)
		}
	} else {
		put("")
	}
	if sv.RequiresPresentPerson {
		// Only when on, so the digest of every server without the switch is
		// what it was before the switch existed.
		put("requires-present-person")
	}
	list := slices.Clone(caps)
	slices.SortFunc(list, func(a, b CapabilityRef) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	put(strconv.Itoa(len(list)))
	for _, c := range list {
		put(c.Kind)
		put(c.Name)
		put(c.Fingerprint)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// digests are the review digests of servers, by ID (for lists and views).
func digests(ctx context.Context, q *dbgen.Queries, servers []dbgen.McpServer) (map[uuid.UUID]string, error) {
	ids := make([]uuid.UUID, len(servers))
	for i, sv := range servers {
		ids[i] = sv.ID
	}
	rows, err := q.ListMCPCapabilityFingerprints(ctx, ids)
	if err != nil {
		return nil, err
	}
	byServer := make(map[uuid.UUID][]CapabilityRef, len(servers))
	for _, r := range rows {
		byServer[r.ServerID] = append(byServer[r.ServerID], CapabilityRef{Kind: r.Kind, Name: r.Name, Fingerprint: r.Fingerprint})
	}
	out := make(map[uuid.UUID]string, len(servers))
	for _, sv := range servers {
		out[sv.ID] = ReviewDigest(sv, byServer[sv.ID])
	}
	return out, nil
}

// serverDigest is one server's review digest as it is now (the caller holds
// the server's row lock when the digest guards a change).
func serverDigest(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer) (string, error) {
	m, err := digests(ctx, q, []dbgen.McpServer{sv})
	return m[sv.ID], err
}
