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
// threat-model.md, F-2): a SHA-256 over the server's URL, auth mode, the kind
// and name of each part of its own credential (never a value) and
// requirement (and its requires-a-present-person switch when on) and over
// every listed (not gone) capability's kind, name and fingerprint (and its
// effective requires-a-present-person, when true), sorted. A refresh that
// adds, drops or changes a definition, a new URL, another auth mode or another
// requirement changes it, and so does relaxing (or adding) a present-person
// requirement on the server or on a capability (L-4), so an approval made on
// the digest of an earlier look is refused (409 changed_since_review) and
// approves nothing.

// digestVersion is hashed first so a future change of what is covered can't
// collide with this one.
const digestVersion = "omp-review-v2"

// CapabilityRef is one listed capability as the digest covers it.
// PresentPerson is whether calls relayed for a person need that person
// present, as it applies to the capability: its own override, else the
// server's switch (PresentPersonRequired).
type CapabilityRef struct {
	Kind, Name, Fingerprint string
	PresentPerson           bool
}

// CapabilityRefOf is the digest's view of a capability of server sv with the
// given own present-person override (nil: follow the server).
func CapabilityRefOf(sv dbgen.McpServer, kind, name, fingerprint string, presentOverride *bool) CapabilityRef {
	return CapabilityRef{Kind: kind, Name: name, Fingerprint: fingerprint,
		PresentPerson: PresentPersonRequired(sv, dbgen.McpCapability{RequiresPresentPerson: presentOverride})}
}

// ReviewDigest is the digest of a server and its listed capabilities. parts
// are the server's credential parts, as ServerView lists them; a server whose
// credential is its legacy header (and none given) is covered by that header.
func ReviewDigest(sv dbgen.McpServer, caps []CapabilityRef, parts ...CredentialView) string {
	h := sha256.New()
	put := func(s string) {
		// Length-prefixed, so no field can run into the next.
		h.Write([]byte(strconv.Itoa(len(s)) + ":" + s + "\n"))
	}
	put(digestVersion)
	put(sv.URL)
	put(AuthModeOf(sv))
	// The kind and name of every part of the server's own credential, sorted,
	// so adding one (a tenant header, a query key) shows to the reviewer and
	// moving a header between the legacy columns and the table does not.
	keys := make([]string, 0, len(parts)+1)
	if len(parts) == 0 && sv.AuthHeaderName != nil {
		parts = []CredentialView{{Kind: CredHeader, Name: *sv.AuthHeaderName}}
	}
	for _, p := range parts {
		keys = append(keys, p.key())
	}
	slices.Sort(keys)
	put(strconv.Itoa(len(keys)))
	for _, k := range keys {
		put(k)
	}
	if cfg, ok := PersonSecretConfig(sv); ok {
		// Only in person_secret mode, so no other server's digest moves: where
		// and how people's own secrets are sent is what a reviewer approves.
		put("person-secret:" + cfg.Placement + ":" + cfg.Name + ":" + cfg.Prefix)
	}
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
		if c.PresentPerson {
			// Only when on, as for the server's switch: the digest of every
			// capability without the requirement is what it was before.
			put("requires-present-person")
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// digests are the review digests of servers, by ID (for lists and views).
func digests(ctx context.Context, q *dbgen.Queries, servers []dbgen.McpServer) (map[uuid.UUID]string, error) {
	creds, err := credentialViews(ctx, q, servers)
	if err != nil {
		return nil, err
	}
	return digestsWith(ctx, q, servers, creds)
}

// digestsWith is digests with the servers' credential parts already read.
func digestsWith(ctx context.Context, q *dbgen.Queries, servers []dbgen.McpServer, creds map[uuid.UUID][]CredentialView) (map[uuid.UUID]string, error) {
	ids := make([]uuid.UUID, len(servers))
	for i, sv := range servers {
		ids[i] = sv.ID
	}
	rows, err := q.ListMCPCapabilityFingerprints(ctx, ids)
	if err != nil {
		return nil, err
	}
	byServer := make(map[uuid.UUID][]dbgen.ListMCPCapabilityFingerprintsRow, len(servers))
	for _, r := range rows {
		byServer[r.ServerID] = append(byServer[r.ServerID], r)
	}
	out := make(map[uuid.UUID]string, len(servers))
	for _, sv := range servers {
		refs := make([]CapabilityRef, len(byServer[sv.ID]))
		for i, r := range byServer[sv.ID] {
			refs[i] = CapabilityRefOf(sv, r.Kind, r.Name, r.Fingerprint, r.RequiresPresentPerson)
		}
		out[sv.ID] = ReviewDigest(sv, refs, creds[sv.ID]...)
	}
	return out, nil
}

// serverDigest is one server's review digest as it is now (the caller holds
// the server's row lock when the digest guards a change).
func serverDigest(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer) (string, error) {
	m, err := digests(ctx, q, []dbgen.McpServer{sv})
	return m[sv.ID], err
}
