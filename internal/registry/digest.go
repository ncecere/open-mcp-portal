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
// and name of each part of its own credential (never a value), the
// fingerprints of its CA bundle and client certificate when it has them (a new
// or changed CA is a trust change, decision 74), the placement of each
// person's own secret (person_secret mode, decision 72), its machine OAuth
// client as a reviewer sees it (token endpoint, client ID, scopes, audience and
// resource, never the secret; machine_oauth mode, decision 73), and its
// requirement and every listed capability's kind, name, fingerprint and owner-set
// tool class, sorted. Changes invalidate an earlier review. Retired platform
// presence settings are deliberately absent; v5 forces pending reviews to reload.
// v6 adds the server's sensitivity and lifecycle (decision 88): what a reviewer
// approves includes how sensitive it is and whether it is being retired, so a
// change of either stales an earlier look. Owner, on-call contact and dates are
// bookkeeping and stay out.

// digestVersion is hashed first so a future change of what is covered can't
// collide with this one.
const digestVersion = "omp-review-v6"

// CapabilityRef is one listed capability as the digest covers it. ToolClass
// is the owner-set class, nil when unclassified; only tools contribute it.
type CapabilityRef struct {
	Kind, Name, Fingerprint string
	ToolClass               *string
}

// CapabilityRefOf is the reviewable identity and classification of a capability.
func CapabilityRefOf(kind, name, fingerprint string, toolClass *string) CapabilityRef {
	return CapabilityRef{Kind: kind, Name: name, Fingerprint: fingerprint, ToolClass: toolClass}
}

// ReviewDigest is the digest of a server and its listed capabilities. parts
// are the server's credential parts, as ServerView lists them; a server whose
// credential is its legacy header (and none given) is covered by that header.
func ReviewDigest(sv dbgen.McpServer, caps []CapabilityRef, parts ...CredentialView) string {
	return reviewDigest(sv, caps, nil, tlsDigest{}, parts)
}

// ReviewDigestMachine is ReviewDigest for a server in machine_oauth mode: the
// digest also covers its OAuth client as a reviewer sees it (the token
// endpoint, the client ID, the scopes, the audience and the resource, never
// the secret), so changing any of them stales an earlier look. Other servers'
// digests do not include it.
func ReviewDigestMachine(sv dbgen.McpServer, caps []CapabilityRef, machine *MachineOAuthView, parts ...CredentialView) string {
	return reviewDigest(sv, caps, machine, tlsDigest{}, parts)
}

// reviewDigest is the digest over everything a reviewer approves: machine is
// the machine OAuth client (nil: none or not that mode) and tls the
// fingerprints of the CA and client certificate (zero: none).
func reviewDigest(sv dbgen.McpServer, caps []CapabilityRef, machine *MachineOAuthView, tls tlsDigest, parts []CredentialView) string {
	h := sha256.New()
	put := func(s string) {
		// Length-prefixed, so no field can run into the next.
		h.Write([]byte(strconv.Itoa(len(s)) + ":" + s + "\n"))
	}
	put(digestVersion)
	put(sv.URL)
	put(AuthModeOf(sv))
	put("governance:" + sv.Sensitivity + ":" + sv.Lifecycle)
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
	if machine != nil && AuthModeOf(sv) == AuthMachineOAuth {
		put("machine-oauth")
		put(machine.TokenURL)
		put(machine.ClientID)
		put(machine.TokenAuthMethod)
		scopes := sorted(machine.Scopes)
		put(strconv.Itoa(len(scopes)))
		for _, sc := range scopes {
			put(sc)
		}
		put(machine.Audience)
		put(machine.Resource)
	}
	if tls != (tlsDigest{}) {
		// Only when set, so the digest of a server without TLS settings changes
		// only with the version: the fingerprint of the CA bundle that replaces
		// the system roots for it, and of the client certificate it presents.
		put("tls")
		put(tls.CASHA)
		put(tls.ClientSHA)
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
		if c.Kind == "tool" {
			put("tool-class:" + deref(c.ToolClass))
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
	machines, err := machineViews(ctx, q, servers)
	if err != nil {
		return nil, err
	}
	tlsByServer, err := tlsRows(ctx, q, servers)
	if err != nil {
		return nil, err
	}
	return digestsWith(ctx, q, servers, creds, machines, tlsByServer)
}

// digestsWith is digests with the servers' credential parts, machine clients
// and TLS settings already read.
func digestsWith(ctx context.Context, q *dbgen.Queries, servers []dbgen.McpServer, creds map[uuid.UUID][]CredentialView,
	machines map[uuid.UUID]*MachineOAuthView, tls map[uuid.UUID]*dbgen.McpServerTl) (map[uuid.UUID]string, error) {
	endpoints, err := endpointViews(ctx, q, servers)
	if err != nil {
		return nil, err
	}
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
			refs[i] = CapabilityRefOf(r.Kind, r.Name, r.Fingerprint, r.ToolClass)
		}
		out[sv.ID] = withEndpointDigest(reviewDigest(sv, refs, machines[sv.ID], digestOf(tls[sv.ID]), creds[sv.ID]), endpoints[sv.ID])
	}
	return out, nil
}

// serverDigest is one server's review digest as it is now (the caller holds
// the server's row lock when the digest guards a change).
func serverDigest(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer) (string, error) {
	m, err := digests(ctx, q, []dbgen.McpServer{sv})
	return m[sv.ID], err
}
