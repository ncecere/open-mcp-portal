package registry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// A server's TLS settings (decision 74, docs/registry.md "TLS to the server"):
// a CA bundle that replaces the system roots for this server only, and a
// client certificate with its private key for mTLS. Verification and the host
// name check are always on; there is no setting that turns them off.
//
//   - The private key is sealed with ENCRYPTION_KEY (AAD bound to the server and
//     the field), and is never returned, logged, audited or captured. Responses
//     carry fingerprints, subjects, issuers and expiry only.
//   - Input is validated when saved (upstream.ParseClientPair and
//     ParseCABundle): PEM only, size and certificate-count caps, a key without a
//     passphrase that belongs to the certificate, algorithm and size minimums,
//     not expired.
//   - F-1: a URL that moves to another origin never carries the client key or
//     the CA along: 422 tls_key_required unless the same request replaces or
//     clears the client certificate (a stored CA alone is dropped, audited).
//   - A new or changed CA (or removing it) is a trust change: under
//     approval_required a published server goes back to review
//     (upstream_tls_changed). A new client certificate is not.

// TLSExpiryWarnDays is how long before a client certificate expires it is
// reported as expiring (health, overview and the key.expiring event).
const TLSExpiryWarnDays = 14

// TLSKeyAAD binds a server's sealed client key to its server and to that field.
func TLSKeyAAD(serverID uuid.UUID) []byte {
	return []byte("mcp_server_tls:" + serverID.String() + ":client_key")
}

// TLSInput is the tls object of a create or update request. A nil field keeps
// what is stored (on create: none). An empty CAPEM removes the CA; an empty
// ClientCertPEM (with no key) removes the client certificate and its key. A
// new ClientKeyPEM always comes with its certificate; a new certificate may
// come without a key, when the stored key belongs to it (a renewal). Clear
// removes everything, and goes with nothing else.
type TLSInput struct {
	CAPEM         *string
	ClientCertPEM *string
	ClientKeyPEM  *string
	Clear         bool
}

func (in *TLSInput) empty() bool {
	return in == nil || (!in.Clear && in.CAPEM == nil && in.ClientCertPEM == nil && in.ClientKeyPEM == nil)
}

// TLS certificate states.
const (
	TLSCertValid    = "valid"
	TLSCertExpiring = "expiring"
	TLSCertExpired  = "expired"
)

// TLSCAView is a server's CA bundle as shown: public facts only.
type TLSCAView struct {
	SHA256       string
	Certificates []upstream.CertInfo
}

// TLSClientView is a server's client certificate as shown. The key is never
// part of a view: HasKey says there is one.
type TLSClientView struct {
	Leaf        upstream.CertInfo
	ChainLength int
	HasKey      bool
	Status      string
	// DaysLeft is the whole days until expiry (0 or less once expired).
	DaysLeft int
}

// TLSView is a server's TLS settings as the API shows them (nil: none).
type TLSView struct {
	CA     *TLSCAView
	Client *TLSClientView
}

// HealthWarning is something about a server that isn't a failure yet.
type HealthWarning struct {
	Code    string
	Message string
	At      time.Time
}

// Warning codes.
const (
	WarnTLSCertExpiring = "tls_certificate_expiring"
	WarnTLSCertExpired  = "tls_certificate_expired"
)

// tlsDigest is what the review digest covers of a server's TLS settings.
type tlsDigest struct{ CASHA, ClientSHA string }

func digestOf(row *dbgen.McpServerTl) tlsDigest {
	if row == nil {
		return tlsDigest{}
	}
	return tlsDigest{CASHA: deref(row.CaSha256), ClientSHA: deref(row.ClientCertSha256)}
}

func certStatus(notAfter, now time.Time) (status string, days int) {
	left := notAfter.Sub(now)
	days = int(left / (24 * time.Hour))
	switch {
	case left <= 0:
		return TLSCertExpired, days
	case left <= TLSExpiryWarnDays*24*time.Hour:
		return TLSCertExpiring, days
	}
	return TLSCertValid, days
}

// viewOfTLS builds a view from a stored row (nil row: nil view). A stored
// value that no longer parses (it was validated when saved) still shows its
// fingerprint and expiry.
func viewOfTLS(row *dbgen.McpServerTl, now time.Time) *TLSView {
	if row == nil {
		return nil
	}
	v := &TLSView{}
	if row.CaPem != nil {
		v.CA = &TLSCAView{SHA256: deref(row.CaSha256)}
		if b, err := upstream.ParseCABundle(*row.CaPem, time.Time{}); err == nil {
			v.CA.Certificates = b.Certs
		}
	}
	if row.ClientCertPem != nil {
		c := &TLSClientView{HasKey: len(row.ClientKeyCipher) > 0, Leaf: upstream.CertInfo{SHA256: deref(row.ClientCertSha256)}}
		if row.ClientNotAfter != nil {
			c.Leaf.NotAfter = row.ClientNotAfter.UTC()
			c.Status, c.DaysLeft = certStatus(*row.ClientNotAfter, now)
		}
		if info, n, err := upstream.DescribeChain(*row.ClientCertPem); err == nil {
			na := c.Leaf.NotAfter
			c.Leaf, c.ChainLength = info, n
			if !na.IsZero() {
				c.Leaf.NotAfter = na
			}
		}
		v.Client = c
	}
	if v.CA == nil && v.Client == nil {
		return nil
	}
	return v
}

// warnings are the health warnings a TLS view carries.
func (v *TLSView) warnings() []HealthWarning {
	if v == nil || v.Client == nil {
		return nil
	}
	switch v.Client.Status {
	case TLSCertExpired:
		return []HealthWarning{{Code: WarnTLSCertExpired, At: v.Client.Leaf.NotAfter,
			Message: "The client certificate expired on " + v.Client.Leaf.NotAfter.Format("2006-01-02") + ". The server will refuse it: upload a renewed certificate and key."}}
	case TLSCertExpiring:
		return []HealthWarning{{Code: WarnTLSCertExpiring, At: v.Client.Leaf.NotAfter,
			Message: fmt.Sprintf("The client certificate expires on %s (in %d days). Upload a renewed certificate before then.",
				v.Client.Leaf.NotAfter.Format("2006-01-02"), max(v.Client.DaysLeft, 0))}}
	}
	return nil
}

// tlsRows reads the TLS rows of servers, by server ID.
func tlsRows(ctx context.Context, q *dbgen.Queries, servers []dbgen.McpServer) (map[uuid.UUID]*dbgen.McpServerTl, error) {
	ids := make([]uuid.UUID, len(servers))
	for i, sv := range servers {
		ids[i] = sv.ID
	}
	rows, err := q.ListMCPServerTLSFor(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]*dbgen.McpServerTl, len(rows))
	for i := range rows {
		out[rows[i].ServerID] = &rows[i]
	}
	return out, nil
}

func loadTLS(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID) (*dbgen.McpServerTl, error) {
	row, err := q.GetMCPServerTLS(ctx, serverID)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// tlsSnapshot is the TLS settings as audited: whether each is set and the
// public fingerprints, never the key, its ciphertext or the certificates.
func tlsSnapshot(row *dbgen.McpServerTl) map[string]any {
	if row == nil {
		return nil
	}
	out := map[string]any{"hasCA": row.CaPem != nil, "hasClientCert": row.ClientCertPem != nil, "hasClientKey": len(row.ClientKeyCipher) > 0}
	if row.CaSha256 != nil {
		out["caSha256"] = *row.CaSha256
	}
	if row.ClientCertSha256 != nil {
		out["clientCertSha256"] = *row.ClientCertSha256
	}
	if row.ClientNotAfter != nil {
		out["clientNotAfter"] = row.ClientNotAfter.UTC()
	}
	return out
}

// withTLS adds the TLS snapshot to an audited snapshot, when there are settings.
func withTLS(snap map[string]any, row *dbgen.McpServerTl) map[string]any {
	if s := tlsSnapshot(row); s != nil {
		snap["tls"] = s
	}
	return snap
}

// Errors of TLS input.
func invalidTLS(e *upstream.TLSInputError) error {
	err := apperr.New(422, "invalid_tls", e.Message)
	err.Details = map[string]any{"field": "tls." + e.Field, "reason": e.Reason}
	return err
}

func tlsConflict(reason, msg string) error {
	return unprocessable("invalid_tls", msg, map[string]any{"field": "tls", "reason": reason})
}

const noteUpstreamTLSChanged = "The server's trusted CA changed; review it again."

var errTLSKeyRequired = unprocessable("tls_key_required",
	"The URL moves to another host, so the stored TLS client key can't be reused there. Upload the client certificate and key again, or remove them.",
	map[string]any{"field": "tls.clientKeyPem"})

var errTLSKeyUndecryptable = &upstream.Error{Class: upstream.ClassConfig,
	Message: "The stored TLS client key can't be decrypted with the current ENCRYPTION_KEY. Upload the client certificate and key again."}

// tlsState is a server's TLS settings during a change.
type tlsState struct {
	caPEM, caSHA     string
	certPEM, certSHA string
	notAfter         *time.Time
	keyCipher        []byte
}

func stateOf(row *dbgen.McpServerTl) tlsState {
	if row == nil {
		return tlsState{}
	}
	return tlsState{caPEM: deref(row.CaPem), caSHA: deref(row.CaSha256), certPEM: deref(row.ClientCertPem),
		certSHA: deref(row.ClientCertSha256), notAfter: row.ClientNotAfter, keyCipher: row.ClientKeyCipher}
}

func (s tlsState) empty() bool { return s.caPEM == "" && s.certPEM == "" }

// tlsPlan is the outcome of a request's tls object.
type tlsPlan struct {
	next tlsState
	// write: the stored row changes (inserted, updated or deleted).
	write bool
	// caChanged: the CA bundle was added, replaced or removed (a trust change);
	// clientChanged: the client certificate or key was added, replaced or removed.
	caChanged, clientChanged bool
	// dropped: the origin moved and the stored settings were dropped.
	droppedCA, droppedClient bool
	// before is the stored row (nil: none), for the audit entry.
	before *dbgen.McpServerTl
}

func (p tlsPlan) changed() bool { return p.write }

// planTLS works out what a request does to a server's TLS settings. stored is
// the current row (nil: none); originMoved says the request moves the URL to
// another origin. The caller holds the server's row lock.
func (s *Service) planTLS(serverID uuid.UUID, stored *dbgen.McpServerTl, in *TLSInput, originMoved bool, now time.Time) (tlsPlan, error) {
	plan := tlsPlan{before: stored}
	cur := stateOf(stored)
	next := cur
	if originMoved && stored != nil {
		// The key was entered for the old origin (F-1), and so was the CA.
		plan.droppedCA, plan.droppedClient = cur.caPEM != "", cur.certPEM != ""
		next = tlsState{}
	}
	// What the request does to the client certificate: none, replace, or remove.
	clientTouched := false
	if in != nil {
		if in.Clear {
			if in.CAPEM != nil || in.ClientCertPEM != nil || in.ClientKeyPEM != nil {
				return plan, tlsConflict("clear_with_other_fields", "clear can't be combined with other tls fields.")
			}
			next, clientTouched = tlsState{}, true
		} else {
			if in.CAPEM != nil {
				if *in.CAPEM == "" {
					next.caPEM, next.caSHA = "", ""
				} else {
					b, err := upstream.ParseCABundle(*in.CAPEM, now)
					if err != nil {
						return plan, asTLSError(err)
					}
					next.caPEM, next.caSHA = b.PEM, b.SHA256
				}
			}
			cert, key := deref(in.ClientCertPEM), deref(in.ClientKeyPEM)
			switch {
			case key != "" && cert == "":
				return plan, invalidTLS(&upstream.TLSInputError{Field: upstream.TLSFieldCert, Reason: "key_without_certificate",
					Message: "Send the client certificate with its private key."})
			case cert != "":
				if key == "" {
					// A renewal: the certificate must belong to the key stored for
					// this origin.
					if originMoved || cur.keyCipher == nil {
						return plan, errTLSKeyRequiredOrMissing(cur.keyCipher != nil, originMoved)
					}
					plain, err := s.box.Open(cur.keyCipher, TLSKeyAAD(serverID))
					if err != nil {
						return plan, errTLSKeyUndecryptable
					}
					key = string(plain)
				}
				pair, err := upstream.ParseClientPair(cert, key, now)
				if err != nil {
					return plan, asTLSError(err)
				}
				// The same certificate again keeps the sealed key it has (it can only be
				// the same key); anything else seals the key now.
				sealed := cur.keyCipher
				if originMoved || cur.certSHA != pair.Leaf.SHA256 || sealed == nil {
					if sealed, err = s.box.Seal([]byte(key), TLSKeyAAD(serverID)); err != nil {
						return plan, err
					}
				}
				na := pair.Leaf.NotAfter
				next.certPEM, next.certSHA, next.notAfter, next.keyCipher = pair.PEM, pair.Leaf.SHA256, &na, sealed
				clientTouched = true
			case in.ClientCertPEM != nil:
				// An empty certificate (and no key) removes the client certificate
				// and its key.
				next.certPEM, next.certSHA, next.notAfter, next.keyCipher = "", "", nil, nil
				clientTouched = true
			}
		}
	}
	if originMoved && cur.keyCipher != nil && !clientTouched {
		return plan, errTLSKeyRequired
	}
	plan.next = next
	plan.caChanged = cur.caSHA != next.caSHA
	plan.clientChanged = cur.certSHA != next.certSHA || (cur.keyCipher == nil) != (next.keyCipher == nil)
	plan.write = plan.caChanged || plan.clientChanged
	return plan, nil
}

func errTLSKeyRequiredOrMissing(haveKey, originMoved bool) error {
	if haveKey && originMoved {
		return errTLSKeyRequired
	}
	return invalidTLS(&upstream.TLSInputError{Field: upstream.TLSFieldKey, Reason: "key_required",
		Message: "Send the private key with the certificate: there is no stored key to check it against."})
}

func asTLSError(err error) error {
	if e, ok := upstream.IsTLSInput(err); ok {
		return invalidTLS(e)
	}
	return err
}

// storeTLS writes a plan in the caller's transaction.
func storeTLS(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID, p tlsPlan) (*dbgen.McpServerTl, error) {
	if !p.write {
		return p.before, nil
	}
	if p.next.empty() {
		return nil, q.DeleteMCPServerTLS(ctx, serverID)
	}
	arg := dbgen.UpsertMCPServerTLSParams{ServerID: serverID}
	if p.next.caPEM != "" {
		arg.CaPem, arg.CaSha256 = ptr(p.next.caPEM), ptr(p.next.caSHA)
	}
	if p.next.certPEM != "" {
		arg.ClientCertPem, arg.ClientCertSha256, arg.ClientNotAfter, arg.ClientKeyCipher =
			ptr(p.next.certPEM), ptr(p.next.certSHA), p.next.notAfter, p.next.keyCipher
	}
	row, err := q.UpsertMCPServerTLS(ctx, arg)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// openTLS reads a server's TLS settings for a request to it: the CA bundle,
// and the client certificate with its key opened (nil: none set).
func (s *Service) openTLS(ctx context.Context, sv dbgen.McpServer) (*upstream.TLSIdentity, error) {
	row, err := loadTLS(ctx, s.q, sv.ID)
	if err != nil || row == nil {
		return nil, err
	}
	key := ""
	if len(row.ClientKeyCipher) > 0 {
		plain, err := s.box.Open(row.ClientKeyCipher, TLSKeyAAD(sv.ID))
		if err != nil {
			return nil, errTLSKeyUndecryptable
		}
		key = string(plain)
	}
	id, err := upstream.NewTLSIdentity(deref(row.CaPem), deref(row.ClientCertPem), key)
	if err != nil {
		// Stored input was validated when saved: this is a version change or
		// damage. The message never quotes the material.
		return nil, &upstream.Error{Class: upstream.ClassConfig, Message: "The stored TLS settings can't be used. Upload them again."}
	}
	return id, nil
}
