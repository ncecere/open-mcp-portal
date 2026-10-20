// Package identity signs the identity the gateway sends to upstream MCP
// servers with every forwarded call (docs/decisions.md, decisions 7 and 19;
// docs/upstream-identity.md): a short-lived ES256 JWT naming the person, their
// teams, the gateway and the tool, for the server's URL as audience.
//
// Signing keys live in signing_keys: the private key sealed with
// ENCRYPTION_KEY (internal/secrets, bound to the kid), the public key as a
// JWK. Their states are next (published, not signing yet), active (signs;
// one at a time), retiring (published, no longer signing) and retired.
//
// The first key, on an empty table, is active at once (on first use or at
// start-up). After that a leader-elected loop (PostgreSQL advisory lock)
// creates the next key at least Prepublish before the active key has signed
// for RotationPeriod, so verifiers that cache the JWKS already know it, and
// promotes it once the active key is due and the next key has been published
// for Prepublish. The old key keeps being published at /.well-known/jwks.json
// for PublishRetiring, far longer than any token it signed lives (TokenTTL),
// and is then retired.
package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Timings.
const (
	// TokenTTL is how long an identity token is valid.
	TokenTTL = 5 * time.Minute
	// RotationPeriod is the age at which the signing key is replaced.
	RotationPeriod = 30 * 24 * time.Hour
	// PublishRetiring is how long a replaced key stays in the JWKS.
	PublishRetiring = 24 * time.Hour
	// DefaultPrepublish is how long a new key is published before it signs
	// (SIGNING_KEY_PREPUBLISH).
	DefaultPrepublish = 24 * time.Hour
	// RotationCheckInterval is how often the rotation loop looks.
	RotationCheckInterval = time.Hour
	// cacheFor is how long a replica signs with the key it loaded before
	// reading the active key again (a rotation on another replica takes
	// effect within this time; the old key is still published).
	cacheFor = time.Minute
)

// rotationLockKey is the advisory lock of the rotation loop. Creating and
// rotating keys also takes the transaction lock omp.signing-keys
// (LockSigningKeys), which is a different key so the loop can't block on
// itself.
const rotationLockKey = "omp.signing-key-rotation"

// Headers that carry the token (decision 19).
const (
	HeaderAuthorization = "Authorization"
	HeaderIdentity      = "MCP-Gateway-Identity"
	// HeaderProvider and HeaderProviderToken carry a person's delegated
	// credential on calls whose capability requires an auth provider
	// (decision 27): the provider's slug, and the bare access token.
	HeaderProvider      = "MCP-Gateway-Provider"
	HeaderProviderToken = "MCP-Gateway-Provider-Token"
)

// Header is where a server receives the token: Authorization (as a Bearer
// token) unless the server's own static header is Authorization, in which
// case MCP-Gateway-Identity (the bare token). It returns the header name and
// its value.
func Header(staticHeader, token string) (name, value string) {
	if strings.EqualFold(staticHeader, HeaderAuthorization) {
		return HeaderIdentity, token
	}
	return HeaderAuthorization, "Bearer " + token
}

// Claims are what a token says beyond iss, iat, exp and jti.
type Claims struct {
	Audience string // the server's URL
	// PrincipalType is who calls: PrincipalUser (a person, with a key or a
	// connected client) or PrincipalServiceAccount.
	PrincipalType string
	Subject       string   // the person's user ID, or the service account's ID
	Email         string   // the person's email (none for a service account)
	Name          string   // the person's display name, or the service account's name
	Teams         []string // slugs of the person's teams, or the service account's team
	Gateway       string   // the gateway's slug
	Tool          string   // the exposed tool name (tools/call)
	Prompt        string   // the exposed prompt name (prompts/get)
	Resource      string   // the exposed resource URI read (resources/read)
	Client        string   // the OAuth client's name; else clientInfo.name when known, else the key's name
	// ClientVerified is set when Client is an OAuth client's name: true for
	// a Client ID Metadata Document client (its host vouches for the name),
	// false for one that registered itself (the name is its own claim).
	ClientVerified *bool
	// Provider is the auth provider's slug when the call carries the
	// person's provider token (MCP-Gateway-Provider-Token); empty otherwise.
	Provider string
	// Act names the agent that is calling for the person (RFC 8693 actor,
	// decision 66): set only on calls relayed by a trusted agent platform
	// that named the person, never otherwise.
	Act *Actor
}

// Actor is the agent behind a call made for a person: the "act" claim
// (docs/upstream-identity.md "Calls from agents").
type Actor struct {
	// Subject is the agent's ID at the platform, Name its name there.
	Subject string `json:"sub"`
	Name    string `json:"name,omitempty"`
	// Issuer is the agent platform's issuer (its iss).
	Issuer string `json:"iss"`
	// PrincipalType is always PrincipalAgent.
	PrincipalType string `json:"principal_type"`
	// PersonPresent is the platform's statement that the person is in the
	// conversation the call belongs to (false: scheduled or background work).
	PersonPresent bool `json:"person_present"`
}

// Principal types (claim principal_type).
const (
	PrincipalUser           = "user"
	PrincipalServiceAccount = "service_account"
	// PrincipalAgent is the actor's type in the act claim.
	PrincipalAgent = "agent"
)

// tokenClaims are the private claims of a token.
type tokenClaims struct {
	PrincipalType string   `json:"principal_type"`
	Email         string   `json:"email,omitempty"`
	Name          string   `json:"name,omitempty"`
	Teams         []string `json:"teams"`
	Gateway       string   `json:"gateway"`
	Tool          string   `json:"tool,omitempty"`
	Prompt        string   `json:"prompt,omitempty"`
	Resource      string   `json:"resource,omitempty"`
	Client        string   `json:"client,omitempty"`
	// ClientVerified: only with an OAuth client's name in client.
	ClientVerified *bool `json:"client_verified,omitempty"`
	// Provider: only when the call carries a provider token.
	Provider string `json:"provider,omitempty"`
	// Act: only on calls an agent platform relayed for a person.
	Act *Actor `json:"act,omitempty"`
}

// Key states.
const (
	StateNext     = "next"
	StateActive   = "active"
	StateRetiring = "retiring"
	StateRetired  = "retired"
)

// Service signs tokens and publishes keys.
type Service struct {
	// Prepublish is how long a new key is published before it signs (set
	// before the rotation loop starts; DefaultPrepublish by default).
	Prepublish time.Duration

	pool   *pgxpool.Pool
	q      *dbgen.Queries
	box    *secrets.Box
	issuer string
	log    *slog.Logger
	now    func() time.Time

	mu       sync.Mutex
	cached   *signingKey
	loadedAt time.Time
}

type signingKey struct {
	kid    string
	signer jose.Signer
}

// New returns a Service; issuer is APP_URL.
func New(pool *pgxpool.Pool, box *secrets.Box, issuer string, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	var q *dbgen.Queries
	if pool != nil {
		q = dbgen.New(pool)
	}
	return &Service{Prepublish: DefaultPrepublish, pool: pool, q: q, box: box, issuer: issuer, log: log, now: time.Now}
}

// Issuer is the iss claim (APP_URL).
func (s *Service) Issuer() string { return s.issuer }

func keyAAD(kid string) []byte { return []byte("signing_key:" + kid) }

// Sign issues a token for c, valid for TokenTTL.
func (s *Service) Sign(ctx context.Context, c Claims) (string, error) {
	k, err := s.active(ctx)
	if err != nil {
		return "", err
	}
	now := s.now()
	reg := jwt.Claims{
		Issuer: s.issuer, Subject: c.Subject, Audience: jwt.Audience{c.Audience},
		IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
		Expiry: jwt.NewNumericDate(now.Add(TokenTTL)), ID: httpx.NewID(16),
	}
	teams := c.Teams
	if teams == nil {
		teams = []string{}
	}
	pt := c.PrincipalType
	if pt == "" {
		pt = PrincipalUser
	}
	priv := tokenClaims{PrincipalType: pt, Email: c.Email, Name: c.Name, Teams: teams, Gateway: c.Gateway, Tool: c.Tool, Prompt: c.Prompt, Resource: c.Resource, Client: c.Client, ClientVerified: c.ClientVerified, Provider: c.Provider, Act: c.Act}
	return jwt.Signed(k.signer).Claims(reg).Claims(priv).Serialize()
}

// active returns the signing key, creating the first one if there is none.
func (s *Service) active(ctx context.Context) (*signingKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != nil && s.now().Sub(s.loadedAt) < cacheFor {
		return s.cached, nil
	}
	row, err := s.q.GetActiveSigningKey(ctx)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		if err := s.ensureKey(ctx); err != nil {
			return nil, err
		}
		row, err = s.q.GetActiveSigningKey(ctx)
	}
	if err != nil {
		return nil, err
	}
	k, err := s.load(row)
	if err != nil {
		return nil, err
	}
	s.cached, s.loadedAt = k, s.now()
	return k, nil
}

func (s *Service) load(row dbgen.SigningKey) (*signingKey, error) {
	der, err := s.box.Open(row.PrivateKeyCipher, keyAAD(row.Kid))
	if err != nil {
		return nil, fmt.Errorf("signing key %s: %w", row.Kid, err)
	}
	priv, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("signing key %s: %w", row.Kid, err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), row.Kid))
	if err != nil {
		return nil, err
	}
	return &signingKey{kid: row.Kid, signer: signer}, nil
}

// ensureKey makes sure a key signs: unless one is active, it promotes the
// next key (already published) or, on an empty table, creates the first
// key, which signs at once.
func (s *Service) ensureKey(ctx context.Context) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if err := q.LockSigningKeys(ctx); err != nil {
			return err
		}
		_, err := firstKey(ctx, q, s)
		return err
	})
}

// firstKey runs with the keys locked when no key is active: it promotes
// the next key if there is one, else creates an active key. It returns what
// it did.
func firstKey(ctx context.Context, q *dbgen.Queries, s *Service) (Rotation, error) {
	var out Rotation
	if _, err := q.GetActiveSigningKey(ctx); err == nil {
		return out, nil
	} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
		return out, err
	}
	next, err := q.GetNextSigningKey(ctx)
	switch {
	case err == nil:
		if _, err := q.PromoteNextSigningKey(ctx); err != nil {
			return out, err
		}
		out.Promoted = next.Kid
		s.log.InfoContext(ctx, "identity signing key promoted (no key was active)", "kid", next.Kid)
	case errors.Is(store.NotFound(err), store.ErrNotFound):
		if out.Created, err = s.insertKey(ctx, q, StateActive); err != nil {
			return out, err
		}
		out.Promoted = out.Created
		s.log.InfoContext(ctx, "identity signing key created", "kid", out.Created)
	default:
		return out, err
	}
	return out, nil
}

// insertKey generates and stores a new key in state (StateActive or
// StateNext).
func (s *Service) insertKey(ctx context.Context, q *dbgen.Queries, state string) (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	pub := jose.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(jose.ES256), Use: "sig"}
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	kid := base64.RawURLEncoding.EncodeToString(thumb)
	pub.KeyID = kid
	jwk, err := json.Marshal(pub)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", err
	}
	sealed, err := s.box.Seal(der, keyAAD(kid))
	if err != nil {
		return "", err
	}
	return kid, q.InsertSigningKey(ctx, dbgen.InsertSigningKeyParams{Kid: kid, PrivateKeyCipher: sealed, PublicJwk: jwk, State: state})
}

// JWKS returns the published keys: the next one (not signing yet), the
// active one and those retiring. The first call creates a key if there is
// none, so the set is never empty.
func (s *Service) JWKS(ctx context.Context) (jose.JSONWebKeySet, error) {
	if _, err := s.active(ctx); err != nil {
		return jose.JSONWebKeySet{}, err
	}
	rows, err := s.q.ListPublishedSigningKeys(ctx)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	set := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(rows))}
	for _, r := range rows {
		var k jose.JSONWebKey
		if err := json.Unmarshal(r.PublicJwk, &k); err != nil {
			return jose.JSONWebKeySet{}, fmt.Errorf("signing key %s: %w", r.Kid, err)
		}
		set.Keys = append(set.Keys, k)
	}
	return set, nil
}

// Rotation is what one rotation pass did.
type Rotation struct {
	Skipped  bool   // another replica holds the lock
	Created  string // the kid of a new key (next, or the first active key)
	Promoted string // the kid of the key that started signing
	Retired  int64  // keys no longer published
}

// Plan is what a rotation pass does to the keys, given where rotation
// stands.
type Plan struct {
	CreateNext, Promote bool
}

// PlanRotation decides a pass from the keys' states (the first key, on an
// empty table, is handled separately): with no next key, create one once
// the active key is due to be prepared (prepublish before its rotation
// time); with one, promote it once the active key is due and the next key
// has been published long enough. A next key that isn't ready yet delays
// the rotation rather than signing before verifiers could have seen it.
func PlanRotation(hasNext, prepareDue, rotateDue, nextReady bool) Plan {
	if !hasNext {
		return Plan{CreateNext: prepareDue}
	}
	return Plan{Promote: rotateDue && nextReady}
}

func seconds(d time.Duration) int64 { return int64(d / time.Second) }

// Rotate runs one pass if no other replica is: it retires keys whose
// publication ended, creates the first key on an empty table (it signs at
// once), creates the next key Prepublish (plus one check interval, so a
// pass that runs late still leaves Prepublish) before the active key has
// signed for RotationPeriod, and then promotes it: the old key stops signing
// and is published for PublishRetiring more.
func (s *Service) Rotate(ctx context.Context) (Rotation, error) {
	release, ok, err := store.TryAdvisoryLockText(ctx, s.pool, rotationLockKey)
	if err != nil {
		return Rotation{}, err
	}
	if !ok {
		return Rotation{Skipped: true}, nil
	}
	defer release()
	prepublish := max(s.Prepublish, 0)
	prepareAfter := max(RotationPeriod-prepublish-RotationCheckInterval, 0)
	var out Rotation
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if err := q.LockSigningKeys(ctx); err != nil {
			return err
		}
		retired, err := q.RetireExpiredSigningKeys(ctx)
		if err != nil {
			return err
		}
		cur, err := q.GetActiveSigningKey(ctx)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			out, err = firstKey(ctx, q, s)
			out.Retired = retired
			return err
		} else if err != nil {
			return err
		}
		out.Retired = retired
		_, err = q.GetNextSigningKey(ctx)
		hasNext := err == nil
		if err != nil && !errors.Is(store.NotFound(err), store.ErrNotFound) {
			return err
		}
		st, err := q.SigningKeyRotationState(ctx, dbgen.SigningKeyRotationStateParams{
			PrepareAfterSeconds: seconds(prepareAfter), RotateAfterSeconds: seconds(RotationPeriod), PublishedSeconds: seconds(prepublish),
		})
		if err != nil {
			return err
		}
		plan := PlanRotation(hasNext, st.PrepareDue, st.RotateDue, st.NextReady)
		if plan.CreateNext {
			if out.Created, err = s.insertKey(ctx, q, StateNext); err != nil {
				return err
			}
			// Without pre-publication the new key may sign in this pass.
			if prepublish == 0 && st.RotateDue {
				plan.Promote = true
			}
		}
		if !plan.Promote {
			return nil
		}
		if _, err := q.RetireActiveSigningKey(ctx, dbgen.RetireActiveSigningKeyParams{
			Kid: cur.Kid, PublishedSeconds: seconds(PublishRetiring),
		}); err != nil {
			return err
		}
		next, err := q.GetNextSigningKey(ctx)
		if err != nil {
			return err
		}
		if _, err := q.PromoteNextSigningKey(ctx); err != nil {
			return err
		}
		out.Promoted = next.Kid
		return nil
	})
	if err != nil {
		return Rotation{}, err
	}
	if out.Promoted != "" {
		s.mu.Lock()
		s.cached = nil
		s.mu.Unlock()
	}
	return out, nil
}

// RotationLoop runs Rotate at start and every RotationCheckInterval until
// ctx is cancelled.
func (s *Service) RotationLoop(ctx context.Context, log *slog.Logger) {
	t := time.NewTicker(RotationCheckInterval)
	defer t.Stop()
	for {
		r, err := s.Rotate(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			log.Warn("identity key rotation failed", "err", err)
		case r.Created != "" || r.Promoted != "" || r.Retired > 0:
			log.Info("identity signing keys rotated", "created", r.Created, "promoted", r.Promoted, "retired", r.Retired)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
