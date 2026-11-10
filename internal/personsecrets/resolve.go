package personsecrets

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// CallContext is the call that needs a secret.
type CallContext struct {
	User    dbgen.User
	Server  dbgen.McpServer
	Gateway dbgen.Gateway
	// CapabilityID, Kind, ExposedName and Title describe the capability.
	CapabilityID             uuid.UUID
	Kind, ExposedName, Title string
}

// Secret is a person's secret as one call uses it. Value is the bare secret;
// it lives only in memory, for the length of the call.
type Secret struct {
	Value                   string
	Placement, Name, Prefix string
	// ID and Sealed identify the stored value that was read, so a rejection
	// marks that value and not one entered since.
	ID     uuid.UUID
	Sealed []byte
}

// NeedsSecret: the person must enter (or enter again) their key at URL.
type NeedsSecret struct {
	Reason, RequestID, URL string
	Server                 ServerRef
	Label                  string
}

func (e *NeedsSecret) Error() string { return "personsecrets: a key is needed (" + e.Reason + ")" }

// Resolve returns the person's secret for a call to a person_secret server,
// or a *NeedsSecret (nothing is sent anywhere), or ErrInactive. It is the
// only way a secret leaves this package. There is no fallback to any other
// credential: without a usable secret the call doesn't go.
func (s *Service) Resolve(ctx context.Context, cc CallContext) (Secret, error) {
	cfg, ok := registry.PersonSecretConfig(cc.Server)
	if !ok {
		return Secret{}, ErrNotConfigured
	}
	if cc.User.Status != "active" {
		return Secret{}, ErrInactive
	}
	origin := registry.OriginOf(cc.Server.URL)
	ps, err := s.q.GetPersonSecret(ctx, dbgen.GetPersonSecretParams{UserID: cc.User.ID, ServerID: cc.Server.ID})
	switch {
	case errors.Is(store.NotFound(err), store.ErrNotFound):
		return Secret{}, s.need(ctx, cc, cfg, origin, ReasonMissing)
	case err != nil:
		return Secret{}, err
	case ps.Origin != origin:
		// Entered for another origin (a reset would have deleted it): never
		// sent here.
		return Secret{}, s.need(ctx, cc, cfg, origin, ReasonMissing)
	case ps.Status != StatusActive:
		return Secret{}, s.need(ctx, cc, cfg, origin, ReasonRejected)
	}
	plain, err := s.box.Open(ps.SecretCipher, registry.PersonSecretAAD(ps.ID))
	if err != nil {
		// Sealed under a key that is gone: enter it again.
		s.log.WarnContext(ctx, "a person secret can't be decrypted with the current ENCRYPTION_KEY", "secret_id", ps.ID)
		return Secret{}, s.need(ctx, cc, cfg, origin, ReasonRejected)
	}
	if err := s.q.TouchPersonSecret(ctx, ps.ID); err != nil {
		s.log.WarnContext(ctx, "could not record a person secret's use", "secret_id", ps.ID, "err", err)
	}
	return Secret{Value: string(plain), Placement: cfg.Placement, Name: cfg.Name, Prefix: cfg.Prefix, ID: ps.ID, Sealed: ps.SecretCipher}, nil
}

// Reject marks a secret the server refused (401 or 403) as rejected, so it
// is not sent again until the person replaces it. Only the value that was
// sent is marked. It reports whether a secret was marked.
func (s *Service) Reject(ctx context.Context, sec Secret) (bool, error) {
	n, err := s.q.RejectPersonSecret(ctx, dbgen.RejectPersonSecretParams{ID: sec.ID, SecretCipher: sec.Sealed})
	return n > 0, err
}

// NeedAgain makes the *NeedsSecret for a secret that was just rejected (the
// same answer a later call gets).
func (s *Service) NeedAgain(ctx context.Context, cc CallContext) error {
	cfg, ok := registry.PersonSecretConfig(cc.Server)
	if !ok {
		return ErrNotConfigured
	}
	return s.need(ctx, cc, cfg, registry.OriginOf(cc.Server.URL), ReasonRejected)
}

func (s *Service) need(ctx context.Context, cc CallContext, cfg registry.PersonSecretInput, origin, reason string) error {
	ref, err := s.serverRef(ctx, s.q, cc.Server.ID)
	if err != nil {
		return err
	}
	n := &NeedsSecret{Reason: reason, Server: ref, Label: label(cfg)}
	id, err := s.request(ctx, cc, origin, reason)
	if err != nil {
		return err
	}
	n.RequestID, n.URL = id, s.RequestURL(id)
	return n
}

func label(cfg registry.PersonSecretInput) string {
	if cfg.Label != "" {
		return cfg.Label
	}
	return "API key"
}

func (s *Service) serverRef(ctx context.Context, q *dbgen.Queries, id uuid.UUID) (ServerRef, error) {
	r, err := q.GetServerRef(ctx, id)
	if err != nil {
		return ServerRef{}, err
	}
	return ServerRef{ID: r.ID, Slug: r.Slug, Name: r.Name, TeamSlug: r.TeamSlug, TeamName: r.TeamName}, nil
}

// request returns the ID of an open link for the call, making one when none
// stays valid for at least two more minutes. A person has at most
// MaxOpenRequests open; the oldest is dropped.
func (s *Service) request(ctx context.Context, cc CallContext, origin, reason string) (string, error) {
	var id string
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		open, err := q.FindOpenSecretRequest(ctx, dbgen.FindOpenSecretRequestParams{UserID: cc.User.ID, GatewayID: cc.Gateway.ID,
			CapabilityID: cc.CapabilityID, ServerID: cc.Server.ID, ServerOrigin: origin, Reason: reason, ValidUntil: s.now().Add(2 * time.Minute)})
		if err == nil {
			if b, err := s.box.Open(open.IDCipher, RequestAAD(open.IDDigest)); err == nil {
				id = string(b)
				return nil
			}
		} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
			return err
		}
		id = randomID()
		digest := requestDigest(id)
		ct, err := s.box.Seal([]byte(id), RequestAAD(digest))
		if err != nil {
			return err
		}
		title := []rune(cc.Title)
		if len(title) > 200 {
			title = title[:200]
		}
		if _, err := q.InsertSecretRequest(ctx, dbgen.InsertSecretRequestParams{
			IDDigest: digest, IDCipher: ct, UserID: cc.User.ID, ServerID: cc.Server.ID, ServerOrigin: origin, Reason: reason,
			GatewayID: cc.Gateway.ID, GatewaySlug: cc.Gateway.Slug, GatewayName: cc.Gateway.Name, CapabilityID: cc.CapabilityID,
			CapabilityKind: cc.Kind, ExposedName: cc.ExposedName, CapabilityTitle: string(title), ExpiresAt: s.now().Add(RequestTTL),
		}); err != nil {
			return err
		}
		if _, err := q.TrimOpenSecretRequests(ctx, dbgen.TrimOpenSecretRequestsParams{UserID: cc.User.ID, Keep: MaxOpenRequests}); err != nil {
			return err
		}
		_, err = q.DeleteStaleSecretRequests(ctx, s.now().Add(-requestKeep))
		return err
	})
	return id, err
}

// Cleanup deletes links that expired a day ago (the retention loop).
func (s *Service) Cleanup(ctx context.Context) (int64, error) {
	return s.q.DeleteStaleSecretRequests(ctx, s.now().Add(-requestKeep))
}
