package personsecrets

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

// SetInput is what a person sends: the key (nil keeps the stored one; needed
// when there is none), the origin of the server they were shown, and whether
// to read the server's capabilities with it.
type SetInput struct {
	Value       *string
	Origin      string
	UseForSetup bool
}

// Set enters, replaces or changes the caller's secret for a server. Refusals:
// 404 server_not_found (a server they may not use, or none), 409
// not_person_secret, 409 server_changed (the origin differs from what they
// were shown), 422 invalid_secret_value or secret_required, 403 when they
// ask to read the server with a key and are not an editor of its team.
// Audited as person_secret.create or person_secret.rotate; never the value.
func (s *Service) Set(ctx context.Context, a authz.Actor, serverID uuid.UUID, in SetInput) (Mine, error) {
	if in.Origin == "" {
		return Mine{}, errShown
	}
	u, err := s.q.GetUser(ctx, a.UserID)
	if err != nil {
		return Mine{}, err
	}
	if u.Status != "active" {
		return Mine{}, apperr.Forbidden("Your account is suspended")
	}
	if _, err := s.reachableServer(ctx, u, serverID); err != nil {
		return Mine{}, err
	}
	var value string
	if in.Value != nil {
		// A pasted key often carries a trailing newline or space.
		value = strings.TrimSpace(*in.Value)
		if err := registry.CheckPersonSecretValue(value); err != nil {
			return Mine{}, err
		}
	}
	var setup bool
	var ref ServerRef
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		// The server's row is locked, so an edit of its address, mode or
		// placement (which deletes the secrets) is before or after this,
		// never between.
		sv, err := q.LockMCPServer(ctx, serverID)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errServerNotFound
		} else if err != nil {
			return err
		}
		if _, ok := registry.PersonSecretConfig(sv); !ok {
			return errNotSecretMode
		}
		origin := registry.OriginOf(sv.URL)
		if origin != in.Origin {
			return errChanged
		}
		if in.UseForSetup {
			role, err := teams.MemberRole(ctx, q, sv.TeamID, u.ID)
			if err != nil {
				return err
			}
			if authz.CheckServerEdit(role) != nil {
				return errSetupRole
			}
		}
		cur, err := q.LockPersonSecret(ctx, dbgen.LockPersonSecretParams{UserID: u.ID, ServerID: serverID})
		exists := err == nil
		if err != nil && !errors.Is(store.NotFound(err), store.ErrNotFound) {
			return err
		}
		if in.Value == nil && !exists {
			return errValueNeeded
		}
		action := ""
		var row dbgen.PersonSecret
		switch {
		case in.Value != nil && exists:
			ct, err := s.box.Seal([]byte(value), registry.PersonSecretAAD(cur.ID))
			if err != nil {
				return err
			}
			row, err = q.ReplacePersonSecret(ctx, dbgen.ReplacePersonSecretParams{ID: cur.ID, Origin: origin, SecretCipher: ct,
				Hint: hintOf(value)})
			if err != nil {
				return err
			}
			action = "person_secret.rotate"
		case in.Value != nil:
			id := uuid.New()
			ct, err := s.box.Seal([]byte(value), registry.PersonSecretAAD(id))
			if err != nil {
				return err
			}
			row, err = q.InsertPersonSecret(ctx, dbgen.InsertPersonSecretParams{ID: id, UserID: u.ID, ServerID: serverID, Origin: origin,
				SecretCipher: ct, Hint: hintOf(value)})
			if err != nil {
				return err
			}
			action = "person_secret.create"
		default:
			row = cur
			action = ""
		}
		if in.Value != nil {
			// Its open links are done.
			if _, err := q.MarkSecretRequestsUsedFor(ctx, dbgen.MarkSecretRequestsUsedForParams{UserID: u.ID, ServerID: serverID}); err != nil {
				return err
			}
		}
		if action != "" {
			e := a.Audit(action, "person_secret", row.ID.String())
			e.TeamID = sv.TeamID
			e.Metadata = map[string]any{"name": displayName(u) + " · " + sv.Name, "userId": u.ID.String(), "serverId": sv.ID.String(),
				"server": sv.Name, "origin": origin}
			if err := audit.Record(ctx, q, e); err != nil {
				return err
			}
		}
		if in.UseForSetup && row.Status == StatusActive {
			if _, err := registry.SetSecretSetup(ctx, q, a, serverID, displayName(u)); err != nil {
				return err
			}
			setup = true
		}
		ref, err = s.serverRef(ctx, q, serverID)
		return err
	})
	if err != nil {
		return Mine{}, err
	}
	if setup && s.Registry != nil {
		// Best effort, like a server's first refresh: a failure is stored as
		// the server's refresh error and shown on its page.
		if err := s.Registry.RefreshAsSetup(ctx, a, serverID); err != nil {
			s.log.WarnContext(ctx, "reading a server with its setup person's key failed", "server", serverID, "err", err)
		}
	}
	sv, err := s.q.GetMCPServer(ctx, serverID)
	if err != nil {
		return Mine{}, err
	}
	return s.mine(ctx, u, sv, ref)
}

// hintOf is the last four characters of a secret (every secret here has at
// least eight).
func hintOf(v string) string {
	r := []rune(v)
	return string(r[len(r)-4:])
}

// Revoke deletes the caller's secret for a server (404 person_secret_not_found
// when there is none). Allowed whether or not they can still use the server.
// Audited as person_secret.revoke.
func (s *Service) Revoke(ctx context.Context, a authz.Actor, serverID uuid.UUID) error {
	return s.revoke(ctx, a, a.UserID, serverID, "self")
}

// AdminRevoke deletes a person's secret (platform admins; reason admin), for
// a leaver or a key that leaked.
func (s *Service) AdminRevoke(ctx context.Context, a authz.Actor, userID, serverID uuid.UUID) error {
	if !a.IsPlatformAdmin() {
		return errAdminOnly
	}
	return s.revoke(ctx, a, userID, serverID, "admin")
}

func (s *Service) revoke(ctx context.Context, a authz.Actor, userID, serverID uuid.UUID, reason string) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if _, err := q.LockMCPServer(ctx, serverID); errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNoSecret
		} else if err != nil {
			return err
		}
		u, err := q.GetUser(ctx, userID)
		if err != nil {
			return store.NotFound(err)
		}
		row, err := q.DeletePersonSecret(ctx, dbgen.DeletePersonSecretParams{UserID: userID, ServerID: serverID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNoSecret
		} else if err != nil {
			return err
		}
		sv, err := q.GetMCPServer(ctx, serverID)
		if err != nil {
			return err
		}
		e := a.Audit("person_secret.revoke", "person_secret", row.ID.String())
		e.TeamID = sv.TeamID
		e.Metadata = map[string]any{"name": displayName(u) + " · " + sv.Name, "reason": reason, "userId": userID.String(),
			"serverId": serverID.String(), "server": sv.Name}
		return audit.Record(ctx, q, e)
	})
}
