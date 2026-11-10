package registry

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Delete removes a server with its capabilities and health (team owners and
// admins). A server in oauth mode first has its connections revoked at the
// authorization server (best effort); its server-bound provider and the
// connections go with it (provider_connection.revoke, reason
// server_deleted). Audited as mcp_server.delete.
func (s *Service) Delete(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) error {
	var revoked map[uuid.UUID]any
	if ta, err := access(ctx, s.q, a, ref); err == nil && ta.writable(authz.CheckServerManage) == nil {
		if sv, err := teamServer(ctx, s.q, ta.team.ID, id, false); err == nil && AuthModeOf(sv) == AuthOAuth && s.oauth.Hooks != nil {
			if p, err := s.q.GetServerProvider(ctx, uuid.NullUUID{UUID: id, Valid: true}); err == nil {
				revoked = s.oauth.Hooks.RevokeConnections(ctx, p)
			}
		}
	}
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := ta.writable(authz.CheckServerManage); err != nil {
			return err
		}
		cur, err := teamServer(ctx, q, ta.team.ID, id, true)
		if err != nil {
			return err
		}
		if p, err := q.GetServerProvider(ctx, uuid.NullUUID{UUID: id, Valid: true}); err == nil && s.oauth.Hooks != nil {
			if err := s.oauth.Hooks.DeleteConnections(ctx, q, a, p, revoked, "server_deleted"); err != nil {
				return err
			}
		} else if err != nil && !errors.Is(store.NotFound(err), store.ErrNotFound) {
			return err
		}
		if err := resetProviderGrants(ctx, q, a, ta.team.ID, id, "server_deleted", nil); err != nil {
			return err
		}
		if err := resetPersonSecrets(ctx, q, a, ta.team.ID, id, "server_deleted", nil); err != nil {
			return err
		}
		deletedTLS, err := loadTLS(ctx, q, id)
		if err != nil {
			return err
		}
		if err := q.DeleteMCPServer(ctx, id); err != nil {
			return err
		}
		stored, err := loadStored(ctx, q, cur)
		if err != nil {
			return err
		}
		e := a.Audit("mcp_server.delete", "mcp_server", id.String())
		e.TeamID, e.Before = ta.team.ID, withTLS(snapshot(cur, stored.views()...), deletedTLS)
		return audit.Record(ctx, q, e)
	})
	if err == nil {
		s.machine.Forget(id.String())
	}
	return err
}
