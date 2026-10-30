package registry

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

// Cross-team transfers (decision 88): a server moves to another team only
// when the receiving team's owner accepts (or a platform admin moves it). The
// move keeps what is bound to the server itself (capabilities, gateway
// selections, people's grants and sealed values, which are bound to the server
// and its origin, not to a team), moves its approval rules with it, names the
// accepting owner as owner and, under approval_required, sends a published
// server back to review: a different team is accountable for it now.

// Transfer states (server_transfers.state).
const (
	TransferPending   = "pending"
	TransferAccepted  = "accepted"
	TransferDeclined  = "declined"
	TransferCancelled = "cancelled"
	TransferForced    = "forced"
)

var (
	errNoTransfer      = apperr.NotFound("transfer_not_found", "Transfer not found")
	errTransferClosed  = apperr.Conflict("transfer_closed", "This transfer was already decided or withdrawn")
	errTransferPending = apperr.Conflict("transfer_pending", "This server already has a transfer waiting for an answer")
	errTransferTeam    = apperr.New(422, "invalid_team", "Choose another team that exists and is active")
	errOwnerToAccept   = apperr.New(403, "owner_required", "Only the receiving team's owners can accept a transfer")
	errTransferTarget  = apperr.Conflict("transfer_stale", "The server is not with the team that offered it any more")
)

// TransferView is a transfer with the names it is shown by.
type TransferView struct {
	Transfer                   dbgen.ServerTransfer
	ServerSlug, ServerName     string
	FromTeamSlug, FromTeamName string
	ToTeamSlug, ToTeamName     string
	RequestedByName            string
}

func transferViewOf(t dbgen.ServerTransfer, r dbgen.GetServerTransferViewRow) TransferView {
	return TransferView{Transfer: t, ServerSlug: r.ServerSlug, ServerName: r.ServerName, FromTeamSlug: r.FromTeamSlug, FromTeamName: r.FromTeamName,
		ToTeamSlug: r.ToTeamSlug, ToTeamName: r.ToTeamName, RequestedByName: r.RequestedByName}
}

func (s *Service) transferView(ctx context.Context, q *dbgen.Queries, id uuid.UUID) (TransferView, error) {
	r, err := q.GetServerTransferView(ctx, id)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return TransferView{}, errNoTransfer
	} else if err != nil {
		return TransferView{}, err
	}
	return transferViewOf(r.ServerTransfer, r), nil
}

// receivingTeam resolves the team a server moves to: it exists, is active and
// is another team. One answer for all of them, so a name is not probed.
func receivingTeam(ctx context.Context, q *dbgen.Queries, ref string, from uuid.UUID) (dbgen.Team, error) {
	t, err := teams.Resolve(ctx, q, ref)
	if err != nil {
		if isNotFound(err) {
			return t, errTransferTeam
		}
		return t, err
	}
	if t.ID == from || t.Status != teams.StatusActive {
		return t, errTransferTeam
	}
	return t, nil
}

// checkTransferProvider refuses a move that would stop the server's calls: it
// requires a restricted auth provider whose list names neither the receiving
// team nor the server (decision 69; the check is made on every call).
func checkTransferProvider(ctx context.Context, q *dbgen.Queries, serverID, toTeam uuid.UUID) error {
	blocked, err := q.ProviderBlocksTeam(ctx, dbgen.ProviderBlocksTeamParams{ServerID: serverID, TeamID: toTeam})
	if err != nil {
		return err
	}
	if blocked {
		return ErrProviderNotAllowed
	}
	return nil
}

// RequestTransfer asks another team to take over a server (team owners and
// admins of the server's team, in a browser session). The receiving team's
// owner accepts; nothing changes until then. 409 transfer_pending when one is
// open. Audited as mcp_server.transfer_request.
func (s *Service) RequestTransfer(ctx context.Context, a authz.Actor, ref string, serverID uuid.UUID, toTeam string, note *string) (TransferView, error) {
	if a.IsToken() {
		return TransferView{}, tokenRefusal("transfer")
	}
	note, err := checkNote(note)
	if err != nil {
		return TransferView{}, err
	}
	if note != nil && len([]rune(*note)) > 500 {
		return TransferView{}, errNoteTooLong
	}
	var out TransferView
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := authz.CheckServerGovernance(ta.role); err != nil {
			return err
		}
		if ta.team.Status != teams.StatusActive {
			return errTeamArchived
		}
		sv, err := teamServer(ctx, q, ta.team.ID, serverID, true)
		if err != nil {
			return err
		}
		to, err := receivingTeam(ctx, q, toTeam, ta.team.ID)
		if err != nil {
			return err
		}
		if err := checkTransferProvider(ctx, q, sv.ID, to.ID); err != nil {
			return err
		}
		t, err := q.InsertServerTransfer(ctx, dbgen.InsertServerTransferParams{ServerID: sv.ID, FromTeamID: ta.team.ID, ToTeamID: to.ID,
			ServerRevision: sv.Revision, Note: note, RequestedBy: by(a)})
		if apperr.IsUniqueViolation(err, "server_transfers_one_pending") {
			return errTransferPending
		} else if err != nil {
			return err
		}
		e := a.Audit("mcp_server.transfer_request", "mcp_server", sv.ID.String())
		e.TeamID = ta.team.ID
		e.Metadata = map[string]any{"name": sv.Name, "transferId": t.ID.String(), "toTeam": to.Slug, "note": deref(note)}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		out, err = s.transferView(ctx, q, t.ID)
		return err
	})
	return out, err
}

// ListTransfers lists a team's transfers, out of it and into it, newest first
// (the team's owners and admins; platform admins and auditors read them).
func (s *Service) ListTransfers(ctx context.Context, a authz.Actor, ref string, pendingOnly bool) ([]TransferView, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return nil, err
	}
	if !a.CanReadPlatform() && !authz.RoleAtLeast(ta.role, authz.RoleAdmin) {
		return nil, authz.CheckServerGovernance(ta.role)
	}
	rows, err := s.q.ListServerTransfers(ctx, dbgen.ListServerTransfersParams{TeamID: ta.team.ID, PendingOnly: pendingOnly, PageSize: 100})
	if err != nil {
		return nil, err
	}
	out := make([]TransferView, len(rows))
	for i, r := range rows {
		out[i] = TransferView{Transfer: r.ServerTransfer, ServerSlug: r.ServerSlug, ServerName: r.ServerName, FromTeamSlug: r.FromTeamSlug,
			FromTeamName: r.FromTeamName, ToTeamSlug: r.ToTeamSlug, ToTeamName: r.ToTeamName, RequestedByName: r.RequestedByName}
	}
	return out, nil
}

// lockTransfer locks a transfer that involves the team and is still pending
// at expectedRevision. Operations that also lock its server must lock the
// server FIRST (as RequestTransfer and ForceTransfer do). A cancellation locks
// only the transfer, so it never waits back on the server.
func lockTransfer(ctx context.Context, q *dbgen.Queries, teamID, id uuid.UUID, expectedRevision int64) (dbgen.ServerTransfer, error) {
	t, err := q.LockServerTransfer(ctx, id)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return t, errNoTransfer
	} else if err != nil {
		return t, err
	}
	if t.FromTeamID != teamID && t.ToTeamID != teamID {
		return t, errNoTransfer
	}
	if t.State != TransferPending {
		return t, errTransferClosed
	}
	if t.Revision != expectedRevision {
		return t, apperr.Stale()
	}
	return t, nil
}

// AcceptTransfer moves the server to the team (its owner, in a browser
// session). expectedRevision is the transfer's; the server must still be as it
// was when the transfer was requested (409 changed_since_request otherwise:
// withdraw it and ask again). The accepting owner becomes the server's owner.
// Audited as mcp_server.transfer.
func (s *Service) AcceptTransfer(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, expectedRevision int64) (TransferView, error) {
	if a.IsToken() {
		return TransferView{}, tokenRefusal("transfer")
	}
	var out TransferView
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		// Read an association hint without a lock, then lock server -> transfer.
		// The transfer row's parties/server are immutable; its state and revision
		// are checked again after both locks. Transfer -> server would deadlock
		// with a forced move that holds the server while cancelling this offer.
		hint, err := q.GetServerTransfer(ctx, id)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNoTransfer
		} else if err != nil {
			return err
		}
		if hint.ToTeamID != ta.team.ID {
			return errNoTransfer
		}
		if !authz.RoleAtLeast(ta.role, authz.RoleOwner) {
			return errOwnerToAccept
		}
		if ta.team.Status != teams.StatusActive {
			return errTeamArchived
		}
		sv, err := anyServer(ctx, q, hint.ServerID, true)
		if err != nil {
			return err
		}
		t, err := lockTransfer(ctx, q, ta.team.ID, id, expectedRevision)
		if err != nil {
			return err
		}
		if sv.TeamID != t.FromTeamID {
			return errTransferTarget
		}
		if sv.Revision != t.ServerRevision {
			e := apperr.Conflict("changed_since_request", "The server changed after this transfer was requested. Ask the owning team to withdraw it and ask again.")
			e.Details = map[string]any{"requestedRevision": t.ServerRevision, "currentRevision": sv.Revision}
			return e
		}
		if _, err := s.moveServer(ctx, q, a, sv, ta.team, by(a), "transfer", map[string]any{"transferId": t.ID.String()}); err != nil {
			return err
		}
		if _, err := q.DecideServerTransfer(ctx, dbgen.DecideServerTransferParams{ID: t.ID, Revision: t.Revision, State: TransferAccepted, Actor: by(a)}); err != nil {
			return err
		}
		out, err = s.transferView(ctx, q, t.ID)
		return err
	})
	return out, err
}

// moveServer is the move itself, shared by an accepted and a forced transfer:
// the server, its approval rules and the review gate. owner is the person
// named owner now (none for a forced transfer). The caller holds the server's
// row lock and has checked the provider list.
func (s *Service) moveServer(ctx context.Context, q *dbgen.Queries, a authz.Actor, sv dbgen.McpServer, to dbgen.Team, owner uuid.NullUUID, kind string, meta map[string]any) (dbgen.McpServer, error) {
	if err := checkTransferProvider(ctx, q, sv.ID, to.ID); err != nil {
		return sv, err
	}
	selections, err := q.GovernanceTeamGatewaySelections(ctx, dbgen.GovernanceTeamGatewaySelectionsParams{ServerID: sv.ID, TeamID: uuid.NullUUID{UUID: sv.TeamID, Valid: true}})
	if err != nil {
		return sv, err
	}
	moved, err := q.MoveMCPServerToTeam(ctx, dbgen.MoveMCPServerToTeamParams{ID: sv.ID, TeamID: to.ID, OwnerUserID: owner, UpdatedBy: by(a)})
	if err != nil {
		return sv, err
	}
	rules, err := q.MoveServerApprovalRules(ctx, dbgen.MoveServerApprovalRulesParams{ServerID: sv.ID, FromTeamID: uuid.NullUUID{UUID: sv.TeamID, Valid: true}, ToTeamID: uuid.NullUUID{UUID: to.ID, Valid: true}})
	if err != nil {
		return sv, err
	}
	e := a.Audit("mcp_server.transfer", "mcp_server", sv.ID.String())
	e.TeamID = to.ID
	e.Before, e.After = map[string]any{"teamId": sv.TeamID.String(), "publishState": sv.PublishState}, map[string]any{"teamId": to.ID.String()}
	e.Metadata = map[string]any{"name": sv.Name, "fromTeamId": sv.TeamID.String(), "toTeam": to.Slug, "kind": kind,
		"approvalRulesMoved": rules, "fromTeamGatewaySelections": selections}
	for k, v := range meta {
		e.Metadata[k] = v
	}
	if err := audit.Record(ctx, q, e); err != nil {
		return moved, err
	}
	// The receiving team's policy decides whether a published server is
	// reviewed again (under self_publish its team approves its own changes).
	if err := s.resubmit(ctx, q, a, to, moved, "transferred", "The server moved to another team; review it again."); err != nil {
		return moved, err
	}
	return moved, nil
}

// CancelTransfer closes a pending transfer without moving anything: the
// offering team's owners and admins withdraw it (cancelled), the receiving
// team's owners and admins decline it (declined), and platform admins may do
// either. expectedRevision is the transfer's. Audited as
// mcp_server.transfer_cancel.
func (s *Service) CancelTransfer(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, expectedRevision int64) (TransferView, error) {
	if a.IsToken() {
		return TransferView{}, tokenRefusal("transfer")
	}
	var out TransferView
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		t, err := lockTransfer(ctx, q, ta.team.ID, id, expectedRevision)
		if err != nil {
			return err
		}
		if !a.IsPlatformAdmin() {
			if err := authz.CheckServerGovernance(ta.role); err != nil {
				return err
			}
		}
		state := TransferCancelled
		if t.ToTeamID == ta.team.ID {
			state = TransferDeclined
		}
		if _, err := q.DecideServerTransfer(ctx, dbgen.DecideServerTransferParams{ID: t.ID, Revision: t.Revision, State: state, Actor: by(a)}); err != nil {
			return err
		}
		e := a.Audit("mcp_server.transfer_cancel", "mcp_server", t.ServerID.String())
		e.TeamID = ta.team.ID
		e.Metadata = map[string]any{"transferId": t.ID.String(), "state": state}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		out, err = s.transferView(ctx, q, t.ID)
		return err
	})
	return out, err
}

// ForceTransfer moves a server to another team without the receiving team's
// say (platform admins, in a browser session; for a server whose team is gone
// or whose owners cannot be reached). Any open transfer of the server is
// cancelled. The server has no owner afterwards: the receiving team names
// one, and it shows in their attention list until then. expectedRevision is
// the server's. Audited as mcp_server.transfer (kind forced).
func (s *Service) ForceTransfer(ctx context.Context, a authz.Actor, serverID uuid.UUID, toTeam string, note *string, expectedRevision int64) (ServerView, error) {
	if a.IsToken() || !a.IsPlatformAdmin() {
		return ServerView{}, errAdminOnly
	}
	note, err := checkNote(note)
	if err != nil {
		return ServerView{}, err
	}
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		sv, err := anyServer(ctx, q, serverID, true)
		if err != nil {
			return err
		}
		if sv.Revision != expectedRevision {
			return apperr.Stale()
		}
		to, err := receivingTeam(ctx, q, toTeam, sv.TeamID)
		if err != nil {
			return err
		}
		open, err := q.PendingServerTransfer(ctx, sv.ID)
		if err == nil {
			if _, err := q.DecideServerTransfer(ctx, dbgen.DecideServerTransferParams{ID: open.ID, Revision: open.Revision, State: TransferCancelled, Actor: by(a)}); err != nil {
				return err
			}
		} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
			return err
		}
		if _, err := q.InsertForcedServerTransfer(ctx, dbgen.InsertForcedServerTransferParams{ServerID: sv.ID, FromTeamID: sv.TeamID, ToTeamID: to.ID,
			ServerRevision: sv.Revision, Note: note, Actor: by(a)}); err != nil {
			return err
		}
		_, err = s.moveServer(ctx, q, a, sv, to, uuid.NullUUID{}, "forced", map[string]any{"note": deref(note)})
		return err
	})
	if err != nil {
		return ServerView{}, err
	}
	return s.view(ctx, s.q, serverID)
}
