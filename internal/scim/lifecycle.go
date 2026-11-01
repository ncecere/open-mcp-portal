package scim

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Sign-in decisions.
const (
	// GateUnmanaged: sign in as before (no directory, another issuer, an
	// existing unmanaged person, or optional enrollment without a resource).
	GateUnmanaged = iota
	// GateManaged: an existing directory-managed person; users.status (which
	// includes directory standing) decides.
	GateManaged
	// GateEnroll: a new identity with exactly one active matching resource.
	GateEnroll
	// GateDeny: refuse before any user, bootstrap, invite or session write.
	GateDeny
)

// Sign-in refusal reasons (auth.login_denied metadata).
const (
	DenyNotProvisioned = "not_provisioned"
	DenyInactive       = "directory_inactive"
	DenyAmbiguous      = "directory_ambiguous"
	DenyProtected      = "protected_principal"
)

// Gate is a sign-in decision.
type Gate struct {
	Kind     int
	Reason   string
	Resource uuid.UUID // GateEnroll: the locked resource to link
}

// LoginGate decides a verified sign-in before the user upsert, in the
// sign-in transaction q. It locks the directory (SHARE) and, for a new
// identity, its matching resources (FOR UPDATE), so a concurrent policy
// change, deactivation or deletion serialises with enrollment. bootstrap is
// whether a one-time bootstrap role would apply to this identity.
func (s *Service) LoginGate(ctx context.Context, q *dbgen.Queries, issuer, subject string, bootstrap bool) (Gate, error) {
	d, err := q.LockSCIMDirectoryShare(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return Gate{Kind: GateUnmanaged}, nil
	} else if err != nil {
		return Gate{}, err
	}
	if !d.Enabled || d.Issuer != issuer {
		return Gate{Kind: GateUnmanaged}, nil
	}
	u, err := q.GetUserByIdentity(ctx, dbgen.GetUserByIdentityParams{OIDCIssuer: issuer, OIDCSubject: subject})
	if err == nil {
		if u.DirectoryStanding != StandingNone {
			return Gate{Kind: GateManaged}, nil
		}
		// Existing unmanaged people keep signing in; adoption is explicit.
		return Gate{Kind: GateUnmanaged}, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Gate{}, err
	}
	cands, err := q.LockEnrollmentCandidates(ctx, dbgen.LockEnrollmentCandidatesParams{DirectoryID: d.ID, Subject: &subject})
	if err != nil {
		return Gate{}, err
	}
	switch {
	case len(cands) == 0 && d.Enrollment == EnrollmentRequired:
		return Gate{Kind: GateDeny, Reason: DenyNotProvisioned}, nil
	case len(cands) == 0:
		return Gate{Kind: GateUnmanaged}, nil
	case len(cands) > 1:
		return Gate{Kind: GateDeny, Reason: DenyAmbiguous}, nil
	case !cands[0].Active:
		return Gate{Kind: GateDeny, Reason: DenyInactive}, nil
	case bootstrap:
		// A bootstrap administrator is a protected, unmanaged break-glass
		// account; it never enrolls as directory managed.
		return Gate{Kind: GateDeny, Reason: DenyProtected}, nil
	}
	return Gate{Kind: GateEnroll, Resource: cands[0].ID}, nil
}

// Enroll links a just-created person to the resource LoginGate locked, in
// the same sign-in transaction, then applies the person's group roles.
func (s *Service) Enroll(ctx context.Context, q *dbgen.Queries, user dbgen.User, resource uuid.UUID, requestID string) (dbgen.User, error) {
	if _, err := q.LinkSCIMUser(ctx, dbgen.LinkSCIMUserParams{ID: resource, UserID: uuid.NullUUID{UUID: user.ID, Valid: true}}); err != nil {
		return user, err
	}
	u, err := q.SetDirectoryStanding(ctx, dbgen.SetDirectoryStandingParams{ID: user.ID, DirectoryStanding: StandingActive})
	if err != nil {
		return user, err
	}
	if err := audit.Record(ctx, q, audit.Entry{ActorKind: audit.ActorSystem, Action: "scim.user_enroll", TargetType: "user", TargetID: u.ID.String(),
		RequestID: requestID, Metadata: map[string]any{"scimUserId": resource.String()}}); err != nil {
		return u, err
	}
	return u, reconcile(ctx, q, []uuid.UUID{u.ID}, requestID)
}

// applyStanding sets a linked person's directory standing (the trigger
// derives users.status, the request epoch and the session generation). It
// never deletes sessions or calls a provider: deactivation is a short fence.
func applyStanding(ctx context.Context, q *dbgen.Queries, userID uuid.UUID, standing string) (dbgen.User, error) {
	return q.SetDirectoryStanding(ctx, dbgen.SetDirectoryStandingParams{ID: userID, DirectoryStanding: standing})
}

func standingFor(active bool) string {
	if active {
		return StandingActive
	}
	return StandingInactive
}

// lockReconcile takes the per-person reconcile locks of users in UUID order
// and returns the sorted, de-duplicated list. Lock order everywhere: these
// locks, then teams. A writer that will touch a team row, even implicitly
// through a foreign key (a mapping insert), takes them first.
func lockReconcile(ctx context.Context, q *dbgen.Queries, users []uuid.UUID) ([]uuid.UUID, error) {
	users = slices.Clone(users)
	slices.SortFunc(users, compareUUID)
	users = slices.Compact(users)
	for _, u := range users {
		if err := q.LockDirectoryReconcile(ctx, u.String()); err != nil {
			return nil, err
		}
	}
	return users, nil
}

// lockGroupReconcile takes the reconcile locks of a locked group's linked
// members before a mapping row (and its team FK) is touched.
func lockGroupReconcile(ctx context.Context, q *dbgen.Queries, group uuid.UUID) error {
	members, err := q.SCIMMembersOfGroup(ctx, group)
	if err != nil || len(members) == 0 {
		return err
	}
	linked, err := q.LinkedUsersOf(ctx, members)
	if err != nil {
		return err
	}
	_, err = lockReconcile(ctx, q, linked)
	return err
}

// roleRank orders the roles a directory can grant.
func roleRank(role string) int {
	switch role {
	case authz.RoleAdmin:
		return 3
	case authz.RoleEditor:
		return 2
	case authz.RoleMember:
		return 1
	}
	return 0
}

// reconcile brings directory-created team memberships of users in line with
// their mapped groups. Manual memberships are never changed. Lock order:
// per-person reconcile locks (UUID order), then teams (UUID order), matching
// the team writers. Changes are audited per
// team as scim.membership_sync.
func reconcile(ctx context.Context, q *dbgen.Queries, users []uuid.UUID, requestID string) error {
	if len(users) == 0 {
		return nil
	}
	// Serialise per person before reading: two writers changing different
	// groups of the same person must not each apply a stale desired role.
	users, err := lockReconcile(ctx, q, users)
	if err != nil {
		return err
	}
	desired, err := q.DirectoryDesiredMemberships(ctx, users)
	if err != nil {
		return err
	}
	owned, err := q.DirectoryOwnedMemberships(ctx, users)
	if err != nil {
		return err
	}
	type key struct{ team, user uuid.UUID }
	want := map[key]string{}
	teamSet := map[uuid.UUID]bool{}
	for _, d := range desired {
		want[key{d.TeamID, d.UserID}] = d.Role
		teamSet[d.TeamID] = true
	}
	have := map[key]string{}
	for _, o := range owned {
		have[key{o.TeamID, o.UserID}] = o.Role
		teamSet[o.TeamID] = true
	}
	if len(teamSet) == 0 {
		return nil
	}
	teams := make([]uuid.UUID, 0, len(teamSet))
	for t := range teamSet {
		teams = append(teams, t)
	}
	slices.SortFunc(teams, func(a, b uuid.UUID) int { return compareUUID(a, b) })
	for _, t := range teams {
		if _, err := q.LockTeam(ctx, t); errors.Is(err, pgx.ErrNoRows) {
			continue
		} else if err != nil {
			return err
		}
	}
	if err := q.MarkDirectoryWriter(ctx); err != nil {
		return err
	}
	type counts struct{ added, updated, removed int64 }
	per := map[uuid.UUID]*counts{}
	bump := func(t uuid.UUID) *counts {
		if per[t] == nil {
			per[t] = &counts{}
		}
		return per[t]
	}
	for k, role := range want {
		if _, ok := have[k]; ok {
			n, err := q.UpdateDirectoryMembershipRole(ctx, dbgen.UpdateDirectoryMembershipRoleParams{TeamID: k.team, UserID: k.user, Role: role})
			if err != nil {
				return err
			}
			bump(k.team).updated += n
			continue
		}
		// No directory row: insert unless a manual membership exists (ON
		// CONFLICT leaves it alone) or the team is archived.
		n, err := q.InsertDirectoryMembership(ctx, dbgen.InsertDirectoryMembershipParams{TeamID: k.team, UserID: k.user, Role: role})
		if err != nil {
			return err
		}
		bump(k.team).added += n
	}
	for k := range have {
		if _, ok := want[k]; ok {
			continue
		}
		n, err := q.DeleteDirectoryMembership(ctx, dbgen.DeleteDirectoryMembershipParams{TeamID: k.team, UserID: k.user})
		if err != nil {
			return err
		}
		bump(k.team).removed += n
	}
	for _, t := range teams {
		c := per[t]
		if c == nil || c.added+c.updated+c.removed == 0 {
			continue
		}
		if err := audit.Record(ctx, q, audit.Entry{ActorKind: audit.ActorSystem, Action: "scim.membership_sync", TargetType: "team", TargetID: t.String(),
			TeamID: t, RequestID: requestID, Metadata: map[string]any{"added": c.added, "updated": c.updated, "removed": c.removed}}); err != nil {
			return err
		}
	}
	return nil
}

func compareUUID(a, b uuid.UUID) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// protectedError maps the database's protected-principal guards to 409.
func protectedError(err error) error {
	if e, ok := apperr.DirectoryGuard(err); ok {
		return e
	}
	return err
}

// Adopt links an unlinked resource to the existing portal person whose
// verified OIDC subject equals its externalId (platform admins, session).
// It also re-enrolls a deleted directory life once clean-up is complete.
// Platform admins and team owners are refused. Audited as scim.user_adopt.
func (s *Service) Adopt(ctx context.Context, a authz.Actor, resource uuid.UUID) error {
	if err := adminActor(a); err != nil {
		return err
	}
	return protectedError(store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		d, err := q.LockSCIMDirectoryShare(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoDirectory
		} else if err != nil {
			return err
		}
		r, err := q.LockSCIMUser(ctx, dbgen.LockSCIMUserParams{ID: resource, DirectoryID: d.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound("scim_user_not_found", "Provisioned person not found")
		} else if err != nil {
			return err
		}
		if r.LinkedUserID.Valid {
			return apperr.Conflict("already_linked", "This provisioned person is already linked")
		}
		if r.ExternalID == nil {
			return apperr.Conflict("no_match", "This provisioned person has no externalId to match a sign-in subject")
		}
		u, err := q.GetUserByIdentity(ctx, dbgen.GetUserByIdentityParams{OIDCIssuer: d.Issuer, OIDCSubject: *r.ExternalID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.Conflict("no_match", "No one has signed in with this subject yet; they enroll on first sign-in")
		} else if err != nil {
			return err
		}
		if u.DirectoryStanding == StandingActive || u.DirectoryStanding == StandingInactive {
			return apperr.Conflict("already_linked", "This person is already directory managed")
		}
		before := u.DirectoryStanding
		if _, err := q.LinkSCIMUser(ctx, dbgen.LinkSCIMUserParams{ID: r.ID, UserID: uuid.NullUUID{UUID: u.ID, Valid: true}}); err != nil {
			return err
		}
		if _, err := applyStanding(ctx, q, u.ID, standingFor(r.Active)); err != nil {
			return err
		}
		e := a.Audit("scim.user_adopt", "user", u.ID.String())
		e.Before = map[string]any{"directoryStanding": before}
		e.After = map[string]any{"directoryStanding": standingFor(r.Active)}
		e.Metadata = map[string]any{"scimUserId": r.ID.String(), "reenrolled": before == StandingDeleted}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		return reconcile(ctx, q, []uuid.UUID{u.ID}, a.RequestID)
	}))
}

// Unlink returns a linked person to manual control (platform admins,
// session): directory standing becomes none, so only manual standing
// applies. Directory-created memberships become manual. Audited as
// scim.user_unlink.
func (s *Service) Unlink(ctx context.Context, a authz.Actor, userID uuid.UUID) error {
	if err := adminActor(a); err != nil {
		return err
	}
	return protectedError(store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if _, err := q.LockSCIMDirectoryShare(ctx); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		r, err := q.GetSCIMUserByLinkedUser(ctx, uuid.NullUUID{UUID: userID, Valid: true})
		hasResource := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if hasResource {
			if r, err = q.LockSCIMUser(ctx, dbgen.LockSCIMUserParams{ID: r.ID, DirectoryID: r.DirectoryID}); err != nil {
				return err
			}
		}
		u, err := q.GetUserForUpdate(ctx, userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound("user_not_found", "User not found")
		} else if err != nil {
			return err
		}
		if u.DirectoryStanding == StandingNone {
			return apperr.Conflict("not_linked", "This person isn't directory managed")
		}
		if hasResource {
			if err := q.UnlinkSCIMUser(ctx, r.ID); err != nil {
				return err
			}
		}
		if _, err := applyStanding(ctx, q, u.ID, StandingNone); err != nil {
			return err
		}
		if err := q.ReleaseDirectoryMemberships(ctx, u.ID); err != nil {
			return err
		}
		e := a.Audit("scim.user_unlink", "user", u.ID.String())
		e.Before = map[string]any{"directoryStanding": u.DirectoryStanding}
		e.After = map[string]any{"directoryStanding": StandingNone}
		return audit.Record(ctx, q, e)
	}))
}

// MappingInput is a new group -> team role mapping.
type MappingInput struct {
	GroupID uuid.UUID
	TeamID  uuid.UUID
	Role    string
}

// CreateMapping adds a reviewed group -> team role bridge and applies it to
// the group's linked members (platform admins, session). Owner is never
// mapped. Audited as scim.mapping_create.
func (s *Service) CreateMapping(ctx context.Context, a authz.Actor, in MappingInput) (dbgen.ScimGroupMapping, error) {
	var out dbgen.ScimGroupMapping
	if err := adminActor(a); err != nil {
		return out, err
	}
	if in.Role != authz.RoleAdmin && in.Role != authz.RoleEditor && in.Role != authz.RoleMember {
		return out, apperr.Invalid("invalid_role", "A directory group can grant admin, editor or member")
	}
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		d, err := q.LockSCIMDirectoryShare(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoDirectory
		} else if err != nil {
			return err
		}
		if _, err := q.LockSCIMGroup(ctx, dbgen.LockSCIMGroupParams{ID: in.GroupID, DirectoryID: d.ID}); errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound("scim_group_not_found", "Directory group not found")
		} else if err != nil {
			return err
		}
		// Before the insert's team FK lock: see lockReconcile.
		if err := lockGroupReconcile(ctx, q, in.GroupID); err != nil {
			return err
		}
		t, err := q.GetTeamByID(ctx, in.TeamID)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound("team_not_found", "Team not found")
		} else if err != nil {
			return err
		}
		out, err = q.InsertSCIMGroupMapping(ctx, dbgen.InsertSCIMGroupMappingParams{GroupID: in.GroupID, TeamID: t.ID, Role: in.Role, CreatedBy: uuid.NullUUID{UUID: a.UserID, Valid: true}})
		if apperr.IsUniqueViolation(err, "scim_group_mappings_key") {
			return apperr.Conflict("mapping_exists", "This group is already mapped to that team")
		} else if err != nil {
			return err
		}
		e := a.Audit("scim.mapping_create", "scim_group_mapping", out.ID.String())
		e.TeamID = t.ID
		e.After = map[string]any{"groupId": in.GroupID.String(), "teamId": t.ID.String(), "role": in.Role}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		return reconcileGroup(ctx, q, in.GroupID, a.RequestID)
	})
	return out, err
}

// DeleteMapping removes a mapping and the memberships only it created
// (platform admins, session). Audited as scim.mapping_delete.
func (s *Service) DeleteMapping(ctx context.Context, a authz.Actor, id uuid.UUID) error {
	if err := adminActor(a); err != nil {
		return err
	}
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		d, err := q.LockSCIMDirectoryShare(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoDirectory
		} else if err != nil {
			return err
		}
		m, err := q.GetSCIMGroupMapping(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound("mapping_not_found", "Mapping not found")
		} else if err != nil {
			return err
		}
		if _, err := q.LockSCIMGroup(ctx, dbgen.LockSCIMGroupParams{ID: m.GroupID, DirectoryID: d.ID}); err != nil {
			return err
		}
		if err := lockGroupReconcile(ctx, q, m.GroupID); err != nil {
			return err
		}
		if err := q.DeleteSCIMGroupMapping(ctx, id); err != nil {
			return err
		}
		e := a.Audit("scim.mapping_delete", "scim_group_mapping", id.String())
		e.TeamID = m.TeamID
		e.Before = map[string]any{"groupId": m.GroupID.String(), "teamId": m.TeamID.String(), "role": m.Role}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		// The departed team's directory rows are no longer desired: removed.
		return reconcileGroup(ctx, q, m.GroupID, a.RequestID)
	})
}

// reconcileGroup reconciles every linked member of a group.
func reconcileGroup(ctx context.Context, q *dbgen.Queries, group uuid.UUID, requestID string) error {
	members, err := q.SCIMMembersOfGroup(ctx, group)
	if err != nil {
		return err
	}
	return reconcileResources(ctx, q, members, requestID)
}

// reconcileResources reconciles the linked people behind SCIM resources.
func reconcileResources(ctx context.Context, q *dbgen.Queries, resources []uuid.UUID, requestID string) error {
	if len(resources) == 0 {
		return nil
	}
	rows, err := q.LinkedUsersOf(ctx, resources)
	if err != nil {
		return err
	}
	return reconcile(ctx, q, rows, requestID)
}

// CleanupResult is one clean-up run.
type CleanupResult struct {
	Completed, Incomplete int
}

// Cleanup advances deprovisioning clean-up jobs. Every replica may run it:
// a job is claimed with SKIP LOCKED, each pass is bounded by a short lock
// timeout and contention leaves the job for the next run. A job completes
// only when a recount under the user row lock finds no usable personal
// artifact. Re-enrollment is refused until then (database trigger).
func (s *Service) Cleanup(ctx context.Context) (CleanupResult, error) {
	var res CleanupResult
	jobs, err := s.q.ListOpenDirectoryCleanupJobs(ctx, 20)
	if err != nil {
		return res, err
	}
	for _, j := range jobs {
		done, err := s.cleanupOne(ctx, j.ID)
		switch {
		case err != nil:
			res.Incomplete++
			_ = s.q.RecordDirectoryCleanupAttempt(ctx, dbgen.RecordDirectoryCleanupAttemptParams{ID: j.ID, LastError: cleanupErrorCode(err)})
		case done:
			res.Completed++
		}
	}
	return res, nil
}

func cleanupErrorCode(err error) *string {
	code := "error"
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		code = "sqlstate_" + pe.Code
	} else if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		code = "cancelled"
	}
	return &code
}

func (s *Service) cleanupOne(ctx context.Context, id uuid.UUID) (bool, error) {
	done := false
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		j, err := q.LockDirectoryCleanupJob(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // another replica has it, or it completed
		} else if err != nil {
			return err
		}
		if err := q.SetCleanupLockTimeout(ctx); err != nil {
			return err
		}
		// FOR UPDATE conflicts with the KEY SHARE any artifact insert takes
		// on its owner: no artifact commits between the pass and recount.
		u, err := q.GetUserForUpdate(ctx, j.UserID)
		if err != nil {
			return err
		}
		if u.DirectoryStanding != StandingDeleted {
			// Re-enrollment can't happen before completion; an unlink by an
			// admin ends the deleted life explicitly. Nothing more to do.
			done = true
			return q.CompleteDirectoryCleanupJob(ctx, j.ID)
		}
		removed, err := q.CleanupDeletedUserCredentials(ctx, u.ID)
		if err != nil {
			return err
		}
		left, err := q.CountDeletedUserArtifacts(ctx, u.ID)
		if err != nil {
			return err
		}
		if left != 0 {
			return fmt.Errorf("clean-up left %d artifacts", left)
		}
		if err := q.CompleteDirectoryCleanupJob(ctx, j.ID); err != nil {
			return err
		}
		done = true
		return audit.Record(ctx, q, audit.Entry{ActorKind: audit.ActorSystem, Action: "scim.user_cleanup", TargetType: "user", TargetID: u.ID.String(),
			Metadata: map[string]any{"sessions": removed.Sessions, "apiKeys": removed.ApiKeys, "oauthGrants": removed.OauthGrants,
				"providerConnections": removed.ProviderConnections, "personSecrets": removed.PersonSecrets, "memberships": removed.Memberships,
				"gatewayGrants": removed.GatewayGrants, "pendingFlows": removed.PendingFlows}})
	})
	return done, err
}
