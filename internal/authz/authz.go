// Package authz holds the authorization rules shared by every module: the
// acting principal and the platform and team roles.
//
// Rules live here as pure functions so they can be unit-tested exhaustively.
// Services call them inside the same transaction that performs the change,
// after locking the rows the decision depends on.
package authz

import (
	"context"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
)

// Platform roles.
const (
	PlatformNone    = "none"
	PlatformAdmin   = "platform_admin"
	PlatformAuditor = "platform_auditor"
)

// Team roles, most to least privileged.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleEditor = "editor"
	RoleMember = "member"
)

// Actor kinds.
const (
	// KindUser is a signed-in person (browser session); the zero value.
	KindUser = "user"
	// KindAutomationToken is an automation token (docs/automation-tokens.md):
	// no person, so UserID is uuid.Nil, and PlatformRole and the team role
	// are derived from the token's scopes.
	KindAutomationToken = "automation_token"
)

// Automation token kinds and scopes.
const (
	TokenPlatformAdmin = "platform_admin"
	TokenTeamPublisher = "team_publisher"

	ScopePlatformRead  = "platform:read"
	ScopePlatformWrite = "platform:write"
	ScopeServersRead   = "servers:read"
	ScopeServersWrite  = "servers:write"
)

// Actor is the principal performing an operation, plus request metadata for
// the audit log: a signed-in person (browser session) or an automation
// token (Kind).
type Actor struct {
	// Kind is KindUser ("" too) or KindAutomationToken.
	Kind         string
	UserID       uuid.UUID
	PlatformRole string
	// RequestEpoch is captured from the authenticated user's request authority
	// before resource waits. It is not a credential or enrollment lifetime;
	// machine actors do not obtain a human epoch merely from attribution.
	RequestEpoch int64
	RequestID    string
	ClientIP     string

	// The automation token acting (Kind KindAutomationToken): its ID, name
	// and kind (TokenPlatformAdmin, TokenTeamPublisher), the team of a
	// publisher token and its scopes.
	TokenID     uuid.UUID
	TokenName   string
	TokenKind   string
	TokenTeamID uuid.UUID
	TokenScopes []string
}

// IsToken reports whether an automation token is acting.
func (a Actor) IsToken() bool { return a.Kind == KindAutomationToken }

// HasScope reports whether the acting token holds a scope.
func (a Actor) HasScope(scope string) bool {
	for _, s := range a.TokenScopes {
		if s == scope {
			return true
		}
	}
	return false
}

// TeamRole is the actor's role in a team given its membership role (""
// for none) from the database. A person has their membership role. A
// publisher token acts in its own team only, as an admin when it holds
// servers:write (the operations it may reach are listed in
// api/openapi.yaml: it publishes but never approves, deletes or manages
// members) and as a member for reads; platform tokens have no team role.
func (a Actor) TeamRole(teamID uuid.UUID, membership string) string {
	if !a.IsToken() {
		return membership
	}
	if a.TokenKind != TokenTeamPublisher || a.TokenTeamID != teamID {
		return ""
	}
	if a.HasScope(ScopeServersWrite) {
		return RoleAdmin
	}
	if a.HasScope(ScopeServersRead) {
		return RoleMember
	}
	return ""
}

func (a Actor) IsPlatformAdmin() bool { return a.PlatformRole == PlatformAdmin }

// CanReadPlatform reports whether the actor may read platform metadata
// (users, teams, audit). It never implies access to team content.
func (a Actor) CanReadPlatform() bool {
	return a.PlatformRole == PlatformAdmin || a.PlatformRole == PlatformAuditor
}

// Audit returns an audit entry pre-filled with the actor.
func (a Actor) Audit(action, targetType, targetID string) audit.Entry {
	e := audit.Entry{
		ActorKind: audit.ActorUser, ActorUserID: a.UserID,
		Action: action, TargetType: targetType, TargetID: targetID,
		RequestID: a.RequestID, ClientIP: a.ClientIP,
	}
	if a.IsToken() {
		e.ActorKind, e.ActorUserID = audit.ActorAutomationToken, uuid.Nil
		e.ActorTokenID, e.ActorTokenName, e.ActorTokenKind = a.TokenID, a.TokenName, a.TokenKind
	}
	return e
}

var roleRank = map[string]int{RoleMember: 1, RoleEditor: 2, RoleAdmin: 3, RoleOwner: 4}

// ValidTeamRole reports whether r is a team role.
func ValidTeamRole(r string) bool { return roleRank[r] > 0 }

// RoleAtLeast reports whether role grants at least min. "" (not a member)
// never does.
func RoleAtLeast(role, min string) bool { return roleRank[role] > 0 && roleRank[role] >= roleRank[min] }

// CheckMemberChange decides whether a team member with actorRole may change
// another member's role from `from` to `to`. Use from = "" to add a member and
// to = "" to remove one. Leaving a team yourself is handled separately.
//
//   - Owners and admins manage members.
//   - Admins cannot add, change or remove owners, or make anyone an owner.
func CheckMemberChange(actorRole, from, to string) error {
	if !RoleAtLeast(actorRole, RoleAdmin) {
		return apperr.Forbidden("Only team owners and admins can manage members")
	}
	if to != "" && !ValidTeamRole(to) {
		return apperr.Invalid("invalid_role", "Role must be owner, admin, editor or member")
	}
	if actorRole != RoleOwner && (from == RoleOwner || to == RoleOwner) {
		return apperr.Forbidden("Only team owners can add, change or remove owners")
	}
	return nil
}

type actorKey struct{}

// WithActor attaches an actor to ctx. Authentication that doesn't go
// through a browser session (automation tokens) uses it; sessions attach an
// auth.Identity instead.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

// ActorFromContext returns the actor attached by WithActor.
func ActorFromContext(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorKey{}).(Actor)
	return a, ok
}
