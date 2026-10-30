package authz

import (
	"net/http"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
)

// Rules of the MCP server registry (SPEC.md §7 phase 2, docs/registry.md):
// members, and platform admins and auditors, read a team's servers; editors
// and above register, change, test and refresh them; owners and admins
// delete, publish and unpublish them, and approve changed capabilities when
// the team's effective policy is self_publish. Platform admins review.
// Platform roles never change team servers through the team routes.

// Publishing policies.
const (
	PolicyApprovalRequired = "approval_required"
	PolicySelfPublish      = "self_publish"
)

// ValidPolicy reports whether p is a publishing policy.
func ValidPolicy(p string) bool { return p == PolicyApprovalRequired || p == PolicySelfPublish }

// EffectivePolicy is the team's override, or the platform default.
func EffectivePolicy(override *string, platformDefault string) string {
	if override != nil && ValidPolicy(*override) {
		return *override
	}
	return platformDefault
}

// CheckServerEdit decides whether a team member with role may register,
// change, test or refresh the team's MCP servers.
func CheckServerEdit(role string) error {
	if !RoleAtLeast(role, RoleEditor) {
		return apperr.Forbidden("Only team owners, admins and editors can change MCP servers")
	}
	return nil
}

// CheckServerManage decides whether a team member with role may delete,
// publish or unpublish the team's MCP servers.
func CheckServerManage(role string) error {
	if !RoleAtLeast(role, RoleAdmin) {
		return apperr.Forbidden("Only team owners and admins can delete, publish or unpublish MCP servers")
	}
	return nil
}

// CheckServerGovernance decides whether a team member with role may change a
// server's governance: its owner, on-call contact, sensitivity, lifecycle and
// replacement (decision 88), or move it to another team. Owners and admins
// only: an editor edits the server, not who is accountable for it.
func CheckServerGovernance(role string) error {
	if !RoleAtLeast(role, RoleAdmin) {
		return apperr.New(http.StatusForbidden, "governance_role",
			"Only team owners and admins can change a server's owner, sensitivity, lifecycle or team")
	}
	return nil
}

// CheckCapabilityApproval decides whether a team member with role may
// approve a changed capability of a published server: owners and admins,
// and only while the team's effective policy is self_publish (otherwise a
// platform admin approves: 403 approval_required).
func CheckCapabilityApproval(role, effectivePolicy string) error {
	if err := CheckServerManage(role); err != nil {
		return err
	}
	if effectivePolicy != PolicySelfPublish {
		return apperr.New(http.StatusForbidden, "approval_required",
			"This team's servers need a platform admin's approval: a platform admin approves changed capabilities")
	}
	return nil
}
