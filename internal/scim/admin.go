package scim

import (
	"context"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// adminListCap bounds the admin views; the identity provider is the source
// of the full list.
const adminListCap = 500

// Provisioned is the admin view of resources and managed people.
type Provisioned struct {
	Resources []dbgen.ListSCIMUsersAdminRow
	People    []dbgen.ListDirectoryManagedUsersRow
	Truncated bool
}

// ListProvisioned lists resources (with link and adoption candidate) and the
// directory-managed people (platform admins and auditors).
func (s *Service) ListProvisioned(ctx context.Context, a authz.Actor) (Provisioned, error) {
	d, err := s.GetDirectory(ctx, a)
	if err != nil {
		return Provisioned{}, err
	}
	var out Provisioned
	rows, err := s.q.ListSCIMUsersAdmin(ctx, dbgen.ListSCIMUsersAdminParams{DirectoryID: d.Row.ID, AfterID: uuid.NullUUID{}, PageSize: adminListCap + 1})
	if err != nil {
		return out, err
	}
	if len(rows) > adminListCap {
		rows, out.Truncated = rows[:adminListCap], true
	}
	out.Resources = rows
	out.People, err = s.q.ListDirectoryManagedUsers(ctx)
	return out, err
}

// ListGroups lists directory groups (platform admins and auditors).
func (s *Service) ListGroups(ctx context.Context, a authz.Actor) ([]dbgen.ListSCIMGroupsAdminRow, error) {
	d, err := s.GetDirectory(ctx, a)
	if err != nil {
		return nil, err
	}
	return s.q.ListSCIMGroupsAdmin(ctx, d.Row.ID)
}

// ListMappings lists group -> team role mappings (platform admins and
// auditors). Without a directory there are none.
func (s *Service) ListMappings(ctx context.Context, a authz.Actor) ([]dbgen.ListSCIMGroupMappingsRow, error) {
	if !a.CanReadPlatform() {
		return nil, errReadOnly
	}
	return s.q.ListSCIMGroupMappings(ctx)
}

// Adoption explains whether a candidate can be adopted, and why not.
func Adoption(r dbgen.ListSCIMUsersAdminRow) (bool, string) {
	switch {
	case r.CandidateIsOwner || (r.CandidatePlatformRole != nil && *r.CandidatePlatformRole == authz.PlatformAdmin):
		return false, "protected_principal"
	case r.CandidateCleanupPending:
		return false, "cleanup_pending"
	case r.CandidateStanding != nil && (*r.CandidateStanding == StandingActive || *r.CandidateStanding == StandingInactive):
		return false, "already_managed"
	}
	return true, ""
}
