package registry

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// UpdateInput holds optional changes. AuthHeaderName "" removes the header
// and its value; AuthValue nil keeps the stored value. Credentials (nil keeps
// them) is the server's whole list of parts: each part keeps its stored values
// (Keep) or has new ones, and a part left out is removed; it replaces the
// single header, and a server that has several parts can't be changed with
// AuthHeaderName and AuthValue.
type UpdateInput struct {
	Name, Description, URL         *string
	AuthHeaderName, AuthValue      *string
	Credentials                    *[]CredentialInput
	Endpoints                      *[]EndpointInput // nil keeps, empty clears; null rejected by HTTP
	TimeoutSeconds                 *int32
	SetRateLimit, SetMaxConcurrent bool
	RateLimitPerMinute             *int64
	MaxConcurrent                  *int32
	Enabled                        *bool
	// SetRequirement changes the requirement to Requirement (nil removes
	// it); false keeps it.
	SetRequirement bool
	Requirement    *RequirementInput
	// CapturePayloads changes the capture switch (nil keeps it; only team
	// owners and admins may change it).
	CapturePayloads *bool
	// AuthMode changes the upstream auth mode (nil keeps it); OAuth changes
	// the sign-in (fields nil keep their values).
	AuthMode *string
	OAuth    *OAuthInput
	// MachineOAuth changes the machine client (fields nil keep their values;
	// a new token endpoint, client or server origin needs the secret again).
	MachineOAuth *MachineOAuthInput
	// SendIdentity changes whether the identity token is sent (nil keeps it).
	SendIdentity *bool
	// PersonSecret changes how each person's own secret is sent (nil keeps
	// it; only for a server in person_secret mode, which it is required for
	// when the mode is being chosen).
	PersonSecret *PersonSecretInput
	// TLS changes the server's CA bundle and client certificate (nil keeps
	// them; see TLSInput).
	TLS *TLSInput
	// Governance changes the server's owner, on-call contact, sensitivity,
	// lifecycle and replacement (nil keeps them; team owners and admins in a
	// browser session only, decision 88).
	Governance *GovernanceInput
}

// Update changes a server's settings (team editors and above); the slug
// never changes. A new URL or header forgets the stored health. A new URL
// also forgets when capabilities were read and reads them again from the new
// endpoint, so nothing is approved on the strength of the old one. A URL with
// another origin never keeps the stored header value (422 auth_value_required
// unless a new value comes with it, or the header goes). Audited as
// mcp_server.update with whether the header value changed (never the value)
// and, for another origin, the old and new one.
// A request that changes nothing (for example the capture switch resent at its
// current value) writes nothing: no revision bump and no audit entry, as a
// member role change to the same role.
func (s *Service) Update(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, in UpdateInput, expectedRevision int64) (ServerView, error) {
	if in.Governance != nil && a.IsToken() {
		return ServerView{}, errGovernanceToken
	}
	// Upstream OAuth changes need the network (discovery, registration,
	// revocation): that happens first, against the server as read now; the
	// transaction then checks the revision again.
	pre, err := s.prepareUpdate(ctx, a, ref, id, in, expectedRevision)
	if err != nil {
		return ServerView{}, err
	}
	var done updateOutcome
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		var err error
		done, err = s.updateTx(ctx, q, a, ref, id, in, expectedRevision, pre)
		return err
	})
	if err != nil {
		return ServerView{}, err
	}
	// A new client, secret or endpoint never reuses the token fetched for the
	// old one (the cache key covers it; this frees it at once), and a server
	// that left machine_oauth keeps none.
	if done.forgetMachine {
		s.machine.Forget(id.String())
	}
	if done.moved || done.tlsChanged {
		if err := s.refreshAfterUpdate(ctx, a, id); err != nil {
			return ServerView{}, err
		}
	}
	return s.view(ctx, s.q, id)
}

// refreshAfterUpdate reads an enabled server's capabilities again after its
// URL or TLS settings changed.
func (s *Service) refreshAfterUpdate(ctx context.Context, a authz.Actor, id uuid.UUID) error {
	// Best effort, like Create: a failure is stored as the refresh error.
	sv, err := s.q.GetMCPServer(ctx, id)
	if err != nil {
		return err
	}
	if !sv.Enabled {
		return nil
	}
	_, _, err = s.refresh(ctx, a, sv)
	return err
}
