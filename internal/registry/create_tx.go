package registry

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// createTx is Create's transaction: it checks authority again, inserts the
// server with its credentials, machine client, TLS settings and endpoints,
// and audits them.
func (s *Service) createTx(ctx context.Context, q *dbgen.Queries, a authz.Actor, ref string, id uuid.UUID, in CreateInput, pre createPrep) error {
	ta, err := access(ctx, q, a, ref)
	if err != nil {
		return err
	}
	if err := ta.writable(authz.CheckServerEdit); err != nil {
		return err
	}
	if err := s.checkProtection(ctx, q, ta.role, in.RateLimitPerMinute, in.MaxConcurrent, in.RateLimitPerMinute != nil || in.MaxConcurrent != nil); err != nil {
		return err
	}
	row, err := s.insertServer(ctx, q, a, ta.team.ID, id, in, pre)
	if err != nil {
		return err
	}
	parts, err := s.storeCreateCredentials(ctx, q, row, in.Credentials)
	if err != nil {
		return err
	}
	if err := setCapture(ctx, q, ta.role, &row, in.CapturePayloads); err != nil {
		return err
	}
	machine, err := s.storeCreateMachine(ctx, q, a, row, in.MachineOAuth, pre.mode)
	if err != nil {
		return err
	}
	tlsRow, err := s.storeCreateTLS(ctx, q, id, in.TLS)
	if err != nil {
		return err
	}
	ep, err := s.planEndpointRows(row, nil, tlsRow != nil, ta.role, pre.endpoints, true)
	if err != nil {
		return err
	}
	if err := storeEndpoints(ctx, q, id, ep); err != nil {
		return err
	}
	e := a.Audit("mcp_server.create", "mcp_server", id.String())
	e.TeamID, e.After = ta.team.ID, withEndpointAudit(withTLS(snapshot(row, parts...), tlsRow), ep.after)
	if err := audit.Record(ctx, q, e); err != nil {
		return err
	}
	if machine != nil {
		ae := a.Audit("mcp_server.auth_update", "mcp_server", id.String())
		ae.TeamID, ae.After, ae.Metadata = ta.team.ID, machineSnapshot(row, machine.view), machineAuditMeta(row, machine)
		if err := audit.Record(ctx, q, ae); err != nil {
			return err
		}
	}
	plan := pre.plan
	if plan == nil {
		return nil
	}
	prov, err := s.insertProvider(ctx, q, a, row, plan)
	if err != nil {
		return err
	}
	return authUpdateAudit(ctx, q, a, nil, nil, row, &prov, map[string]any{"registered": plan.registered,
		"clientIdChanged": true, "clientSecretChanged": plan.secret != nil, "connectionsReset": 0})
}

// insertServer validates the input, inserts the server's row and stores its
// person secret settings.
func (s *Service) insertServer(ctx context.Context, q *dbgen.Queries, a authz.Actor, teamID, id uuid.UUID, in CreateInput, pre createPrep) (dbgen.McpServer, error) {
	p, err := s.insertParams(ctx, id, teamID, a, in)
	if err != nil {
		return dbgen.McpServer{}, err
	}
	if p.AuthProviderID, p.AuthScopes, err = checkRequirement(ctx, q, in.Requirement, uuid.NullUUID{}, teamID, uuid.Nil); err != nil {
		return dbgen.McpServer{}, err
	}
	p.AuthMode, p.SendIdentity = pre.mode, pre.sendIdentity
	if pre.mode == AuthMachineOAuth {
		if err := machineConflicts(createAuthorization(in), p.AuthProviderID.Valid); err != nil {
			return dbgen.McpServer{}, err
		}
	}
	row, err := q.InsertMCPServer(ctx, p)
	if apperr.IsUniqueViolation(err, "mcp_servers_slug_key") {
		return row, errSlugTaken
	} else if err != nil {
		return row, err
	}
	if pre.secret != nil {
		if row, err = q.SetMCPServerSecretConfig(ctx, secretConfigParams(id, pre.secret, true)); err != nil {
			return row, err
		}
	}
	return row, nil
}

// storeCreateCredentials seals and stores a new server's credential parts
// (none: nothing is written) and returns their views for the audit entry.
func (s *Service) storeCreateCredentials(ctx context.Context, q *dbgen.Queries, row dbgen.McpServer, in []CredentialInput) ([]CredentialView, error) {
	if len(in) == 0 {
		return nil, nil
	}
	cp, err := s.planCredentials(row, storedCredentials{}, in)
	if err != nil {
		return nil, err
	}
	if err := storeCredentials(ctx, q, row.ID, cp); err != nil {
		return nil, err
	}
	return cp.views, nil
}

// storeCreateMachine plans and stores a new machine_oauth server's client
// (nil: another mode).
func (s *Service) storeCreateMachine(ctx context.Context, q *dbgen.Queries, a authz.Actor, row dbgen.McpServer, in *MachineOAuthInput, mode string) (*machinePlan, error) {
	if mode != AuthMachineOAuth {
		return nil, nil
	}
	machine, err := s.planMachine(ctx, q, row, row.URL, in)
	if err != nil {
		return nil, err
	}
	mp := machine.row
	mp.By = by(a)
	if _, err := q.UpsertMachineOAuth(ctx, mp); err != nil {
		return nil, err
	}
	return machine, nil
}

// storeCreateTLS stores a new server's TLS settings (nil: none sent).
func (s *Service) storeCreateTLS(ctx context.Context, q *dbgen.Queries, id uuid.UUID, in *TLSInput) (*dbgen.McpServerTl, error) {
	if in.empty() || in.Clear {
		return nil, nil
	}
	tp, err := s.planTLS(id, nil, in, false, time.Now())
	if err != nil {
		return nil, err
	}
	return storeTLS(ctx, q, id, tp)
}

func (s *Service) insertParams(ctx context.Context, id, teamID uuid.UUID, a authz.Actor, in CreateInput) (dbgen.InsertMCPServerParams, error) {
	if !slugRE.MatchString(in.Slug) {
		return dbgen.InsertMCPServerParams{}, apperr.Invalid("invalid_slug",
			"Slug must be 1-48 lowercase letters, digits or hyphens, and cannot start or end with a hyphen")
	}
	if err := checkFields(in.Name, in.Description, in.TimeoutSeconds); err != nil {
		return dbgen.InsertMCPServerParams{}, err
	}
	u, err := s.client.NormalizeURL(ctx, in.URL)
	if err != nil {
		return dbgen.InsertMCPServerParams{}, err
	}
	p := dbgen.InsertMCPServerParams{ID: id, TeamID: teamID, Slug: in.Slug, Name: in.Name, Description: in.Description, URL: u,
		TimeoutSeconds: in.TimeoutSeconds, Enabled: in.Enabled, CreatedBy: by(a), AuthScopes: []string{}, OwnerUserID: creatorOwner(a),
		RateLimitPerMinute: in.RateLimitPerMinute, MaxConcurrent: in.MaxConcurrent}
	if len(in.Credentials) == 0 && (in.AuthHeaderName != "" || in.AuthValue != "") {
		if err := checkHeader(in.AuthHeaderName, in.AuthValue); err != nil {
			return p, err
		}
		if p.AuthValueCipher, err = s.box.Seal([]byte(in.AuthValue), ServerAAD(id)); err != nil {
			return p, err
		}
		name := in.AuthHeaderName
		p.AuthHeaderName, p.AuthValueHint = &name, valueHint(in.AuthValue)
	}
	return p, nil
}
