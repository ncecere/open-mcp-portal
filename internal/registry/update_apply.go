package registry

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// applyOAuth stores an update's sign-in changes in its transaction and
// reports whether they need review again (a switch to oauth, another
// authorization server, or a scope not asked for before). A URL change,
// another authorization server or another client ID erases every
// connection's tokens; leaving oauth deletes the connections. Audited as
// mcp_server.auth_update.
func (s *Service) applyOAuth(ctx context.Context, q *dbgen.Queries, a authz.Actor, cur, row dbgen.McpServer, pre updatePrep) (bool, error) {
	beforeMode, afterMode := AuthModeOf(cur), AuthModeOf(row)
	prov := pre.provider
	switch {
	case afterMode == AuthOAuth && pre.plan != nil && prov == nil:
		np, err := s.insertProvider(ctx, q, a, row, pre.plan)
		if err != nil {
			return false, err
		}
		return true, authUpdateAudit(ctx, q, a, &cur, nil, row, &np, map[string]any{"registered": pre.plan.registered,
			"clientIdChanged": true, "clientSecretChanged": pre.plan.secret != nil, "connectionsReset": 0})
	case afterMode == AuthOAuth && prov != nil:
		// Tokens are for one resource: another origin always starts over, even
		// when discovery at the new host happens to give an identical plan (F-1).
		originMoved := !sameOrigin(cur.URL, row.URL)
		if originMoved && pre.plan == nil {
			return false, errors.New("registry: another origin without a sign-in plan")
		}
		if !originMoved && (pre.plan == nil || planUnchanged(*prov, pre.plan)) {
			if row.Name != cur.Name {
				if err := q.RenameServerProvider(ctx, dbgen.RenameServerProviderParams{Name: row.Name, ServerID: uuid.NullUUID{UUID: row.ID, Valid: true}}); err != nil {
					return false, err
				}
			}
			if row.SendIdentity != cur.SendIdentity {
				return false, authUpdateAudit(ctx, q, a, &cur, prov, row, prov, nil)
			}
			return false, nil
		}
		np, err := s.updateProvider(ctx, q, a, row.Name, *prov, pre.plan)
		if err != nil {
			return false, err
		}
		otherServer := deref(prov.Issuer) != deref(np.Issuer) || deref(prov.AuthorizationServer) != deref(np.AuthorizationServer)
		clientChanged := prov.ClientID != np.ClientID || prov.LinkProviderID != np.LinkProviderID
		var reset int64
		if otherServer || clientChanged || row.URL != cur.URL {
			if reset, err = q.ResetProviderConnections(ctx, dbgen.ResetProviderConnectionsParams{ProviderID: prov.ID,
				ErrorClass: ptr("server_auth_changed")}); err != nil {
				return false, err
			}
		}
		meta := map[string]any{"registered": pre.plan.registered, "clientIdChanged": clientChanged,
			"clientSecretChanged": pre.plan.secret != nil || (pre.plan.clearSecret && prov.ClientSecretCipher != nil), "connectionsReset": reset}
		for k, v := range originChange(cur.URL, row.URL) {
			meta[k] = v
		}
		if err := authUpdateAudit(ctx, q, a, &cur, prov, row, &np, meta); err != nil {
			return false, err
		}
		return otherServer || originMoved || widensScopes(nonNil(prov.DefaultScopes), nonNil(np.DefaultScopes)), nil
	case afterMode != AuthOAuth && prov != nil:
		if s.oauth.Hooks != nil {
			if err := s.oauth.Hooks.DeleteConnections(ctx, q, a, *prov, pre.revoked, "server_auth_changed"); err != nil {
				return false, err
			}
		}
		if err := q.DeleteServerProvider(ctx, uuid.NullUUID{UUID: row.ID, Valid: true}); err != nil {
			return false, err
		}
		return false, authUpdateAudit(ctx, q, a, &cur, prov, row, nil, map[string]any{"connectionsReset": 0,
			"connectionsDeleted": len(pre.revoked)})
	case beforeMode == AuthMachineOAuth || afterMode == AuthMachineOAuth:
		// A machine client's changes are audited with its details (applyMachine).
	case beforeMode != afterMode || cur.SendIdentity != row.SendIdentity:
		return false, authUpdateAudit(ctx, q, a, &cur, nil, row, nil, nil)
	}
	return false, nil
}

func ptr[T any](v T) *T { return &v }

// applied is what an update decided about the server's row and its credential.
type applied struct {
	p            dbgen.UpdateMCPServerParams
	valueChanged bool
	// plan is the new list of parts to store (nil: the stored parts stay,
	// the legacy header columns in p included).
	plan *credentialPlan
	// before and views are the parts before and after, for the audit entry
	// and the conflict checks.
	before, views []CredentialView
}

// rewrites reports whether the update stores a new list of parts.
func (a applied) rewrites() bool { return a.plan != nil && a.plan.write }

func (a applied) afterParts() []CredentialView { return a.views }

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (s *Service) applyUpdate(ctx context.Context, q *dbgen.Queries, cur dbgen.McpServer, in UpdateInput, mode string) (applied, error) {
	stored, err := loadStored(ctx, q, cur)
	if err != nil {
		return applied{}, err
	}
	if err := checkUpdateCredentials(in, stored); err != nil {
		return applied{}, err
	}
	p := dbgen.UpdateMCPServerParams{ID: cur.ID, Name: cur.Name, Description: cur.Description, URL: cur.URL,
		AuthHeaderName: cur.AuthHeaderName, AuthValueCipher: cur.AuthValueCipher, AuthValueHint: cur.AuthValueHint,
		TimeoutSeconds: cur.TimeoutSeconds, Enabled: cur.Enabled, AuthProviderID: cur.AuthProviderID, AuthScopes: nonNil(cur.AuthScopes),
		AuthMode: mode, SendIdentity: cur.SendIdentity, RateLimitPerMinute: cur.RateLimitPerMinute, MaxConcurrent: cur.MaxConcurrent}
	if in.SetRateLimit {
		p.RateLimitPerMinute = in.RateLimitPerMinute
	}
	if in.SetMaxConcurrent {
		p.MaxConcurrent = in.MaxConcurrent
	}
	out := applied{p: p, before: stored.views(), views: stored.views()}
	setIf(&p.Name, in.Name)
	p.Name = strings.TrimSpace(p.Name)
	setIf(&p.Description, in.Description)
	setIf(&p.TimeoutSeconds, in.TimeoutSeconds)
	setIf(&p.Enabled, in.Enabled)
	if err := checkFields(p.Name, p.Description, p.TimeoutSeconds); err != nil {
		return out, err
	}
	if in.URL != nil {
		u, err := s.client.NormalizeURL(ctx, *in.URL)
		if err != nil {
			return out, err
		}
		p.URL = u
	}
	if err := requireValueForOrigin(cur, stored, p.URL, in, mode); err != nil {
		return out, err
	}
	switch {
	case mode == AuthNone:
		// authMode none removes the static credential with its values.
		if (in.AuthHeaderName != nil && *in.AuthHeaderName != "") || (in.AuthValue != nil && *in.AuthValue != "") ||
			(in.Credentials != nil && len(*in.Credentials) > 0) {
			return out, apperr.Invalid("invalid_auth_header", "authMode none has no static credential")
		}
		p.AuthHeaderName, p.AuthValueCipher, p.AuthValueHint = nil, nil, ""
		if len(stored.rows) > 0 {
			out.plan = &credentialPlan{write: true}
		}
		out.p, out.valueChanged, out.views = p, stored.any(), nil
		return out, nil
	case in.Credentials != nil:
		plan, err := s.planCredentials(cur, stored, *in.Credentials)
		if err != nil {
			return out, err
		}
		if plan.write {
			// The credential moves into (or stays in, or leaves) the table:
			// the legacy columns are never kept next to it.
			p.AuthHeaderName, p.AuthValueCipher, p.AuthValueHint = nil, nil, ""
			out.plan = &plan
		}
		out.views, out.valueChanged = plan.views, plan.valueChanged
		if mode == AuthStaticHeader && len(plan.views) == 0 {
			return out, apperr.Invalid("invalid_auth_header", "Add at least one credential part")
		}
		out.p = p
		return out, nil
	case len(stored.rows) > 0:
		// Several parts, and the request doesn't touch them.
		out.p = p
		return out, nil
	}
	removed := in.AuthHeaderName != nil && *in.AuthHeaderName == "" && cur.AuthValueCipher != nil
	if err := s.applyAuth(&p, cur, in); err != nil {
		return out, err
	}
	if mode == AuthStaticHeader && p.AuthHeaderName == nil {
		return out, apperr.Invalid("invalid_auth_header", "Enter the static header's name and value")
	}
	out.p, out.valueChanged = p, in.AuthValue != nil || removed
	out.views = nil
	if p.AuthHeaderName != nil {
		out.views = []CredentialView{{Kind: CredHeader, Name: *p.AuthHeaderName, Hint: p.AuthValueHint}}
	}
	return out, nil
}

// applyAuth applies a header change: "" removes it; a new name keeps the
// stored value unless a new one is given.
func (s *Service) applyAuth(p *dbgen.UpdateMCPServerParams, cur dbgen.McpServer, in UpdateInput) error {
	if in.AuthHeaderName != nil && *in.AuthHeaderName == "" {
		if in.AuthValue != nil && *in.AuthValue != "" {
			return apperr.Invalid("invalid_auth_header", "Enter the header's name with its value")
		}
		p.AuthHeaderName, p.AuthValueCipher, p.AuthValueHint = nil, nil, ""
		return nil
	}
	name := ""
	if cur.AuthHeaderName != nil {
		name = *cur.AuthHeaderName
	}
	setIf(&name, in.AuthHeaderName)
	if in.AuthValue == nil {
		if in.AuthHeaderName == nil {
			return nil
		}
		if cur.AuthValueCipher == nil {
			return apperr.Invalid("invalid_auth_value", "Enter the header's value")
		}
		if err := checkHeader(name, "x"); err != nil {
			return err
		}
		p.AuthHeaderName = &name
		return nil
	}
	if err := checkHeader(name, *in.AuthValue); err != nil {
		return err
	}
	ct, err := s.box.Seal([]byte(*in.AuthValue), ServerAAD(cur.ID))
	if err != nil {
		return err
	}
	p.AuthHeaderName, p.AuthValueCipher, p.AuthValueHint = &name, ct, valueHint(*in.AuthValue)
	return nil
}

// unchanged reports whether an update would leave the server as it is: the
// same settings, no new or removed header value, and the capture switch
// absent or at its current value.
func unchanged(cur dbgen.McpServer, p dbgen.UpdateMCPServerParams, valueChanged bool, capture *bool) bool {
	return !valueChanged && p.Name == cur.Name && p.Description == cur.Description && p.URL == cur.URL &&
		p.TimeoutSeconds == cur.TimeoutSeconds && p.Enabled == cur.Enabled && equalPtr(p.AuthHeaderName, cur.AuthHeaderName) &&
		p.AuthProviderID == cur.AuthProviderID && slices.Equal(p.AuthScopes, cur.AuthScopes) && p.SendIdentity == cur.SendIdentity &&
		p.AuthMode == AuthModeOf(cur) && equalPtr(p.RateLimitPerMinute, cur.RateLimitPerMinute) && equalPtr(p.MaxConcurrent, cur.MaxConcurrent) &&
		(capture == nil || *capture == cur.CapturePayloads)
}

// grantResetReason says why an update ends people's grants for a server
// ("": it doesn't): the URL moved to another origin, or the requirement
// names another provider (or none).
func grantResetReason(cur, row dbgen.McpServer) string {
	switch {
	case !sameOrigin(cur.URL, row.URL):
		return "origin_changed"
	case row.AuthProviderID != cur.AuthProviderID:
		return "provider_changed"
	}
	return ""
}

func setIf[T any](dst *T, v *T) {
	if v != nil {
		*dst = *v
	}
}

func equalPtr[T comparable](a, b *T) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
