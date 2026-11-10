package providers

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// snapshot is a provider's audited configuration: never the secret.
func snapshot(p dbgen.AuthProvider) map[string]any {
	return map[string]any{
		"slug": p.Slug, "name": p.Name, "preset": p.Preset, "enabled": p.Enabled, "clientId": p.ClientID,
		"hasClientSecret": p.ClientSecretCipher != nil, "tokenAuthMethod": p.TokenAuthMethod, "pkce": p.Pkce,
		"authorizationUrl": p.AuthorizationUrl, "tokenUrl": p.TokenUrl, "revocationUrl": p.RevocationUrl,
		"userinfoUrl": p.UserinfoUrl, "defaultScopes": nonNil(p.DefaultScopes), "scopeParam": p.ScopeParam,
		"scopeSeparator": p.ScopeSeparator, "tokenResponseFormat": p.TokenResponseFormat,
		"extraAuthorizeParams": extraParams(p.ExtraAuthorizeParams), "logoUrl": p.LogoUrl,
		"accessMode": p.AccessMode, "narrowOnRefresh": p.NarrowOnRefresh,
	}
}

func ptr[T any](v T) *T { return &v }

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// secretHint is the last four characters of a secret of at least eight.
func secretHint(v string) string {
	r := []rune(v)
	if len(r) < 8 {
		return ""
	}
	return string(r[len(r)-4:])
}

func or[T any](p *T, def T) T {
	if p != nil {
		return *p
	}
	return def
}

// Create configures a provider (platform admins). Audited as
// auth_provider.create.
func (s *Service) Create(ctx context.Context, a authz.Actor, in CreateInput) (View, error) {
	if !a.IsPlatformAdmin() {
		return View{}, errAdminOnly
	}
	in.Slug = strings.TrimSpace(in.Slug)
	if !slugRE.MatchString(in.Slug) {
		return View{}, apperr.Invalid("invalid_slug", "Slug must be 1-48 lowercase letters, digits or hyphens, and cannot start or end with a hyphen")
	}
	if reservedSlugs[in.Slug] || strings.HasPrefix(in.Slug, ServerSlugPrefix) {
		// /connect/{slug} is the consent page: these paths are taken.
		return View{}, unprocessable("invalid_slug", "This slug is reserved", map[string]any{"reason": "reserved"})
	}
	f := fields{
		name: in.Name, clientID: in.ClientID, method: or(in.TokenAuthMethod, AuthClientSecretPost), preset: in.Preset,
		enabled: or(in.Enabled, true), pkce: or(in.PKCE, true), secret: in.ClientSecret,
		authorizationURL: in.AuthorizationURL, tokenURL: in.TokenURL, revocationURL: in.RevocationURL, userinfoURL: in.UserinfoURL,
		logoURL: in.LogoURL, scopes: or(in.DefaultScopes, []string{}), scopeParam: or(in.ScopeParam, "scope"),
		separator: or(in.ScopeSeparator, " "), format: or(in.RespFormat, FormatStandard), params: or(in.ExtraParams, map[string]string{}),
	}
	if f.secret != nil && *f.secret == "" {
		f.secret = nil
	}
	if err := s.validate(ctx, &f); err != nil {
		return View{}, err
	}
	id := uuid.New()
	params, _ := json.Marshal(f.params)
	p := dbgen.InsertAuthProviderParams{
		ID: id, Slug: in.Slug, Name: f.name, Preset: f.preset, Enabled: f.enabled, ClientID: f.clientID, TokenAuthMethod: f.method,
		Pkce: f.pkce, AuthorizationUrl: f.authorizationURL, TokenUrl: f.tokenURL, RevocationUrl: f.revocationURL,
		UserinfoUrl: f.userinfoURL, DefaultScopes: f.scopes, ScopeParam: f.scopeParam, ScopeSeparator: f.separator,
		TokenResponseFormat: f.format, ExtraAuthorizeParams: params, LogoUrl: f.logoURL, CreatedBy: by(a),
		// New providers start restricted: no team or server may require
		// them until an admin lists some (decision 69).
		AccessMode: AccessRestricted, NarrowOnRefresh: or(in.NarrowOnRefresh, false),
	}
	if f.secret != nil {
		ct, err := s.box.Seal([]byte(*f.secret), SecretAAD(id))
		if err != nil {
			return View{}, err
		}
		p.ClientSecretCipher, p.ClientSecretHint = ct, secretHint(*f.secret)
	}
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, tx pgx.Tx) error {
		// One creation at a time keeps the limit exact.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('omp.auth-providers'))`); err != nil {
			return err
		}
		n, err := q.CountAuthProviders(ctx)
		if err != nil {
			return err
		}
		if n >= MaxProviders {
			return apperr.Conflict("too_many_providers", "At most 100 auth providers can be configured")
		}
		row, err := q.InsertAuthProvider(ctx, p)
		if apperr.IsUniqueViolation(err, "auth_providers_slug_key") {
			return errSlugTaken
		} else if err != nil {
			return err
		}
		e := a.Audit("auth_provider.create", "auth_provider", id.String())
		e.After = snapshot(row)
		e.Metadata = map[string]any{"name": row.Name}
		return audit.Record(ctx, q, e)
	})
	if err != nil {
		return View{}, err
	}
	return s.view(ctx, s.q, id)
}

// Update changes a provider (platform admins); the slug never changes.
// Changing the client ID marks every connection needs_reconsent and erases
// their tokens (they belong to the old app). Audited as auth_provider.update
// with clientSecretChanged and connectionsReset.
func (s *Service) Update(ctx context.Context, a authz.Actor, id uuid.UUID, in UpdateInput, expectedRevision int64) (View, error) {
	if !a.IsPlatformAdmin() {
		return View{}, errAdminOnly
	}
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := getPlatformProvider(ctx, q, id, true)
		if err != nil {
			return err
		}
		if cur.Revision != expectedRevision {
			return apperr.Stale()
		}
		linked, err := q.LinkedServerProviders(ctx, uuid.NullUUID{UUID: id, Valid: true})
		if err != nil {
			return err
		}
		f := fields{
			name: or(in.Name, cur.Name), clientID: or(in.ClientID, cur.ClientID), method: or(in.TokenAuthMethod, cur.TokenAuthMethod),
			preset: cur.Preset, enabled: or(in.Enabled, cur.Enabled), pkce: or(in.PKCE, cur.Pkce), secret: in.ClientSecret,
			storedSecret: cur.ClientSecretCipher != nil, authorizationURL: or(in.AuthorizationURL, cur.AuthorizationUrl),
			tokenURL: or(in.TokenURL, cur.TokenUrl), revocationURL: cur.RevocationUrl, userinfoURL: cur.UserinfoUrl, logoURL: cur.LogoUrl,
			scopes: or(in.DefaultScopes, nonNil(cur.DefaultScopes)), scopeParam: or(in.ScopeParam, cur.ScopeParam),
			separator: or(in.ScopeSeparator, cur.ScopeSeparator), format: or(in.RespFormat, cur.TokenResponseFormat),
			params: or(in.ExtraParams, extraParams(cur.ExtraAuthorizeParams)),
		}
		switch {
		case in.ClearPreset:
			f.preset = nil
		case in.Preset != nil:
			f.preset = in.Preset
		}
		switch {
		case in.ClearRevocationURL:
			f.revocationURL = nil
		case in.RevocationURL != nil:
			f.revocationURL = in.RevocationURL
		}
		switch {
		case in.ClearUserinfoURL:
			f.userinfoURL = nil
		case in.UserinfoURL != nil:
			f.userinfoURL = in.UserinfoURL
		}
		switch {
		case in.ClearLogoURL:
			f.logoURL = nil
		case in.LogoURL != nil:
			f.logoURL = in.LogoURL
		}
		if err := s.validate(ctx, &f); err != nil {
			return err
		}
		params, _ := json.Marshal(f.params)
		p := dbgen.UpdateAuthProviderParams{
			ID: id, Name: f.name, Preset: f.preset, Enabled: f.enabled, ClientID: f.clientID, ClientSecretCipher: cur.ClientSecretCipher,
			ClientSecretHint: cur.ClientSecretHint, TokenAuthMethod: f.method, Pkce: f.pkce, AuthorizationUrl: f.authorizationURL,
			TokenUrl: f.tokenURL, RevocationUrl: f.revocationURL, UserinfoUrl: f.userinfoURL, DefaultScopes: f.scopes,
			ScopeParam: f.scopeParam, ScopeSeparator: f.separator, TokenResponseFormat: f.format, ExtraAuthorizeParams: params,
			LogoUrl: f.logoURL, UpdatedBy: by(a), NarrowOnRefresh: or(in.NarrowOnRefresh, cur.NarrowOnRefresh),
		}
		secretChanged := false
		if f.secret != nil {
			secretChanged = true
			if *f.secret == "" {
				p.ClientSecretCipher, p.ClientSecretHint = nil, ""
			} else {
				ct, err := s.box.Seal([]byte(*f.secret), SecretAAD(id))
				if err != nil {
					return err
				}
				p.ClientSecretCipher, p.ClientSecretHint = ct, secretHint(*f.secret)
			}
		}
		if len(linked) > 0 && (f.authorizationURL != cur.AuthorizationUrl || f.tokenURL != cur.TokenUrl) {
			// oauth servers use this client because its endpoints matched
			// their authorization server's.
			return s.inUse(ctx, q, id)
		}
		row, err := q.UpdateAuthProvider(ctx, p)
		if err != nil {
			return err
		}
		var reset int64
		if row.ClientID != cur.ClientID {
			if reset, err = q.MarkProviderConnectionsReconsent(ctx, id); err != nil {
				return err
			}
			// The linked servers' connections belong to the old client too.
			for _, l := range linked {
				n, err := q.ResetProviderConnections(ctx, dbgen.ResetProviderConnectionsParams{ProviderID: l.ID, ErrorClass: ptr("client_changed")})
				if err != nil {
					return err
				}
				reset += n
			}
		}
		e := a.Audit("auth_provider.update", "auth_provider", id.String())
		e.Before, e.After = snapshot(cur), snapshot(row)
		e.Metadata = map[string]any{"name": row.Name, "clientSecretChanged": secretChanged, "connectionsReset": reset}
		return audit.Record(ctx, q, e)
	})
	if err != nil {
		return View{}, err
	}
	return s.view(ctx, s.q, id)
}

// Delete deletes a provider and every connection to it (platform admins).
// 409 in_use while any MCP server requires it. Connections' tokens are
// revoked at the provider first where it has a revocation endpoint (best
// effort, at most a minute in all). Audited as auth_provider.delete
// (connectionCount) and provider_connection.revoke (reason
// provider_deleted) per connection.
func (s *Service) Delete(ctx context.Context, a authz.Actor, id uuid.UUID) error {
	if !a.IsPlatformAdmin() {
		return errAdminOnly
	}
	p, err := getPlatformProvider(ctx, s.q, id, false)
	if err != nil {
		return err
	}
	if err := s.inUse(ctx, s.q, id); err != nil {
		return err
	}
	conns, err := s.q.ListProviderConnectionsForProvider(ctx, id)
	if err != nil {
		return err
	}
	revoked := s.revokeAll(ctx, p, conns)
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := getPlatformProvider(ctx, q, id, true)
		if err != nil {
			return err
		}
		if err := s.inUse(ctx, q, id); err != nil {
			return err
		}
		all, err := q.ListProviderConnectionsForProvider(ctx, id)
		if err != nil {
			return err
		}
		names, err := s.userNames(ctx, q, all)
		if err != nil {
			return err
		}
		for _, c := range all {
			if err := q.DeleteProviderConnection(ctx, c.ID); err != nil {
				return err
			}
			result, ok := revoked[c.ID]
			if !ok {
				result = revokeResult(cur, false)
			}
			e := a.Audit("provider_connection.revoke", "provider_connection", c.ID.String())
			e.Before = connectionSnapshot(c)
			e.Metadata = map[string]any{"name": names[c.UserID] + " · " + cur.Name, "reason": "provider_deleted",
				"providerRevoked": result, "userId": c.UserID.String(), "provider": cur.Slug}
			if err := audit.Record(ctx, q, e); err != nil {
				return err
			}
		}
		if err := q.DeleteAuthProvider(ctx, id); err != nil {
			if apperr.IsForeignKeyViolation(err, "") {
				return s.inUse(ctx, q, id)
			}
			return err
		}
		e := a.Audit("auth_provider.delete", "auth_provider", id.String())
		e.Before = snapshot(cur)
		e.Metadata = map[string]any{"name": cur.Name, "connectionCount": len(all)}
		return audit.Record(ctx, q, e)
	})
}

// inUse is 409 in_use while a server requires the provider.
func (s *Service) inUse(ctx context.Context, q *dbgen.Queries, id uuid.UUID) error {
	rows, err := q.ServersRequiringProvider(ctx, dbgen.ServersRequiringProviderParams{ProviderID: uuid.NullUUID{UUID: id, Valid: true}, PageSize: 1000})
	if err != nil || len(rows) == 0 {
		return err
	}
	servers := []map[string]any{}
	for i, r := range rows {
		if i == 20 {
			break
		}
		servers = append(servers, map[string]any{"id": r.ID, "slug": r.Slug, "name": r.Name, "teamSlug": r.TeamSlug})
	}
	e := apperr.Conflict("in_use", "MCP servers require this provider or use its client. Remove their requirement or sign-in first.")
	e.Details = map[string]any{"serverCount": len(rows), "servers": servers}
	return e
}

// userNames are the display names (else emails) of connections' people.
func (s *Service) userNames(ctx context.Context, q *dbgen.Queries, conns []dbgen.ProviderConnection) (map[uuid.UUID]string, error) {
	out := map[uuid.UUID]string{}
	for _, c := range conns {
		if _, ok := out[c.UserID]; ok {
			continue
		}
		u, err := q.GetUser(ctx, c.UserID)
		if err != nil {
			return nil, err
		}
		out[c.UserID] = displayName(u)
	}
	return out, nil
}

func displayName(u dbgen.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

// connectionSnapshot is a connection as audited: never a token.
func connectionSnapshot(c dbgen.ProviderConnection) map[string]any {
	return map[string]any{"status": c.Status, "scopes": nonNil(c.Scopes), "accountLabel": c.AccountLabel,
		"refreshable": c.RefreshTokenCipher != nil}
}
