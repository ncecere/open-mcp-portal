package registry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Per-person secrets (decision 72, docs/person-secrets.md). A server in
// person_secret mode has no secret of its own for the person's calls: its team
// says how one travels (a header, a bearer token or a query parameter, with a
// name and an optional prefix), and each person pastes their own key once
// (internal/personsecrets). This file is the registry's side: the
// configuration of the mode, its conflicts, the F-1 origin rule (a URL on
// another origin, another mode or another placement deletes everyone's
// secrets), and reading capabilities with the setup person's own secret.

// AuthPersonSecret is the auth mode in which each person's calls carry their
// own secret.
const AuthPersonSecret = "person_secret"

// Placements of a person's secret (the API's values).
const (
	PlaceHeader = upstream.PlaceHeader
	PlaceBearer = upstream.PlaceBearer
	PlaceQuery  = upstream.PlaceQuery
)

// SetupRejected is the setup secret's state when the server refused it (the
// other states are SetupActive and SetupMissing).
const SetupRejected = "rejected"

// MinPersonSecret and MaxPersonSecret bound a person's secret. The floor keeps
// redaction honest: a value shorter than this would blank ordinary words from
// every message and recorded payload.
const (
	MinPersonSecret = 8
	MaxPersonSecret = 4096
)

// PersonSecretAAD binds a person's sealed secret to its row.
func PersonSecretAAD(id uuid.UUID) []byte { return []byte("person_secret:" + id.String()) }

// PersonSecretInput says how a server's person secrets travel and how the
// paste page describes the key.
type PersonSecretInput struct {
	// Placement is header, bearer or query; Name is the header or parameter
	// (empty for bearer); Prefix is sent before the secret ("Token "), never
	// for bearer.
	Placement, Name, Prefix string
	// Label names the key ("Acme API key"); Help says where to find it
	// (plain text).
	Label, Help string
}

// PersonSecretView is a server's person secret settings as the API shows
// them, with how many people have entered one.
type PersonSecretView struct {
	PersonSecretInput
	People, Rejected int64
	Setup            SecretSetup
}

// SecretSetup is the setup secret's state (decision 42's counterpart): the
// editor whose own secret reads the server's capabilities.
type SecretSetup struct {
	Status     string // SetupActive, SetupRejected or SetupMissing
	PersonID   uuid.NullUUID
	PersonName *string
	At         *time.Time
}

// PersonSecretConfig is a server's configuration (ok false: not in
// person_secret mode).
func PersonSecretConfig(sv dbgen.McpServer) (PersonSecretInput, bool) {
	if AuthModeOf(sv) != AuthPersonSecret || sv.SecretPlacement == nil {
		return PersonSecretInput{}, false
	}
	return PersonSecretInput{Placement: *sv.SecretPlacement, Name: deref(sv.SecretName), Prefix: sv.SecretPrefix,
		Label: sv.SecretLabel, Help: sv.SecretHelp}, true
}

func invalidSecretConfig(field, msg string) error {
	e := apperr.Invalid("invalid_person_secret", msg)
	e.Details = map[string]any{"field": "personSecret." + field}
	return e
}

// normalizePersonSecret checks a configuration and returns it trimmed (the
// name and label; the prefix is kept exactly, a trailing space is usual).
func normalizePersonSecret(in PersonSecretInput) (PersonSecretInput, error) {
	in.Name, in.Label = strings.TrimSpace(in.Name), strings.TrimSpace(in.Label)
	switch in.Placement {
	case PlaceHeader:
		if !headerNameRE.MatchString(in.Name) || reservedHeaders[strings.ToLower(in.Name)] {
			return in, invalidSecretConfig("name", "The header name must be a valid HTTP header such as X-API-Key or Authorization")
		}
	case PlaceQuery:
		if !queryNameRE.MatchString(in.Name) || strings.HasPrefix(strings.ToLower(in.Name), "mcp-") {
			return in, invalidSecretConfig("name",
				"The query parameter name must be 1-64 letters, digits, dots, hyphens or underscores, and can't start with mcp-")
		}
	case PlaceBearer:
		if in.Name != "" {
			return in, invalidSecretConfig("name", "A bearer secret has no name")
		}
		if in.Prefix != "" {
			return in, invalidSecretConfig("prefix", "A bearer secret has no prefix: it is sent as Authorization: Bearer")
		}
	default:
		return in, invalidSecretConfig("placement", "placement must be header, bearer or query")
	}
	if len(in.Prefix) > 64 || strings.IndexFunc(in.Prefix, unicode.IsControl) >= 0 {
		return in, invalidSecretConfig("prefix", "The prefix must be at most 64 characters on one line")
	}
	if n := len([]rune(in.Label)); n > 100 || strings.IndexFunc(in.Label, unicode.IsControl) >= 0 {
		return in, invalidSecretConfig("label", "The label must be at most 100 characters on one line")
	}
	if len([]rune(in.Help)) > 2000 || strings.ContainsRune(in.Help, 0) {
		return in, invalidSecretConfig("help", "The help text must be at most 2000 characters")
	}
	return in, nil
}

// CheckPersonSecretValue checks a secret a person pastes: MinPersonSecret to
// MaxPersonSecret characters on one line, no surrounding space (a pasted key
// often carries a trailing newline, which is trimmed by the caller first).
func CheckPersonSecretValue(v string) error {
	if len(v) < MinPersonSecret || len(v) > MaxPersonSecret || strings.ContainsAny(v, "\r\n\x00") || strings.TrimSpace(v) != v {
		e := apperr.Invalid("invalid_secret_value",
			fmt.Sprintf("The key must be %d-%d characters on one line, with no space around it", MinPersonSecret, MaxPersonSecret))
		e.Details = map[string]any{"field": "value"}
		return e
	}
	return nil
}

// personSecretConflicts: person_secret mode excludes a user authorization
// requirement (one credential per call, as oauth), a static part that sets
// the same header or query parameter, and, for a bearer or an Authorization
// header, a static Authorization part. statics are the server's own
// credential parts after the change.
func personSecretConflicts(cfg PersonSecretInput, statics []CredentialView, requirement bool) error {
	if requirement {
		return unprocessable("auth_conflict", "A server whose callers each enter their own secret can't also have a user authorization requirement",
			map[string]any{"reason": "requirement"})
	}
	onAuthz := cfg.Placement == PlaceBearer || (cfg.Placement == PlaceHeader && strings.EqualFold(cfg.Name, "Authorization"))
	for _, v := range statics {
		switch {
		case onAuthz && occupiesAuthorization(v.Kind, v.Name):
			return unprocessable("auth_conflict", "The secret is sent as the Authorization header, which the server's own credential already sets",
				map[string]any{"reason": "static_authorization"})
		case cfg.Placement == PlaceHeader && v.Kind == CredHeader && strings.EqualFold(v.Name, cfg.Name),
			cfg.Placement == PlaceQuery && v.Kind == CredQuery && strings.EqualFold(v.Name, cfg.Name):
			return unprocessable("auth_conflict", "The server's own credential already sets "+cfg.Name+": the person's secret would replace it",
				map[string]any{"reason": "static_duplicate"})
		}
	}
	return nil
}

// secretResetReason says why an update ends everyone's secrets for a server
// ("": it doesn't): the URL moved to another origin (F-1), the mode changed, or
// the secret would now travel another way (a header to a query parameter puts
// it in URLs and logs it was never meant for).
func secretResetReason(cur, row dbgen.McpServer) string {
	switch {
	case !sameOrigin(cur.URL, row.URL):
		return "origin_changed"
	case AuthModeOf(cur) != AuthModeOf(row):
		return "mode_changed"
	case AuthModeOf(row) == AuthPersonSecret && deref(cur.SecretPlacement) != deref(row.SecretPlacement):
		return "placement_changed"
	}
	return ""
}

// resetPersonSecrets deletes everyone's secrets for a server: its URL moved to
// another origin, its mode or placement changed, or it is being deleted.
// Audited, when there were any, as mcp_server.person_secrets_reset (a count;
// no names, no values). Open links for the server go with them (cascade on
// the server; here only the secrets).
func resetPersonSecrets(ctx context.Context, q *dbgen.Queries, a authz.Actor, teamID, serverID uuid.UUID, reason string, extra map[string]any) error {
	n, err := q.DeletePersonSecretsForServer(ctx, serverID)
	if err != nil || n == 0 {
		return err
	}
	e := a.Audit("mcp_server.person_secrets_reset", "mcp_server", serverID.String())
	e.TeamID = teamID
	e.Metadata = map[string]any{"reason": reason, "secretsDeleted": n}
	for k, v := range extra {
		e.Metadata[k] = v
	}
	return audit.Record(ctx, q, e)
}

// secretSnapshot is the configuration as audited: never a value.
func secretSnapshot(sv dbgen.McpServer) map[string]any {
	cfg, ok := PersonSecretConfig(sv)
	if !ok {
		return nil
	}
	out := map[string]any{"placement": cfg.Placement, "prefix": cfg.Prefix, "label": cfg.Label}
	if cfg.Name != "" {
		out["name"] = cfg.Name
	}
	return out
}

const noteSecretChanged = "The way people's own secret is sent to the server changed; review it again."

// secretViews completes person_secret servers' views: how many people have a
// secret and the setup secret's state.
func secretViews(ctx context.Context, q *dbgen.Queries, out []ServerView, index map[uuid.UUID]int) error {
	var ids []uuid.UUID
	for _, v := range out {
		if AuthModeOf(v.Server) == AuthPersonSecret {
			ids = append(ids, v.Server.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	counts, err := q.CountPersonSecretsForServers(ctx, ids)
	if err != nil {
		return err
	}
	by := map[uuid.UUID]dbgen.CountPersonSecretsForServersRow{}
	for _, c := range counts {
		by[c.ServerID] = c
	}
	for _, id := range ids {
		v := &out[index[id]]
		cfg, ok := PersonSecretConfig(v.Server)
		if !ok {
			continue
		}
		pv := &PersonSecretView{PersonSecretInput: cfg, People: by[id].People, Rejected: by[id].Rejected}
		if pv.Setup, err = secretSetupStatus(ctx, q, v.Server); err != nil {
			return err
		}
		v.PersonSecret = pv
	}
	return nil
}

// secretSetupStatus is a server's setup secret now: it counts only while its
// person is active and an editor or above of the team, and the secret is for
// the server's origin now.
func secretSetupStatus(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer) (SecretSetup, error) {
	out := SecretSetup{Status: SetupMissing}
	if !sv.SecretSetupUserID.Valid {
		return out, nil
	}
	uid := sv.SecretSetupUserID.UUID
	u, err := q.GetUser(ctx, uid)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return out, nil
	} else if err != nil {
		return out, err
	}
	name := u.DisplayName
	if name == "" {
		name = u.Email
	}
	out.PersonID, out.PersonName, out.At = sv.SecretSetupUserID, &name, sv.SecretSetupAt
	role, err := teams.MemberRole(ctx, q, sv.TeamID, uid)
	if err != nil {
		return out, err
	}
	if u.Status != "active" || authz.CheckServerEdit(role) != nil {
		return out, nil
	}
	ps, err := q.GetPersonSecret(ctx, dbgen.GetPersonSecretParams{UserID: uid, ServerID: sv.ID})
	switch {
	case errors.Is(store.NotFound(err), store.ErrNotFound):
		return out, nil
	case err != nil:
		return out, err
	case ps.Origin != originOf(sv.URL):
		return out, nil
	case ps.Status == "active":
		out.Status = SetupActive
	default:
		out.Status = SetupRejected
	}
	return out, nil
}

// SetSecretSetup makes a person the server's setup person (the one whose
// secret reads its capabilities), in the caller's transaction. The caller has
// checked that they are an editor or above of the server's team. Audited as
// mcp_server.auth_update with setupBy.
func SetSecretSetup(ctx context.Context, q *dbgen.Queries, a authz.Actor, serverID uuid.UUID, person string) (dbgen.McpServer, error) {
	cur, err := q.LockMCPServer(ctx, serverID)
	if err != nil {
		return cur, err
	}
	row, err := q.SetMCPServerSecretSetup(ctx, dbgen.SetMCPServerSecretSetupParams{ID: serverID, UserID: by(a)})
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return cur, apperr.Conflict("not_person_secret", "The server isn't in person_secret mode")
	} else if err != nil {
		return cur, err
	}
	e := a.Audit("mcp_server.auth_update", "mcp_server", serverID.String())
	e.TeamID = row.TeamID
	before := map[string]any{"setupBy": nil}
	if cur.SecretSetupUserID.Valid {
		before["setupBy"] = cur.SecretSetupUserID.UUID.String()
	}
	e.Before, e.After = before, map[string]any{"setupBy": a.UserID.String()}
	e.Metadata = map[string]any{"name": row.Name, "setupBy": person}
	return row, audit.Record(ctx, q, e)
}

// errSecretSetupRequired: nobody's secret can read the server's capabilities
// yet.
var errSecretSetupRequired = apperr.New(http.StatusConflict, "setup_secret_required",
	"No key can read this server's capabilities yet: an editor of the team enters theirs under Account › My connections, choosing to use it to read the server")

// setupSecret is the setup person's secret for a probe: the bare value and
// their name; a TestResult naming why not when it can't be used (the caller
// returns it). A rejected key, one for another origin, one that can't be
// opened and one whose person is no longer an active editor all count as
// missing.
func (s *Service) setupSecret(ctx context.Context, sv dbgen.McpServer) (secret, person string, id uuid.UUID, sealed []byte, res *TestResult) {
	missing := &TestResult{SecretRequired: true, Err: &upstream.Error{Class: upstream.ClassAuth,
		Message: "No key to read this server with: an editor enters theirs under Account › My connections, choosing to use it to read the server."}}
	st, err := secretSetupStatus(ctx, s.q, sv)
	if err != nil {
		return "", "", uuid.Nil, nil, &TestResult{Err: &upstream.Error{Class: upstream.ClassUnavailable, Message: "The key to read this server with couldn't be looked up."}}
	}
	if st.Status != SetupActive {
		return "", "", uuid.Nil, nil, missing
	}
	ps, err := s.q.GetPersonSecret(ctx, dbgen.GetPersonSecretParams{UserID: st.PersonID.UUID, ServerID: sv.ID})
	if err != nil {
		return "", "", uuid.Nil, nil, missing
	}
	plain, err := s.box.Open(ps.SecretCipher, PersonSecretAAD(ps.ID))
	if err != nil {
		return "", "", uuid.Nil, nil, missing
	}
	return string(plain), deref(st.PersonName), ps.ID, ps.SecretCipher, nil
}

// probeSecretRequired is a scheduled check of a person_secret server: it uses
// nobody's secret (a robot must not use anyone's), so a server that wants a
// personal key answers 401 or 403, which counts as healthy ("requires a
// personal key"). The server's own static parts, if it has any, are sent.
func (s *Service) probeSecretRequired(ctx context.Context, sv dbgen.McpServer, t upstream.Target) (TestResult, upstream.Discovery, []string) {
	d, err := s.client.Discover(ctx, t)
	res := TestResult{Latency: d.Latency, ServerName: d.ServerName, ServerVersion: d.ServerVersion, ProtocolVersion: d.ProtocolVersion, Protocol: d.Protocol}
	if err == nil {
		res.OK, res.Counts, res.Note = true, upstream.CountKinds(d.Capabilities), "The server answered without a personal key."
		return res, d, t.Secrets()
	}
	e, ok := err.(*upstream.Error)
	if !ok {
		e = &upstream.Error{Class: upstream.ClassUnavailable, Message: "The test failed."}
	}
	if e.Class == upstream.ClassAuth && (e.HTTPStatus == http.StatusUnauthorized || e.HTTPStatus == http.StatusForbidden) {
		res.OK, res.SignInRequired, res.Note = true, true, "The server requires each person's own key."
		return res, d, t.Secrets()
	}
	res.Err = &upstream.Error{Class: e.Class, HTTPStatus: e.HTTPStatus, Message: upstream.SafeMessage(e.Message, t.Secrets()...)}
	return res, d, t.Secrets()
}

// createViews are a new server's credential parts as the conflict checks see
// them.
func createViews(in CreateInput) []CredentialView {
	var out []CredentialView
	for _, c := range in.Credentials {
		out = append(out, CredentialView{Kind: c.Kind, Name: c.Name})
	}
	if len(in.Credentials) == 0 && in.AuthHeaderName != "" {
		out = append(out, CredentialView{Kind: CredHeader, Name: in.AuthHeaderName})
	}
	return out
}

// secretConfigParams are the arguments of SetMCPServerSecretConfig: cfg nil
// clears the settings (any other mode); keepSetup keeps the setup person.
func secretConfigParams(id uuid.UUID, cfg *PersonSecretInput, keepSetup bool) dbgen.SetMCPServerSecretConfigParams {
	p := dbgen.SetMCPServerSecretConfigParams{ID: id, KeepSetup: keepSetup && cfg != nil}
	if cfg == nil {
		return p
	}
	p.SecretPlacement = &cfg.Placement
	if cfg.Name != "" {
		name := cfg.Name
		p.SecretName = &name
	}
	p.SecretPrefix, p.SecretLabel, p.SecretHelp = cfg.Prefix, cfg.Label, cfg.Help
	return p
}

// finalViews are the server's own credential parts after an update, for the
// conflict checks: the new list, else the stored parts, else the legacy header.
func finalViews(cur dbgen.McpServer, stored storedCredentials, in UpdateInput) []CredentialView {
	switch {
	case in.Credentials != nil:
		out := make([]CredentialView, len(*in.Credentials))
		for i, c := range *in.Credentials {
			out[i] = CredentialView{Kind: c.Kind, Name: c.Name}
		}
		return out
	case len(stored.rows) > 0:
		return rowViews(stored.rows)
	}
	name := deref(cur.AuthHeaderName)
	if in.AuthHeaderName != nil {
		name = *in.AuthHeaderName
	}
	if name == "" {
		return nil
	}
	return []CredentialView{{Kind: CredHeader, Name: name}}
}

// secretConfigFor is the configuration a server will have after an update that
// ends in person_secret mode: the request's, else the stored one (an error
// when it is being chosen with none).
func secretConfigFor(cur dbgen.McpServer, in UpdateInput) (PersonSecretInput, error) {
	if in.PersonSecret != nil {
		return normalizePersonSecret(*in.PersonSecret)
	}
	if cfg, ok := PersonSecretConfig(cur); ok {
		return cfg, nil
	}
	return PersonSecretInput{}, invalidSecretConfig("placement", "Choose how each person's secret is sent: personSecret is required to switch to person_secret mode")
}

// samePersonSecret reports whether cfg is what the server already has (the
// request changes none of how the secret travels or is described).
func samePersonSecret(sv dbgen.McpServer, cfg PersonSecretInput) bool {
	cur, ok := PersonSecretConfig(sv)
	return ok && cur == cfg
}

// withSecretConfig is the row as it will be once cfg is stored, for deciding
// whether the secrets are reset (placement is what that looks at).
func withSecretConfig(row dbgen.McpServer, cfg *PersonSecretInput) dbgen.McpServer {
	if cfg == nil {
		row.SecretPlacement = nil
	} else {
		row.SecretPlacement = &cfg.Placement
	}
	return row
}

// secretAuthChanged reports whether an update changed what a published server
// sends people's own secrets as: into or out of person_secret mode, or another
// placement, name or prefix. Such a change goes back to review under
// approval_required, as another auth mode does.
func secretAuthChanged(cur, row dbgen.McpServer) bool {
	before, bok := PersonSecretConfig(cur)
	after, aok := PersonSecretConfig(row)
	if bok != aok {
		return true
	}
	return aok && (before.Placement != after.Placement || before.Name != after.Name || before.Prefix != after.Prefix)
}
