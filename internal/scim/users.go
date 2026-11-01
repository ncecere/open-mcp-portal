package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// userAttrs are the stored, client-writable User attributes.
type userAttrs struct {
	UserName, DisplayName, GivenName, FamilyName, Email string
	ExternalID                                          *string
	Active                                              bool
}

func attrsOf(u dbgen.ScimUser) userAttrs {
	return userAttrs{UserName: u.UserName, ExternalID: u.ExternalID, Active: u.Active, DisplayName: u.DisplayName,
		GivenName: u.GivenName, FamilyName: u.FamilyName, Email: u.Email}
}

func (a userAttrs) validate() error {
	n := utf8.RuneCountInString(a.UserName)
	switch {
	case strings.TrimSpace(a.UserName) == "" || n > 256:
		return badRequest("invalidValue", "userName is required (1-256 characters)")
	case a.ExternalID != nil && (*a.ExternalID == "" || utf8.RuneCountInString(*a.ExternalID) > 512):
		return badRequest("invalidValue", "externalId must be 1-512 characters")
	case utf8.RuneCountInString(a.DisplayName) > 256 || utf8.RuneCountInString(a.GivenName) > 256 || utf8.RuneCountInString(a.FamilyName) > 256:
		return badRequest("invalidValue", "Names are limited to 256 characters")
	case utf8.RuneCountInString(a.Email) > 320:
		return badRequest("invalidValue", "Email is limited to 320 characters")
	}
	for _, v := range []string{a.UserName, a.DisplayName, a.GivenName, a.FamilyName, a.Email} {
		if !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			return badRequest("invalidValue", "Attribute values must be valid text")
		}
	}
	return nil
}

// userResource is the representation of a User (RFC 7643 4.1).
type userResource struct {
	Schemas     []string         `json:"schemas"`
	ID          string           `json:"id"`
	ExternalID  *string          `json:"externalId,omitempty"`
	UserName    string           `json:"userName"`
	Name        map[string]any   `json:"name,omitempty"`
	DisplayName string           `json:"displayName,omitempty"`
	Active      bool             `json:"active"`
	Emails      []map[string]any `json:"emails,omitempty"`
	Groups      []map[string]any `json:"groups"`
	Meta        map[string]any   `json:"meta"`
	version     int64
	loc         string
}

func (u userResource) etag() string     { return etag(u.version) }
func (u userResource) location() string { return u.loc }

func (s *Service) userView(u dbgen.ScimUser, groups []dbgen.ListSCIMUserGroupsRow, base string) userResource {
	loc := base + "/Users/" + u.ID.String()
	out := userResource{Schemas: []string{SchemaUser}, ID: u.ID.String(), ExternalID: u.ExternalID, UserName: u.UserName, DisplayName: u.DisplayName,
		Active: u.Active, Groups: []map[string]any{}, Meta: meta("User", u.CreatedAt, u.UpdatedAt, loc, u.Version), version: u.Version, loc: loc}
	if u.GivenName != "" || u.FamilyName != "" {
		out.Name = map[string]any{"givenName": u.GivenName, "familyName": u.FamilyName, "formatted": strings.TrimSpace(u.GivenName + " " + u.FamilyName)}
	}
	if u.Email != "" {
		out.Emails = []map[string]any{{"value": u.Email, "type": "work", "primary": true}}
	}
	for _, g := range groups {
		if g.ScimUserID == u.ID {
			out.Groups = append(out.Groups, map[string]any{"value": g.ID.String(), "display": g.DisplayName, "$ref": base + "/Groups/" + g.ID.String()})
		}
	}
	return out
}

// lower keys a JSON object case-insensitively (attribute names are
// case-insensitive, RFC 7643 2.1).
func lowerKeys(m map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		k = strings.ToLower(k)
		k = strings.TrimPrefix(k, strings.ToLower(SchemaUser)+":")
		out[k] = v
	}
	return out
}

// boolValue accepts JSON booleans and the "True"/"False" strings some
// clients send.
func boolValue(raw json.RawMessage) (bool, error) {
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		switch strings.ToLower(s) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, badRequest("invalidValue", "active must be a boolean")
}

func stringValue(raw json.RawMessage, name string) (string, error) {
	if string(raw) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", badRequest("invalidValue", name+" must be a string")
	}
	return s, nil
}

// primaryEmail picks the primary email, else the first.
func primaryEmail(raw json.RawMessage) (string, error) {
	if string(raw) == "null" {
		return "", nil
	}
	var emails []struct {
		Value   string          `json:"value"`
		Primary json.RawMessage `json:"primary"`
	}
	if err := json.Unmarshal(raw, &emails); err != nil {
		return "", badRequest("invalidValue", "emails must be a list of {value}")
	}
	for _, e := range emails {
		if p, err := boolValue(e.Primary); err == nil && p {
			return e.Value, nil
		}
	}
	if len(emails) > 0 {
		return emails[0].Value, nil
	}
	return "", nil
}

// applyUserObject sets attributes from a (full or partial) User object.
// readOnly attributes (id, meta, groups) are ignored, as are unknown and
// extension attributes.
func applyUserObject(a *userAttrs, raw map[string]json.RawMessage) error {
	m := lowerKeys(raw)
	for k, v := range m {
		var err error
		switch k {
		case "username":
			a.UserName, err = stringValue(v, "userName")
		case "externalid":
			var s string
			if s, err = stringValue(v, "externalId"); err == nil {
				if s == "" {
					a.ExternalID = nil
				} else {
					a.ExternalID = &s
				}
			}
		case "displayname":
			a.DisplayName, err = stringValue(v, "displayName")
		case "active":
			a.Active, err = boolValue(v)
		case "emails":
			a.Email, err = primaryEmail(v)
		case "name":
			if string(v) == "null" {
				a.GivenName, a.FamilyName = "", ""
				continue
			}
			var name map[string]json.RawMessage
			if err = json.Unmarshal(v, &name); err != nil {
				return badRequest("invalidValue", "name must be an object")
			}
			for nk, nv := range lowerKeys(name) {
				switch nk {
				case "givenname":
					a.GivenName, err = stringValue(nv, "name.givenName")
				case "familyname":
					a.FamilyName, err = stringValue(nv, "name.familyName")
				}
				if err != nil {
					return err
				}
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) users(r *http.Request, p Principal, rawID, base string) (int, any, error) {
	ctx := r.Context()
	if rawID == "" {
		switch r.Method {
		case http.MethodGet:
			out, err := s.listUsers(ctx, r, p, base)
			return http.StatusOK, out, err
		case http.MethodPost:
			out, err := s.createUser(ctx, r, p, base)
			return http.StatusCreated, out, err
		}
		return 0, nil, &scimError{Status: http.StatusMethodNotAllowed, Detail: "Method not allowed"}
	}
	id, err := parseID(rawID)
	if err != nil {
		return 0, nil, err
	}
	switch r.Method {
	case http.MethodGet:
		out, err := s.getUser(ctx, p, id, base)
		return http.StatusOK, out, err
	case http.MethodPut, http.MethodPatch:
		out, err := s.updateUser(ctx, r, p, id, base)
		return http.StatusOK, out, err
	case http.MethodDelete:
		return http.StatusNoContent, nil, s.deleteUser(ctx, r, p, id)
	}
	return 0, nil, &scimError{Status: http.StatusMethodNotAllowed, Detail: "Method not allowed"}
}

func (s *Service) listUsers(ctx context.Context, r *http.Request, p Principal, base string) (any, error) {
	lp, err := pagination(r)
	if err != nil {
		return nil, err
	}
	attr, value, err := parseFilter(r.URL.Query().Get("filter"), "userName", "externalId", "id")
	if err != nil {
		return nil, err
	}
	if attr == "id" {
		id, err := uuid.Parse(value)
		if err != nil {
			return listResponse{Schemas: []string{schemaList}, StartIndex: lp.start, Resources: []any{}}, nil
		}
		u, err := s.q.GetSCIMUser(ctx, dbgen.GetSCIMUserParams{ID: id, DirectoryID: p.DirectoryID})
		if errors.Is(err, pgx.ErrNoRows) {
			return listResponse{Schemas: []string{schemaList}, StartIndex: lp.start, Resources: []any{}}, nil
		} else if err != nil {
			return nil, err
		}
		groups, err := s.q.ListSCIMUserGroups(ctx, []uuid.UUID{u.ID})
		if err != nil {
			return nil, err
		}
		res := []any{}
		if lp.start == 1 && lp.count > 0 {
			res = append(res, s.userView(u, groups, base))
		}
		return listResponse{Schemas: []string{schemaList}, TotalResults: 1, StartIndex: lp.start, ItemsPerPage: len(res), Resources: res}, nil
	}
	var userName, externalID *string
	switch attr {
	case "userName":
		userName = &value
	case "externalId":
		externalID = &value
	}
	total, err := s.q.CountSCIMUsers(ctx, dbgen.CountSCIMUsersParams{DirectoryID: p.DirectoryID, UserName: userName, ExternalID: externalID})
	if err != nil {
		return nil, err
	}
	rows, err := s.q.ListSCIMUsers(ctx, dbgen.ListSCIMUsersParams{DirectoryID: p.DirectoryID, UserName: userName, ExternalID: externalID,
		Skip: int32(lp.start - 1), PageSize: int32(lp.count)})
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, len(rows))
	for i, u := range rows {
		ids[i] = u.ID
	}
	groups, err := s.q.ListSCIMUserGroups(ctx, ids)
	if err != nil {
		return nil, err
	}
	res := make([]any, len(rows))
	for i, u := range rows {
		res[i] = s.userView(u, groups, base)
	}
	return listResponse{Schemas: []string{schemaList}, TotalResults: total, StartIndex: lp.start, ItemsPerPage: len(res), Resources: res}, nil
}

func (s *Service) getUser(ctx context.Context, p Principal, id uuid.UUID, base string) (any, error) {
	u, err := s.q.GetSCIMUser(ctx, dbgen.GetSCIMUserParams{ID: id, DirectoryID: p.DirectoryID})
	if err != nil {
		return nil, notFound(err)
	}
	groups, err := s.q.ListSCIMUserGroups(ctx, []uuid.UUID{u.ID})
	if err != nil {
		return nil, err
	}
	return s.userView(u, groups, base), nil
}

func uniquenessError(err error) error {
	if apperr.IsUniqueViolation(err, "scim_users_user_name_key") {
		return &scimError{Status: http.StatusConflict, ScimType: "uniqueness", Detail: "userName is already in use"}
	}
	return err
}

// createUser stores a new resource. It never links a portal person: a new
// identity enrolls at its first verified sign-in; an existing person is
// adopted by an admin. Audited as scim.user_create.
func (s *Service) createUser(ctx context.Context, r *http.Request, p Principal, base string) (any, error) {
	var raw map[string]json.RawMessage
	if err := decode(r, &raw); err != nil {
		return nil, err
	}
	a := userAttrs{Active: true}
	if err := applyUserObject(&a, raw); err != nil {
		return nil, err
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	var out dbgen.ScimUser
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if _, err := s.directory(ctx, q, p); err != nil {
			return err
		}
		var err error
		out, err = q.InsertSCIMUser(ctx, dbgen.InsertSCIMUserParams{DirectoryID: p.DirectoryID, UserName: a.UserName, ExternalID: a.ExternalID,
			Active: a.Active, DisplayName: a.DisplayName, GivenName: a.GivenName, FamilyName: a.FamilyName, Email: a.Email})
		if err != nil {
			return uniquenessError(err)
		}
		e := p.audit("scim.user_create", "scim_user", out.ID.String(), httpx.RequestID(ctx))
		e.After = map[string]any{"userName": out.UserName, "active": out.Active, "externalIdSet": out.ExternalID != nil}
		return audit.Record(ctx, q, e)
	})
	if err != nil {
		return nil, err
	}
	return s.userView(out, nil, base), nil
}

// updateUser applies PUT (replace) or PATCH to a resource atomically. When
// a linked person's active changes, the directory standing follows in the
// same transaction: deactivation is a short non-key fence (status, request
// epoch, session generation), never a session deletion or provider call.
func (s *Service) updateUser(ctx context.Context, r *http.Request, p Principal, id uuid.UUID, base string) (any, error) {
	var put map[string]json.RawMessage
	var patch patchRequest
	if r.Method == http.MethodPut {
		if err := decode(r, &put); err != nil {
			return nil, err
		}
	} else if err := decodePatch(r, &patch); err != nil {
		return nil, err
	}
	var out dbgen.ScimUser
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if _, err := s.directory(ctx, q, p); err != nil {
			return err
		}
		cur, err := q.LockSCIMUser(ctx, dbgen.LockSCIMUserParams{ID: id, DirectoryID: p.DirectoryID})
		if err != nil {
			return notFound(err)
		}
		if err := checkIfMatch(r, cur.Version); err != nil {
			return err
		}
		a := attrsOf(cur)
		if put != nil {
			// PUT replaces writable attributes; omitted optional ones clear.
			a = userAttrs{Active: true}
			if err := applyUserObject(&a, put); err != nil {
				return err
			}
		} else if err := patch.applyUser(&a); err != nil {
			return err
		}
		if err := a.validate(); err != nil {
			return err
		}
		if out, err = q.UpdateSCIMUser(ctx, dbgen.UpdateSCIMUserParams{ID: id, UserName: a.UserName, ExternalID: a.ExternalID, Active: a.Active,
			DisplayName: a.DisplayName, GivenName: a.GivenName, FamilyName: a.FamilyName, Email: a.Email}); err != nil {
			return uniquenessError(err)
		}
		e := p.audit("scim.user_update", "scim_user", id.String(), httpx.RequestID(ctx))
		e.Before = map[string]any{"userName": cur.UserName, "active": cur.Active}
		e.After = map[string]any{"userName": out.UserName, "active": out.Active}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		if cur.LinkedUserID.Valid && cur.Active != out.Active {
			u, err := applyStanding(ctx, q, cur.LinkedUserID.UUID, standingFor(out.Active))
			if err != nil {
				return protectedError(err)
			}
			action := "scim.user_deactivate"
			if out.Active {
				action = "scim.user_reactivate"
			}
			ue := p.audit(action, "user", u.ID.String(), httpx.RequestID(ctx))
			ue.After = map[string]any{"directoryStanding": u.DirectoryStanding, "status": u.Status}
			return audit.Record(ctx, q, ue)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	groups, err := s.q.ListSCIMUserGroups(ctx, []uuid.UUID{out.ID})
	if err != nil {
		return nil, err
	}
	return s.userView(out, groups, base), nil
}

// deleteUser removes a resource. For a linked person it is irreversible for
// that directory life: standing becomes deleted (fencing sessions, requests
// and every credential use at once) and a clean-up job removes personal
// credentials, memberships and user grants. Re-enrollment needs an admin,
// after clean-up. Audited as scim.user_delete.
func (s *Service) deleteUser(ctx context.Context, r *http.Request, p Principal, id uuid.UUID) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if _, err := s.directory(ctx, q, p); err != nil {
			return err
		}
		cur, err := q.LockSCIMUser(ctx, dbgen.LockSCIMUserParams{ID: id, DirectoryID: p.DirectoryID})
		if err != nil {
			return notFound(err)
		}
		if err := checkIfMatch(r, cur.Version); err != nil {
			return err
		}
		e := p.audit("scim.user_delete", "scim_user", id.String(), httpx.RequestID(ctx))
		e.Before = map[string]any{"userName": cur.UserName, "linked": cur.LinkedUserID.Valid}
		if cur.LinkedUserID.Valid {
			u, err := applyStanding(ctx, q, cur.LinkedUserID.UUID, StandingDeleted)
			if err != nil {
				return err
			}
			if err := q.InsertDirectoryCleanupJob(ctx, u.ID); err != nil {
				return err
			}
			e.Metadata["userId"] = u.ID.String()
		}
		if err := q.DeleteSCIMUser(ctx, id); err != nil {
			return err
		}
		return audit.Record(ctx, q, e)
	})
}

var errReadOnlyPath = badRequest("mutability", "That attribute is read-only")
