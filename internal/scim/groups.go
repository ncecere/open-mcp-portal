package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// groupResource is the representation of a Group (RFC 7643 4.2).
type groupResource struct {
	Schemas     []string         `json:"schemas"`
	ID          string           `json:"id"`
	ExternalID  *string          `json:"externalId,omitempty"`
	DisplayName string           `json:"displayName"`
	Members     []map[string]any `json:"members,omitempty"`
	Meta        map[string]any   `json:"meta"`
	version     int64
	loc         string
}

func (g groupResource) etag() string     { return etag(g.version) }
func (g groupResource) location() string { return g.loc }

func groupView(g dbgen.ScimGroup, members []dbgen.ListSCIMGroupMembersRow, withMembers bool, base string) groupResource {
	loc := base + "/Groups/" + g.ID.String()
	out := groupResource{Schemas: []string{SchemaGroup}, ID: g.ID.String(), ExternalID: g.ExternalID, DisplayName: g.DisplayName,
		Meta: meta("Group", g.CreatedAt, g.UpdatedAt, loc, g.Version), version: g.Version, loc: loc}
	if withMembers {
		out.Members = []map[string]any{}
		for _, m := range members {
			if m.GroupID == g.ID {
				display := m.DisplayName
				if display == "" {
					display = m.UserName
				}
				out.Members = append(out.Members, map[string]any{"value": m.ID.String(), "display": display, "$ref": base + "/Users/" + m.ID.String(), "type": "User"})
			}
		}
	}
	return out
}

// excludesMembers honours excludedAttributes=members (RFC 7644 3.9), which
// clients use to avoid fetching large groups.
func excludesMembers(r *http.Request) bool {
	for _, a := range strings.Split(r.URL.Query().Get("excludedAttributes"), ",") {
		if strings.EqualFold(strings.TrimSpace(a), "members") {
			return true
		}
	}
	return false
}

func validGroupName(name string) error {
	if strings.TrimSpace(name) == "" || utf8.RuneCountInString(name) > 256 || !utf8.ValidString(name) || strings.ContainsRune(name, 0) {
		return badRequest("invalidValue", "displayName is required (1-256 characters)")
	}
	return nil
}

func validExternal(ext *string) error {
	if ext != nil && (utf8.RuneCountInString(*ext) > 512 || !utf8.ValidString(*ext)) {
		return badRequest("invalidValue", "externalId must be 1-512 characters")
	}
	return nil
}

func (s *Service) groups(r *http.Request, p Principal, rawID, base string) (int, any, error) {
	ctx := r.Context()
	if rawID == "" {
		switch r.Method {
		case http.MethodGet:
			out, err := s.listGroups(ctx, r, p, base)
			return http.StatusOK, out, err
		case http.MethodPost:
			out, err := s.createGroup(ctx, r, p, base)
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
		g, err := s.q.GetSCIMGroup(ctx, dbgen.GetSCIMGroupParams{ID: id, DirectoryID: p.DirectoryID})
		if err != nil {
			return 0, nil, notFound(err)
		}
		members, err := s.q.ListSCIMGroupMembers(ctx, []uuid.UUID{g.ID})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, groupView(g, members, !excludesMembers(r), base), nil
	case http.MethodPut, http.MethodPatch:
		out, err := s.updateGroup(ctx, r, p, id, base)
		return http.StatusOK, out, err
	case http.MethodDelete:
		return http.StatusNoContent, nil, s.deleteGroup(ctx, r, p, id)
	}
	return 0, nil, &scimError{Status: http.StatusMethodNotAllowed, Detail: "Method not allowed"}
}

func (s *Service) listGroups(ctx context.Context, r *http.Request, p Principal, base string) (any, error) {
	lp, err := pagination(r)
	if err != nil {
		return nil, err
	}
	attr, value, err := parseFilter(r.URL.Query().Get("filter"), "displayName", "externalId", "id")
	if err != nil {
		return nil, err
	}
	withMembers := !excludesMembers(r)
	var rows []dbgen.ScimGroup
	var total int64
	if attr == "id" {
		if id, err := uuid.Parse(value); err == nil {
			g, err := s.q.GetSCIMGroup(ctx, dbgen.GetSCIMGroupParams{ID: id, DirectoryID: p.DirectoryID})
			if err == nil {
				total = 1
				if lp.start == 1 && lp.count > 0 {
					rows = []dbgen.ScimGroup{g}
				}
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}
		}
	} else {
		var name, ext *string
		switch attr {
		case "displayName":
			name = &value
		case "externalId":
			ext = &value
		}
		if total, err = s.q.CountSCIMGroups(ctx, dbgen.CountSCIMGroupsParams{DirectoryID: p.DirectoryID, DisplayName: name, ExternalID: ext}); err != nil {
			return nil, err
		}
		if rows, err = s.q.ListSCIMGroups(ctx, dbgen.ListSCIMGroupsParams{DirectoryID: p.DirectoryID, DisplayName: name, ExternalID: ext,
			Skip: int32(lp.start - 1), PageSize: int32(lp.count)}); err != nil {
			return nil, err
		}
	}
	var members []dbgen.ListSCIMGroupMembersRow
	if withMembers && len(rows) > 0 {
		ids := make([]uuid.UUID, len(rows))
		for i, g := range rows {
			ids[i] = g.ID
		}
		if members, err = s.q.ListSCIMGroupMembers(ctx, ids); err != nil {
			return nil, err
		}
	}
	res := make([]any, len(rows))
	for i, g := range rows {
		res[i] = groupView(g, members, withMembers, base)
	}
	return listResponse{Schemas: []string{schemaList}, TotalResults: total, StartIndex: lp.start, ItemsPerPage: len(res), Resources: res}, nil
}

type groupBody struct {
	DisplayName string          `json:"displayName"`
	ExternalID  *string         `json:"externalId"`
	Members     json.RawMessage `json:"members"`
}

// parseGroupBody reads a full Group object, attribute names case-insensitive.
func parseGroupBody(r *http.Request) (groupBody, []uuid.UUID, error) {
	var raw map[string]json.RawMessage
	var b groupBody
	if err := decode(r, &raw); err != nil {
		return b, nil, err
	}
	m := lowerKeys(raw)
	for k, v := range m {
		k = strings.TrimPrefix(k, strings.ToLower(SchemaGroup)+":")
		switch k {
		case "displayname":
			s, err := stringValue(v, "displayName")
			if err != nil {
				return b, nil, err
			}
			b.DisplayName = s
		case "externalid":
			s, err := stringValue(v, "externalId")
			if err != nil {
				return b, nil, err
			}
			if s != "" {
				b.ExternalID = &s
			}
		case "members":
			b.Members = v
		}
	}
	if err := validGroupName(b.DisplayName); err != nil {
		return b, nil, err
	}
	if err := validExternal(b.ExternalID); err != nil {
		return b, nil, err
	}
	ids, err := memberIDs(b.Members)
	return b, ids, err
}

// addMembers adds resources that must all exist in the directory: a
// reference to an unknown resource fails the whole request.
func addMembers(ctx context.Context, q *dbgen.Queries, p Principal, group uuid.UUID, ids []uuid.UUID) ([]uuid.UUID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	ids = dedupe(ids)
	n, err := q.CountExistingSCIMUsers(ctx, dbgen.CountExistingSCIMUsersParams{DirectoryID: p.DirectoryID, Ids: ids})
	if err != nil {
		return nil, err
	}
	if int(n) != len(ids) {
		return nil, badRequest("invalidValue", "A member is not a provisioned user of this directory")
	}
	return q.AddSCIMGroupMembers(ctx, dbgen.AddSCIMGroupMembersParams{GroupID: group, DirectoryID: p.DirectoryID, Ids: ids})
}

func dedupe(ids []uuid.UUID) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

func (s *Service) createGroup(ctx context.Context, r *http.Request, p Principal, base string) (any, error) {
	b, ids, err := parseGroupBody(r)
	if err != nil {
		return nil, err
	}
	var out dbgen.ScimGroup
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if _, err := s.directory(ctx, q, p); err != nil {
			return err
		}
		var err error
		if out, err = q.InsertSCIMGroup(ctx, dbgen.InsertSCIMGroupParams{DirectoryID: p.DirectoryID, DisplayName: b.DisplayName, ExternalID: b.ExternalID}); err != nil {
			return err
		}
		added, err := addMembers(ctx, q, p, out.ID, ids)
		if err != nil {
			return err
		}
		e := p.audit("scim.group_create", "scim_group", out.ID.String(), httpx.RequestID(ctx))
		e.After = map[string]any{"displayName": out.DisplayName, "members": len(added)}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		// A new group has no mapping yet; nothing to reconcile.
		return nil
	})
	if err != nil {
		return nil, err
	}
	members, err := s.q.ListSCIMGroupMembers(ctx, []uuid.UUID{out.ID})
	if err != nil {
		return nil, err
	}
	return groupView(out, members, true, base), nil
}

// updateGroup applies PUT or PATCH atomically, then reconciles the team
// roles of every member whose membership changed.
func (s *Service) updateGroup(ctx context.Context, r *http.Request, p Principal, id uuid.UUID, base string) (any, error) {
	var change groupChange
	if r.Method == http.MethodPut {
		b, ids, err := parseGroupBody(r)
		if err != nil {
			return nil, err
		}
		ext := b.ExternalID
		change = groupChange{displayName: &b.DisplayName, externalID: &ext, members: []memberAction{{memberReplace, ids}}}
	} else {
		var patch patchRequest
		if err := decodePatch(r, &patch); err != nil {
			return nil, err
		}
		var err error
		if change, err = patch.group(); err != nil {
			return nil, err
		}
	}
	var out dbgen.ScimGroup
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if _, err := s.directory(ctx, q, p); err != nil {
			return err
		}
		cur, err := q.LockSCIMGroup(ctx, dbgen.LockSCIMGroupParams{ID: id, DirectoryID: p.DirectoryID})
		if err != nil {
			return notFound(err)
		}
		if err := checkIfMatch(r, cur.Version); err != nil {
			return err
		}
		name, ext := cur.DisplayName, cur.ExternalID
		if change.displayName != nil {
			name = *change.displayName
		}
		if change.externalID != nil {
			ext = *change.externalID
		}
		if err := validGroupName(name); err != nil {
			return err
		}
		if err := validExternal(ext); err != nil {
			return err
		}
		touched := []uuid.UUID{}
		for _, a := range change.members {
			var ids []uuid.UUID
			switch a.kind {
			case memberAdd:
				ids, err = addMembers(ctx, q, p, id, a.ids)
			case memberRemove:
				ids, err = q.RemoveSCIMGroupMembers(ctx, dbgen.RemoveSCIMGroupMembersParams{GroupID: id, Ids: dedupe(a.ids)})
			case memberReplace:
				if ids, err = q.RemoveAllSCIMGroupMembers(ctx, id); err == nil {
					var added []uuid.UUID
					added, err = addMembers(ctx, q, p, id, a.ids)
					ids = append(ids, added...)
				}
			}
			if err != nil {
				return err
			}
			touched = append(touched, ids...)
		}
		if out, err = q.UpdateSCIMGroup(ctx, dbgen.UpdateSCIMGroupParams{ID: id, DisplayName: name, ExternalID: ext}); err != nil {
			return err
		}
		e := p.audit("scim.group_update", "scim_group", id.String(), httpx.RequestID(ctx))
		e.Before = map[string]any{"displayName": cur.DisplayName}
		e.After = map[string]any{"displayName": out.DisplayName, "membershipChanges": len(touched)}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		return reconcileResources(ctx, q, dedupe(touched), httpx.RequestID(ctx))
	})
	if err != nil {
		return nil, err
	}
	withMembers := !excludesMembers(r)
	var members []dbgen.ListSCIMGroupMembersRow
	if withMembers {
		if members, err = s.q.ListSCIMGroupMembers(ctx, []uuid.UUID{out.ID}); err != nil {
			return nil, err
		}
	}
	return groupView(out, members, withMembers, base), nil
}

// deleteGroup removes a group, its memberships and mappings, then
// reconciles its former members (losing roles only that group granted).
func (s *Service) deleteGroup(ctx context.Context, r *http.Request, p Principal, id uuid.UUID) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if _, err := s.directory(ctx, q, p); err != nil {
			return err
		}
		cur, err := q.LockSCIMGroup(ctx, dbgen.LockSCIMGroupParams{ID: id, DirectoryID: p.DirectoryID})
		if err != nil {
			return notFound(err)
		}
		if err := checkIfMatch(r, cur.Version); err != nil {
			return err
		}
		members, err := q.SCIMMembersOfGroup(ctx, id)
		if err != nil {
			return err
		}
		if err := q.DeleteSCIMGroup(ctx, id); err != nil {
			return err
		}
		e := p.audit("scim.group_delete", "scim_group", id.String(), httpx.RequestID(ctx))
		e.Before = map[string]any{"displayName": cur.DisplayName, "members": len(members)}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		return reconcileResources(ctx, q, members, httpx.RequestID(ctx))
	})
}
