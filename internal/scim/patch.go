package scim

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// patchRequest is an RFC 7644 3.5.2 PatchOp. Operations apply atomically:
// the whole request fails on the first invalid operation.
type patchRequest struct {
	Schemas    []string    `json:"schemas"`
	Operations []patchOp   `json:"Operations"`
	ops        []patchOpIn `json:"-"`
}

type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

// patchOpIn is a normalised operation: op lower-cased, path case-folded
// and stripped of the core schema URN.
type patchOpIn struct {
	op, path string
	value    json.RawMessage
}

func decodePatch(r *http.Request, p *patchRequest) error {
	if err := decode(r, p); err != nil {
		return err
	}
	ok := false
	for _, s := range p.Schemas {
		ok = ok || s == schemaPatch
	}
	if !ok {
		return badRequest("invalidSyntax", "A PATCH needs the PatchOp schema")
	}
	if len(p.Operations) == 0 || len(p.Operations) > maxPatchOps {
		return badRequest("invalidSyntax", "A PATCH needs 1-100 Operations")
	}
	for _, o := range p.Operations {
		op := strings.ToLower(o.Op)
		if op != "add" && op != "replace" && op != "remove" {
			return badRequest("invalidSyntax", "op must be add, replace or remove")
		}
		path := strings.TrimSpace(o.Path)
		for _, urn := range []string{SchemaUser + ":", SchemaGroup + ":"} {
			if len(path) > len(urn) && strings.EqualFold(path[:len(urn)], urn) {
				path = path[len(urn):]
			}
		}
		p.ops = append(p.ops, patchOpIn{op: op, path: path, value: o.Value})
	}
	return nil
}

// extension reports a path into an extension schema (ignored, like unknown
// extension attributes on PUT/POST).
func extension(path string) bool {
	return strings.HasPrefix(strings.ToLower(path), "urn:")
}

var emailsPathRE = regexp.MustCompile(`(?i)^emails(\[.*\])?(\.value)?$`)

// applyUser applies the operations to user attributes.
func (p *patchRequest) applyUser(a *userAttrs) error {
	for _, o := range p.ops {
		if o.path == "" {
			if o.op == "remove" {
				return badRequest("noTarget", "remove needs a path")
			}
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(o.value, &obj); err != nil {
				return badRequest("invalidValue", "A PATCH without a path needs an object value")
			}
			if err := applyUserObject(a, obj); err != nil {
				return err
			}
			continue
		}
		if extension(o.path) {
			continue
		}
		path := strings.ToLower(o.path)
		var err error
		switch {
		case path == "active":
			if o.op == "remove" {
				return badRequest("mutability", "active can't be removed")
			}
			a.Active, err = boolValue(o.value)
		case path == "username":
			if o.op == "remove" {
				return badRequest("mutability", "userName is required")
			}
			a.UserName, err = stringValue(o.value, "userName")
		case path == "externalid":
			if o.op == "remove" {
				a.ExternalID = nil
				continue
			}
			var s string
			if s, err = stringValue(o.value, "externalId"); err == nil {
				if s == "" {
					a.ExternalID = nil
				} else {
					a.ExternalID = &s
				}
			}
		case path == "displayname":
			if o.op == "remove" {
				a.DisplayName = ""
				continue
			}
			a.DisplayName, err = stringValue(o.value, "displayName")
		case path == "name":
			if o.op == "remove" {
				a.GivenName, a.FamilyName = "", ""
				continue
			}
			err = applyUserObject(a, map[string]json.RawMessage{"name": o.value})
		case path == "name.givenname":
			if o.op == "remove" {
				a.GivenName = ""
				continue
			}
			a.GivenName, err = stringValue(o.value, "name.givenName")
		case path == "name.familyname":
			if o.op == "remove" {
				a.FamilyName = ""
				continue
			}
			a.FamilyName, err = stringValue(o.value, "name.familyName")
		case emailsPathRE.MatchString(o.path):
			switch {
			case o.op == "remove":
				a.Email = ""
			case strings.HasSuffix(path, ".value"):
				a.Email, err = stringValue(o.value, "emails.value")
			default:
				a.Email, err = primaryEmail(o.value)
			}
		case path == "id" || path == "groups" || strings.HasPrefix(path, "meta"):
			return errReadOnlyPath
		default:
			return badRequest("invalidPath", "Unsupported attribute path "+o.path)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// memberValuePathRE is `members[value eq "id"]`.
var memberValuePathRE = regexp.MustCompile(`(?i)^members\[\s*value\s+eq\s+"([^"]+)"\s*\]$`)

// Member actions, applied in operation order.
const (
	memberAdd = iota
	memberRemove
	memberReplace // remove everyone, then add ids
)

type memberAction struct {
	kind int
	ids  []uuid.UUID
}

// groupChange is the effect of a Group PATCH.
type groupChange struct {
	displayName *string
	externalID  **string
	members     []memberAction
}

func memberIDs(raw json.RawMessage) ([]uuid.UUID, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var list []struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		var one struct {
			Value string `json:"value"`
		}
		if err2 := json.Unmarshal(raw, &one); err2 != nil || one.Value == "" {
			return nil, badRequest("invalidValue", "members must be a list of {value}")
		}
		list = append(list, one)
	}
	if len(list) > maxMemberOps {
		return nil, badRequest("tooMany", "At most 1000 members per operation")
	}
	out := make([]uuid.UUID, 0, len(list))
	for _, m := range list {
		id, err := uuid.Parse(m.Value)
		if err != nil {
			return nil, badRequest("invalidValue", "Unknown member "+m.Value)
		}
		out = append(out, id)
	}
	return out, nil
}

// group parses Group operations.
func (p *patchRequest) group() (groupChange, error) {
	var c groupChange
	for _, o := range p.ops {
		path := strings.ToLower(o.path)
		switch {
		case o.path == "":
			if o.op == "remove" {
				return c, badRequest("noTarget", "remove needs a path")
			}
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(o.value, &obj); err != nil {
				return c, badRequest("invalidValue", "A PATCH without a path needs an object value")
			}
			for k, v := range lowerKeys(obj) {
				switch k {
				case "displayname":
					s, err := stringValue(v, "displayName")
					if err != nil {
						return c, err
					}
					c.displayName = &s
				case "externalid":
					s, err := stringValue(v, "externalId")
					if err != nil {
						return c, err
					}
					var ext *string
					if s != "" {
						ext = &s
					}
					c.externalID = &ext
				case "members":
					ids, err := memberIDs(v)
					if err != nil {
						return c, err
					}
					kind := memberAdd
					if o.op == "replace" {
						kind = memberReplace
					}
					c.members = append(c.members, memberAction{kind, ids})
				}
			}
		case extension(o.path):
		case path == "displayname":
			if o.op == "remove" {
				return c, badRequest("mutability", "displayName is required")
			}
			s, err := stringValue(o.value, "displayName")
			if err != nil {
				return c, err
			}
			c.displayName = &s
		case path == "externalid":
			var ext *string
			if o.op != "remove" {
				s, err := stringValue(o.value, "externalId")
				if err != nil {
					return c, err
				}
				if s != "" {
					ext = &s
				}
			}
			c.externalID = &ext
		case path == "members":
			ids, err := memberIDs(o.value)
			if err != nil {
				return c, err
			}
			switch o.op {
			case "add":
				c.members = append(c.members, memberAction{memberAdd, ids})
			case "replace":
				c.members = append(c.members, memberAction{memberReplace, ids})
			case "remove":
				if ids == nil {
					c.members = append(c.members, memberAction{memberReplace, nil})
				} else {
					c.members = append(c.members, memberAction{memberRemove, ids})
				}
			}
		case memberValuePathRE.MatchString(o.path):
			if o.op != "remove" {
				return c, badRequest("invalidPath", "Use add with path members to add members")
			}
			id, err := uuid.Parse(memberValuePathRE.FindStringSubmatch(o.path)[1])
			if err != nil {
				continue // an id that isn't ours is not a member: nothing to remove
			}
			c.members = append(c.members, memberAction{memberRemove, []uuid.UUID{id}})
		case path == "id" || strings.HasPrefix(path, "meta"):
			return c, errReadOnlyPath
		default:
			return c, badRequest("invalidPath", "Unsupported attribute path "+o.path)
		}
	}
	return c, nil
}
