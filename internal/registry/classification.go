package registry

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

const (
	ClassRead        = "read"
	ClassWrite       = "write"
	ClassDestructive = "destructive"
)

// SuggestedClass interprets untrusted MCP annotations, never an authorization
// decision. Missing or malformed hints take the conservative MCP defaults.
func SuggestedClass(definition []byte) string {
	var def struct {
		Annotations map[string]json.RawMessage `json:"annotations"`
	}
	if json.Unmarshal(definition, &def) != nil {
		return ClassDestructive
	}
	var readOnly bool
	if json.Unmarshal(def.Annotations["readOnlyHint"], &readOnly) == nil && readOnly {
		return ClassRead
	}
	var destructive any
	if json.Unmarshal(def.Annotations["destructiveHint"], &destructive) == nil && destructive == false {
		return ClassWrite
	}
	return ClassDestructive
}

// ClassDrift is meaningful only for an owner-classified tool.
func ClassDrift(c dbgen.McpCapability) bool {
	return c.Kind == "tool" && c.ToolClass != nil && *c.ToolClass != SuggestedClass(c.Definition)
}

// ClassInput sets or clears a tool's owner classification.
type ClassInput struct {
	CapabilityID  uuid.UUID
	ToolClass     *string
	ViaSuggestion bool
}

func classRank(c *string) int {
	if c == nil {
		return 2
	}
	switch *c {
	case ClassRead:
		return 0
	case ClassWrite:
		return 1
	}
	return 2
}

// SetCapabilityClasses atomically classifies up to 500 unique tools. Only
// team owners and admins classify; platform roles grant no additional rights.
// Definition and fingerprint are deliberately untouched.
func (s *Service) SetCapabilityClasses(ctx context.Context, a authz.Actor, ref string, serverID uuid.UUID, items []ClassInput, expectedRevision int64) ([]CapabilityView, int64, error) {
	if len(items) == 0 || len(items) > 500 {
		return nil, 0, apperr.Invalid("invalid_items", "Supply between 1 and 500 unique capabilities")
	}
	seen := make(map[uuid.UUID]bool, len(items))
	for _, in := range items {
		if seen[in.CapabilityID] {
			return nil, 0, apperr.Invalid("duplicate_capability", "Capability IDs must be unique")
		}
		seen[in.CapabilityID] = true
		if in.ToolClass != nil && *in.ToolClass != ClassRead && *in.ToolClass != ClassWrite && *in.ToolClass != ClassDestructive {
			return nil, 0, apperr.Invalid("invalid_tool_class", "toolClass must be read, write, destructive or null")
		}
	}
	var out []CapabilityView
	var revision int64
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := ta.writable(authz.CheckServerManage); err != nil {
			return err
		}
		sv, err := teamServer(ctx, q, ta.team.ID, serverID, true)
		if err != nil {
			return err
		}
		if sv.Revision != expectedRevision {
			return apperr.Stale()
		}
		lowered := false
		for _, in := range items {
			cur, err := q.LockMCPCapability(ctx, dbgen.LockMCPCapabilityParams{ID: in.CapabilityID, ServerID: sv.ID})
			if store.NotFound(err) == store.ErrNotFound {
				return errNoCapability
			}
			if err != nil {
				return err
			}
			if cur.Kind != "tool" {
				return apperr.Invalid("not_a_tool", "Only tools can be classified")
			}
			if cur.GoneAt != nil {
				return apperr.Conflict("capability_gone", "A gone tool cannot be classified")
			}
			if in.ViaSuggestion && (in.ToolClass == nil || *in.ToolClass != SuggestedClass(cur.Definition)) {
				return apperr.Conflict("suggestion_changed", "The class must match the current suggestion")
			}
			if classRank(in.ToolClass) < classRank(cur.ToolClass) {
				lowered = true
			}
			_, err = q.SetMCPCapabilityClass(ctx, dbgen.SetMCPCapabilityClassParams{ID: cur.ID, ServerID: sv.ID, ToolClass: in.ToolClass, ClassSetBy: a.UserID})
			if err != nil {
				return err
			}
			e := a.Audit("mcp_capability.class_set", "mcp_capability", cur.ID.String())
			e.TeamID = ta.team.ID
			e.Before = map[string]any{"toolClass": cur.ToolClass}
			e.After = map[string]any{"toolClass": in.ToolClass}
			e.Metadata = map[string]any{"serverId": sv.ID, "server": sv.Name, "name": sv.Name + " · " + cur.Name, "capability": cur.Name, "viaSuggestion": in.ViaSuggestion}
			if err := audit.Record(ctx, q, e); err != nil {
				return err
			}
		}
		bumped, err := q.BumpMCPServerRevision(ctx, dbgen.BumpMCPServerRevisionParams{ID: sv.ID, UpdatedBy: by(a)})
		if err != nil {
			return err
		}
		if lowered {
			if err := s.resubmit(ctx, q, a, ta.team, bumped, "classification_changed", "Tool classification was lowered; review it again."); err != nil {
				return err
			}
			bumped, err = q.GetMCPServer(ctx, sv.ID)
			if err != nil {
				return err
			}
		}
		all, err := capabilities(ctx, q, bumped, nil)
		if err != nil {
			return err
		}
		byID := make(map[uuid.UUID]CapabilityView, len(all))
		for _, c := range all {
			byID[c.Capability.ID] = c
		}
		out = make([]CapabilityView, len(items))
		for i, in := range items {
			out[i] = byID[in.CapabilityID]
		}
		revision = bumped.Revision
		return nil
	})
	return out, revision, err
}

func (s *Service) SetCapabilityClass(ctx context.Context, a authz.Actor, ref string, serverID uuid.UUID, in ClassInput, expectedRevision int64) (CapabilityView, int64, error) {
	out, rev, err := s.SetCapabilityClasses(ctx, a, ref, serverID, []ClassInput{in}, expectedRevision)
	if err != nil {
		return CapabilityView{}, 0, err
	}
	return out[0], rev, nil
}
