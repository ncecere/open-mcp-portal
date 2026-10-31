package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type metadataSource struct {
	team   bool
	reader *reader
}

func (s *metadataSource) Metadata(_ context.Context, req datasource.MetadataRequest, r *datasource.MetadataResponse) {
	r.TypeName = req.ProviderTypeName + "_team_mcp_server"
	if s.team {
		r.TypeName = req.ProviderTypeName + "_team"
	}
}
func (s *metadataSource) Schema(_ context.Context, _ datasource.SchemaRequest, r *datasource.SchemaResponse) {
	attrs := map[string]schema.Attribute{
		"lookup":   schema.StringAttribute{Required: true, Description: "Exact slug or canonical UUID of the object."},
		"id":       schema.StringAttribute{Computed: true, Description: "Portal-local UUID."},
		"slug":     schema.StringAttribute{Computed: true, Description: "Immutable slug."},
		"name":     schema.StringAttribute{Computed: true, Description: "Display name (metadata; do not place secrets in names)."},
		"revision": schema.Int64Attribute{Computed: true, Description: "Revision observed on this read."},
	}
	desc := "Exact-team MCP server metadata, not a global catalog lookup. Requires a publisher token with servers:read."
	if s.team {
		desc = "Platform team metadata via adminGetTeam only. Requires a platform token with platform:read."
		attrs["status"] = schema.StringAttribute{Computed: true, Description: "Active or archived."}
	} else {
		attrs["team"] = schema.StringAttribute{Required: true, Description: "Exact token team slug or canonical UUID."}
		attrs["team_id"] = schema.StringAttribute{Computed: true, Description: "Owning team's UUID."}
		attrs["team_slug"] = schema.StringAttribute{Computed: true, Description: "Owning team's slug."}
		attrs["enabled"] = schema.BoolAttribute{Computed: true, Description: "Observed enablement; not a claim of governance approval or availability."}
		attrs["supports_tasks"] = schema.BoolAttribute{Computed: true, Description: "Last advertised task support; null if not reported. Not permission to run tasks."}
		for _, k := range []string{"tools", "prompts", "resources", "resource_templates"} {
			attrs[k] = schema.Int64Attribute{Computed: true, Description: "Observed capability count; not a claim that a gateway may serve them."}
		}
	}
	r.Schema = schema.Schema{Description: desc, Attributes: attrs}
}
func (s *metadataSource) Configure(_ context.Context, req datasource.ConfigureRequest, r *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	var ok bool
	s.reader, ok = req.ProviderData.(*reader)
	if !ok {
		r.Diagnostics.AddError("Invalid provider client", "Reconfigure the omp provider.")
	}
}
func (s *metadataSource) Read(ctx context.Context, req datasource.ReadRequest, r *datasource.ReadResponse) {
	if s.reader == nil {
		r.Diagnostics.AddError("Provider not configured", "Configure the portal URL and token environment variable.")
		return
	}
	var lookup types.String
	r.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("lookup"), &lookup)...)
	if r.Diagnostics.HasError() {
		return
	}
	if lookup.IsUnknown() || lookup.IsNull() {
		r.Diagnostics.AddError("Unknown lookup", "Set lookup before reading metadata.")
		return
	}
	values := map[string]any{}
	if s.team {
		t, err := s.reader.team(ctx, lookup.ValueString())
		if err != nil {
			r.Diagnostics.AddError("Team metadata read failed", err.Error())
			return
		}
		values = map[string]any{"id": *t.ID, "slug": *t.Slug, "name": *t.Name, "revision": *t.Revision, "status": *t.Status}
	} else {
		var team types.String
		r.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("team"), &team)...)
		if r.Diagnostics.HasError() {
			return
		}
		if team.IsUnknown() || team.IsNull() {
			r.Diagnostics.AddError("Unknown team", "Set the exact token team before reading metadata.")
			return
		}
		m, err := s.reader.server(ctx, team.ValueString(), lookup.ValueString())
		if err != nil {
			r.Diagnostics.AddError("Server metadata read failed", err.Error())
			return
		}
		values = map[string]any{"id": *m.ID, "slug": *m.Slug, "name": *m.Name, "revision": *m.Revision, "team_id": *m.TeamID, "team_slug": *m.TeamSlug, "enabled": *m.Enabled, "tools": *m.Counts.Tools, "prompts": *m.Counts.Prompts, "resources": *m.Counts.Resources, "resource_templates": *m.Counts.Templates, "supports_tasks": types.BoolPointerValue(m.SupportsTasks)}
	}
	r.State.Raw = req.Config.Raw
	for k, v := range values {
		r.Diagnostics.Append(r.State.SetAttribute(ctx, path.Root(k), v)...)
	}
}
