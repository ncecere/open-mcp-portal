// Package provider implements only token-authorized, read-only metadata reads.
package provider

import (
	"context"
	"os"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type ompProvider struct{}
type config struct {
	URL      types.String `tfsdk:"url"`
	TokenEnv types.String `tfsdk:"token_env"`
}

func New() provider.Provider { return &ompProvider{} }
func (*ompProvider) Metadata(_ context.Context, _ provider.MetadataRequest, r *provider.MetadataResponse) {
	r.TypeName = "omp"
	r.Version = "0.0.0-dev"
}
func (*ompProvider) Schema(_ context.Context, _ provider.SchemaRequest, r *provider.SchemaResponse) {
	r.Schema = schema.Schema{Description: "Read-only Open MCP Portal metadata. Authentication is environment-only.", Attributes: map[string]schema.Attribute{
		"url":       schema.StringAttribute{Optional: true, Description: "Portal base URL; defaults to OMP_URL. HTTPS or loopback HTTP only."},
		"token_env": schema.StringAttribute{Optional: true, Description: "Environment variable NAME, not a token: OMP_TOKEN (default) or OMP_TOKEN_[A-Z0-9_]+."},
	}}
}
func (*ompProvider) Configure(ctx context.Context, req provider.ConfigureRequest, r *provider.ConfigureResponse) {
	var c config
	r.Diagnostics.Append(req.Config.Get(ctx, &c)...)
	if r.Diagnostics.HasError() {
		return
	}
	if c.URL.IsUnknown() || c.TokenEnv.IsUnknown() {
		r.Diagnostics.AddError("Unknown provider configuration", "Set url and token_env to known values before reading metadata.")
		return
	}
	base := c.URL.ValueString()
	if c.URL.IsNull() {
		base = os.Getenv("OMP_URL")
	}
	env := c.TokenEnv.ValueString()
	if c.TokenEnv.IsNull() {
		env = "OMP_TOKEN"
	}
	if !regexp.MustCompile(`^OMP_TOKEN(?:_[A-Z0-9_]+)?$`).MatchString(env) {
		r.Diagnostics.AddError("Invalid token environment name", "Use OMP_TOKEN or OMP_TOKEN_[A-Z0-9_]+; never put a credential in HCL.")
		return
	}
	client, err := newReader(base, os.Getenv(env))
	if err != nil {
		r.Diagnostics.AddError("Invalid provider configuration", err.Error())
		return
	}
	r.DataSourceData = client
}
func (*ompProvider) Resources(context.Context) []func() resource.Resource { return nil }
func (*ompProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{func() datasource.DataSource { return &metadataSource{} }, func() datasource.DataSource { return &metadataSource{team: true} }}
}
