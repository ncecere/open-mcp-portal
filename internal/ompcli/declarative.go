package ompcli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// SchemaID is the declarative file format shared by `omp export`, `omp import`
// and (issue #47) the GitHub Action and Terraform provider. The JSON Schema is
// api/omp-v1.schema.json; docs/cli.md describes the semantics.
const SchemaID = "omp/v1"

// File is an omp/v1 document.
//
// Every optional field means "leave it alone" when it is absent: a plan never
// changes what the file does not say, including the curation of a selected tool,
// the tool ceiling of a grant and a grant's deadline. Lists such as gateway
// capabilities and grants are authoritative only when the key is present (an
// empty list means none). Secrets are never in the file: a static header's value
// is read from the environment variable named by authValueEnv.
type File struct {
	Schema   string                   `yaml:"schema" json:"schema"`
	Servers  []Server                 `yaml:"servers,omitempty" json:"servers,omitempty"`
	Teams    []Team                   `yaml:"teams,omitempty" json:"teams,omitempty"`
	Gateways []Gateway                `yaml:"gateways,omitempty" json:"gateways,omitempty"`
	Limits   map[string]PlatformLimit `yaml:"limits,omitempty" json:"limits,omitempty"`
}

// Server is a team's MCP server. The natural key is slug, which is unique
// across the portal and never changes. Needs a team publisher token.
type Server struct {
	Team           string  `yaml:"team" json:"team"`
	Slug           string  `yaml:"slug" json:"slug"`
	Name           string  `yaml:"name" json:"name"`
	Description    *string `yaml:"description,omitempty" json:"description,omitempty"`
	URL            string  `yaml:"url" json:"url"`
	Enabled        *bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	TimeoutSeconds *int32  `yaml:"timeoutSeconds,omitempty" json:"timeoutSeconds,omitempty"`
	// AuthMode is none or static_header. Absent leaves the mode alone (and
	// creates the server with none). Other modes need a browser session.
	AuthMode string `yaml:"authMode,omitempty" json:"authMode,omitempty"`
	// AuthHeaderName names the header of a static_header server.
	AuthHeaderName string `yaml:"authHeaderName,omitempty" json:"authHeaderName,omitempty"`
	// AuthValueEnv names the environment variable holding the header's value.
	// The value is sent on create, or with --replace-secrets; never exported.
	AuthValueEnv string `yaml:"authValueEnv,omitempty" json:"authValueEnv,omitempty"`
	// Publish is none (private) or request (published, or pending review).
	// Absent leaves the publication alone.
	Publish string `yaml:"publish,omitempty" json:"publish,omitempty"`
	// Governance is comparison-only: tokens cannot write it. New servers
	// with a declaration must first be prepared through the browser UI.
	Governance *GovernancePolicy `yaml:"governance,omitempty" json:"governance,omitempty"`
}

// Team is a platform team. The natural key is slug. Needs platform:write.
type Team struct {
	Slug        string  `yaml:"slug" json:"slug"`
	Name        string  `yaml:"name" json:"name"`
	Description *string `yaml:"description,omitempty" json:"description,omitempty"`
	// Status is active or archived; absent leaves it alone.
	Status string `yaml:"status,omitempty" json:"status,omitempty"`
	// OwnerEmail is used only to create the team; it is not compared or exported.
	OwnerEmail string `yaml:"ownerEmail,omitempty" json:"ownerEmail,omitempty"`
	// Limits are the team's rate-limit overrides by key; null inherits the platform default.
	Limits map[string]*int64 `yaml:"limits,omitempty" json:"limits,omitempty"`
}

// Gateway is a platform gateway. The natural key is slug. Team gateways are
// not reachable by tokens and are not part of omp/v1.
type Gateway struct {
	Slug           string           `yaml:"slug" json:"slug"`
	Name           string           `yaml:"name" json:"name"`
	Description    *string          `yaml:"description,omitempty" json:"description,omitempty"`
	Enabled        *bool            `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Capabilities   *[]CapabilityRef `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	Grants         *[]Grant         `yaml:"grants,omitempty" json:"grants,omitempty"`
	MaxSensitivity *string          `yaml:"maxSensitivity,omitempty" json:"maxSensitivity,omitempty"`
}

// CapabilityRef selects a capability of a published server by its server's
// slug, its kind and the name the server uses.
type CapabilityRef struct {
	Server string `yaml:"server" json:"server"`
	Kind   string `yaml:"kind" json:"kind"`
	Name   string `yaml:"name" json:"name"`
	// Curation is a tool's policy in this gateway (name and description
	// overrides, fixed or allowed arguments). Absent: leave the selection's
	// policy alone (an addition or removal of other capabilities never changes
	// it). null: declared to have none. An object: declared to equal the
	// portal's. omp cannot write policy (a token may not edit curation), so a
	// declaration that differs from the portal's is refused before any change.
	Curation *Curation `yaml:"curation,omitempty" json:"curation,omitempty"`
}

// Grant gives a team, an SSO group or a person access to a platform gateway:
// exactly one of team, group and userEmail.
type Grant struct {
	Team      string `yaml:"team,omitempty" json:"team,omitempty"`
	Group     string `yaml:"group,omitempty" json:"group,omitempty"`
	UserEmail string `yaml:"userEmail,omitempty" json:"userEmail,omitempty"`
	// ToolScope is the grant's tool ceiling. Absent: a new grant is
	// unrestricted and an existing grant keeps its ceiling. null: declared
	// unrestricted. {} : no tools.
	ToolScope *ToolScope `yaml:"toolScope,omitempty" json:"toolScope,omitempty"`
	// ExpiresAt is the grant's deadline (RFC 3339). Absent: a new grant is
	// permanent and an existing grant keeps its deadline. CLI v1 compares
	// exact authoritative timestamps but refuses any write requiring a new
	// absolute deadline (docs/cli.md, "Grant expiry").
	ExpiresAt string `yaml:"expiresAt,omitempty" json:"expiresAt,omitempty"`
}

// ToolScope is a grant's optional tool ceiling (null: unrestricted; empty: no
// tools).
type ToolScope struct {
	Classes *[]string `yaml:"classes,omitempty" json:"classes,omitempty"`
	Tools   *[]string `yaml:"tools,omitempty" json:"tools,omitempty"`
	// Unrestricted is `toolScope: null`, declared explicitly.
	Unrestricted bool `yaml:"-" json:"-"`
}

type toolScopeFields struct {
	Classes *[]string `yaml:"classes,omitempty" json:"classes,omitempty"`
	Tools   *[]string `yaml:"tools,omitempty" json:"tools,omitempty"`
}

// MarshalYAML writes an explicitly unrestricted scope as null.
func (t ToolScope) MarshalYAML() (any, error) {
	if t.Unrestricted {
		return nil, nil
	}
	return toolScopeFields{Classes: t.Classes, Tools: t.Tools}, nil
}

// MarshalJSON writes an explicitly unrestricted scope as null.
func (t ToolScope) MarshalJSON() ([]byte, error) {
	if t.Unrestricted {
		return []byte("null"), nil
	}
	return json.Marshal(toolScopeFields{Classes: t.Classes, Tools: t.Tools})
}

// PlatformLimit is a platform rate-limit setting. Both values are declared
// when the key is listed; absent or null is unlimited (default) or no ceiling.
type PlatformLimit struct {
	Default *int64 `yaml:"default" json:"default"`
	Ceiling *int64 `yaml:"ceiling" json:"ceiling"`
}

// ParseFile reads an omp/v1 document (YAML, which includes JSON) and validates
// it. Unknown fields are errors, so a typo never silently does nothing.
func ParseFile(raw []byte) (*File, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, usageErr("the file is empty (expected schema: %s)", SchemaID)
		}
		return nil, usageErr("invalid %s file: %v", SchemaID, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, usageErr("invalid %s file: malformed trailing YAML", SchemaID)
		}
		return nil, usageErr("invalid %s file: more than one YAML document", SchemaID)
	}
	if err := f.markExplicitNulls(raw); err != nil {
		return nil, err
	}
	if problems := f.Validate(); len(problems) > 0 {
		return nil, usageErr("invalid %s file:\n  - %s", SchemaID, strings.Join(problems, "\n  - "))
	}
	return &f, nil
}

// markExplicitNulls tells an explicit null from an absent key, which a typed
// decode cannot: `curation: null` and `toolScope: null` are declarations (no
// policy; unrestricted), while the same key absent leaves the setting alone.
// `expiresAt: null` is refused: omp never turns a deadline into permanent
// access, and silently reading null as "absent" would hide that.
func (f *File) markExplicitNulls(raw []byte) error {
	var root yaml.Node
	if yaml.Unmarshal(raw, &root) != nil {
		return nil // ParseFile has decoded it already
	}
	doc := &root
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		doc = doc.Content[0]
	}
	if err := rejectNullGovernance(doc); err != nil {
		return err
	}
	gateways := yamlField(doc, "gateways")
	if gateways == nil || gateways.Kind != yaml.SequenceNode {
		return nil
	}
	isNull := func(n *yaml.Node) bool {
		n = yamlResolve(n)
		return n != nil && n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null"
	}
	for i, gn := range gateways.Content {
		if i >= len(f.Gateways) {
			break
		}
		g := &f.Gateways[i]
		if caps := yamlField(gn, "capabilities"); caps != nil && caps.Kind == yaml.SequenceNode && g.Capabilities != nil {
			for j, cn := range caps.Content {
				if j < len(*g.Capabilities) && isNull(yamlField(cn, "curation")) {
					(*g.Capabilities)[j].Curation = &Curation{Clear: true}
				}
			}
		}
		if grants := yamlField(gn, "grants"); grants != nil && grants.Kind == yaml.SequenceNode && g.Grants != nil {
			for j, gr := range grants.Content {
				if j >= len(*g.Grants) {
					break
				}
				if isNull(yamlField(gr, "toolScope")) {
					(*g.Grants)[j].ToolScope = &ToolScope{Unrestricted: true}
				}
				if isNull(yamlField(gr, "expiresAt")) {
					return usageErr("invalid %s file: gateways[%d] (%s): grants[%d].expiresAt is null; omit it instead (omp never makes an expiring grant permanent)", SchemaID, i, g.Slug, j)
				}
			}
		}
	}
	return nil
}

func yamlResolve(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// yamlField is the value of a key of a mapping node, or nil.
func yamlField(n *yaml.Node, key string) *yaml.Node {
	n = yamlResolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return yamlResolve(n.Content[i+1])
		}
	}
	return nil
}

func (c CapabilityRef) key() string { return c.Kind + "|" + c.Server + "|" + c.Name }

func (g Grant) subject() string {
	switch {
	case g.Team != "":
		return "team:" + g.Team
	case g.Group != "":
		return "group:" + g.Group
	}
	return "user:" + strings.ToLower(g.UserEmail)
}

// Sort puts the document in its canonical order, so export is deterministic.
func (f *File) Sort() {
	sort.Slice(f.Servers, func(i, j int) bool { return f.Servers[i].Slug < f.Servers[j].Slug })
	sort.Slice(f.Teams, func(i, j int) bool { return f.Teams[i].Slug < f.Teams[j].Slug })
	sort.Slice(f.Gateways, func(i, j int) bool { return f.Gateways[i].Slug < f.Gateways[j].Slug })
	for i := range f.Gateways {
		if c := f.Gateways[i].Capabilities; c != nil {
			sort.Slice(*c, func(a, b int) bool { return (*c)[a].key() < (*c)[b].key() })
		}
		if g := f.Gateways[i].Grants; g != nil {
			sort.Slice(*g, func(a, b int) bool { return (*g)[a].subject() < (*g)[b].subject() })
		}
	}
}

// Marshal writes the document as YAML.
func (f *File) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
