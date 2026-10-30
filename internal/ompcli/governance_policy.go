package ompcli

import (
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
	"gopkg.in/yaml.v3"
)

// GovernancePolicy declares a read-only view, not permission to write it.
// Its core fields are required; empty sunsetAt explicitly means no cutoff.
// Optional metadata is compared only when declared. UUIDs are portal-local
// references, never authentication. Historical review dates are not policy.
type GovernancePolicy struct {
	Sensitivity          string  `yaml:"sensitivity" json:"sensitivity"`
	SensitivityConfirmed *bool   `yaml:"sensitivityConfirmed,omitempty" json:"sensitivityConfirmed,omitempty"`
	Lifecycle            string  `yaml:"lifecycle" json:"lifecycle"`
	SunsetAt             *string `yaml:"sunsetAt" json:"sunsetAt"`
	OwnerUserID          *string `yaml:"ownerUserId,omitempty" json:"ownerUserId,omitempty"`
	OncallContact        *string `yaml:"oncallContact,omitempty" json:"oncallContact,omitempty"`
	ReplacementServerID  *string `yaml:"replacementServerId,omitempty" json:"replacementServerId,omitempty"`
}

func validSensitivity(s string) bool {
	return s == "public" || s == "internal" || s == "confidential" || s == "restricted"
}

func (g *GovernancePolicy) validate() error {
	if !validSensitivity(g.Sensitivity) {
		return fmt.Errorf("sensitivity must be public, internal, confidential or restricted")
	}
	if g.Lifecycle != "active" && g.Lifecycle != "deprecated" && g.Lifecycle != "sunset" {
		return fmt.Errorf("lifecycle must be active, deprecated or sunset")
	}
	if g.SunsetAt == nil {
		return fmt.Errorf("sunsetAt is required (an empty string declares no cutoff)")
	}
	if *g.SunsetAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, *g.SunsetAt); err != nil {
			return fmt.Errorf("sunsetAt must be an RFC 3339 timestamp or an empty string")
		}
	}
	if g.OwnerUserID != nil && *g.OwnerUserID != "" {
		if _, err := uuid.Parse(*g.OwnerUserID); err != nil {
			return fmt.Errorf("ownerUserId must be a UUID or an empty string")
		}
	}
	if g.ReplacementServerID != nil {
		if _, err := uuid.Parse(*g.ReplacementServerID); err != nil {
			return fmt.Errorf("replacementServerId must be a visible server UUID; omit it when not declared")
		}
	}
	if g.OncallContact != nil && utf8.RuneCountInString(*g.OncallContact) > 200 {
		return fmt.Errorf("oncallContact must be at most 200 characters")
	}
	return nil
}

func governanceFrom(g *ompclient.McpServerGovernance) (*GovernancePolicy, error) {
	if g == nil {
		return nil, nil // Older portals did not expose governance. Do not invent it.
	}
	deadline, owner, contact := "", "", deref(g.OncallContact)
	if g.SunsetAt != nil {
		deadline = g.SunsetAt.UTC().Format(time.RFC3339Nano)
	}
	if g.OwnerUserId != nil {
		owner = g.OwnerUserId.String()
	}
	p := &GovernancePolicy{Sensitivity: string(g.Sensitivity), Lifecycle: string(g.Lifecycle), SunsetAt: &deadline, OwnerUserID: &owner, OncallContact: &contact}
	if g.SensitivityConfirmed != nil {
		confirmed := *g.SensitivityConfirmed
		p.SensitivityConfirmed = &confirmed
	}
	if g.Replacement != nil {
		id := g.Replacement.Id.String()
		p.ReplacementServerID = &id
	}
	// An absent replacement may be hidden, not absent in storage. Never
	// export it as an assertion that none is configured.
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("unreadable server governance: %w", err)
	}
	return p, nil
}

func checkGovernanceDeclaration(d Server, cur *ompclient.McpServer) error {
	if d.Governance == nil {
		return nil // Omission preserves all existing governance, including hidden fields.
	}
	if err := d.Governance.validate(); err != nil {
		return usageErr("server %s: invalid governance declaration: %v", d.Slug, err)
	}
	if cur == nil {
		return refuseErr("server %s: governance is comparison-only; omp cannot recreate its owner, label or retirement policy. Prepare the server in the web UI before importing this declaration.", d.Slug)
	}
	have, err := governanceFrom(cur.Governance)
	if err != nil || have == nil {
		return refuseErr("server %s: governance cannot be read and compared safely. Use the web UI.", d.Slug)
	}
	want := d.Governance
	sameDeadline := *want.SunsetAt == "" && *have.SunsetAt == ""
	if *want.SunsetAt != "" && *have.SunsetAt != "" {
		a, aerr := time.Parse(time.RFC3339Nano, *want.SunsetAt)
		b, berr := time.Parse(time.RFC3339Nano, *have.SunsetAt)
		sameDeadline = aerr == nil && berr == nil && a.Equal(b)
	}
	sameID := func(a, b *string) bool {
		if a == nil {
			return true
		}
		if b == nil {
			return false
		}
		if *a == "" || *b == "" {
			return *a == *b
		}
		x, err1 := uuid.Parse(*a)
		y, err2 := uuid.Parse(*b)
		return err1 == nil && err2 == nil && x == y
	}
	if (want.SensitivityConfirmed != nil && (have.SensitivityConfirmed == nil || *want.SensitivityConfirmed != *have.SensitivityConfirmed)) ||
		want.Sensitivity != have.Sensitivity || want.Lifecycle != have.Lifecycle || !sameDeadline ||
		!sameID(want.OwnerUserID, have.OwnerUserID) || !sameID(want.ReplacementServerID, have.ReplacementServerID) ||
		(want.OncallContact != nil && *want.OncallContact != *have.OncallContact) {
		return refuseErr("server %s: declared governance differs from the portal's. Automation tokens cannot change it; align the policy in the web UI. Comparison values are not printed.", d.Slug)
	}
	return nil
}

func checkCeilingDeclaration(d Gateway, cur *ompclient.Gateway) error {
	if d.MaxSensitivity == nil {
		return nil
	}
	if cur == nil {
		if *d.MaxSensitivity == "restricted" {
			return nil
		} // Documented no-ceiling default.
		return refuseErr("gateway %s: its sensitivity ceiling cannot be recreated by an automation token. Prepare the gateway and ceiling in the web UI.", d.Slug)
	}
	if cur.MaxSensitivity == nil || string(*cur.MaxSensitivity) != *d.MaxSensitivity {
		return refuseErr("gateway %s: its sensitivity ceiling is unreadable or differs from the declaration. Automation tokens cannot change it; use the web UI.", d.Slug)
	}
	return nil
}

func rejectNullGovernance(doc *yaml.Node) error {
	// Decode the already type-checked document's effective mappings so aliases
	// and YAML merge keys cannot hide a declared null as an omitted field.
	var view struct {
		Servers  []map[string]any `yaml:"servers"`
		Gateways []map[string]any `yaml:"gateways"`
	}
	if err := doc.Decode(&view); err != nil {
		return usageErr("invalid governance declaration")
	}
	for _, s := range view.Servers {
		g, present := s["governance"]
		if present && g == nil {
			return usageErr("governance cannot be null; omit it to preserve existing policy")
		}
		if fields, ok := g.(map[string]any); ok {
			if v, present := fields["sensitivityConfirmed"]; present {
				if _, ok := v.(bool); !ok {
					return usageErr("governance.sensitivityConfirmed must be a boolean comparison, never a confirmation request")
				}
			}
			for key, value := range fields {
				if value == nil {
					return usageErr("governance.%s cannot be null; use an explicit value or omit an optional declaration", key)
				}
			}
		}
	}
	for _, g := range view.Gateways {
		if v, present := g["maxSensitivity"]; present && v == nil {
			return usageErr("maxSensitivity cannot be null; omit it to preserve the ceiling")
		}
	}
	return nil
}
