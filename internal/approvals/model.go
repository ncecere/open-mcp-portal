// Package approvals governs one sensitive tool dispatch, never underlying access.
package approvals

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const (
	Pending   = "pending"
	Approved  = "approved"
	Denied    = "denied"
	Expired   = "expired"
	Used      = "used"
	Cancelled = "cancelled"
)

// Selector names a person or an SSO group, never a machine credential.
type Selector struct {
	Kind      string     `json:"kind"`
	UserID    *uuid.UUID `json:"userId"`
	GroupName *string    `json:"groupName"`
}

// RuleInput replaces the editable rule policy. A replacement cannot move its target.
type RuleInput struct {
	Name                      string     `json:"name"`
	TargetKind                string     `json:"targetKind"`
	TargetID                  uuid.UUID  `json:"targetId"`
	CapabilityID              *uuid.UUID `json:"capabilityId"`
	Classes                   []string   `json:"classes"`
	Enabled                   bool       `json:"enabled"`
	PendingMinutes            int32      `json:"pendingMinutes"`
	ValidMinutes              int32      `json:"validMinutes"`
	AllowServiceAccountAdmins bool       `json:"allowServiceAccountAdmins"`
	Approvers                 []Selector `json:"approvers"`
}

// Rule is configuration, not an authorization grant.
type Rule struct {
	RuleInput
	ID        uuid.UUID  `json:"id"`
	TeamID    *uuid.UUID `json:"teamId"`
	Revision  int64      `json:"revision"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
}

// Binding is constructed only from a freshly authorized, immutable tool offer.
// Epoch is captured BEFORE request authentication/preparation. A change during
// that work is refused under the final fence, rather than blessed as current.
type Binding struct {
	Epoch                 int64
	RequesterKind         string
	RequesterID           uuid.UUID
	RequesterTeamID       *uuid.UUID
	GatewayID             uuid.UUID
	ServerID              uuid.UUID
	CapabilityID          uuid.UUID
	ExposedName           string
	ToolClass             *string
	CapabilityFingerprint string
	ServerOrigin          string
}

// BeginInput contains transient arguments/credentials used for digest/redaction.
// They must never enter audit metadata, notifications or unsealed database fields.
type BeginInput struct {
	Binding   Binding
	Arguments json.RawMessage
	Secrets   []string
	// CredentialExpiresAt is the current MCP credential's deadline, not the
	// approval deadline. Zero means no fixed expiry for that credential.
	CredentialExpiresAt time.Time
}

// Plan is the result of matching policy and finding/creating an exact request.
// A plan with no matching rule still fences context at every transport.
type Plan struct {
	Binding             Binding
	Required            bool
	Receipt             Receipt
	BindingDigest       string
	CredentialExpiresAt time.Time
}

// Receipt is safe metadata; lists never include Preview. Human detail may add
// the redacted preview only for a live pending/approved request and authorized reader.
// Used means authorization spent, never proof of upstream effect.
type Receipt struct {
	ID                    uuid.UUID  `json:"id"`
	RuleID                uuid.UUID  `json:"ruleId"`
	RuleRevision          int64      `json:"ruleRevision"`
	ContextEpoch          int64      `json:"contextEpoch"`
	RequesterKind         string     `json:"requesterKind"`
	RequesterID           uuid.UUID  `json:"requesterId"`
	RequesterTeamID       *uuid.UUID `json:"requesterTeamId"`
	GatewayID             uuid.UUID  `json:"gatewayId"`
	ServerID              uuid.UUID  `json:"serverId"`
	CapabilityID          uuid.UUID  `json:"capabilityId"`
	ExposedName           string     `json:"exposedName"`
	ToolClass             *string    `json:"toolClass"`
	ArgsDigest            string     `json:"argsDigest"`
	CapabilityFingerprint string     `json:"capabilityFingerprint"`
	ServerOrigin          string     `json:"serverOrigin"`
	Status                string     `json:"status"`
	ReviewRevision        int64      `json:"reviewRevision"`
	CreatedAt             time.Time  `json:"createdAt"`
	ExpiresAt             time.Time  `json:"expiresAt"`
	ValidUntil            *time.Time `json:"validUntil"`
	DecidedBy             *uuid.UUID `json:"decidedBy"`
	DecidedAt             *time.Time `json:"decidedAt"`
	UsedAt                *time.Time `json:"usedAt"`
	TerminalAt            *time.Time `json:"terminalAt"`
	Stale                 bool       `json:"stale"`
	CanDecide             bool       `json:"canDecide"`
	CanCancel             bool       `json:"canCancel"`
	CanRenew              bool       `json:"canRenew"`
	PreviewTruncated      bool       `json:"previewTruncated"`
	PreviewRedacted       bool       `json:"previewRedacted"`
	Preview               *string    `json:"preview,omitempty"`
}

// Decision protects the exact revision and merged-arguments digest reviewed.
type Decision struct {
	Decision               string
	ExpectedReviewRevision int64
	ExpectedArgsDigest     string
}
