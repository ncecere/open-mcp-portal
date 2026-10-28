package approvals

import "github.com/ncecere/open-mcp-portal/internal/store/dbgen"

// Metadata scans expose only whether a redacted preview can be renewed, never
// its ciphertext. Keep the conversion explicit to make that privacy boundary
// visible when sqlc rows evolve.
func metadataRequest(r dbgen.ApprovalRequestMetadataBatchRow) dbgen.ApprovalRequest {
	return dbgen.ApprovalRequest{ID: r.ID, RuleID: r.RuleID, RuleRevision: r.RuleRevision, ContextEpoch: r.ContextEpoch, RequesterKind: r.RequesterKind, RequesterID: r.RequesterID, RequesterTeamID: r.RequesterTeamID, GatewayID: r.GatewayID, ServerID: r.ServerID, CapabilityID: r.CapabilityID, ExposedName: r.ExposedName, ToolClass: r.ToolClass, ArgsDigest: r.ArgsDigest, BindingDigest: r.BindingDigest, CapabilityFingerprint: r.CapabilityFingerprint, ServerOrigin: r.ServerOrigin, PreviewTruncated: r.PreviewTruncated, PreviewRedacted: r.PreviewRedacted, Status: r.Status, ReviewRevision: r.ReviewRevision, DecidedBy: r.DecidedBy, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, ValidUntil: r.ValidUntil, DecidedAt: r.DecidedAt, UsedAt: r.UsedAt, TerminalAt: r.TerminalAt}
}
