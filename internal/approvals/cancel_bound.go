package approvals

import (
	"context"
	"crypto/hmac"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// CancelBound handles only a verified MCP approval-decline continuation. The
// runtime first verifies its sealed approval-purpose state; this service still
// compares the entire freshly authorized binding and exact merged arguments.
// It never creates a request or forges a browser actor. Declining cannot grant
// authority, resurrect a terminal receipt, or cancel somebody else's request.
func (s *Service) CancelBound(ctx context.Context, in BeginInput, requestID uuid.UUID, expectedReviewRevision int64) error {
	canonical, err := CanonicalArguments(in.Arguments)
	if err != nil {
		return missingRequest()
	}
	return s.transaction(ctx, nil, false, func(q *dbgen.Queries, epoch int64) error {
		if epoch != in.Binding.Epoch {
			return ErrContextChanged
		}
		if !credentialLive(s.clock(), in.CredentialExpiresAt) {
			return ErrUnavailable
		}
		if e := q.LockApprovalRequester(ctx, dbgen.LockApprovalRequesterParams{RequesterKind: in.Binding.RequesterKind, RequesterID: in.Binding.RequesterID}); e != nil {
			return e
		}
		r, e := q.LockApprovalRequest(ctx, requestID)
		if e != nil {
			if noRows(e) {
				return missingRequest()
			}
			return e
		}
		matched := false
		for _, key := range s.keys {
			args := argumentDigest(key, canonical)
			digest := bindingDigest(key, in.Binding, r.RuleID, r.RuleRevision, args)
			if hmac.Equal([]byte(args), []byte(r.ArgsDigest)) && hmac.Equal([]byte(digest), []byte(r.BindingDigest)) {
				matched = true
				break
			}
		}
		if !matched {
			return missingRequest()
		}
		if r.ContextEpoch != epoch {
			return ErrContextChanged
		}
		if r.ReviewRevision != expectedReviewRevision {
			return changedReview()
		}
		if terminal(r.Status) || !liveDeadline(r, s.clock()) {
			return ErrUnavailable
		}
		if _, e = s.currentRequestRule(ctx, q, r, epoch); e != nil {
			return ErrUnavailable
		}
		at := s.clock()
		if !credentialLive(at, in.CredentialExpiresAt) || !liveDeadline(r, at) {
			return ErrUnavailable
		}
		r, e = q.CancelApprovalRequest(ctx, dbgen.CancelApprovalRequestParams{ID: r.ID, AtTime: &at, ExpectedReviewRevision: expectedReviewRevision})
		if e != nil {
			return ErrUnavailable
		}
		return s.auditRequest(ctx, q, nil, r, "cancelled")
	})
}
