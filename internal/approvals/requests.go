package approvals

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func requesterAgent(ctx context.Context, q *dbgen.Queries, a authz.Actor, r dbgen.ApprovalRequest) (bool, error) {
	if r.RequesterKind == "user" {
		return a.UserID == r.RequesterID, nil
	}
	if r.RequesterKind != "service_account" || !r.RequesterTeamID.Valid {
		return false, nil
	}
	return q.ApprovalRequesterAgent(ctx, dbgen.ApprovalRequesterAgentParams{ServiceAccountID: r.RequesterID, TeamID: r.RequesterTeamID.UUID, UserID: a.UserID})
}

// Metadata visibility is deliberately independent of preview eligibility.
func (s *Service) permissions(ctx context.Context, q *dbgen.Queries, a authz.Actor, r dbgen.ApprovalRequest, epoch int64) (Receipt, bool, bool, error) {
	out := receipt(r)
	agent, err := requesterAgent(ctx, q, a, r)
	if err != nil {
		return out, false, false, err
	}
	row, err := q.GetApprovalRule(ctx, r.RuleID)
	reviewer := false
	if err == nil {
		rule, e := loadRule(ctx, q, row)
		if e != nil {
			return out, false, false, e
		}
		ids, e := reviewers(ctx, q, rule, requestBinding(r))
		if e != nil {
			return out, false, false, e
		}
		reviewer = slices.Contains(ids, a.UserID)
	} else if !noRows(err) {
		return out, false, false, err
	}
	current, e := s.currentRequestRule(ctx, q, r, epoch)
	if e != nil && e != ErrContextChanged && e != ErrUnavailable {
		return out, false, false, e
	}
	live := e == nil && current != nil
	out.Stale = !live || !liveDeadline(r, s.clock())
	out.CanDecide = reviewer && live && r.Status == Pending && liveDeadline(r, s.clock())
	out.CanCancel = agent && !terminal(r.Status) && liveDeadline(r, s.clock())
	out.CanRenew = agent && terminal(r.Status) && live && len(r.PreviewCipher) > 0
	if out.CanRenew {
		latest, e := q.FindApprovalRequestBinding(ctx, r.BindingDigest)
		if e != nil {
			return out, false, false, e
		}
		out.CanRenew = latest.ID == r.ID
		if out.CanRenew {
			ids, e := reviewers(ctx, q, *current, requestBinding(r))
			if e != nil {
				return out, false, false, e
			}
			out.CanRenew = len(ids) > 0
		}
	}
	return out, agent || reviewer || a.CanReadPlatform(), (agent || reviewer) && live && !terminal(r.Status) && liveDeadline(r, s.clock()), nil
}
func lockRequest(ctx context.Context, q *dbgen.Queries, id uuid.UUID) (dbgen.ApprovalRequest, error) {
	// Read snapshot without a lock to choose the immutable requester advisory
	// key. Every service mutation uses advisory -> request in that order.
	r, err := q.GetApprovalRequest(ctx, id)
	if err != nil {
		if noRows(err) {
			return dbgen.ApprovalRequest{}, missingRequest()
		}
		return dbgen.ApprovalRequest{}, err
	}
	if err = q.LockApprovalRequester(ctx, dbgen.LockApprovalRequesterParams{RequesterKind: r.RequesterKind, RequesterID: r.RequesterID}); err != nil {
		return dbgen.ApprovalRequest{}, err
	}
	out, err := q.LockApprovalRequest(ctx, id)
	if noRows(err) {
		return out, missingRequest()
	}
	return out, err
}
func (s *Service) GetRequest(ctx context.Context, a authz.Actor, id uuid.UUID) (Receipt, error) {
	var out Receipt
	err := s.transaction(ctx, &a, false, func(q *dbgen.Queries, epoch int64) error {
		r, e := lockRequest(ctx, q, id)
		if e != nil {
			return e
		}
		_, visible, _, e := s.permissions(ctx, q, a, r, epoch)
		if e != nil {
			return e
		}
		if !visible {
			return missingRequest()
		}
		r, e = s.expire(ctx, q, r, epoch, &a)
		if e != nil {
			return e
		}
		var preview bool
		out, _, preview, e = s.permissions(ctx, q, a, r, epoch)
		if e != nil {
			return e
		}
		if preview && len(r.PreviewCipher) > 0 {
			plain, e := s.box.Open(r.PreviewCipher, PreviewAAD(id))
			if e != nil {
				return ErrUnavailable
			}
			text := string(plain)
			out.Preview = &text
		}
		return nil
	})
	if err != nil {
		return Receipt{}, err
	}
	return out, nil
}
func (s *Service) ListRequests(ctx context.Context, a authz.Actor, view string, offset, limit int32) ([]Receipt, error) {
	out := []Receipt{}
	err := s.transaction(ctx, &a, false, func(q *dbgen.Queries, epoch int64) error {
		if view == "" {
			view = "actionable"
		}
		if view != "requested" && view != "actionable" {
			return apperr.Invalid("invalid_view", "View must be requested or actionable")
		}
		if e := pagination(offset, limit); e != nil {
			return e
		}
		scan := dbgen.ApprovalRequestMetadataBatchParams{PageLimit: 200}
		for {
			rows, e := q.ApprovalRequestMetadataBatch(ctx, scan)
			if e != nil {
				return e
			}
			for _, row := range rows {
				r := dbgen.ApprovalRequest(row)
				p, _, _, e := s.permissions(ctx, q, a, r, epoch)
				if e != nil {
					return e
				}
				include := p.CanDecide
				if view == "requested" {
					include, e = requesterAgent(ctx, q, a, r)
					if e != nil {
						return e
					}
				}
				if !include {
					continue
				}
				if offset > 0 {
					offset--
					continue
				}
				// A list never carries a preview (nor cipher); metadata scans are
				// bounded/keyset-based and visibility is applied BEFORE pagination.
				out = append(out, p)
				if int32(len(out)) == limit {
					return nil
				}
			}
			if len(rows) < int(scan.PageLimit) {
				return nil
			}
			last := rows[len(rows)-1]
			scan.BeforeTime = &last.CreatedAt
			scan.BeforeID = nullable(last.ID)
		}
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) Decide(ctx context.Context, a authz.Actor, id uuid.UUID, in Decision) (Receipt, error) {
	var out Receipt
	var resultErr error
	err := s.transaction(ctx, &a, false, func(q *dbgen.Queries, epoch int64) error {
		if in.Decision != "approve" && in.Decision != "deny" {
			return apperr.Invalid("invalid_decision", "Decision must be approve or deny")
		}
		r, e := lockRequest(ctx, q, id)
		if e != nil {
			return e
		}
		p, visible, _, e := s.permissions(ctx, q, a, r, epoch)
		if e != nil {
			return e
		}
		if !visible {
			return missingRequest()
		}
		if in.ExpectedReviewRevision != r.ReviewRevision || in.ExpectedArgsDigest != r.ArgsDigest {
			return changedReview()
		}
		if !p.CanDecide {
			// An authorized receipt reader gets the same safe unavailable error;
			// unrelated humans cannot distinguish a private ID from a missing one.
			_, e = s.expire(ctx, q, r, epoch, &a)
			if e != nil {
				return e
			}
			resultErr = ErrUnavailable
			return nil
		}
		rule, e := s.currentRequestRule(ctx, q, r, epoch)
		if e != nil {
			return ErrUnavailable
		}
		at := s.clock()
		if in.Decision == "approve" {
			r, e = q.ApproveApprovalRequest(ctx, dbgen.ApproveApprovalRequestParams{ID: id, AtTime: &at, DecidedBy: nullable(a.UserID), ValidUntil: at.Add(time.Duration(rule.ValidMinutes) * time.Minute), BindingDigest: r.BindingDigest, ExpectedReviewRevision: in.ExpectedReviewRevision})
		} else {
			r, e = q.DenyApprovalRequest(ctx, dbgen.DenyApprovalRequestParams{ID: id, AtTime: &at, DecidedBy: nullable(a.UserID), BindingDigest: r.BindingDigest, ExpectedReviewRevision: in.ExpectedReviewRevision})
		}
		if e != nil {
			return ErrUnavailable
		}
		if e = s.auditRequest(ctx, q, &a, r, r.Status); e != nil {
			return e
		}
		out, _, _, e = s.permissions(ctx, q, a, r, epoch)
		return e
	})
	if err != nil {
		return Receipt{}, err
	}
	if resultErr != nil {
		return Receipt{}, resultErr
	}
	return out, nil
}
func (s *Service) Cancel(ctx context.Context, a authz.Actor, id uuid.UUID, expectedReviewRevision int64) (Receipt, error) {
	var out Receipt
	var resultErr error
	err := s.transaction(ctx, &a, false, func(q *dbgen.Queries, epoch int64) error {
		r, e := lockRequest(ctx, q, id)
		if e != nil {
			return e
		}
		agent, e := requesterAgent(ctx, q, a, r)
		if e != nil {
			return e
		}
		if !agent {
			return missingRequest()
		}
		if r.ReviewRevision != expectedReviewRevision {
			return changedReview()
		}
		if terminal(r.Status) {
			return ErrUnavailable
		}
		before := r.Status
		r, e = s.expire(ctx, q, r, epoch, &a)
		if e != nil {
			return e
		}
		if r.Status != before {
			resultErr = ErrUnavailable
			return nil
		}
		at := s.clock()
		r, e = q.CancelApprovalRequest(ctx, dbgen.CancelApprovalRequestParams{ID: id, AtTime: &at, ExpectedReviewRevision: expectedReviewRevision})
		if e != nil {
			return ErrUnavailable
		}
		if e = s.auditRequest(ctx, q, &a, r, "cancelled"); e != nil {
			return e
		}
		out, _, _, e = s.permissions(ctx, q, a, r, epoch)
		return e
	})
	if err != nil {
		return Receipt{}, err
	}
	if resultErr != nil {
		return Receipt{}, resultErr
	}
	return out, nil
}
func (s *Service) Renew(ctx context.Context, a authz.Actor, id uuid.UUID, expectedReviewRevision int64) (Receipt, error) {
	var out Receipt
	err := s.transaction(ctx, &a, false, func(q *dbgen.Queries, epoch int64) error {
		r, e := lockRequest(ctx, q, id)
		if e != nil {
			return e
		}
		agent, e := requesterAgent(ctx, q, a, r)
		if e != nil {
			return e
		}
		if !agent {
			return missingRequest()
		}
		if r.ReviewRevision != expectedReviewRevision {
			return changedReview()
		}
		p, _, _, e := s.permissions(ctx, q, a, r, epoch)
		if e != nil {
			return e
		}
		if !p.CanRenew {
			return ErrUnavailable
		}
		rule, e := s.currentRequestRule(ctx, q, r, epoch)
		if e != nil {
			return ErrUnavailable
		}
		plain, e := s.box.Open(r.PreviewCipher, PreviewAAD(id))
		if e != nil {
			return ErrUnavailable
		}
		nextID := uuid.New()
		cipher, e := s.box.Seal(plain, PreviewAAD(nextID))
		if e != nil {
			return ErrUnavailable
		}
		next, e := s.insertRequest(ctx, q, &a, requestBinding(r), *rule, nextID, r.ArgsDigest, r.BindingDigest, cipher, r.PreviewTruncated, r.PreviewRedacted)
		if e != nil {
			return e
		}
		if e = s.auditRequest(ctx, q, &a, r, "renewed"); e != nil {
			return e
		}
		out, _, _, e = s.permissions(ctx, q, a, next, epoch)
		return e
	})
	if err != nil {
		return Receipt{}, err
	}
	return out, nil
}
func (s *Service) Cleanup(ctx context.Context, batch int32) error {
	if batch < 1 || batch > 1000 {
		return apperr.Invalid("invalid_batch", "Cleanup batch must be from 1 to 1000")
	}
	return s.transaction(ctx, nil, false, func(q *dbgen.Queries, epoch int64) error {
		at := s.clock()
		ids, e := q.ApprovalCleanupCandidates(ctx, dbgen.ApprovalCleanupCandidatesParams{AtTime: at, BatchSize: batch})
		if e != nil {
			return e
		}
		for _, id := range ids {
			r, e := q.LockApprovalRequest(ctx, id)
			if e != nil {
				return e
			}
			if _, e = s.expire(ctx, q, r, epoch, nil); e != nil {
				return e
			}
		}
		if _, e = q.ClearApprovalRequestPreviews(ctx, dbgen.ClearApprovalRequestPreviewsParams{BeforeTime: at.Add(-24 * time.Hour), BatchSize: batch}); e != nil {
			return e
		}
		_, e = q.PurgeApprovalRequestMetadata(ctx, dbgen.PurgeApprovalRequestMetadataParams{AtTime: at, BatchSize: batch})
		return e
	})
}
