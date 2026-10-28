package approvals

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// These typed, safe sentinels intentionally carry no database or guard details.
// Is supports sentinel checks; As also works with the concrete exported types.
type ContextChangedError struct{}

func (*ContextChangedError) Error() string { return "Approval context changed; make a fresh tool call" }
func (*ContextChangedError) Unwrap() error {
	return apperr.Conflict("approval_unavailable", "Approval context changed; make a fresh tool call")
}

type UnavailableError struct{}

func (*UnavailableError) Error() string { return "Approval is unavailable" }
func (*UnavailableError) Unwrap() error {
	return apperr.Conflict("approval_unavailable", "Approval is unavailable")
}

type SpentError struct{}

func (*SpentError) Error() string {
	return "Approval authorization is already spent; execution may be unknown"
}
func (*SpentError) Unwrap() error {
	return apperr.Conflict("approval_unavailable", "Approval authorization is already spent; execution may be unknown")
}

var (
	ErrContextChanged = &ContextChangedError{}
	ErrUnavailable    = &UnavailableError{}
	ErrSpent          = &SpentError{}
)

// Service performs no network I/O inside a transaction. Pattern loading and
// redaction happen before acquiring any locks. SetClock is safe during tests.
type Service struct {
	pool     *pgxpool.Pool
	box      *secrets.Box
	keys     [][]byte
	patterns func(context.Context) ([]*regexp.Regexp, error)
	appURL   string
	clockMu  sync.RWMutex
	now      func() time.Time
}

func New(pool *pgxpool.Pool, box *secrets.Box, patterns func(context.Context) ([]*regexp.Regexp, error), appURL string) (*Service, error) {
	u, err := url.Parse(appURL)
	if pool == nil || box == nil || err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrUnavailable
	}
	keys, err := box.Derive("open-mcp-portal/tool-approvals/argument-binding/v1")
	if err != nil || len(keys) == 0 {
		return nil, ErrUnavailable
	}
	return &Service{pool: pool, box: box, keys: keys, patterns: patterns, appURL: strings.TrimRight(appURL, "/"), now: time.Now}, nil
}
func (s *Service) SetClock(now func() time.Time) {
	s.clockMu.Lock()
	defer s.clockMu.Unlock()
	if now == nil {
		now = time.Now
	}
	s.now = now
}
func (s *Service) clock() time.Time {
	s.clockMu.RLock()
	defer s.clockMu.RUnlock()
	return s.now().UTC()
}
func PreviewAAD(id uuid.UUID) []byte              { return []byte("approval_request:" + id.String()) }
func (s *Service) PreviewAAD(id uuid.UUID) []byte { return PreviewAAD(id) }
func (s *Service) URL(id uuid.UUID) string        { return s.appURL + "/approvals/" + id.String() }
func (s *Service) Epoch(ctx context.Context) (int64, error) {
	e, err := dbgen.New(s.pool).GetApprovalContext(ctx)
	return e, safeError(err)
}
func safeError(err error) error {
	if err == nil {
		return nil
	}
	var ae *apperr.Error
	var ce *ContextChangedError
	var ue *UnavailableError
	var se *SpentError
	if errors.As(err, &ae) || errors.As(err, &ce) || errors.As(err, &ue) || errors.As(err, &se) {
		return err
	}
	return ErrUnavailable
}
func missingRequest() error { return apperr.NotFound("approval_not_found", "Approval not found") }
func missingRule() error    { return apperr.NotFound("rule_not_found", "Approval rule not found") }
func changedReview() error {
	return apperr.Conflict("changed_since_review", "Approval changed since review; reload the receipt")
}
func nullable(id uuid.UUID) uuid.NullUUID { return uuid.NullUUID{UUID: id, Valid: id != uuid.Nil} }
func optional(id *uuid.UUID) uuid.NullUUID {
	if id == nil {
		return uuid.NullUUID{}
	}
	return nullable(*id)
}
func pointer(id uuid.NullUUID) *uuid.UUID {
	if !id.Valid {
		return nil
	}
	v := id.UUID
	return &v
}
func credentialLive(at, expires time.Time) bool { return expires.IsZero() || at.Before(expires) }
func liveDeadline(r dbgen.ApprovalRequest, at time.Time) bool {
	return at.Before(r.ExpiresAt) && (r.Status != Approved || (r.ValidUntil != nil && at.Before(*r.ValidUntil)))
}
func terminal(status string) bool { return status != Pending && status != Approved }

// Human audit FK protection MUST precede the epoch lock. Reads after the
// fence are intentionally non-locking, including the actor's current status.
func (s *Service) transaction(ctx context.Context, a *authz.Actor, exclusive bool, fn func(*dbgen.Queries, int64) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := dbgen.New(tx)
	if a != nil {
		if a.IsToken() || (a.Kind != "" && a.Kind != authz.KindUser) || a.UserID == uuid.Nil {
			return apperr.Forbidden("A human browser session is required")
		}
		if _, err = q.LockApprovalActor(ctx, a.UserID); err != nil {
			return apperr.Forbidden("An active human browser session is required")
		}
	}
	var epoch int64
	if exclusive {
		epoch, err = q.LockApprovalContextExclusive(ctx)
	} else {
		epoch, err = q.LockApprovalContext(ctx)
	}
	if err != nil {
		return ErrUnavailable
	}
	if a != nil {
		u, e := q.GetUser(ctx, a.UserID)
		if e != nil || u.Status != "active" {
			return apperr.Forbidden("An active human browser session is required")
		}
		a.PlatformRole = u.PlatformRole
	}
	if err = fn(q, epoch); err != nil {
		return safeError(err)
	}
	// NEVER retry this commit or a failed Consume. A possibly committed spend
	// yields no dispatch permit: only a confirmed commit returns nil.
	return safeError(tx.Commit(ctx))
}
func (s *Service) CheckContext(ctx context.Context, epoch int64, expires time.Time) error {
	return s.transaction(ctx, nil, false, func(_ *dbgen.Queries, current int64) error {
		if current != epoch {
			return ErrContextChanged
		}
		if !credentialLive(s.clock(), expires) {
			return ErrUnavailable
		}
		return nil
	})
}
func bindingDigest(key []byte, b Binding, rule uuid.UUID, revision int64, args string) string {
	data, _ := json.Marshal(struct {
		Binding   Binding
		Rule      uuid.UUID
		Revision  int64
		Arguments string
	}{b, rule, revision, args})
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("tool-approval-binding/v1\n"))
	_, _ = h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
func requestBinding(r dbgen.ApprovalRequest) Binding {
	return Binding{Epoch: r.ContextEpoch, RequesterKind: r.RequesterKind, RequesterID: r.RequesterID, RequesterTeamID: pointer(r.RequesterTeamID), GatewayID: r.GatewayID, ServerID: r.ServerID, CapabilityID: r.CapabilityID, ExposedName: r.ExposedName, ToolClass: r.ToolClass, CapabilityFingerprint: r.CapabilityFingerprint, ServerOrigin: r.ServerOrigin}
}
func receipt(r dbgen.ApprovalRequest) Receipt {
	return Receipt{ID: r.ID, RuleID: r.RuleID, RuleRevision: r.RuleRevision, ContextEpoch: r.ContextEpoch, RequesterKind: r.RequesterKind, RequesterID: r.RequesterID, RequesterTeamID: pointer(r.RequesterTeamID), GatewayID: r.GatewayID, ServerID: r.ServerID, CapabilityID: r.CapabilityID, ExposedName: r.ExposedName, ToolClass: r.ToolClass, ArgsDigest: r.ArgsDigest, CapabilityFingerprint: r.CapabilityFingerprint, ServerOrigin: r.ServerOrigin, Status: r.Status, ReviewRevision: r.ReviewRevision, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, ValidUntil: r.ValidUntil, DecidedBy: pointer(r.DecidedBy), DecidedAt: r.DecidedAt, UsedAt: r.UsedAt, TerminalAt: r.TerminalAt, PreviewTruncated: r.PreviewTruncated, PreviewRedacted: r.PreviewRedacted}
}
func (s *Service) auditRequest(ctx context.Context, q *dbgen.Queries, a *authz.Actor, r dbgen.ApprovalRequest, action string) error {
	e := audit.Entry{ActorKind: audit.ActorSystem, Action: "approval_request." + action, TargetType: "approval_request", TargetID: r.ID.String()}
	if a != nil {
		e = a.Audit(e.Action, e.TargetType, e.TargetID)
	}
	e.TeamID = r.RequesterTeamID.UUID
	e.Metadata = map[string]any{"requesterKind": r.RequesterKind, "requesterId": r.RequesterID, "ruleId": r.RuleID, "ruleRevision": r.RuleRevision, "reviewRevision": r.ReviewRevision, "status": r.Status}
	if r.DecidedBy.Valid {
		e.Metadata["deciderId"] = r.DecidedBy.UUID
	}
	return audit.Record(ctx, q, e)
}
func (s *Service) requesterLive(ctx context.Context, q *dbgen.Queries, b Binding) (bool, error) {
	return q.ApprovalRequesterLive(ctx, dbgen.ApprovalRequesterLiveParams{GatewayID: b.GatewayID, CapabilityID: b.CapabilityID, ServerID: b.ServerID, Fingerprint: b.CapabilityFingerprint, RequesterKind: b.RequesterKind, RequesterID: b.RequesterID, RequesterTeamID: optional(b.RequesterTeamID)})
}
func reviewers(ctx context.Context, q *dbgen.Queries, r Rule, b Binding) ([]uuid.UUID, error) {
	return q.ApprovalEligibleReviewers(ctx, dbgen.ApprovalEligibleReviewersParams{RuleID: r.ID, ServerID: b.ServerID, RequesterKind: b.RequesterKind, RequesterID: b.RequesterID, AllowServiceAccountAdmins: r.AllowServiceAccountAdmins})
}
func (s *Service) selectedRule(ctx context.Context, q *dbgen.Queries, b Binding) (*Rule, error) {
	rows, err := q.ListMatchingApprovalRules(ctx, dbgen.ListMatchingApprovalRulesParams{ServerID: b.ServerID, GatewayID: b.GatewayID})
	if err != nil {
		return nil, err
	}
	rules := make([]Rule, 0, len(rows))
	for _, row := range rows {
		r, e := loadRule(ctx, q, row)
		if e != nil {
			return nil, e
		}
		rules = append(rules, r)
	}
	return MatchRule(rules, b)
}
func loadRule(ctx context.Context, q *dbgen.Queries, row dbgen.ApprovalRule) (Rule, error) {
	selectors, err := q.ListApprovalRuleApprovers(ctx, row.ID)
	if err != nil {
		return Rule{}, err
	}
	r := Rule{ID: row.ID, TeamID: pointer(row.TeamID), Revision: row.Revision, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, RuleInput: RuleInput{Name: row.Name, TargetKind: row.TargetKind, TargetID: row.TargetID, CapabilityID: pointer(row.CapabilityID), Classes: row.Classes, Enabled: row.Enabled, PendingMinutes: row.PendingMinutes, ValidMinutes: row.ValidMinutes, AllowServiceAccountAdmins: row.AllowServiceAccountAdmins, Approvers: []Selector{}}}
	for _, a := range selectors {
		r.Approvers = append(r.Approvers, Selector{Kind: a.Kind, UserID: pointer(a.UserID), GroupName: a.GroupName})
	}
	normalized, err := NormalizeRule(r.RuleInput)
	if err != nil {
		return Rule{}, ErrUnavailable
	}
	r.RuleInput = normalized
	return r, nil
}

// expire performs one audited terminal transition, never a bulk unaudited UPDATE.
func (s *Service) expire(ctx context.Context, q *dbgen.Queries, r dbgen.ApprovalRequest, epoch int64, a *authz.Actor) (dbgen.ApprovalRequest, error) {
	if terminal(r.Status) {
		return r, nil
	}
	at := s.clock()
	var out dbgen.ApprovalRequest
	var err error
	action := "expired"
	if !liveDeadline(r, at) {
		out, err = q.ExpireApprovalRequest(ctx, dbgen.ExpireApprovalRequestParams{ID: r.ID, AtTime: &at})
	} else if r.ContextEpoch != epoch {
		action = "cancelled"
		out, err = q.CancelApprovalRequest(ctx, dbgen.CancelApprovalRequestParams{ID: r.ID, AtTime: &at, ExpectedReviewRevision: r.ReviewRevision})
	} else {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	return out, s.auditRequest(ctx, q, a, out, action)
}

// Keep pgx linked here for helpers sharing the no-rows classification.
func noRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
