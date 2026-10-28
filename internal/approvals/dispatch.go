package approvals

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/capture"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// capturePreview never persists unredacted arguments. It deliberately does not
// consult capture enablement. Redact short known credentials too (capture's
// general-purpose redactor ignores short strings), including encoded forms and
// object keys. All substitutions precede the UTF-8-safe approval size limit.
func (s *Service) capturePreview(ctx context.Context, canonical []byte, known []string) (string, bool, bool, error) {
	var patterns []*regexp.Regexp
	var err error
	if s.patterns != nil {
		patterns, err = s.patterns(ctx)
		if err != nil {
			return "", false, false, ErrUnavailable
		}
	}
	for _, p := range patterns {
		if p == nil {
			return "", false, false, ErrUnavailable
		}
	}
	values := make([]string, 0, len(known)*4)
	for _, v := range known {
		if v != "" {
			values = append(values, v, url.QueryEscape(v), strings.ReplaceAll(url.QueryEscape(v), "+", "%20"), url.PathEscape(v))
		}
	}
	slices.SortFunc(values, func(a, b string) int { return len(b) - len(a) })
	redacted, truncated := false, false
	replace := func(text string) string {
		for _, v := range values {
			if strings.Contains(text, v) {
				text = strings.ReplaceAll(text, v, capture.Redacted)
				redacted = true
			}
		}
		return text
	}
	// Decode with exact JSON numbers. Redact known secrets (including member
	// names) before capture's document-level truncation can cut a value in half.
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.UseNumber()
	var value any
	if dec.Decode(&value) != nil {
		return "", false, false, ErrUnavailable
	}
	redactor := capture.NewRedactor(patterns, known...)
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case string:
			// Embedded JSON can materialize escaped secrets or member names only
			// after a second decode. Mask JSON-looking strings in their entirety:
			// the general capture walker intentionally ignores short credentials
			// and keys, and is not an approval-specific recursive safety boundary.
			trimmed := strings.TrimSpace(x)
			if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
				redacted = true
				return capture.Redacted
			}
			return replace(x)
		case json.Number:
			for _, secret := range known {
				if string(x) == secret {
					redacted = true
					return capture.Redacted
				}
			}
			return x
		case []any:
			for i, item := range x {
				x[i] = walk(item)
			}
			return x
		case map[string]any:
			out := make(map[string]any, len(x))
			for k, item := range x {
				key := replace(k)
				part := redactor.Text(key)
				redacted = redacted || part.Redactions > 0
				truncated = truncated || part.Truncated
				if part.Content != k {
					out[part.Content] = capture.Redacted
					redacted = true
				} else {
					out[k] = walk(item)
				}
			}
			return out
		default:
			return v
		}
	}
	clean, err := json.Marshal(walk(value))
	if err != nil {
		return "", false, false, ErrUnavailable
	}
	p := redactor.Redact(clean)
	return p.Content, truncated || p.Truncated, redacted || p.Redactions > 0, nil
}
func (s *Service) Begin(ctx context.Context, in BeginInput) (Plan, error) {
	plan := Plan{Binding: in.Binding, CredentialExpiresAt: in.CredentialExpiresAt}
	// A preliminary non-locking policy read allows all expensive/local preview
	// work before the fence, without changing legacy ungoverned arguments. The
	// authoritative match and the originally captured epoch are checked below.
	preliminary, err := s.selectedRule(ctx, dbgen.New(s.pool), in.Binding)
	if err != nil {
		return Plan{}, safeError(err)
	}
	var canonical, cipher []byte
	var truncated, redacted bool
	id := uuid.New()
	if preliminary != nil {
		canonical, err = CanonicalArguments(in.Arguments)
		if err != nil {
			return Plan{}, err
		}
		var preview string
		preview, truncated, redacted, err = s.capturePreview(ctx, canonical, in.Secrets)
		if err != nil {
			return Plan{}, err
		}
		cipher, err = s.box.Seal([]byte(preview), PreviewAAD(id))
		if err != nil {
			return Plan{}, ErrUnavailable
		}
	}
	err = s.transaction(ctx, nil, false, func(q *dbgen.Queries, epoch int64) error {
		if epoch != in.Binding.Epoch {
			return ErrContextChanged
		}
		if !credentialLive(s.clock(), in.CredentialExpiresAt) {
			return ErrUnavailable
		}
		live, e := s.requesterLive(ctx, q, in.Binding)
		if e != nil {
			return e
		}
		if !live {
			return ErrUnavailable
		}
		rule, e := s.selectedRule(ctx, q, in.Binding)
		if e != nil {
			return e
		}
		if rule == nil {
			if !credentialLive(s.clock(), in.CredentialExpiresAt) {
				return ErrUnavailable
			}
			return nil
		}
		if preliminary == nil {
			return ErrContextChanged
		}
		plan.Required = true
		eligible, e := reviewers(ctx, q, *rule, in.Binding)
		if e != nil {
			return e
		}
		if len(eligible) == 0 {
			return ErrUnavailable
		}
		if e = q.LockApprovalRequester(ctx, dbgen.LockApprovalRequesterParams{RequesterKind: in.Binding.RequesterKind, RequesterID: in.Binding.RequesterID}); e != nil {
			return e
		}
		// Try all configured digest keys during key rotation; the newest attempt
		// wins, so an explicit renewal supersedes an older remembered denial.
		var found dbgen.ApprovalRequest
		foundAny := false
		for _, key := range s.keys {
			args := argumentDigest(key, canonical)
			digest := bindingDigest(key, in.Binding, rule.ID, rule.Revision, args)
			r, e := q.FindApprovalRequestBinding(ctx, digest)
			if noRows(e) {
				continue
			}
			if e != nil {
				return e
			}
			if !foundAny || r.CreatedAt.After(found.CreatedAt) || (r.CreatedAt.Equal(found.CreatedAt) && r.ID.String() > found.ID.String()) {
				found = r
				foundAny = true
			}
		}
		if foundAny {
			found, e = q.LockApprovalRequest(ctx, found.ID)
			if e != nil {
				return e
			}
			found, e = s.expire(ctx, q, found, epoch, nil)
			if e != nil {
				return e
			}
			if found.Status == Pending || found.Status == Approved || found.Status == Denied {
				if !credentialLive(s.clock(), in.CredentialExpiresAt) {
					return ErrUnavailable
				}
				plan.Receipt = receipt(found)
				plan.BindingDigest = found.BindingDigest
				return nil
			}
		}
		if !credentialLive(s.clock(), in.CredentialExpiresAt) {
			return ErrUnavailable
		}
		args := argumentDigest(s.keys[0], canonical)
		digest := bindingDigest(s.keys[0], in.Binding, rule.ID, rule.Revision, args)
		r, e := s.insertRequest(ctx, q, nil, in.Binding, *rule, id, args, digest, cipher, truncated, redacted)
		if e != nil {
			return e
		}
		if !credentialLive(s.clock(), in.CredentialExpiresAt) {
			return ErrUnavailable
		}
		plan.Receipt = receipt(r)
		plan.BindingDigest = digest
		return nil
	})
	if err != nil {
		return Plan{}, err
	}
	return plan, nil
}
func (s *Service) insertRequest(ctx context.Context, q *dbgen.Queries, a *authz.Actor, b Binding, rule Rule, id uuid.UUID, args, digest string, cipher []byte, truncated, redacted bool) (dbgen.ApprovalRequest, error) {
	// The advisory lock is held by Begin/Renew. Old-epoch pending rows
	// otherwise consume quota despite having an entirely different digest.
	if err := s.clearStaleRequester(ctx, q, b); err != nil {
		return dbgen.ApprovalRequest{}, err
	}
	at := s.clock().Truncate(time.Microsecond)
	// PostgreSQL timestamps have microsecond precision. A new attempt must
	// sort after the previous one even with a fixed test clock or fast renewal;
	// UUID ordering must never resurrect a remembered denial.
	previous, e := q.FindApprovalRequestBinding(ctx, digest)
	if e != nil && !noRows(e) {
		return dbgen.ApprovalRequest{}, e
	}
	if e == nil && !at.After(previous.CreatedAt) {
		at = previous.CreatedAt.Add(time.Microsecond)
	}
	n, err := q.CountPendingApprovalRequests(ctx, dbgen.CountPendingApprovalRequestsParams{RequesterKind: b.RequesterKind, RequesterID: b.RequesterID, AtTime: at})
	if err != nil {
		return dbgen.ApprovalRequest{}, err
	}
	if n >= 20 {
		return dbgen.ApprovalRequest{}, apperr.Conflict("approval_unavailable", "At most 20 approval requests may be pending")
	}
	r, err := q.InsertApprovalRequest(ctx, dbgen.InsertApprovalRequestParams{ID: id, RuleID: rule.ID, RuleRevision: rule.Revision, ContextEpoch: b.Epoch, RequesterKind: b.RequesterKind, RequesterID: b.RequesterID, RequesterTeamID: optional(b.RequesterTeamID), GatewayID: b.GatewayID, ServerID: b.ServerID, CapabilityID: b.CapabilityID, ExposedName: b.ExposedName, ToolClass: b.ToolClass, ArgsDigest: args, BindingDigest: digest, CapabilityFingerprint: b.CapabilityFingerprint, ServerOrigin: b.ServerOrigin, PreviewCipher: cipher, PreviewTruncated: truncated, PreviewRedacted: redacted, CreatedAt: at, ExpiresAt: at.Add(time.Duration(rule.PendingMinutes) * time.Minute)})
	if err != nil {
		return r, err
	}
	if err = s.auditRequest(ctx, q, a, r, "requested"); err != nil {
		return r, err
	}
	if s.EmitNotice != nil {
		s.EmitNotice(ctx, q, receipt(r), true)
	}
	return r, nil
}
func (s *Service) Consume(ctx context.Context, plan Plan) error {
	err := s.transaction(ctx, nil, false, func(q *dbgen.Queries, epoch int64) error {
		// Context and credential deadline precede every other guard, including
		// already-spent detection. Never bless a freshly read current epoch.
		if epoch != plan.Binding.Epoch {
			return ErrContextChanged
		}
		at := s.clock()
		if !credentialLive(at, plan.CredentialExpiresAt) {
			return ErrUnavailable
		}
		if !plan.Required {
			rule, e := s.selectedRule(ctx, q, plan.Binding)
			if e != nil {
				return e
			}
			if rule != nil || !credentialLive(s.clock(), plan.CredentialExpiresAt) {
				return ErrUnavailable
			}
			return nil
		}
		if e := q.LockApprovalRequester(ctx, dbgen.LockApprovalRequesterParams{RequesterKind: plan.Binding.RequesterKind, RequesterID: plan.Binding.RequesterID}); e != nil {
			return e
		}
		r, e := q.LockApprovalRequest(ctx, plan.Receipt.ID)
		if e != nil {
			return ErrUnavailable
		}
		if r.Status == Used {
			return ErrSpent
		}
		if r.ContextEpoch != epoch {
			return ErrContextChanged
		}
		if r.Status != Approved || !liveDeadline(r, at) {
			return ErrUnavailable
		}
		validBinding := false
		for _, key := range s.keys {
			expected := bindingDigest(key, plan.Binding, r.RuleID, r.RuleRevision, plan.Receipt.ArgsDigest)
			if hmac.Equal([]byte(expected), []byte(r.BindingDigest)) && hmac.Equal([]byte(expected), []byte(plan.BindingDigest)) {
				validBinding = true
				break
			}
		}
		if !validBinding || r.ReviewRevision != plan.Receipt.ReviewRevision || r.ArgsDigest != plan.Receipt.ArgsDigest || r.RuleRevision != plan.Receipt.RuleRevision || r.RuleID != plan.Receipt.RuleID {
			return ErrUnavailable
		}
		rule, e := s.currentRequestRule(ctx, q, r, epoch)
		if e != nil {
			return e
		}
		eligible, e := reviewers(ctx, q, *rule, requestBinding(r))
		if e != nil {
			return e
		}
		if !r.DecidedBy.Valid || !slices.Contains(eligible, r.DecidedBy.UUID) {
			return ErrUnavailable
		}
		if _, e = s.openPreview(r); e != nil {
			return e
		}
		// Waiting for the requester/request lock must not freeze the time guard.
		at = s.clock()
		if !credentialLive(at, plan.CredentialExpiresAt) || !liveDeadline(r, at) {
			return ErrUnavailable
		}
		r, e = q.UseApprovalRequest(ctx, dbgen.UseApprovalRequestParams{ID: r.ID, AtTime: &at, BindingDigest: r.BindingDigest, ArgsDigest: r.ArgsDigest, RuleRevision: r.RuleRevision, ExpectedReviewRevision: plan.Receipt.ReviewRevision, ContextEpoch: epoch})
		if e != nil {
			return ErrUnavailable
		}
		return s.auditRequest(ctx, q, nil, r, "used")
	})
	if err != nil {
		return err
	}
	// A slow commit acknowledgement must not turn an elapsed credential or
	// approval deadline into a dispatch permit. Spending remains committed;
	// never retry it or claim the upstream side effect happened.
	at := s.clock()
	if !credentialLive(at, plan.CredentialExpiresAt) || (plan.Required &&
		(!at.Before(plan.Receipt.ExpiresAt) || plan.Receipt.ValidUntil == nil || !at.Before(*plan.Receipt.ValidUntil))) {
		if plan.Required {
			return ErrSpent
		}
		return ErrUnavailable
	}
	return nil
}

// Epoch triggers cover all mutable authority (including credential revocation).
// Runtime supplies the actual MCP credential's absolute expiry to every guard.
// Browser/consume also validate live structural requester authority and exact
// selected policy. No browser operation recomputes a stale context as current.
func (s *Service) currentRequestRule(ctx context.Context, q *dbgen.Queries, r dbgen.ApprovalRequest, epoch int64) (*Rule, error) {
	if r.ContextEpoch != epoch {
		return nil, ErrContextChanged
	}
	b := requestBinding(r)
	live, err := s.requesterLive(ctx, q, b)
	if err != nil {
		return nil, err
	}
	if !live {
		return nil, ErrUnavailable
	}
	rule, err := s.selectedRule(ctx, q, b)
	if err != nil {
		return nil, err
	}
	if rule == nil || rule.ID != r.RuleID || rule.Revision != r.RuleRevision {
		return nil, ErrUnavailable
	}
	return rule, nil
}
