package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestApprovalsHTTPMCPServiceAccountOwnerExcludedAndDefaultFallback(t *testing.T) {
	e := newApprovalWire(t, testutil.ProtocolModern, nil)
	sa := createSA(t, e.owner, map[string]any{"name": "governed-worker"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "worker key"})
	out := e.call(t, true, key.Secret, approvalParams("service account"), urlCaps)
	rows := approvalList(t, e.owner, "requested")
	if len(rows) != 1 {
		t.Fatalf("service-account owner's request queue: %+v", rows)
	}
	r := approvalDetail(t, e.owner, rows[0].ID)
	if r.RequesterKind != "service_account" || r.RequesterID != sa.Id || r.Preview == nil || r.CanDecide || !r.CanCancel {
		t.Fatalf("account owner separation of duties: %+v", r)
	}
	state := approvalState(t, out, r.ID, e.app.URL)
	// Being an owning human must not be confused with being the machine caller.
	c, ec := e.owner.call("POST", "/v1/approvals/"+r.ID.String()+"/decision", map[string]any{"decision": "approve", "expectedArgsDigest": r.ArgsDigest, "expectedReviewRevision": r.ReviewRevision}, nil, nil)
	mustCode(t, "account owner cannot approve", c, ec, 409, "approval_unavailable")
	if v := approvalDetail(t, e.auditor, r.ID); v.Preview != nil || v.CanDecide {
		t.Fatalf("auditor preview: %+v", v)
	}
	fallback := approvalDetail(t, e.admin, r.ID)
	if fallback.Preview == nil || !fallback.CanDecide {
		t.Fatalf("non-requester platform-admin fallback unavailable: %+v", fallback)
	}
	p := approvalParams("service account")
	p["requestState"] = state
	p["inputResponses"] = map[string]any{"approval_" + r.ID.String(): map[string]any{"action": "cancel"}}
	e.call(t, true, key.Secret, p, urlCaps)
	if v := approvalDetail(t, e.owner, r.ID); v.Status != approvals.Cancelled {
		t.Fatalf("verified machine decline: %+v", v)
	}
	out = e.call(t, true, key.Secret, approvalParams("service account dispatch"), urlCaps)
	rows = approvalList(t, e.admin, "actionable")
	if len(rows) != 1 {
		t.Fatalf("fallback actionable queue: %+v", rows)
	}
	r = approvalDetail(t, e.admin, rows[0].ID)
	approvalDecide(t, e.admin, r, "approve")
	out = e.call(t, true, key.Secret, approvalParams("service account dispatch"), nil)
	if resultOf(t, out)["isError"] == true || e.posts.Load() != 1 {
		t.Fatalf("approved machine dispatch: %v", out)
	}
}

func TestApprovalsHTTPMCPActualNegotiationDoesNotConsumeAndFailureLeavesApproved(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "successful negotiation"
		if fail {
			name = "failed negotiation"
		}
		t.Run(name, func(t *testing.T) {
			var enabled atomic.Bool
			var negotiations atomic.Int64
			var e *approvalWire
			var receipt approvals.Receipt
			e = newApprovalWire(t, testutil.ProtocolLegacy, func(w http.ResponseWriter, r *http.Request, msg map[string]any) bool {
				if !enabled.Load() || (msg["method"] != "initialize" && msg["method"] != "server/discover") {
					return false
				}
				negotiations.Add(1)
				// A real HTTP negotiation arrives only after Begin has selected the
				// approved binding. Reading it here proves no fence survives into I/O.
				if v := approvalDetail(t, e.member, receipt.ID); v.Status != approvals.Approved || e.posts.Load() != 0 {
					t.Errorf("negotiation spent authorization: %+v", v)
				}
				if fail {
					http.Error(w, "negotiation unavailable", http.StatusUnauthorized)
					return true
				}
				return false
			})
			e.call(t, true, e.key.Secret, approvalParams("negotiate"), urlCaps)
			receipt = soleApproval(t, e.member)
			approvalDecide(t, e.owner, receipt, "approve")
			enabled.Store(true)
			out := e.call(t, true, e.key.Secret, approvalParams("negotiate"), urlCaps)
			if negotiations.Load() == 0 {
				t.Fatal("test never observed actual upstream negotiation")
			}
			got := approvalDetail(t, e.member, receipt.ID)
			if fail {
				if got.Status != approvals.Approved || e.posts.Load() != 0 {
					t.Fatalf("pre-tool negotiation failure spent approval: %+v %v", got, out)
				}
			} else if got.Status != approvals.Used || e.posts.Load() != 1 {
				t.Fatalf("negotiated dispatch: %+v %v", got, out)
			}
		})
	}
}

func TestApprovalsHTTPMCPExpiredCredentialCannotConsumeAtUnchangedEpoch(t *testing.T) {
	// The service's test clock advances at an observed real HTTP handshake,
	// after gateway authentication, but before Consume. The approval remains
	// within its own validity; only the credential deadline has elapsed.
	for _, kind := range []string{"API key", "OAuth access token"} {
		t.Run(kind, func(t *testing.T) {
			var enabled atomic.Bool
			var observed atomic.Int64
			var e *approvalWire
			var expiredAt time.Time
			e = newApprovalWire(t, testutil.ProtocolLegacy, func(_ http.ResponseWriter, _ *http.Request, msg map[string]any) bool {
				if enabled.Load() && (msg["method"] == "initialize" || msg["method"] == "server/discover") {
					observed.Add(1)
					e.svc.SetClock(func() time.Time { return expiredAt })
				}
				return false
			})
			key := e.key.Secret
			if kind == "OAuth access token" {
				key = approvalOAuthToken(t, e)
			}
			base := time.Now().UTC()
			deadline := base.Add(30 * time.Second)
			expiredAt = deadline.Add(time.Microsecond)
			if kind == "API key" {
				sessionExec(t, e.app, `UPDATE api_keys SET expires_at=$1 WHERE id=$2`, deadline, e.key.Key.Id)
			} else {
				// A real authorization-code/PKCE-issued credential; only shorten its
				// stored deadline before binding. No token or principal mock is used.
				sessionExec(t, e.app, `UPDATE oauth_tokens SET expires_at=$1 WHERE kind='access'`, deadline)
			}
			e.svc.SetClock(func() time.Time { return base })
			e.call(t, true, key, approvalParams("credential deadline"), urlCaps)
			receipt := soleApproval(t, e.member)
			approved := approvalDecide(t, e.owner, receipt, "approve")
			if approved.ValidUntil == nil || !approved.ValidUntil.After(expiredAt) {
				t.Fatal("test approval would also have expired")
			}
			before, err := e.svc.Epoch(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			enabled.Store(true)
			out := e.call(t, true, key, approvalParams("credential deadline"), urlCaps)
			after, err := e.svc.Epoch(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if observed.Load() == 0 || before != after {
				t.Fatalf("credential-expiry schedule not exercised: handshakes=%d epoch=%d/%d", observed.Load(), before, after)
			}
			if e.posts.Load() != 0 || rpcErrorCode(out) != -32010 {
				t.Fatalf("expired credential authorized upstream: posts=%d %v", e.posts.Load(), out)
			}
			if v := approvalDetail(t, e.member, receipt.ID); v.Status != approvals.Approved {
				t.Fatalf("expired credential consumed still-valid approval: %+v", v)
			}
		})
	}
}

func approvalOAuthToken(t *testing.T, e *approvalWire) string {
	t.Helper()
	// Dynamic registration is an actual browser/MCP OAuth client registration.
	c, raw := e.app.do("POST", "/oauth/register", map[string]any{"client_name": "approval deadline client", "redirect_uris": []string{testRedirect}, "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none"}, nil)
	if c != 201 {
		t.Fatalf("OAuth registration: %d %s", c, raw)
	}
	var registration struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(raw, &registration); err != nil {
		t.Fatal(err)
	}
	p := newPKCE()
	q := authQuery(e.app, registration.ClientID, "approvals", p, nil)
	loc := scopeConsent(t, e.member, q, nil, false)
	code := codeFrom(t, e.app, "approval OAuth", loc)
	status, out, _ := tokenCall(t, e.app, "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {registration.ClientID}, "code": {code}, "code_verifier": {p.verifier}, "redirect_uri": {testRedirect}, "resource": {e.app.URL + "/mcp/approvals"}})
	if status != 200 {
		t.Fatalf("OAuth exchange: %d %v", status, out)
	}
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatal("no actual OAuth access token")
	}
	return token
}

func TestApprovalsHTTPMCPNarrowedCredentialScopeIsCheckedBeforeConsumption(t *testing.T) {
	e := newApprovalWire(t, testutil.ProtocolModern, nil)
	sa := createSA(t, e.owner, map[string]any{"name": "scope-worker"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "scope key"})
	e.call(t, true, key.Secret, approvalParams("scope"), urlCaps)
	r := soleApproval(t, e.owner)
	approvalDecide(t, e.admin, r, "approve")
	patchSA(t, e.owner, sa.Id.String(), map[string]any{"toolScope": map[string]any{}})
	out := e.call(t, true, key.Secret, approvalParams("scope"), urlCaps)
	if rpcErrorCode(out) != -32602 || e.posts.Load() != 0 {
		t.Fatalf("narrowed scope bypassed: %v", out)
	}
	if v := approvalDetail(t, e.owner, r.ID); v.Status == approvals.Used {
		t.Fatal("scope refusal spent old approval")
	}
}
