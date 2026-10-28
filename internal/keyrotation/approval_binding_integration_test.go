package keyrotation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/keyrotation"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// This fixture deliberately installs no authority-bearing ciphertext. Rewrapping
// a server/provider credential may advance the epoch for independent reasons and
// would mask the bug: retiring encryption A must preserve live HMACs at SAME epoch.
func bindingServiceFixture(t *testing.T, db *pgxpool.Pool) (*approvals.Service, authz.Actor, authz.Actor, approvals.BeginInput) {
	t.Helper()
	ctx := context.Background()
	requester := authz.Actor{UserID: uuid.New(), PlatformRole: authz.PlatformNone}
	reviewer := authz.Actor{UserID: uuid.New(), PlatformRole: authz.PlatformNone}
	team, server, cap, gateway := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	for i, a := range []authz.Actor{requester, reviewer} {
		exec(`INSERT INTO users(id,oidc_issuer,oidc_subject,email) VALUES($1,'rotation',$2,$3)`, a.UserID, fmt.Sprint(i), fmt.Sprintf("r%d@test.invalid", i))
	}
	exec(`INSERT INTO teams(id,slug,name) VALUES($1,'rotation','Rotation')`, team)
	exec(`INSERT INTO team_members(team_id,user_id,role) VALUES($1,$2,'owner')`, team, reviewer.UserID)
	exec(`INSERT INTO mcp_servers(id,team_id,slug,name,url,publish_state,published_at,enabled) VALUES($1,$2,'server','Server','https://server.test/mcp','published',now(),true)`, server, team)
	exec(`INSERT INTO mcp_capabilities(id,server_id,kind,name,definition,fingerprint,approved_fingerprint,tool_class) VALUES($1,$2,'tool','delete','{}',repeat('a',64),repeat('a',64),'destructive')`, cap, server)
	exec(`INSERT INTO gateways(id,slug,name,owner_kind,enabled) VALUES($1,'rotation','Rotation','platform',true)`, gateway)
	exec(`INSERT INTO gateway_capabilities(gateway_id,capability_id) VALUES($1,$2)`, gateway, cap)
	exec(`INSERT INTO gateway_grants(gateway_id,subject_kind,user_id) VALUES($1,'user',$2)`, gateway, requester.UserID)
	s := newBindingService(t, db, box(t, oldKey))
	_, err := s.CreateRule(ctx, reviewer, team.String(), approvals.RuleInput{Name: "Destructive", TargetKind: "server", TargetID: server, Classes: []string{"destructive"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := s.Epoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	class := "destructive"
	in := approvals.BeginInput{Binding: approvals.Binding{Epoch: epoch, RequesterKind: "user", RequesterID: requester.UserID, GatewayID: gateway, ServerID: server, CapabilityID: cap, ExposedName: "server__delete", ToolClass: &class, CapabilityFingerprint: strings.Repeat("a", 64), ServerOrigin: "https://server.test"}, CredentialExpiresAt: time.Now().Add(time.Hour)}
	return s, requester, reviewer, in
}

func newBindingService(t *testing.T, db *pgxpool.Pool, b *secrets.Box) *approvals.Service {
	t.Helper()
	s, err := approvals.New(db, b, nil, "https://portal.test")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestServiceBindingsSurviveEncryptionKeyRetirement(t *testing.T) {
	ctx := context.Background()
	db, _ := testutil.NewDB(t)
	s, requester, reviewer, in := bindingServiceFixture(t, db)
	inputs := make([]approvals.BeginInput, 3)
	plans := make([]approvals.Plan, 3)
	for i := range plans {
		inputs[i] = in
		inputs[i].Arguments = json.RawMessage(fmt.Sprintf(`{"id":%d}`, 9007199254740991+int64(i)))
		var err error
		plans[i], err = s.Begin(ctx, inputs[i])
		if err != nil || !plans[i].Required || plans[i].Receipt.Status != approvals.Pending {
			t.Fatalf("create actual request %d: %v", i, err)
		}
	}
	for i, decision := range []string{"approve", "deny"} {
		p := &plans[i+1]
		r, err := s.Decide(ctx, reviewer, p.Receipt.ID, approvals.Decision{Decision: decision, ExpectedReviewRevision: p.Receipt.ReviewRevision, ExpectedArgsDigest: p.Receipt.ArgsDigest})
		if err != nil {
			t.Fatal(err)
		}
		p.Receipt = r
	}
	var beforeRoot []byte
	if err := db.QueryRow(ctx, `SELECT binding_key_cipher FROM approval_binding_keys WHERE id=1`).Scan(&beforeRoot); err != nil {
		t.Fatal(err)
	}
	root, err := box(t, oldKey).Open(beforeRoot, approvals.BindingKeyAAD())
	if err != nil || len(root) != 32 {
		t.Fatal("missing root", err)
	}
	// A -> B+A must not start signing with a newly derived B key either.
	dual := newBindingService(t, db, box(t, newKey, oldKey))
	checkDedup := func(s *approvals.Service) []approvals.Plan {
		t.Helper()
		out := make([]approvals.Plan, len(plans))
		for i, want := range plans {
			got, err := s.Begin(ctx, inputs[i])
			if err != nil || got.Receipt.ID != want.Receipt.ID || got.Receipt.Status != want.Receipt.Status || got.Receipt.ArgsDigest != want.Receipt.ArgsDigest || got.BindingDigest != want.BindingDigest || !got.Receipt.ExpiresAt.Equal(want.Receipt.ExpiresAt) {
				t.Fatalf("binding %d changed across key rotation: got=%s/%s want=%s/%s err=%v", i, got.Receipt.ID, got.Receipt.Status, want.Receipt.ID, want.Receipt.Status, err)
			}
			out[i] = got
		}
		return out
	}
	checkDedup(dual)
	rotating := box(t, newKey, oldKey)
	sum, err := keyrotation.Run(ctx, db, rotating, keyrotation.Peppers{}, keyrotation.Options{DryRun: true})
	if err != nil || sum.Reencrypted() != 0 {
		t.Fatal("dry run", err)
	}
	previous := 0
	for _, c := range sum.Columns {
		previous += c.Previous
	}
	if previous != 4 {
		t.Fatalf("expected only root + three previews on previous key, got %d", previous)
	}
	sum, err = keyrotation.Run(ctx, db, rotating, keyrotation.Peppers{}, keyrotation.Options{BatchSize: 1})
	if err != nil || sum.Reencrypted() != 4 {
		t.Fatalf("rotation: %d %v", sum.Reencrypted(), err)
	}
	onlyB := box(t, newKey)
	retired := newBindingService(t, db, onlyB)
	if epoch, err := retired.Epoch(ctx); err != nil || epoch != in.Binding.Epoch {
		t.Fatalf("rotation advanced epoch, masking HMAC regression: %d %v", epoch, err)
	}
	current := checkDedup(retired)
	checkDedup(s) // Already-running A service retains the same cached plaintext.
	var afterRoot []byte
	if err := db.QueryRow(ctx, `SELECT binding_key_cipher FROM approval_binding_keys WHERE id=1`).Scan(&afterRoot); err != nil {
		t.Fatal(err)
	}
	afterPlain, err := onlyB.Open(afterRoot, approvals.BindingKeyAAD())
	if err != nil || !bytes.Equal(root, afterPlain) || bytes.Equal(beforeRoot, afterRoot) {
		t.Fatal("rotation replaced rather than rewrapped root", err)
	}
	for i, p := range current {
		var cipher []byte
		if err := db.QueryRow(ctx, `SELECT preview_cipher FROM approval_requests WHERE id=$1`, p.Receipt.ID).Scan(&cipher); err != nil {
			t.Fatal(err)
		}
		if plain, err := onlyB.Open(cipher, approvals.PreviewAAD(p.Receipt.ID)); err != nil || !bytes.Equal(plain, inputs[i].Arguments) {
			t.Fatal("retained preview did not survive retirement", err)
		}
		detail, err := retired.GetRequest(ctx, reviewer, p.Receipt.ID)
		if err != nil || detail.Stale || detail.CanDecide != (i == 0) || (detail.Preview != nil) != (i != 2) {
			t.Fatalf("review flags %d: %+v %v", i, detail, err)
		}
	}
	// Even the plan held before rotation must remain usable, not just a newly
	// fetched plan whose digests might accidentally have changed.
	if err := retired.Consume(ctx, plans[1]); err != nil {
		t.Fatal("approved authorization unreachable after retirement", err)
	}
	if err := retired.Consume(ctx, current[1]); !errors.Is(err, approvals.ErrSpent) {
		t.Fatalf("approved authorization spent more than once: %v", err)
	}
	denied, err := retired.GetRequest(ctx, requester, current[2].Receipt.ID)
	if err != nil || !denied.CanRenew || denied.Preview != nil {
		t.Fatalf("denied receipt cannot explicitly renew: %+v %v", denied, err)
	}
	renewed, err := retired.Renew(ctx, requester, denied.ID, denied.ReviewRevision)
	if err != nil || renewed.Status != approvals.Pending || renewed.ID == denied.ID {
		t.Fatal("explicit renewal failed", err)
	}
	retry, err := retired.Begin(ctx, inputs[2])
	if err != nil || retry.Receipt.ID != renewed.ID || retry.Receipt.Status != approvals.Pending {
		t.Fatal("renewed pending binding unreachable after retirement", err)
	}
	p := current[0].Receipt
	if _, err := retired.Decide(ctx, reviewer, p.ID, approvals.Decision{Decision: "approve", ExpectedReviewRevision: p.ReviewRevision, ExpectedArgsDigest: p.ArgsDigest}); err != nil {
		t.Fatal("old pending receipt cannot be decided after retirement", err)
	}
}
