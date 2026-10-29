package mcptasks_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/mcptasks"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

type taskStoreFixture struct {
	pool                                  *pgxpool.Pool
	store                                 *mcptasks.Store
	box                                   *secrets.Box
	binding                               mcptasks.Binding
	payload                               mcptasks.Payload
	secondKey, grant, account, accountKey uuid.UUID
}

// Actual-role SQL/crypto integration only. These snapshots intentionally do
// not establish live offer/scope/no-rule authority or any working MCP relay.
func newTaskStoreFixture(t *testing.T, cap int) taskStoreFixture {
	t.Helper()
	pool, _ := testutil.NewDB(t)
	box, err := secrets.New(bytes.Repeat([]byte{0x27}, 32))
	if err != nil {
		t.Fatal(err)
	}
	payload := mcptasks.Payload{Arguments: json.RawMessage(`{"private_argument":"owned-sentinel"}`), RedactionOnly: []string{"initial-upstream-secret-28193"}}
	args, err := mcptasks.DigestArguments(payload.Arguments)
	if err != nil {
		t.Fatal(err)
	}
	b := mcptasks.Binding{PrincipalKind: mcptasks.PrincipalUser, PrincipalID: uuid.New(), CredentialKind: mcptasks.CredentialAPIKey, CredentialID: uuid.New(), GatewayID: uuid.New(), ServerID: uuid.New(), CapabilityID: uuid.New(), ExposedName: "owned__task", ServerURL: "https://tasks.example/mcp", ServerRevision: 1, ToolClass: "read", DefinitionFingerprint: strings.Repeat("a", 64), CurationDigest: strings.Repeat("b", 64), ArgumentsDigest: args, DependencyDigest: strings.Repeat("c", 64)}
	team, key2, grant, account, accountKey := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO users(id,oidc_issuer,oidc_subject,email) VALUES($1,'task-fixture','user','task@example.invalid')`, b.PrincipalID)
	exec(`INSERT INTO teams(id,slug,name) VALUES($1,'task','Task')`, team)
	exec(`INSERT INTO mcp_servers(id,team_id,slug,name,url) VALUES($1,$2,'task','Task',$3)`, b.ServerID, team, b.ServerURL)
	exec(`INSERT INTO mcp_capabilities(id,server_id,kind,name,definition,fingerprint) VALUES($1,$2,'tool','task','{}',$3)`, b.CapabilityID, b.ServerID, b.DefinitionFingerprint)
	exec(`INSERT INTO gateways(id,slug,name,owner_kind) VALUES($1,'task','Task','platform')`, b.GatewayID)
	exec(`INSERT INTO api_keys(id,user_id,name,prefix,digest,expires_at) VALUES($1,$2,'first','omp_12345678',repeat('a',64),now()+interval '1 day'),($3,$2,'second','omp_87654321',repeat('b',64),now()+interval '1 day')`, b.CredentialID, b.PrincipalID, key2)
	exec(`INSERT INTO oauth_grants(id,user_id,gateway_id,client_id,client_kind,client_name,resource) VALUES($1,$2,$3,'task-client','metadata','Task','https://portal.example/mcp/task')`, grant, b.PrincipalID, b.GatewayID)
	exec(`INSERT INTO service_accounts(id,team_id,name) VALUES($1,$2,'task')`, account, team)
	exec(`INSERT INTO service_account_keys(id,service_account_id,name,prefix,digest,expires_at) VALUES($1,$2,'task','omp_sa_12345678',repeat('c',64),now()+interval '1 day')`, accountKey, account)
	store, err := mcptasks.NewStore(pool, box, time.Hour, cap)
	if err != nil {
		t.Fatal(err)
	}
	return taskStoreFixture{pool, store, box, b, payload, key2, grant, account, accountKey}
}

func taskRoot(b mcptasks.Binding) mcptasks.Root {
	return mcptasks.Root{PrincipalKind: b.PrincipalKind, PrincipalID: b.PrincipalID, CredentialKind: b.CredentialKind, CredentialID: b.CredentialID, GatewayID: b.GatewayID}
}

func observation(t *testing.T, pool *pgxpool.Pool, id string) mcptasks.Observation {
	t.Helper()
	var now time.Time
	if err := pool.QueryRow(context.Background(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return mcptasks.Observation{ID: id, Status: "working", CreatedAt: now, UpdatedAt: now}
}

func activate(t *testing.T, f taskStoreFixture, b mcptasks.Binding) (string, mcptasks.Snapshot) {
	t.Helper()
	r, err := f.store.Reserve(context.Background(), b, f.payload)
	if err != nil {
		t.Fatal(err)
	}
	h, s, err := f.store.Activate(context.Background(), r, observation(t, f.pool, "private-upstream-task-"+uuid.NewString()))
	if err != nil {
		t.Fatal(err)
	}
	return h, s
}

func TestTaskStoreDurableSealedActivationAndLookup(t *testing.T) {
	f := newTaskStoreFixture(t, 100)
	ctx := context.Background()
	r, err := f.store.Reserve(ctx, f.binding, f.payload)
	if err != nil || r.Deadline().IsZero() {
		t.Fatalf("reserve: %v", err)
	}
	var rawBinding, cipher []byte
	var id uuid.UUID
	var digest, status string
	if err := f.pool.QueryRow(ctx, `SELECT id,binding,state_cipher,handle_digest,status FROM mcp_tasks`).Scan(&id, &rawBinding, &cipher, &digest, &status); err != nil {
		t.Fatal(err)
	}
	if status != "reserved" || bytes.Contains(cipher, f.payload.Arguments) || bytes.Contains(cipher, []byte(f.payload.RedactionOnly[0])) || bytes.Contains(rawBinding, []byte(f.payload.RedactionOnly[0])) {
		t.Fatal("reservation state not private/sealed")
	}
	p, err := mcptasks.OpenState(f.box, id, digest, f.binding, cipher)
	if err != nil || p.UpstreamID != "" {
		t.Fatalf("prepared association: %v", err)
	}
	if raw, err := json.Marshal(r); err != nil || string(raw) != "{}" {
		t.Fatal("reservation serialized private state")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(format, r); got != "private task reservation" {
			t.Fatal("reservation formatter exposed state")
		}
	}
	obs := observation(t, f.pool, "actual-upstream-private-sentinel-91731")
	h, s, err := f.store.Activate(ctx, r, obs)
	if err != nil {
		t.Fatal(err)
	}
	if h == obs.ID || !strings.HasPrefix(h, "omptask_") || s.Binding() != f.binding || s.Payload().UpstreamID != obs.ID || s.Status() != "working" || s.PollMillis() != 5000 || s.ExpiresAt().Sub(s.CreatedAt()) != time.Hour {
		t.Fatal("activation association/lifetime incorrect")
	}
	if err := f.store.AbandonReservation(ctx, r); !errors.Is(err, mcptasks.ErrNotFound) {
		t.Fatal("abandon deleted active mapping", err)
	}
	if _, _, err := f.store.Activate(ctx, r, obs); !errors.Is(err, mcptasks.ErrNotFound) {
		t.Fatal("reservation activated twice", err)
	}
	otherPool, err := pgxpool.NewWithConfig(ctx, f.pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer otherPool.Close()
	restarted, err := mcptasks.NewStore(otherPool, f.box, time.Hour, 100)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.Lookup(ctx, h, taskRoot(f.binding))
	if err != nil || got.Payload().UpstreamID != obs.ID {
		t.Fatal("independent pool could not reopen durable mapping", err)
	}
	copy := got.Payload()
	copy.Arguments[0] = 'x'
	copy.RedactionOnly[0] = "changed"
	if !bytes.Equal(got.Payload().Arguments, f.payload.Arguments) || got.Payload().RedactionOnly[0] != f.payload.RedactionOnly[0] {
		t.Fatal("snapshot payload accessor aliases private state")
	}
	if raw, err := json.Marshal(got); err != nil || string(raw) != "{}" {
		t.Fatal("snapshot serialized private state")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if fmt.Sprintf(format, got) != "private task snapshot" {
			t.Fatal("snapshot formatter exposed state")
		}
	}
	if err := f.pool.QueryRow(ctx, `SELECT state_cipher,handle_digest FROM mcp_tasks WHERE id=$1`, id).Scan(&cipher, &digest); err != nil {
		t.Fatal(err)
	}
	want, _ := mcptasks.DigestHandle(h)
	if digest != want || bytes.Contains(cipher, []byte(obs.ID)) || bytes.Contains(cipher, []byte(h)) {
		t.Fatal("active mapping contains plaintext identity")
	}
	rotating, _ := secrets.New(bytes.Repeat([]byte{0x28}, 32), bytes.Repeat([]byte{0x27}, 32))
	rotatedStore, _ := mcptasks.NewStore(f.pool, rotating, time.Hour, 100)
	if _, err := rotatedStore.Lookup(ctx, h, taskRoot(f.binding)); err != nil {
		t.Fatal("previous-key reopen failed", err)
	}
	wrong, _ := secrets.New(bytes.Repeat([]byte{0x29}, 32))
	wrongStore, _ := mcptasks.NewStore(f.pool, wrong, time.Hour, 100)
	if _, err := wrongStore.Lookup(ctx, h, taskRoot(f.binding)); !errors.Is(err, mcptasks.ErrNotFound) {
		t.Fatal("wrong-key state did not fail privately", err)
	}
	if f.pool.Stat().AcquiredConns() != 0 || otherPool.Stat().AcquiredConns() != 0 {
		t.Fatal("a storage API returned with a SQL connection still acquired")
	}
}

func TestTaskStoreRootIsolationAndAssociation(t *testing.T) {
	f := newTaskStoreFixture(t, 100)
	ctx := context.Background()
	h, _ := activate(t, f, f.binding)
	root := taskRoot(f.binding)
	for _, mutate := range []func(*mcptasks.Root){
		func(r *mcptasks.Root) { r.PrincipalID = uuid.New() },
		func(r *mcptasks.Root) { r.CredentialID = f.secondKey },
		func(r *mcptasks.Root) { r.CredentialKind = mcptasks.CredentialOAuthGrant; r.CredentialID = f.grant },
		func(r *mcptasks.Root) { r.GatewayID = uuid.New() },
		func(r *mcptasks.Root) {
			r.PrincipalKind = mcptasks.PrincipalServiceAccount
			r.PrincipalID = f.account
			r.CredentialKind = mcptasks.CredentialServiceKey
			r.CredentialID = f.accountKey
		},
	} {
		foreign := root
		mutate(&foreign)
		if _, err := f.store.Lookup(ctx, h, foreign); !errors.Is(err, mcptasks.ErrNotFound) {
			t.Fatal("foreign association did not fail privately", err)
		}
	}
	bad := f.binding
	bad.PrincipalID = uuid.New()
	if _, err := f.store.Reserve(ctx, bad, f.payload); !errors.Is(err, mcptasks.ErrNotFound) {
		t.Fatal("mismatched credential owner accepted", err)
	}
	for _, kind := range []string{mcptasks.CredentialOAuthGrant, mcptasks.CredentialServiceKey} {
		b := f.binding
		b.CredentialKind = kind
		b.CredentialID = f.grant
		if kind == mcptasks.CredentialServiceKey {
			b.PrincipalKind = mcptasks.PrincipalServiceAccount
			b.PrincipalID = f.account
			b.CredentialID = f.accountKey
		}
		h, _ := activate(t, f, b)
		if _, err := f.store.Lookup(ctx, h, taskRoot(b)); err != nil {
			t.Fatal("valid root kind refused", err)
		}
	}
	// Forced expiry is not a natural-expiry/load soak. Effective lookup denies
	// without invoking retention, independently of valid encryption/root IDs.
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_tasks SET expires_at=created_at+interval '1 microsecond' WHERE handle_digest=$1`, mustDigest(t, h)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Lookup(ctx, h, root); !errors.Is(err, mcptasks.ErrNotFound) {
		t.Fatal("expired mapping returned", err)
	}
}

func mustDigest(t *testing.T, h string) string {
	t.Helper()
	d, err := mcptasks.DigestHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestTaskStoreTamperedMappingAndExpiredReservation(t *testing.T) {
	f := newTaskStoreFixture(t, 100)
	ctx := context.Background()
	h1, _ := activate(t, f, f.binding)
	h2, _ := activate(t, f, f.binding)
	var cipher []byte
	if err := f.pool.QueryRow(ctx, `SELECT state_cipher FROM mcp_tasks WHERE handle_digest=$1`, mustDigest(t, h1)).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_tasks SET state_cipher=$1 WHERE handle_digest=$2`, cipher, mustDigest(t, h2)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Lookup(ctx, h2, taskRoot(f.binding)); !errors.Is(err, mcptasks.ErrNotFound) {
		t.Fatal("swapped row cipher accepted", err)
	}
	changed := f.binding
	changed.ServerRevision++
	raw, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := mcptasks.DigestBinding(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_tasks SET binding=$1,binding_digest=$2 WHERE handle_digest=$3`, raw, digest, mustDigest(t, h1)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Lookup(ctx, h1, taskRoot(f.binding)); !errors.Is(err, mcptasks.ErrNotFound) {
		t.Fatal("metadata and recomputed digest rebound old cipher", err)
	}
	r, err := f.store.Reserve(ctx, f.binding, f.payload)
	if err != nil {
		t.Fatal(err)
	}
	obs := observation(t, f.pool, "private-expired-reservation")
	for _, bad := range []mcptasks.Observation{
		{ID: obs.ID, Status: "reserved", CreatedAt: obs.CreatedAt, UpdatedAt: obs.UpdatedAt},
		{ID: obs.ID, Status: "working", CreatedAt: obs.CreatedAt, UpdatedAt: obs.CreatedAt.Add(-time.Second)},
		{ID: obs.ID, Status: "working", CreatedAt: obs.CreatedAt.Add(10 * time.Minute), UpdatedAt: obs.UpdatedAt.Add(10 * time.Minute)},
	} {
		if h, _, err := f.store.Activate(ctx, r, bad); err == nil || h != "" {
			t.Fatal("invalid observation exposed a handle")
		}
	}
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_tasks SET reservation_deadline=created_at+interval '1 microsecond' WHERE status='reserved'`); err != nil {
		t.Fatal(err)
	}
	if h, _, err := f.store.Activate(ctx, r, obs); !errors.Is(err, mcptasks.ErrNotFound) || h != "" {
		t.Fatal("expired reservation activated", err)
	}
	bad := f.payload
	bad.Arguments = json.RawMessage(`{}`)
	if _, err := f.store.Reserve(ctx, f.binding, bad); !errors.Is(err, mcptasks.ErrUnavailable) {
		t.Fatal("argument digest mismatch reserved capacity", err)
	}
	b := f.binding
	b.CredentialKind = mcptasks.CredentialOAuthGrant
	b.CredentialID = f.grant
	b.GatewayID = uuid.New()
	if _, err := f.store.Reserve(ctx, b, f.payload); !errors.Is(err, mcptasks.ErrNotFound) {
		t.Fatal("OAuth root silently moved gateways", err)
	}
}

func TestTaskStoreSharedCapacityAcrossPoolsAndKeys(t *testing.T) {
	f := newTaskStoreFixture(t, 3)
	ctx := context.Background()
	pool2, err := pgxpool.NewWithConfig(ctx, f.pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer pool2.Close()
	store2, err := mcptasks.NewStore(pool2, f.box, time.Hour, 3)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	accepted := make(chan mcptasks.Reservation, 24)
	errs := make(chan error, 24)
	for i := range 24 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, b := f.store, f.binding
			if i%2 == 0 {
				s = store2
				b.CredentialID = f.secondKey
			}
			r, err := s.Reserve(ctx, b, f.payload)
			if err == nil {
				accepted <- r
			} else if !errors.Is(err, mcptasks.ErrCapacity) {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(accepted)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if len(accepted) != 3 {
		t.Fatalf("shared principal admitted %d, want3", len(accepted))
	}
	for r := range accepted {
		if err := f.store.AbandonReservation(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store2.Reserve(ctx, f.binding, f.payload); err != nil {
		t.Fatal("abandoned capacity not released", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.store.Reserve(cancelled, f.binding, f.payload); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled reservation", err)
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM mcp_tasks`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("failed/cancelled reservations persisted: %d %v", count, err)
	}
}
