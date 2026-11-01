package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// This executes authentication and the actual consent lock queries. It proves
// the physical footprint, not a whole blocked-provider/SCIM lifecycle service.
func TestSessionGenerationFenceKeepsOldCookieEndedWithoutDeletingLockedSession(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	now := time.Now().UTC()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,display_name,oidc_issuer,oidc_subject)
VALUES ($1,'session-generation@example.test','Session generation','test','session-generation')`, userID); err != nil {
		t.Fatal("subject fixture:", err)
	}
	q := dbgen.New(pool)
	user, err := q.GetUser(ctx, userID)
	if err != nil || user.SessionGeneration != 1 || user.RequestEpoch != 1 {
		t.Fatal("initial user generations:", err)
	}
	svc := NewService(config.Config{AppURL: "http://localhost", SessionTTL: time.Hour, RequestsPerMinute: 1000}, pool, nil).WithClock(func() time.Time { return now })
	create := func(snapshot dbgen.User) (string, error) {
		t.Helper()
		var secret string
		err := store.InTx(ctx, pool, func(q *dbgen.Queries, _ pgx.Tx) error {
			var err error
			secret, err = svc.createSession(ctx, httptest.NewRequest(http.MethodGet, "http://localhost/auth/callback", nil), q, snapshot)
			return err
		})
		return secret, err
	}
	cookieStatus := func(secret string) int {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "http://localhost/private", nil).WithContext(ctx)
		r.AddCookie(&http.Cookie{Name: svc.sessionCookieName(), Value: secret})
		w := httptest.NewRecorder()
		svc.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := FromContext(r.Context())
			if !ok || identity.User.ID != userID {
				t.Fatal("actual authentication did not attach original identity")
			}
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(w, r)
		return w.Code
	}
	oldSecret, err := create(user)
	if err != nil || oldSecret == "" || cookieStatus(oldSecret) != http.StatusNoContent {
		t.Fatal("original session positive failed:", err)
	}
	var sessionID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM sessions WHERE token_digest=$1`, Digest(oldSecret)).Scan(&sessionID); err != nil {
		t.Fatal(err)
	}
	// Retain the real shared-consent USER KEY SHARE and SESSION FOR UPDATE
	// footprint. A non-key generation fence must commit before their release.
	locked, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Rollback(context.Background())
	lq := dbgen.New(locked)
	if status, err := lq.LockServiceConsentUser(ctx, userID); err != nil || status != StatusActive {
		t.Fatal("real consent user lock:", err)
	}
	if _, err := lq.LockServiceConsentSession(ctx, dbgen.LockServiceConsentSessionParams{ID: sessionID, UserID: userID, AsOf: now, IdleSince: time.Time{}}); err != nil {
		t.Fatal("real consent session lock:", err)
	}
	fenceCtx, fenceCancel := context.WithTimeout(ctx, 2*time.Second)
	var generation, epoch int64
	err = pool.QueryRow(fenceCtx, `UPDATE users SET session_generation=session_generation+1 WHERE id=$1 RETURNING session_generation,request_epoch`, userID).Scan(&generation, &epoch)
	fenceCancel()
	if err != nil || generation != 2 || epoch != 2 {
		t.Fatal("non-key cookie fence did not commit while consent locks remained held:", err)
	}
	t.Log("SESSION_GENERATION_NONKEY_FENCE_COMMITTED_WITH_CONSENT_LOCKS")
	if cookieStatus(oldSecret) != http.StatusUnauthorized {
		t.Fatal("generation-fenced active cookie authenticated while row was retained")
	}
	if _, err := q.LockPersonalConsentSession(ctx, dbgen.LockPersonalConsentSessionParams{ID: sessionID, UserID: userID, AsOf: now, IdleSince: time.Time{}}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("original personal consent accepted ended generation:", err)
	}
	if _, err := q.LockServiceConsentSession(ctx, dbgen.LockServiceConsentSessionParams{ID: sessionID, UserID: userID, AsOf: now, IdleSince: time.Time{}}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("original shared consent accepted ended generation:", err)
	}
	if err := locked.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET status='suspended' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if cookieStatus(oldSecret) != http.StatusForbidden {
		t.Fatal("existing explicit suspended-account refusal changed")
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET status='active' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if cookieStatus(oldSecret) != http.StatusUnauthorized {
		t.Fatal("reactivation revived a physically retained ended cookie")
	}
	var retained int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id=$1`, sessionID).Scan(&retained); err != nil || retained != 1 {
		t.Fatal("test lost the retained old row; cookie denial must not rely on deletion")
	}
	current, err := q.GetUser(ctx, userID)
	if err != nil || current.SessionGeneration != 3 || current.RequestEpoch != 4 {
		t.Fatal("standing cycle did not preserve distinct counter semantics:", err)
	}
	for _, gen := range []int64{0, 1, current.SessionGeneration + 1} {
		bad := current
		bad.SessionGeneration = gen
		secret, err := create(bad)
		if err == nil || secret != "" {
			t.Fatal("new-code missing/stale/future session admission minted or refreshed a secret")
		}
	}
	fresh, err := create(current)
	if err != nil || fresh == "" || cookieStatus(fresh) != http.StatusNoContent {
		t.Fatal("fresh admitted session after fence/reactivation failed:", err)
	}
	// Reproduce the previous binary's omitted-column SQL, not a new-code
	// zero-generation admission. The trigger bridge must stamp generation3.
	legacy := "owned-legacy-session-generation-fixture"
	if err := pool.QueryRow(ctx, `INSERT INTO sessions(user_id,token_digest,csrf_token,expires_at)
VALUES ($1,$2,'fixture-csrf',$3) RETURNING session_generation`, userID, Digest(legacy), now.Add(time.Hour)).Scan(&generation); err != nil || generation != current.SessionGeneration || cookieStatus(legacy) != http.StatusNoContent {
		t.Fatal("legacy omitted-column session bridge failed:", err)
	}
	listed, err := svc.ListSessions(ctx, (Identity{User: current}).Actor("generation-session-list", ""), userID, false)
	if err != nil || len(listed) != 2 {
		t.Fatal("active-session list included ended generation or omitted a fresh session:", err)
	}
}
