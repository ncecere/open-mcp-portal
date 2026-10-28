package httpapi_test

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Count actual tuple updates, not just changed timestamp values, and race the
// authentication requests so only the conditional SQL write can arbitrate.
func TestSessionActivityWriteThrottleConcurrent(t *testing.T) {
	var nanos atomic.Int64
	nanos.Store(time.Now().UTC().Truncate(time.Microsecond).UnixNano())
	app := newTestAppDeps(t, nil, testutil.Logger(), func(d *httpapi.Deps) {
		d.Auth.WithClock(func() time.Time { return time.Unix(0, nanos.Load()).UTC() })
	})
	me := app.signIn("alex")
	if _, err := testutil.OwnerPool(t, app.Pool).Exec(context.Background(), `CREATE TABLE session_touch_test (writes integer NOT NULL); INSERT INTO session_touch_test VALUES (0);
 CREATE FUNCTION count_session_touch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE session_touch_test SET writes = writes + 1; RETURN NEW; END $$;
 CREATE TRIGGER count_session_touch AFTER UPDATE ON sessions FOR EACH ROW EXECUTE FUNCTION count_session_touch()`); err != nil {
		t.Fatal(err)
	}
	testutil.Regrant(t, app.Pool)
	count := func() int {
		var n int
		if err := app.Pool.QueryRow(context.Background(), `SELECT writes FROM session_touch_test`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	concurrent := func() {
		var wg sync.WaitGroup
		statuses := make(chan int, 24)
		for range 24 {
			wg.Go(func() {
				res, err := me.client.Get(app.URL + "/v1/me")
				if err != nil {
					statuses <- 0
					return
				}
				res.Body.Close()
				statuses <- res.StatusCode
			})
		}
		wg.Wait()
		close(statuses)
		for code := range statuses {
			if code != http.StatusOK {
				t.Fatalf("concurrent auth = %d", code)
			}
		}
	}
	concurrent()
	if n := count(); n != 0 {
		t.Fatalf("fresh session writes = %d", n)
	}
	nanos.Add(int64(time.Minute))
	concurrent()
	if n := count(); n != 1 {
		t.Fatalf("first minute writes = %d", n)
	}
	nanos.Add(int64(59 * time.Second))
	concurrent()
	if n := count(); n != 1 {
		t.Fatalf("sub-minute writes = %d", n)
	}
	nanos.Add(int64(time.Second))
	concurrent()
	if n := count(); n != 2 {
		t.Fatalf("second minute writes = %d", n)
	}
}
