package providers

import (
	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"testing"
	"time"
)

func TestServiceConnectionCacheOwnerGenerationAndScopes(t *testing.T) {
	now := time.Now()
	id := uuid.New()
	var cache narrowCache
	personal := narrowKeyOf(dbgen.ProviderConnection{ID: id, ConnectedAt: time.Unix(0, 77)}, []string{"repo", "read:user"})
	shared := dbgen.ServiceConnection{ID: id, Generation: 77}
	key := serviceNarrowKey(shared, []string{"read:user", "repo"})
	cache.put(personal, "personal", now.Add(time.Hour), now)
	if _, ok := cache.get(key, now); ok {
		t.Fatal("service owner found personal cached credential")
	}
	cache.put(key, "shared", now.Add(time.Hour), now)
	if got, ok := cache.get(serviceNarrowKey(shared, []string{"repo", "read:user"}), now); !ok || got != "shared" {
		t.Fatal("scope set order changed cache identity")
	}
	if got, _ := cache.get(personal, now); got != "personal" {
		t.Fatal("service publication overwrote personal namespace")
	}
	shared.Generation++
	if _, ok := cache.get(serviceNarrowKey(shared, []string{"repo", "read:user"}), now); ok {
		t.Fatal("new consent generation reused old credential")
	}
	if _, ok := cache.get(serviceNarrowKey(dbgen.ServiceConnection{ID: id, Generation: 77}, []string{"repo"}), now); ok {
		t.Fatal("another scope set reused credential")
	}
}
func TestServiceConnectionCipherNamespaces(t *testing.T) {
	s := testService(t, nil)
	id := uuid.New()
	ct, err := s.serviceSeal(id, "access", "sentinel-service-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.open(id, "access", ct); err == nil {
		t.Fatal("service token opened under personal owner")
	}
	if _, err = s.serviceOpen(id, "refresh", ct); err == nil {
		t.Fatal("access token replayed as refresh")
	}
	if _, err = s.serviceOpen(uuid.New(), "access", ct); err == nil {
		t.Fatal("cipher replayed in another connection")
	}
	verifier, err := s.box.Seal([]byte("sentinel-verifier"), ServiceStateAAD("state"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.box.Open(verifier, stateAAD("state")); err == nil {
		t.Fatal("service state replayed in personal state table")
	}
}
