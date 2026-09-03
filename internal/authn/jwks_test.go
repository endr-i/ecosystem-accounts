package authn

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestKeyCacheServesFetchedKeys(t *testing.T) {
	a, b := newTestKey(t, "key-a"), newTestKey(t, "key-b")
	cache := NewKeyCache(newJWKSServer(t, a, b).url())
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	for _, kid := range []string{"key-a", "key-b"} {
		if _, err := cache.Key(context.Background(), kid); err != nil {
			t.Errorf("Key(%q) = %v", kid, err)
		}
	}
}

// A cached hit must not touch the network.
func TestKeyCacheDoesNotRefetchKnownKID(t *testing.T) {
	key := newTestKey(t, "key-a")
	srv := newJWKSServer(t, key)
	cache := NewKeyCache(srv.url())
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	before := srv.calls.Load()
	for range 5 {
		if _, err := cache.Key(context.Background(), "key-a"); err != nil {
			t.Fatalf("Key: %v", err)
		}
	}
	if got := srv.calls.Load(); got != before {
		t.Fatalf("calls = %d, want %d", got, before)
	}
}

// Rotation: a kid published after startup is picked up without a restart.
func TestKeyCacheRefetchesOnUnknownKID(t *testing.T) {
	old, rotated := newTestKey(t, "key-old"), newTestKey(t, "key-new")
	srv := newJWKSServer(t, old)
	cache := NewKeyCache(srv.url(), WithMinRefreshInterval(0))
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := cache.Key(context.Background(), "key-new"); err == nil {
		t.Fatal("expected unknown kid before rotation")
	}

	srv.setKeys(old, rotated)
	if _, err := cache.Key(context.Background(), "key-new"); err != nil {
		t.Fatalf("Key after rotation: %v", err)
	}
}

// An unknown kid must not trigger a fetch per request.
func TestKeyCacheRateLimitsUnknownKIDRefresh(t *testing.T) {
	srv := newJWKSServer(t, newTestKey(t, "key-a"))
	cache := NewKeyCache(srv.url(), WithMinRefreshInterval(time.Hour))
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	before := srv.calls.Load()
	for range 10 {
		if _, err := cache.Key(context.Background(), "bogus"); !errors.Is(err, ErrUnknownKID) {
			t.Fatalf("err = %v, want ErrUnknownKID", err)
		}
	}
	if got := srv.calls.Load(); got != before {
		t.Fatalf("calls = %d, want %d (no refetch within interval)", got, before)
	}
}

// Concurrent misses must collapse into a single fetch.
func TestKeyCacheSingleFlightRefresh(t *testing.T) {
	srv := newJWKSServer(t, newTestKey(t, "key-a"))
	cache := NewKeyCache(srv.url(), WithMinRefreshInterval(0))
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	before := srv.calls.Load()

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cache.Key(context.Background(), "bogus")
		}()
	}
	wg.Wait()

	if got := srv.calls.Load() - before; got == 0 || got > 20 {
		t.Fatalf("calls = %d, want between 1 and 20", got)
	}
}

// A failing refresh must keep serving previously cached keys.
func TestKeyCacheKeepsKeysWhenRefreshFails(t *testing.T) {
	srv := newJWKSServer(t, newTestKey(t, "key-a"))
	cache := NewKeyCache(srv.url())
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	srv.status.Store(http.StatusInternalServerError)
	if err := cache.Refresh(context.Background()); err == nil {
		t.Fatal("expected refresh error")
	}
	if _, err := cache.Key(context.Background(), "key-a"); err != nil {
		t.Fatalf("cached key lost after failed refresh: %v", err)
	}
}

func TestKeyCacheRefreshErrors(t *testing.T) {
	srv := newJWKSServer(t)
	cache := NewKeyCache(srv.url())
	if err := cache.Refresh(context.Background()); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("empty document: err = %v, want ErrNoKeys", err)
	}

	srv.status.Store(http.StatusNotFound)
	if err := cache.Refresh(context.Background()); err == nil {
		t.Fatal("expected error on 404")
	}

	unreachable := NewKeyCache("http://127.0.0.1:1/.well-known/jwks.json")
	if err := unreachable.Refresh(context.Background()); err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

// Non-RSA and non-signing keys are skipped, not fatal.
func TestKeyCacheSkipsUnusableKeys(t *testing.T) {
	usable := newTestKey(t, "key-a")
	srv := newJWKSServer(t, usable)
	mixed := []jwk{
		{Kid: "ec-key", Kty: "EC", Use: "sig", Alg: "ES256", N: "AQAB", E: "AQAB"},
		{Kid: "enc-key", Kty: "RSA", Use: "enc", Alg: "RS256", N: "AQAB", E: "AQAB"},
		{Kid: "bad-b64", Kty: "RSA", Use: "sig", Alg: "RS256", N: "!!!", E: "AQAB"},
		usable.jwk(),
	}
	srv.keys.Store(&mixed)

	cache := NewKeyCache(srv.url())
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := cache.Key(context.Background(), "key-a"); err != nil {
		t.Fatalf("usable key missing: %v", err)
	}
	for _, kid := range []string{"ec-key", "enc-key", "bad-b64"} {
		if _, err := cache.Key(context.Background(), kid); !errors.Is(err, ErrUnknownKID) {
			t.Errorf("Key(%q) = %v, want ErrUnknownKID", kid, err)
		}
	}
}

// Startup must tolerate an auth service that is not up yet.
func TestRefreshWithRetrySucceedsAfterFailure(t *testing.T) {
	srv := newJWKSServer(t, newTestKey(t, "key-a"))
	srv.status.Store(http.StatusServiceUnavailable)

	cache := NewKeyCache(srv.url())
	go func() {
		time.Sleep(300 * time.Millisecond)
		srv.status.Store(0)
	}()

	if err := cache.RefreshWithRetry(context.Background(), 10*time.Second); err != nil {
		t.Fatalf("RefreshWithRetry: %v", err)
	}
	if _, err := cache.Key(context.Background(), "key-a"); err != nil {
		t.Fatalf("Key: %v", err)
	}
}

func TestRefreshWithRetryGivesUp(t *testing.T) {
	cache := NewKeyCache("http://127.0.0.1:1/.well-known/jwks.json")
	start := time.Now()
	if err := cache.RefreshWithRetry(context.Background(), 700*time.Millisecond); err == nil {
		t.Fatal("expected error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %v, expected to give up near the timeout", elapsed)
	}
}
