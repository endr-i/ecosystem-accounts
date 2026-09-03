package authn

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	// maxJWKSBody caps the JWKS response we are willing to read.
	maxJWKSBody = 1 << 20
	// defaultMinRefreshInterval rate limits refetches triggered by an unknown kid,
	// so a flood of bogus tokens cannot hammer the auth service.
	defaultMinRefreshInterval = 30 * time.Second
	defaultFetchTimeout       = 5 * time.Second
)

var (
	ErrUnknownKID = errors.New("unknown key id")
	ErrNoKeys     = errors.New("jwks contains no usable RSA keys")
)

// jwk is a single public key as published by ecosystem-auth.
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

// KeyCache fetches and caches the RSA public keys published by the auth
// service at its JWKS endpoint.
//
// Keys are loaded once at startup and refreshed periodically. A token signed
// with a kid that is not cached also triggers an out-of-band refresh (rate
// limited), so key rotation is picked up without a restart.
type KeyCache struct {
	url        string
	client     *http.Client
	minRefresh time.Duration
	log        *slog.Logger
	now        func() time.Time

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time

	// refreshMu serializes refreshes so concurrent requests cause one fetch.
	refreshMu sync.Mutex
}

type CacheOption func(*KeyCache)

func WithHTTPClient(c *http.Client) CacheOption {
	return func(k *KeyCache) { k.client = c }
}

func WithMinRefreshInterval(d time.Duration) CacheOption {
	return func(k *KeyCache) { k.minRefresh = d }
}

func WithLogger(l *slog.Logger) CacheOption {
	return func(k *KeyCache) { k.log = l }
}

func NewKeyCache(url string, opts ...CacheOption) *KeyCache {
	k := &KeyCache{
		url:        url,
		client:     &http.Client{Timeout: defaultFetchTimeout},
		minRefresh: defaultMinRefreshInterval,
		log:        slog.New(slog.DiscardHandler),
		now:        time.Now,
		keys:       make(map[string]*rsa.PublicKey),
	}
	for _, opt := range opts {
		opt(k)
	}
	return k
}

// Refresh fetches the JWKS document and replaces the cached key set.
func (k *KeyCache) Refresh(ctx context.Context) error {
	k.refreshMu.Lock()
	defer k.refreshMu.Unlock()
	return k.refreshLocked(ctx)
}

func (k *KeyCache) refreshLocked(ctx context.Context) error {
	keys, err := k.fetch(ctx)
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.keys = keys
	k.lastFetch = k.now()
	k.mu.Unlock()
	k.log.Info("jwks refreshed", "url", k.url, "keys", len(keys))
	return nil
}

func (k *KeyCache) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return nil, fmt.Errorf("build jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks: unexpected status %s", resp.Status)
	}

	var doc jwksDocument
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, maxJWKSBody)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, key := range doc.Keys {
		// Ignore keys we cannot use rather than failing the whole document:
		// the auth service may publish other key types or usages later.
		if key.Kty != "RSA" || key.Kid == "" {
			continue
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if key.Alg != "" && key.Alg != "RS256" {
			continue
		}
		pub, err := parseRSAPublicKey(key)
		if err != nil {
			k.log.Warn("skipping unusable jwk", "kid", key.Kid, "err", err)
			continue
		}
		keys[key.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	return keys, nil
}

func parseRSAPublicKey(key jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, errors.New("empty modulus or exponent")
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, fmt.Errorf("unsupported exponent %s", e)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e.Int64())}, nil
}

// Key returns the cached public key for kid, refreshing once if the kid is
// unknown and the cache is not already fresh.
func (k *KeyCache) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	k.mu.RLock()
	pub, ok := k.keys[kid]
	last := k.lastFetch
	k.mu.RUnlock()
	if ok {
		return pub, nil
	}

	if k.now().Sub(last) < k.minRefresh {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKID, kid)
	}

	k.refreshMu.Lock()
	// Another goroutine may have refreshed while we waited for the lock.
	k.mu.RLock()
	pub, ok = k.keys[kid]
	last = k.lastFetch
	k.mu.RUnlock()
	if ok {
		k.refreshMu.Unlock()
		return pub, nil
	}
	if k.now().Sub(last) < k.minRefresh {
		k.refreshMu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrUnknownKID, kid)
	}
	err := k.refreshLocked(ctx)
	k.refreshMu.Unlock()
	if err != nil {
		k.log.Error("jwks refresh for unknown kid failed", "kid", kid, "err", err)
		return nil, fmt.Errorf("%w: %s", ErrUnknownKID, kid)
	}

	k.mu.RLock()
	pub, ok = k.keys[kid]
	k.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKID, kid)
	}
	return pub, nil
}

// RefreshWithRetry fetches the key set, retrying with backoff until it
// succeeds or the context is done. Used at startup, where the auth service may
// still be coming up.
func (k *KeyCache) RefreshWithRetry(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	backoff := 500 * time.Millisecond
	for attempt := 1; ; attempt++ {
		err := k.Refresh(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("fetch jwks from %s: %w", k.url, err)
		}
		k.log.Warn("jwks fetch failed, retrying", "url", k.url, "attempt", attempt, "err", err)
		select {
		case <-ctx.Done():
			return fmt.Errorf("fetch jwks from %s: %w", k.url, err)
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

// StartBackgroundRefresh periodically refreshes the key set until ctx is done.
func (k *KeyCache) StartBackgroundRefresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := k.Refresh(ctx); err != nil && ctx.Err() == nil {
					// Keep serving the previously cached keys.
					k.log.Error("scheduled jwks refresh failed", "url", k.url, "err", err)
				}
			}
		}
	}()
}
