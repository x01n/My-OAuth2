package service

import (
	"context"
	"testing"
	"time"

	"server/pkg/cache"
)

func TestCacheWarmerDoesNotWriteOIDCPlaceholderDocuments(t *testing.T) {
	ctx := context.Background()
	memoryCache := cache.NewMemoryCache(5 * time.Minute)
	defer memoryCache.Close()

	warmer := NewCacheWarmer(memoryCache, nil, nil)
	if err := warmer.Warmup(ctx, true); err != nil {
		t.Fatalf("Warmup() error: %v", err)
	}

	for _, key := range []string{
		"oidc:discovery:my-oauth2",
		"oidc:jwks:my-oauth2",
		"oidc:discovery:http://localhost:8080",
		"oidc:jwks:http://localhost:8080",
	} {
		if exists, err := memoryCache.Exists(ctx, key); err != nil {
			t.Fatalf("Exists(%q) error: %v", key, err)
		} else if exists {
			t.Fatalf("Warmup() must not write OIDC placeholder cache key %q", key)
		}
	}

	if exists, err := memoryCache.Exists(ctx, "meta:cache_warmed"); err != nil {
		t.Fatalf("Exists(meta:cache_warmed) error: %v", err)
	} else if !exists {
		t.Fatalf("Warmup() should still write meta:cache_warmed")
	}
}
