// Copyright 2026 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// invalidateCountingCache wraps a DiscoveryCache and records how many times
// Invalidate was called, so tests can assert the corrupt-entry purge fires.
type invalidateCountingCache struct {
	inner         DiscoveryCache
	mutex         sync.Mutex
	invalidations int
}

func newInvalidateCountingCache(inner DiscoveryCache) *invalidateCountingCache {
	return &invalidateCountingCache{inner: inner}
}

func (c *invalidateCountingCache) Read(ctx context.Context, issuer string, maxAge time.Duration) ([]byte, error) {
	return c.inner.Read(ctx, issuer, maxAge)
}

func (c *invalidateCountingCache) Write(issuer string, val []byte) error {
	return c.inner.Write(issuer, val)
}

func (c *invalidateCountingCache) Invalidate(ctx context.Context, issuer string) error {
	c.mutex.Lock()
	c.invalidations++
	c.mutex.Unlock()
	return c.inner.Invalidate(ctx, issuer)
}

func (c *invalidateCountingCache) Invalidations() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.invalidations
}

// A corrupt cache entry should be invalidated (purged) when it is read, not
// merely skipped, so it cannot survive a provider outage or mask the provider
// error on the fallback read.
func TestCorruptCacheEntryIsInvalidatedOnRead(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	inner := NewMapDiscoveryCache()
	require.NoError(t, inner.Write(issuer, []byte("{ this is not json")))
	cache := newInvalidateCountingCache(inner)

	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := NewPubkeyFinderWithCache(source.Fetch, cache, time.Hour)

	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.NoError(t, err, "corrupt entry should fall through to a fresh fetch")
	require.False(t, pubkeyRecord.WasCached)
	require.Equal(t, signer.Public(), pubkeyRecord.PublicKey)
	require.GreaterOrEqual(t, cache.Invalidations(), 1, "corrupt entry should have been invalidated on read")

	// The corrupt bytes must be gone, not lurking for a future fallback read.
	cached, err := inner.Read(ctx, issuer, 24*time.Hour)
	require.NoError(t, err, "the fresh fetch should have repopulated the entry")
	parsed, err := parseJwks(cached)
	require.NoError(t, err, "the repopulated entry should be the valid fresh JWKS, not the corrupt bytes")
	_, ok := parsed.LookupKeyID("1234")
	require.True(t, ok)
}

// If the cached bytes are corrupt AND the provider is unreachable, the fallback
// read must not resurrect the same garbage: the entry is purged on the standard
// read, so the fallback is a clean miss and the provider error surfaces.
func TestCorruptEntryPurgedThenProviderDown(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	inner := NewMapDiscoveryCache()
	require.NoError(t, inner.Write(issuer, []byte("{ this is not json")))
	cache := newInvalidateCountingCache(inner)

	source := NewMockJwksSource(nil)
	providerErr := errors.New("provider unreachable")
	source.Fail(providerErr)
	finder := NewPubkeyFinderWithCache(source.Fetch, cache, time.Hour)

	pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
	require.ErrorIs(t, err, providerErr, "provider error must surface, not a stale unmarshal error")
	require.Nil(t, pubkeyRecord.PublicKey)
	require.GreaterOrEqual(t, cache.Invalidations(), 1)

	// Entry is gone; nothing rewrote it because the fetch failed.
	_, err = inner.Read(ctx, issuer, 24*time.Hour)
	require.ErrorIs(t, err, ErrCacheMiss, "corrupt entry should have been purged and not resurrected")
}

// A non-nil cache with a zero StandardMaxAge disables caching entirely: no entry
// is ever served, and (unlike before) no entry is ever written either.
func TestZeroMaxAgeSkipsReadsAndWrites(t *testing.T) {
	ctx := context.Background()
	issuer := "testIssuer"

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cache := NewMapDiscoveryCache()
	source := NewMockJwksSource(createMockJwks(t, issuer, []crypto.PublicKey{signer.Public()}, []string{"1234"}, []string{"RS256"}))
	finder := &PublicKeyFinder{
		JwksFunc:    source.Fetch,
		CacheConfig: DiscoveryCacheConfig{Cache: cache, StandardMaxAge: 0},
	}

	for i := range 2 {
		pubkeyRecord, err := finder.ByKeyID(ctx, issuer, "1234", true)
		require.NoError(t, err)
		require.False(t, pubkeyRecord.WasCached, "zero StandardMaxAge should never serve a cached entry")
		require.Equal(t, i+1, source.Calls(), "every lookup should reach the provider")
	}

	// The key point of the change: with caching effectively off, we must not do
	// pointless writes of entries that can never be read back.
	_, err = cache.Read(ctx, issuer, 24*time.Hour)
	require.ErrorIs(t, err, ErrCacheMiss, "zero StandardMaxAge should not write entries")
}
