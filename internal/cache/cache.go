// Package cache is an optional Redis layer shared across auth replicas: an
// access-token denylist (revoked jti) and a per-user permission cache. When
// REDIS_URL is unset or unreachable every method is a no-op/miss and callers
// fall back to Postgres, so single-instance/dev keeps working unchanged.
package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

const permsTTL = 60 * time.Second

type Cache struct {
	rdb *redis.Client // nil when Redis is not configured/reachable
}

// New connects to Redis if redisURL is set and reachable, else returns a
// disabled cache (all methods are no-ops).
func New(redisURL string) *Cache {
	if redisURL == "" {
		return &Cache{}
	}
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return &Cache{}
	}
	rdb := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return &Cache{}
	}
	return &Cache{rdb: rdb}
}

// Enabled reports whether Redis is active (for startup logging).
func (c *Cache) Enabled() bool { return c.rdb != nil }

// Deny denylists a revoked access-token jti until ttl elapses.
func (c *Cache) Deny(ctx context.Context, jti string, ttl time.Duration) {
	if c.rdb == nil || jti == "" || ttl <= 0 {
		return
	}
	_ = c.rdb.Set(ctx, "denylist:"+jti, 1, ttl).Err()
}

// IsDenied reports whether jti is denylisted. ok=false means "ask Postgres"
// (Redis off, or a transient Redis error — fail safe to the durable store).
func (c *Cache) IsDenied(ctx context.Context, jti string) (denied, ok bool) {
	if c.rdb == nil || jti == "" {
		return false, false
	}
	n, err := c.rdb.Exists(ctx, "denylist:"+jti).Result()
	if err != nil {
		return false, false
	}
	return n > 0, true
}

// GetPerms returns a cached permission list for a user; ok=false on miss.
func (c *Cache) GetPerms(ctx context.Context, userID string) ([]string, bool) {
	if c.rdb == nil {
		return nil, false
	}
	v, err := c.rdb.Get(ctx, "perms:"+userID).Result()
	if err != nil {
		return nil, false
	}
	var perms []string
	if json.Unmarshal([]byte(v), &perms) != nil {
		return nil, false
	}
	return perms, true
}

// SetPerms caches a user's permissions for a short TTL.
func (c *Cache) SetPerms(ctx context.Context, userID string, perms []string) {
	if c.rdb == nil {
		return
	}
	b, err := json.Marshal(perms)
	if err != nil {
		return
	}
	_ = c.rdb.Set(ctx, "perms:"+userID, b, permsTTL).Err()
}

// InvalidatePerms drops a user's cached permissions (after a role change).
func (c *Cache) InvalidatePerms(ctx context.Context, userID string) {
	if c.rdb == nil {
		return
	}
	_ = c.rdb.Del(ctx, "perms:"+userID).Err()
}
