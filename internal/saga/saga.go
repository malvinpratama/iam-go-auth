// Package saga handles permanently-failed profile creation. When the user
// service gives up (ProfileCreationFailed), auth records the incident for ops
// visibility but keeps the identity active — the profile is recreated by
// lazy-heal on the next GET /users/me, so the user is never locked out
// (forward recovery, not a destructive rollback).
package saga

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/malvinpratama/iam-go-auth/internal/db"
	"github.com/malvinpratama/iam-go-libs/events"
)

// Compensator subscribes to profile-creation-failed events and compensates.
type Compensator struct {
	q   *db.Queries
	js  nats.JetStreamContext
	log *slog.Logger
}

func NewCompensator(q *db.Queries, js nats.JetStreamContext, log *slog.Logger) *Compensator {
	return &Compensator{q: q, js: js, log: log}
}

// Start binds the subscription in the background, retrying on error so a
// transient "already bound" during a rolling restart doesn't crash boot.
func (c *Compensator) Start(ctx context.Context) {
	go func() {
		for {
			sub, err := c.js.Subscribe(events.SubjectProfileFailed, c.handle,
				nats.Durable("auth-saga-profile-failed"), nats.ManualAck(), nats.AckExplicit())
			if err != nil {
				c.log.Warn("saga subscribe failed; retrying", "err", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(3 * time.Second):
				}
				continue
			}
			c.log.Info("saga compensator started")
			<-ctx.Done()
			_ = sub.Drain()
			return
		}
	}()
}

func (c *Compensator) handle(m *nats.Msg) {
	var ev events.ProfileCreationFailed
	if err := json.Unmarshal(m.Data, &ev); err != nil {
		c.log.Warn("bad ProfileCreationFailed payload", "err", err)
		_ = m.Term()
		return
	}
	if _, err := uuid.Parse(ev.UserID); err != nil {
		_ = m.Term()
		return
	}
	// Forward recovery, not rollback: keep the identity active and record the
	// failure for ops visibility. The profile is recreated lazily on the next
	// GET /users/me (lazy-heal), so the user is never locked out of an account
	// they registered.
	_ = c.q.InsertAuditEvent(context.Background(), db.InsertAuditEventParams{
		ActorID: "system", ActorEmail: "saga",
		Action: "profile.creation_failed", Target: ev.UserID, Detail: ev.Reason,
	})
	_ = m.Ack()
	c.log.Warn("profile creation failed permanently; identity kept active, profile will self-heal on next /users/me read", "user_id", ev.UserID, "reason", ev.Reason)
}
