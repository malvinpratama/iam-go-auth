// Package saga implements the registration compensation: if the user service
// gives up creating a profile (ProfileCreationFailed), auth rolls back the
// half-created identity by soft-deleting it, so registration leaves no orphans.
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
	uid, err := uuid.Parse(ev.UserID)
	if err != nil {
		_ = m.Term()
		return
	}
	// Compensate: disable the orphaned identity (recoverable, audited).
	if err := c.q.SoftDeleteUser(context.Background(), uid); err != nil {
		c.log.Warn("compensation soft-delete failed; will retry", "err", err)
		_ = m.Nak()
		return
	}
	_ = c.q.InsertAuditEvent(context.Background(), db.InsertAuditEventParams{
		ActorID: "system", ActorEmail: "saga",
		Action: "saga.profile_failed.compensated", Target: ev.UserID, Detail: ev.Reason,
	})
	_ = m.Ack()
	c.log.Warn("compensated half-created identity (soft-deleted)", "user_id", ev.UserID, "reason", ev.Reason)
}
