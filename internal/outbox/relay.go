// Package outbox publishes pending auth domain events to NATS JetStream.
//
// The relay polls the outbox table (written transactionally with the domain
// change), publishes each unpublished row to JetStream with the row id as the
// NATS message id (so a double-publish after a crash is de-duplicated by the
// server), then marks the row published. Delivery is at-least-once.
package outbox

import (
	"context"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/malvinpratama/iam-go-auth/internal/db"
	"github.com/malvinpratama/iam-go-libs/events"
)

// Relay drains the outbox to the broker on an interval.
type Relay struct {
	q        *db.Queries
	js       nats.JetStreamContext
	log      *slog.Logger
	interval time.Duration
	batch    int32
}

// NewRelay builds a Relay over the given queries and JetStream context.
func NewRelay(q *db.Queries, js nats.JetStreamContext, log *slog.Logger) *Relay {
	return &Relay{q: q, js: js, log: log, interval: time.Second, batch: 100}
}

// Run polls until ctx is cancelled. Intended to be started in its own goroutine.
func (r *Relay) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.drain(ctx); err != nil {
				r.log.Warn("outbox drain failed", "err", err)
			}
		}
	}
}

func (r *Relay) drain(ctx context.Context) error {
	rows, err := r.q.FetchUnpublishedOutbox(ctx, r.batch)
	if err != nil {
		return err
	}
	for _, row := range rows {
		subject := events.SubjectPrefix + row.EventType
		// MsgId = outbox id → JetStream dedupe collapses any re-publish.
		if _, err := r.js.Publish(subject, row.Payload, nats.MsgId(row.ID.String())); err != nil {
			// Leave the row unpublished; it is retried on the next tick.
			return err
		}
		if err := r.q.MarkOutboxPublished(ctx, row.ID); err != nil {
			return err
		}
		r.log.Info("event published", "subject", subject, "id", row.ID)
	}
	return nil
}
