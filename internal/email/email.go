// Package email abstracts sending account emails (verification, password reset).
// The default sender logs the message instead of using SMTP, so the flows work
// in development without an email server. Swap in an SMTP sender for production.
package email

import (
	"log/slog"

	"github.com/malvinpratama/iam-go-libs/config"
)

// Sender delivers a message to a recipient.
type Sender interface {
	Send(to, subject, body string)
}

// LogSender writes emails to the structured log (development default).
type LogSender struct{ log *slog.Logger }

// NewLogSender builds a LogSender.
func NewLogSender(log *slog.Logger) Sender { return LogSender{log: log} }

func (s LogSender) Send(to, subject, body string) {
	// The body carries a credential (verification / password-reset token). Never
	// write it to logs in production — emit a warning instead so the
	// misconfiguration is visible, and wire a real SMTP sender for prod.
	if config.IsProduction() {
		s.log.Warn("email suppressed: LogSender must not be used in production (no SMTP configured)", "to", to, "subject", subject)
		return
	}
	s.log.Info("email (dev log sender)", "to", to, "subject", subject, "body", body)
}
