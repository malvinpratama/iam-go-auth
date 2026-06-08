// Package email abstracts sending account emails (verification, password reset).
// The default sender logs the message instead of using SMTP, so the flows work
// in development without an email server. Swap in an SMTP sender for production.
package email

import "log/slog"

// Sender delivers a message to a recipient.
type Sender interface {
	Send(to, subject, body string)
}

// LogSender writes emails to the structured log (development default).
type LogSender struct{ log *slog.Logger }

// NewLogSender builds a LogSender.
func NewLogSender(log *slog.Logger) Sender { return LogSender{log: log} }

func (s LogSender) Send(to, subject, body string) {
	s.log.Info("email (dev log sender)", "to", to, "subject", subject, "body", body)
}
