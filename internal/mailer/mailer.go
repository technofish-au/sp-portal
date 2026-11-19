// Package mailer delivers outbound notification email. Delivery is bound
// behind the Mailer interface so tests substitute a stub and devs can run
// either the log sink (smtp_host empty) or Mailpit (see deploy/compose).
//
// Production mail is enqueued as a `mail.send` job so HTTP handlers never
// block on SMTP and failed deliveries retry through the job queue.
package mailer

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/technofish-au/sp-portal/internal/config"
	"github.com/technofish-au/sp-portal/internal/secrets"
)

// Message is one outbound email.
type Message struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
}

// Mailer sends one message. Implementations must be safe for concurrent use.
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

// New returns the configured Mailer: an SMTP sender when smtp_host is set
// (smtp_password_file resolves the password, mode 0400/0600 enforced), or
// the log sink otherwise.
func New(cfg config.Config, log *slog.Logger) (Mailer, error) {
	if cfg.SMTPHost == "" {
		return &LogMailer{Log: log}, nil
	}
	var password string
	if cfg.SMTPPasswordFile != "" {
		pw, err := secrets.ReadString(cfg.SMTPPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("mailer: password file: %w", err)
		}
		password = pw
	}
	return &SMTPMailer{
		Addr:     fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort),
		Host:     cfg.SMTPHost,
		User:     cfg.SMTPUser,
		Password: password,
		StartTLS: cfg.SMTPStartTLS,
		From:     cfg.MailFrom,
		FromName: cfg.MailFromName,
	}, nil
}

// LogMailer is the dev default Mailer: it writes each message to the log
// (with the body trimmed) instead of delivering it.
type LogMailer struct {
	Log *slog.Logger
}

var _ Mailer = (*LogMailer)(nil)

// Send logs the message at info level; the body is truncated so verification
// links still show up in dev logs without flooding them.
func (m *LogMailer) Send(_ context.Context, msg Message) error {
	body := msg.Text
	if len(body) > 400 {
		body = body[:400] + "…"
	}
	m.Log.Info("mail (not delivered: no smtp_host)",
		slog.String("to", msg.To),
		slog.String("subject", msg.Subject),
		slog.String("body", body),
	)
	return nil
}
