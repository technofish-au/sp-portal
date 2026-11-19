package mailer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// dialTimeout bounds the SMTP connection setup.
const dialTimeout = 10 * time.Second

// SMTPMailer delivers through a plain SMTP relay (Mailpit in dev, a real
// relay in production). TLS is STARTTLS-only when StartTLS is set; auth is
// PLAIN over the (then hopefully encrypted) connection when User is set.
type SMTPMailer struct {
	Addr     string // host:port
	Host     string // host for tls.ServerName / auth
	User     string
	Password string
	StartTLS bool
	From     string
	FromName string
}

var _ Mailer = (*SMTPMailer)(nil)

// Send delivers msg to every address in msg.To (comma-separated accepted).
func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", m.Addr)
	if err != nil {
		return fmt.Errorf("mailer: dial %s: %w", m.Addr, err)
	}
	// smtp.Client has no context support; the dial deadline above bounds
	// connect and the per-op deadline bounds the conversation.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	c, err := smtp.NewClient(conn, m.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mailer: smtp client: %w", err)
	}
	defer func() { _ = c.Close() }()

	if m.StartTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: m.Host, MinVersion: tls.VersionTLS12}); err != nil {
				return fmt.Errorf("mailer: starttls: %w", err)
			}
		}
	}
	if m.User != "" {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(smtp.PlainAuth("", m.User, m.Password, m.Host)); err != nil {
				return fmt.Errorf("mailer: auth: %w", err)
			}
		}
	}
	if err := c.Mail(m.From); err != nil {
		return fmt.Errorf("mailer: MAIL FROM: %w", err)
	}
	for _, rcpt := range strings.Split(msg.To, ",") {
		if err := c.Rcpt(strings.TrimSpace(rcpt)); err != nil {
			return fmt.Errorf("mailer: RCPT TO %q: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("mailer: DATA: %w", err)
	}
	if _, err := fmt.Fprint(w, m.render(msg)); err != nil {
		_ = w.Close()
		return fmt.Errorf("mailer: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mailer: end data: %w", err)
	}
	return c.Quit()
}

// render formats msg as a minimal RFC 5322 text email.
func (m *SMTPMailer) render(msg Message) string {
	from := m.From
	if m.FromName != "" {
		from = fmt.Sprintf("%s <%s>", m.FromName, m.From)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", msg.To)
	fmt.Fprintf(&b, "Subject: %s\r\n", msg.Subject)
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	// CRLF-normalise the body (bare \n breaks strict parsers).
	b.WriteString(strings.ReplaceAll(msg.Text, "\n", "\r\n"))
	return b.String()
}
