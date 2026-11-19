package mailer

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/technofish-au/sp-portal/internal/jobs"
)

// KindSend is the jobs-table kind for outbound mail. The payload is a
// serialised Message.
const KindSend = "mail.send"

// SendJobHandler returns a jobs.Handler for mail.send: it unmarshals the
// Message payload and delivers it. A transient SMTP failure errors the job
// so the worker retries with backoff.
func SendJobHandler(m Mailer) jobs.Handler {
	return func(ctx context.Context, job jobs.Job) error {
		var msg Message
		if err := json.Unmarshal(job.Payload, &msg); err != nil {
			return fmt.Errorf("mailer: bad %s payload: %w", KindSend, err)
		}
		if err := m.Send(ctx, msg); err != nil {
			return fmt.Errorf("mailer: %w", err)
		}
		return nil
	}
}
