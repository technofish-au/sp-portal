package billing

import (
	"database/sql"
	"log/slog"
	"time"

	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/jobs"
)

// Deps wires the billing domain: DB + queue always, the Stripe Client and
// webhook secret when Stripe is configured (both empty = billing disabled,
// endpoints answer 503 and the webhook 503s).
type Deps struct {
	DB    *sql.DB
	Queue *jobs.Queue
	Log   *slog.Logger

	Client        Client
	WebhookSecret string

	PublicBaseURL string
	// Prices maps plan name (starter|pro|enterprise) to the Stripe price id.
	Prices       map[string]string
	AutomaticTax bool

	// PastDueGrace is how long a subscription may stay past_due before the
	// sweep suspends it; SweepInterval is the sweep cadence.
	PastDueGrace  time.Duration
	SweepInterval time.Duration

	// Now overrides the clock (tests).
	Now func() time.Time
}

func (d Deps) queries() *dbq.Queries { return dbq.New(d.DB) }

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now().UTC()
}

// Enabled reports whether outbound Stripe calls are configured.
func (d Deps) Enabled() bool { return d.Client != nil }
