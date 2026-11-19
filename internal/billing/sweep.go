package billing

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/technofish-au/sp-portal/internal/audit"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/jobs"
)

// KindSuspendSweep is the self-rescheduling job that suspends
// subscriptions which stayed past_due beyond PastDueGrace. The schema's
// status enum has no 'suspended' value — the post-grace state is 'unpaid'
// and the audit action records the suspension.
const KindSuspendSweep = "billing.suspend_sweep"

// SuspendSweepHandler returns the sweep job handler. Each run marks
// overdue subscriptions and reschedules itself one interval out; a chain
// that dies (job goes dead) is re-seeded at worker start by SeedSweep.
func (d Deps) SuspendSweepHandler() jobs.Handler {
	return func(ctx context.Context, _ jobs.Job) error {
		if err := d.sweep(ctx); err != nil {
			return err
		}
		return d.scheduleNextSweep(ctx)
	}
}

// scheduleNextSweep enqueues the following run. The dedupe key is the
// truncated run time so duplicate chains (e.g. two workers seeding at
// once) converge onto one job per interval bucket.
func (d Deps) scheduleNextSweep(ctx context.Context) error {
	if d.Queue == nil {
		return nil
	}
	runAt := d.now().Add(d.SweepInterval).Truncate(d.SweepInterval)
	_, err := d.Queue.Enqueue(ctx, KindSuspendSweep, map[string]any{},
		jobs.WithRunAt(runAt),
		jobs.WithDedupeKey(fmt.Sprintf("%s:%d", KindSuspendSweep, runAt.Unix())))
	return err
}

// SeedSweep enqueues the first sweep job when no pending/running sweep
// exists; called once at worker startup.
func (d Deps) SeedSweep(ctx context.Context) error {
	if d.Queue == nil {
		return nil
	}
	n, err := d.queries().CountRunnableJobsByKind(ctx, KindSuspendSweep)
	if err != nil {
		return fmt.Errorf("billing: sweep seed: %w", err)
	}
	if n > 0 {
		return nil
	}
	return d.scheduleNextSweep(ctx)
}

// sweep marks every subscription still past_due after the grace period as
// unpaid (suspended) with an audit row and a notification email per org.
func (d Deps) sweep(ctx context.Context) error {
	q := d.queries()
	cutoff := d.now().Add(-d.PastDueGrace)
	subs, err := q.ListPastDueSubscriptions(ctx, cutoff)
	if err != nil {
		return fmt.Errorf("billing: sweep list: %w", err)
	}
	for _, sub := range subs {
		if err := q.UpdateSubscriptionState(ctx, dbq.UpdateSubscriptionStateParams{
			ID: sub.ID, StripeSubscriptionID: sub.StripeSubscriptionID,
			StripePriceID: sub.StripePriceID, Plan: sub.Plan, Status: "unpaid",
			Seats: sub.Seats, CurrentPeriodStart: sub.CurrentPeriodStart,
			CurrentPeriodEnd: sub.CurrentPeriodEnd, CancelAt: sub.CancelAt,
		}); err != nil {
			return fmt.Errorf("billing: suspend %s: %w", sub.ID, err)
		}
		if err := audit.Write(ctx, q, audit.Entry{
			OrgID: sub.OrgID, Action: audit.ActionSubSuspended,
			TargetType: "subscription", TargetID: sub.ID,
			Detail: map[string]any{
				"from": sub.Status, "to": "unpaid",
				"grace_hours": int(d.PastDueGrace.Hours()), "sweep": true,
			},
		}); err != nil {
			return fmt.Errorf("billing: suspend audit %s: %w", sub.ID, err)
		}
		if org, err := q.GetOrganisation(ctx, sub.OrgID); err == nil {
			err = d.queueMail(ctx, org, "ServerPerch subscription suspended",
				"Your ServerPerch subscription was suspended after payment stayed "+
					fmt.Sprintf("overdue for more than %d days.\n\n", int(d.PastDueGrace.Hours()/24))+
					"Sign in to the customer portal to update your payment method and reactivate.\n")
			if err != nil && d.Log != nil {
				d.Log.Warn("suspension mail enqueue failed",
					slog.String("org_id", sub.OrgID), slog.String("error", err.Error()))
			}
		}
	}
	if len(subs) > 0 && d.Log != nil {
		d.Log.Info("past-due sweep suspended subscriptions", slog.Int("count", len(subs)))
	}
	return nil
}
