package billing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	gomysql "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/audit"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/jobs"
	"github.com/technofish-au/sp-portal/internal/mailer"
)

// StripeEventHandler returns the worker handler for billing.stripe_event
// jobs. The handler is idempotent on event.id twice over: the unique
// stripe_events.event_id row is the inbox (a redelivery never enqueues a
// second job) and processed_at short-circuits re-runs of the same job.
func (d Deps) StripeEventHandler() jobs.Handler {
	return func(ctx context.Context, job jobs.Job) error {
		var p struct {
			EventID string `json:"event_id"`
		}
		if err := json.Unmarshal(job.Payload, &p); err != nil || p.EventID == "" {
			return fmt.Errorf("billing: bad %s payload", KindStripeEvent)
		}
		return d.ProcessEvent(ctx, p.EventID)
	}
}

// ProcessEvent applies one stored Stripe event. Called by the jobs
// handler; returns nil when the event is already processed.
func (d Deps) ProcessEvent(ctx context.Context, eventID string) error {
	q := d.queries()
	ev, err := q.GetStripeEvent(ctx, eventID)
	if err != nil {
		return fmt.Errorf("billing: load event %s: %w", eventID, err)
	}
	if ev.ProcessedAt != nil {
		return nil // idempotent: already applied
	}
	var env eventEnvelope
	if err := json.Unmarshal(ev.Payload, &env); err != nil {
		_ = q.MarkStripeEventError(ctx, dbq.MarkStripeEventErrorParams{
			EventID: eventID, ProcessError: sqlString("unparseable envelope: " + err.Error()),
		})
		return fmt.Errorf("billing: event %s: bad payload: %w", eventID, err)
	}
	if err := d.dispatch(ctx, q, ev, env); err != nil {
		_ = q.MarkStripeEventError(ctx, dbq.MarkStripeEventErrorParams{
			EventID: eventID, ProcessError: sqlString(err.Error()),
		})
		return err
	}
	if err := q.MarkStripeEventProcessed(ctx, eventID); err != nil {
		return fmt.Errorf("billing: mark processed %s: %w", eventID, err)
	}
	return nil
}

// dispatch routes the event to its applier. Unknown types are a no-op —
// Stripe sends the full catalogue regardless of what we subscribe to.
func (d Deps) dispatch(ctx context.Context, q *dbq.Queries, ev dbq.StripeEvent, env eventEnvelope) error {
	switch ev.Type {
	case "checkout.session.completed":
		return d.onCheckoutCompleted(ctx, q, ev, env.Data.Object)
	case "customer.subscription.created", "customer.subscription.updated":
		return d.onSubscriptionUpsert(ctx, q, ev, env.Data.Object)
	case "customer.subscription.deleted":
		return d.onSubscriptionDeleted(ctx, q, ev, env.Data.Object)
	case "invoice.paid":
		return d.onInvoicePaid(ctx, q, ev, env.Data.Object)
	case "invoice.payment_failed":
		return d.onInvoiceFailed(ctx, q, ev, env.Data.Object)
	case "customer.updated":
		return d.onCustomerUpdated(ctx, q, ev, env.Data.Object)
	default:
		if d.Log != nil {
			d.Log.Debug("stripe event ignored", slog.String("type", ev.Type), slog.String("event_id", ev.EventID))
		}
		return nil
	}
}

// --- payload shapes (only the fields the portal uses) -------------------

type checkoutSessionObject struct {
	ID                string `json:"id"`
	Mode              string `json:"mode"`
	Customer          string `json:"customer"`
	Subscription      string `json:"subscription"`
	ClientReferenceID string `json:"client_reference_id"`
	Metadata          struct {
		OrgID string `json:"org_id"`
	} `json:"metadata"`
	CustomerDetails struct {
		Email  string `json:"email"`
		TaxIDs []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"tax_ids"`
	} `json:"customer_details"`
}

type subscriptionObject struct {
	ID       string `json:"id"`
	Customer string `json:"customer"`
	Status   string `json:"status"`
	Metadata struct {
		OrgID string `json:"org_id"`
	} `json:"metadata"`
	Items struct {
		Data []struct {
			Price struct {
				ID string `json:"id"`
			} `json:"price"`
			Quantity int `json:"quantity"`
		} `json:"data"`
	} `json:"items"`
	CurrentPeriodStart int64 `json:"current_period_start"`
	CurrentPeriodEnd   int64 `json:"current_period_end"`
	CancelAt           int64 `json:"cancel_at"`
}

type invoiceObject struct {
	ID               string `json:"id"`
	Customer         string `json:"customer"`
	Subscription     string `json:"subscription"`
	BillingReason    string `json:"billing_reason"`
	Status           string `json:"status"`
	CustomerEmail    string `json:"customer_email"`
	HostedInvoiceURL string `json:"hosted_invoice_url"`
	AmountPaid       int64  `json:"amount_paid"`
	AmountDue        int64  `json:"amount_due"`
	Currency         string `json:"currency"`
}

type customerObject struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Metadata struct {
		OrgID string `json:"org_id"`
		ABN   string `json:"abn"`
	} `json:"metadata"`
	TaxIDs struct {
		Data []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"data"`
	} `json:"tax_ids"`
}

// --- appliers -----------------------------------------------------------

// onCheckoutCompleted links the Stripe customer/subscription ids to the
// org + its subscription row. Status changes arrive via the subscription
// events — this event only carries ids (and collected tax ids for audit).
func (d Deps) onCheckoutCompleted(ctx context.Context, q *dbq.Queries, ev dbq.StripeEvent, obj json.RawMessage) error {
	var o checkoutSessionObject
	if err := json.Unmarshal(obj, &o); err != nil {
		return fmt.Errorf("billing: checkout.session.completed: %w", err)
	}
	orgID := o.ClientReferenceID
	if orgID == "" {
		orgID = o.Metadata.OrgID
	}
	org, err := q.GetOrganisation(ctx, orgID)
	if err != nil {
		return fmt.Errorf("billing: checkout for unknown org %q: %w", orgID, err)
	}
	if o.Customer != "" && (!org.StripeCustomerID.Valid || org.StripeCustomerID.String != o.Customer) {
		if err := q.SetOrganisationStripeCustomer(ctx, dbq.SetOrganisationStripeCustomerParams{
			ID: org.ID, StripeCustomerID: sqlString(o.Customer),
		}); err != nil {
			return fmt.Errorf("billing: link customer: %w", err)
		}
	}
	if o.Subscription != "" {
		if sub, err := q.GetLatestSubscriptionByOrg(ctx, org.ID); err == nil {
			if err := q.UpdateSubscriptionState(ctx, dbq.UpdateSubscriptionStateParams{
				ID: sub.ID, StripeSubscriptionID: sqlString(o.Subscription),
				StripePriceID: sub.StripePriceID, Plan: sub.Plan, Status: sub.Status,
				Seats: sub.Seats, CurrentPeriodStart: sub.CurrentPeriodStart,
				CurrentPeriodEnd: sub.CurrentPeriodEnd, CancelAt: sub.CancelAt,
			}); err != nil {
				return fmt.Errorf("billing: link subscription: %w", err)
			}
		}
	}
	detail := map[string]any{"session_id": o.ID, "stripe_event_id": ev.EventID, "customer": o.Customer}
	if len(o.CustomerDetails.TaxIDs) > 0 {
		detail["tax_ids"] = o.CustomerDetails.TaxIDs
		for _, t := range o.CustomerDetails.TaxIDs {
			if t.Type == "au_abn" && t.Value != "" && org.TaxID != t.Value {
				if err := q.SetOrganisationTaxID(ctx, dbq.SetOrganisationTaxIDParams{ID: org.ID, TaxID: t.Value}); err != nil {
					return fmt.Errorf("billing: set org tax id: %w", err)
				}
			}
		}
	}
	return audit.Write(ctx, q, audit.Entry{
		OrgID: org.ID, ActorEmail: o.CustomerDetails.Email, Action: audit.ActionCheckoutDone,
		TargetType: "subscription", TargetID: o.Subscription, Detail: detail,
	})
}

// onSubscriptionUpsert mirrors a Stripe subscription into our row and
// audits every status transition.
func (d Deps) onSubscriptionUpsert(ctx context.Context, q *dbq.Queries, ev dbq.StripeEvent, obj json.RawMessage) error {
	var o subscriptionObject
	if err := json.Unmarshal(obj, &o); err != nil {
		return fmt.Errorf("billing: %s: %w", ev.Type, err)
	}
	org, err := d.orgForCustomer(ctx, q, o.Customer, o.Metadata.OrgID)
	if err != nil {
		return err
	}
	sub, err := q.GetSubscriptionByStripeID(ctx, sqlString(o.ID))
	if err != nil {
		sub, err = q.GetLatestSubscriptionByOrg(ctx, org.ID)
	}
	if err != nil {
		// No local subscription row at all (e.g. a subscription created
		// out-of-band): create one so billing state converges.
		return d.createFromStripe(ctx, q, org, o, ev)
	}
	from := sub.Status
	to := mapStripeStatus(o.Status)
	priceID, seats := firstItem(o)
	if priceID == "" {
		priceID = sub.StripePriceID
	}
	if seats == 0 {
		seats = int(sub.Seats)
	}
	plan := d.planForPrice(priceID)
	if plan == "" {
		plan = sub.Plan
	}
	if err := q.UpdateSubscriptionState(ctx, dbq.UpdateSubscriptionStateParams{
		ID: sub.ID, StripeSubscriptionID: sqlString(o.ID),
		StripePriceID: priceID, Plan: plan, Status: to, Seats: int32(seats),
		CurrentPeriodStart: epochPtr(o.CurrentPeriodStart),
		CurrentPeriodEnd:   epochPtr(o.CurrentPeriodEnd),
		CancelAt:           epochPtr(o.CancelAt),
	}); err != nil {
		return fmt.Errorf("billing: update subscription: %w", err)
	}
	if from != to {
		return audit.Write(ctx, q, audit.Entry{
			OrgID: org.ID, Action: audit.ActionSubStatus, TargetType: "subscription", TargetID: sub.ID,
			Detail: map[string]any{"from": from, "to": to, "stripe_event_id": ev.EventID, "stripe_subscription_id": o.ID},
		})
	}
	return nil
}

// createFromStripe inserts a local subscription row for a Stripe sub we
// hadn't seen (created outside checkout).
func (d Deps) createFromStripe(ctx context.Context, q *dbq.Queries, org dbq.Organisation, o subscriptionObject, ev dbq.StripeEvent) error {
	priceID, seats := firstItem(o)
	plan := d.planForPrice(priceID)
	if plan == "" {
		plan = "pro"
	}
	if seats == 0 {
		seats = 1
	}
	subID := uuid.Must(uuid.NewV7()).String()
	if err := q.CreateSubscription(ctx, dbq.CreateSubscriptionParams{
		ID: subID, OrgID: org.ID, StripeSubscriptionID: sqlString(o.ID),
		StripePriceID: priceID, Plan: plan, Status: mapStripeStatus(o.Status),
		Seats:              int32(seats),
		CurrentPeriodStart: epochPtr(o.CurrentPeriodStart),
		CurrentPeriodEnd:   epochPtr(o.CurrentPeriodEnd),
		CancelAt:           epochPtr(o.CancelAt),
	}); err != nil {
		return fmt.Errorf("billing: create subscription: %w", err)
	}
	return audit.Write(ctx, q, audit.Entry{
		OrgID: org.ID, Action: audit.ActionSubStatus, TargetType: "subscription", TargetID: subID,
		Detail: map[string]any{"from": "", "to": mapStripeStatus(o.Status), "stripe_event_id": ev.EventID, "stripe_subscription_id": o.ID},
	})
}

// onSubscriptionDeleted marks the row cancelled (the schema's word for
// Stripe's "canceled") and audits the transition.
func (d Deps) onSubscriptionDeleted(ctx context.Context, q *dbq.Queries, ev dbq.StripeEvent, obj json.RawMessage) error {
	var o subscriptionObject
	if err := json.Unmarshal(obj, &o); err != nil {
		return fmt.Errorf("billing: %s: %w", ev.Type, err)
	}
	return d.onSubscriptionUpsertStatus(ctx, q, ev, o, "cancelled")
}

// onSubscriptionUpsertStatus updates a subscription's status with the
// same audit semantics as onSubscriptionUpsert.
func (d Deps) onSubscriptionUpsertStatus(ctx context.Context, q *dbq.Queries, ev dbq.StripeEvent, o subscriptionObject, status string) error {
	org, err := d.orgForCustomer(ctx, q, o.Customer, o.Metadata.OrgID)
	if err != nil {
		return err
	}
	sub, err := q.GetSubscriptionByStripeID(ctx, sqlString(o.ID))
	if err != nil {
		return fmt.Errorf("billing: unknown subscription %s: %w", o.ID, err)
	}
	if sub.Status == status {
		return nil // already in the target state
	}
	if err := q.UpdateSubscriptionState(ctx, dbq.UpdateSubscriptionStateParams{
		ID: sub.ID, StripeSubscriptionID: sub.StripeSubscriptionID,
		StripePriceID: sub.StripePriceID, Plan: sub.Plan, Status: status,
		Seats: sub.Seats, CurrentPeriodStart: sub.CurrentPeriodStart,
		CurrentPeriodEnd: sub.CurrentPeriodEnd, CancelAt: sub.CancelAt,
	}); err != nil {
		return fmt.Errorf("billing: update subscription: %w", err)
	}
	return audit.Write(ctx, q, audit.Entry{
		OrgID: org.ID, Action: audit.ActionSubStatus, TargetType: "subscription", TargetID: sub.ID,
		Detail: map[string]any{"from": sub.Status, "to": status, "stripe_event_id": ev.EventID, "stripe_subscription_id": o.ID},
	})
}

// onInvoicePaid records the payment and reactivates a past_due/unpaid
// subscription (Stripe Smart Retries recover payments without a matching
// subscription.updated in every path).
func (d Deps) onInvoicePaid(ctx context.Context, q *dbq.Queries, ev dbq.StripeEvent, obj json.RawMessage) error {
	var o invoiceObject
	if err := json.Unmarshal(obj, &o); err != nil {
		return fmt.Errorf("billing: invoice.paid: %w", err)
	}
	org, err := d.orgForCustomer(ctx, q, o.Customer, "")
	if err != nil {
		return err
	}
	if o.Subscription != "" {
		if sub, err := q.GetSubscriptionByStripeID(ctx, sqlString(o.Subscription)); err == nil {
			if sub.Status == "past_due" || sub.Status == "suspended" || sub.Status == "unpaid" {
				if err := q.UpdateSubscriptionState(ctx, dbq.UpdateSubscriptionStateParams{
					ID: sub.ID, StripeSubscriptionID: sub.StripeSubscriptionID,
					StripePriceID: sub.StripePriceID, Plan: sub.Plan, Status: "active",
					Seats: sub.Seats, CurrentPeriodStart: sub.CurrentPeriodStart,
					CurrentPeriodEnd: sub.CurrentPeriodEnd, CancelAt: sub.CancelAt,
				}); err != nil {
					return fmt.Errorf("billing: reactivate: %w", err)
				}
				if err := audit.Write(ctx, q, audit.Entry{
					OrgID: org.ID, Action: audit.ActionSubStatus, TargetType: "subscription", TargetID: sub.ID,
					Detail: map[string]any{"from": sub.Status, "to": "active", "stripe_event_id": ev.EventID, "invoice_id": o.ID},
				}); err != nil {
					return err
				}
			}
		}
	}
	if err := audit.Write(ctx, q, audit.Entry{
		OrgID: org.ID, ActorEmail: o.CustomerEmail, Action: audit.ActionInvoicePaid,
		TargetType: "invoice", TargetID: o.ID,
		Detail: map[string]any{
			"amount_paid": o.AmountPaid, "currency": o.Currency,
			"billing_reason": o.BillingReason, "stripe_event_id": ev.EventID,
		},
	}); err != nil {
		return err
	}
	return d.queueMail(ctx, org, "Your ServerPerch receipt",
		fmt.Sprintf("Thank you — payment of %d %s was received for invoice %s.\n\nView it online: %s\n",
			o.AmountPaid, o.Currency, o.ID, o.HostedInvoiceURL))
}

// onInvoiceFailed moves the subscription to past_due (start of the
// PastDueGrace suspension clock) and queues the dunning email.
func (d Deps) onInvoiceFailed(ctx context.Context, q *dbq.Queries, ev dbq.StripeEvent, obj json.RawMessage) error {
	var o invoiceObject
	if err := json.Unmarshal(obj, &o); err != nil {
		return fmt.Errorf("billing: invoice.payment_failed: %w", err)
	}
	org, err := d.orgForCustomer(ctx, q, o.Customer, "")
	if err != nil {
		return err
	}
	if o.Subscription != "" {
		if sub, err := q.GetSubscriptionByStripeID(ctx, sqlString(o.Subscription)); err == nil {
			if sub.Status != "past_due" && sub.Status != "cancelled" {
				if err := q.UpdateSubscriptionState(ctx, dbq.UpdateSubscriptionStateParams{
					ID: sub.ID, StripeSubscriptionID: sub.StripeSubscriptionID,
					StripePriceID: sub.StripePriceID, Plan: sub.Plan, Status: "past_due",
					Seats: sub.Seats, CurrentPeriodStart: sub.CurrentPeriodStart,
					CurrentPeriodEnd: sub.CurrentPeriodEnd, CancelAt: sub.CancelAt,
				}); err != nil {
					return fmt.Errorf("billing: mark past_due: %w", err)
				}
				if err := audit.Write(ctx, q, audit.Entry{
					OrgID: org.ID, Action: audit.ActionSubStatus, TargetType: "subscription", TargetID: sub.ID,
					Detail: map[string]any{"from": sub.Status, "to": "past_due", "stripe_event_id": ev.EventID, "invoice_id": o.ID},
				}); err != nil {
					return err
				}
			}
		}
	}
	if err := audit.Write(ctx, q, audit.Entry{
		OrgID: org.ID, ActorEmail: o.CustomerEmail, Action: audit.ActionInvoiceFailed,
		TargetType: "invoice", TargetID: o.ID,
		Detail: map[string]any{"amount_due": o.AmountDue, "currency": o.Currency, "stripe_event_id": ev.EventID},
	}); err != nil {
		return err
	}
	return d.queueMail(ctx, org, "ServerPerch payment failed",
		fmt.Sprintf("We couldn't collect payment for invoice %s (%d %s).\n\n"+
			"Please update your payment method — subscriptions unpaid after %s are suspended.\n\nPay online: %s\n",
			o.ID, o.AmountDue, o.Currency, d.PastDueGrace, o.HostedInvoiceURL))
}

// onCustomerUpdated syncs name/billing email and audits captured tax ids.
func (d Deps) onCustomerUpdated(ctx context.Context, q *dbq.Queries, ev dbq.StripeEvent, obj json.RawMessage) error {
	var o customerObject
	if err := json.Unmarshal(obj, &o); err != nil {
		return fmt.Errorf("billing: customer.updated: %w", err)
	}
	org, err := d.orgForCustomer(ctx, q, o.ID, o.Metadata.OrgID)
	if err != nil {
		return err
	}
	name, email := o.Name, o.Email
	if name == "" {
		name = org.Name
	}
	if email == "" {
		email = org.BillingEmail
	}
	changed := name != org.Name || email != org.BillingEmail
	if changed {
		if err := q.UpdateOrganisationBilling(ctx, dbq.UpdateOrganisationBillingParams{
			ID: org.ID, Name: name, BillingEmail: email,
		}); err != nil {
			return fmt.Errorf("billing: update org billing: %w", err)
		}
	}
	detail := map[string]any{"stripe_event_id": ev.EventID, "stripe_customer_id": o.ID}
	abn := abnOf(o)
	if abn != "" {
		detail["abn"] = abn
		if org.TaxID != abn {
			if err := q.SetOrganisationTaxID(ctx, dbq.SetOrganisationTaxIDParams{ID: org.ID, TaxID: abn}); err != nil {
				return fmt.Errorf("billing: set org tax id: %w", err)
			}
			changed = true
		}
	}
	if !changed {
		return nil // nothing material changed
	}
	return audit.Write(ctx, q, audit.Entry{
		OrgID: org.ID, Action: audit.ActionCustomerUpdated, TargetType: "organisation", TargetID: org.ID, Detail: detail,
	})
}

// --- helpers --------------------------------------------------------------

// orgForCustomer resolves the org by Stripe customer id, falling back to
// the metadata org id (checkout sets both).
func (d Deps) orgForCustomer(ctx context.Context, q *dbq.Queries, customerID, orgID string) (dbq.Organisation, error) {
	if customerID != "" {
		if org, err := q.GetOrganisationByStripeCustomer(ctx, sqlString(customerID)); err == nil {
			return org, nil
		}
	}
	if orgID != "" {
		return q.GetOrganisation(ctx, orgID)
	}
	return dbq.Organisation{}, fmt.Errorf("billing: no org for customer %q", customerID)
}

// planForPrice reverse-maps a Stripe price id to the configured plan name.
func (d Deps) planForPrice(priceID string) string {
	for plan, id := range d.Prices {
		if id != "" && id == priceID {
			return plan
		}
	}
	return ""
}

// queueMail enqueues a notification email to the org's billing address.
func (d Deps) queueMail(ctx context.Context, org dbq.Organisation, subject, text string) error {
	if d.Queue == nil || org.BillingEmail == "" {
		return nil
	}
	_, err := d.Queue.Enqueue(ctx, mailer.KindSend, mailer.Message{
		To: org.BillingEmail, Subject: subject, Text: text,
	})
	return err
}

// mapStripeStatus normalises Stripe's spellings to the schema check
// constraint (canceled -> cancelled); unknown statuses pass through so
// new Stripe states surface rather than silently rewriting.
func mapStripeStatus(s string) string {
	if s == "canceled" {
		return "cancelled"
	}
	return s
}

func firstItem(o subscriptionObject) (priceID string, seats int) {
	if len(o.Items.Data) == 0 {
		return "", 0
	}
	return o.Items.Data[0].Price.ID, o.Items.Data[0].Quantity
}

func abnOf(o customerObject) string {
	if o.Metadata.ABN != "" {
		return o.Metadata.ABN
	}
	for _, t := range o.TaxIDs.Data {
		if t.Type == "au_abn" {
			return t.Value
		}
	}
	return ""
}

func epochPtr(sec int64) *time.Time {
	if sec == 0 {
		return nil
	}
	t := time.Unix(sec, 0).UTC()
	return &t
}

func sqlString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func isDup(err error) bool {
	var merr *gomysql.MySQLError
	return errors.As(err, &merr) && merr.Number == 1062
}
