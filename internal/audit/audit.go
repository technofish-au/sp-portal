// Package audit appends rows to the audit_log table. Every auth and
// billing state change writes one entry; the log is append-only by
// convention (no update/delete queries exist).
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/db/dbq"
)

// Auth/billing action names (target_type identifies what changed).
const (
	ActionSignup           = "auth.signup"
	ActionLogin            = "auth.login"
	ActionLoginFailed      = "auth.login_failed"
	ActionLogout           = "auth.logout"
	ActionEmailVerified    = "auth.email_verified"
	ActionTOTPEnabled      = "auth.totp_enabled"
	ActionTOTPDisabled     = "auth.totp_disabled"
	ActionOrgCreated       = "org.created"
	ActionCheckoutStarted  = "billing.checkout.started"
	ActionCheckoutDone     = "billing.checkout.completed"
	ActionCustomerCreated  = "billing.customer.created"
	ActionCustomerUpdated  = "billing.customer.updated"
	ActionSubStatus        = "billing.subscription.status"
	ActionSubSuspended     = "billing.subscription.suspended"
	ActionInvoicePaid      = "billing.invoice.paid"
	ActionInvoiceFailed    = "billing.invoice.payment_failed"
	ActionInvoiceSent      = "billing.invoice.sent"
	ActionPortalSession    = "billing.portal_session"
	ActionStripeEventError = "billing.stripe_event.error"
)

// Entry is one audit_log row. Empty OrgID/ActorUserID store NULL (the
// columns are deliberately not foreign keys). Detail is marshalled to
// JSON; nil stores NULL.
type Entry struct {
	OrgID       string
	ActorUserID string
	ActorEmail  string
	Action      string
	TargetType  string
	TargetID    string
	Detail      any
	IP          string
}

// Write appends e to audit_log.
func Write(ctx context.Context, q *dbq.Queries, e Entry) error {
	var detail json.RawMessage
	if e.Detail != nil {
		raw, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("audit: marshal detail: %w", err)
		}
		detail = raw
	}
	return q.InsertAuditLog(ctx, dbq.InsertAuditLogParams{
		ID:          uuid.Must(uuid.NewV7()).String(),
		OrgID:       nullStr(e.OrgID),
		ActorUserID: nullStr(e.ActorUserID),
		ActorEmail:  e.ActorEmail,
		Action:      e.Action,
		TargetType:  e.TargetType,
		TargetID:    e.TargetID,
		Detail:      detail,
		Ip:          e.IP,
	})
}

func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
