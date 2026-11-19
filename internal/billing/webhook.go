package billing

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/jobs"
)

// KindStripeEvent is the jobs-table kind carrying a received Stripe event
// to the worker.
const KindStripeEvent = "billing.stripe_event"

// maxWebhookBody bounds webhook payloads read into memory.
const maxWebhookBody = 1 << 20

// eventEnvelope is the outer shape of every Stripe webhook payload; the
// object itself is re-parsed per event type by the worker handler.
type eventEnvelope struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Livemode bool   `json:"livemode"`
	Data     struct {
		Object json.RawMessage `json:"object"`
	} `json:"data"`
}

// WebhookRoutes returns the unversioned Stripe webhook handler
// (POST /stripe/webhook). Flow: verify signature → store the raw event in
// stripe_events (unique event_id → idempotent redelivery) → enqueue a
// billing.stripe_event job → 200 immediately. All real work happens in the
// worker.
func WebhookRoutes(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Post("/webhook", webhookHandler(d))
	return r
}

func webhookHandler(d Deps) http.HandlerFunc {
	q := d.queries()
	return func(w http.ResponseWriter, r *http.Request) {
		if d.WebhookSecret == "" {
			writeJSON(w, http.StatusServiceUnavailable,
				map[string]string{"error": "webhook_not_configured"})
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read_failed"})
			return
		}
		if err := VerifySignature(body, r.Header.Get("Stripe-Signature"), d.WebhookSecret, d.now()); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_signature"})
			return
		}
		var env eventEnvelope
		if err := json.Unmarshal(body, &env); err != nil || env.ID == "" || env.Type == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_payload"})
			return
		}
		if err := q.InsertStripeEvent(r.Context(), dbq.InsertStripeEventParams{
			ID: uuid.Must(uuid.NewV7()).String(), EventID: env.ID,
			Type: env.Type, Livemode: env.Livemode, Payload: body,
		}); err != nil {
			// The unique event_id key means a redelivery already stored the
			// event (possibly already processed): acknowledge without
			// re-enqueueing so the event is handled exactly once.
			if isDup(err) {
				writeJSON(w, http.StatusOK, map[string]any{"received": true, "duplicate": true})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_failed"})
			return
		}
		_, err = d.Queue.Enqueue(r.Context(), KindStripeEvent,
			map[string]string{"event_id": env.ID},
			jobs.WithDedupeKey("stripe:"+env.ID))
		if err != nil {
			// The event row is durable; a lost enqueue is recoverable by
			// scanning unprocessed stripe_events — still 500 so Stripe retries.
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "enqueue_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"received": true})
	}
}
