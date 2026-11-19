// Package licensing is the licence domain: appliance activation, periodic
// check-ins, licence retrieval and offline (air-gapped) activation. It
// owns the signed licence document format and uses internal/instauth for
// the SP-Ed25519 instance-authentication scheme. docs/fakeportal.md is the
// external contract.
package licensing

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/instauth"
)

// Options configures the domain; zero values take the dev defaults.
type Options struct {
	// Issuer signs licence documents. Nil uses the embedded DEV-ONLY
	// issuer (DevIssuer) — acceptable for dev/tests, never for production.
	Issuer *Issuer
	// MaxSkew is the instance-auth timestamp window (default 10m).
	MaxSkew time.Duration
	// RateLimitPerMin bounds authenticated requests per instance (default
	// 60).
	RateLimitPerMin int
	// Now is the clock (tests).
	Now func() time.Time
}

// service carries the handlers' dependencies.
type service struct {
	q      *dbq.Queries
	keys   *instauth.Store
	issuer *Issuer
	now    func() time.Time
}

// Routes returns the domain handler mounted under /v1:
//
//	POST /activations          (licence-key credential)
//	POST /offline/activations  (org + licence-key credential — auth stub)
//	POST /check-ins            (SP-Ed25519 instance auth)
//	GET  /licence              (SP-Ed25519 instance auth)
func Routes(db *sql.DB, logger *slog.Logger, opts Options) http.Handler {
	issuer := opts.Issuer
	if issuer == nil {
		var err error
		issuer, err = DevIssuer()
		if err != nil {
			// Only possible if the embedded key were corrupted.
			panic(err)
		}
		if logger != nil {
			logger.Warn("using embedded DEV licence signing key — never for production",
				slog.String("kid", issuer.KID()))
		}
	}
	authn := instauth.New(db, instauth.Options{
		MaxSkew:         opts.MaxSkew,
		RateLimitPerMin: opts.RateLimitPerMin,
		Now:             opts.Now,
	})
	svc := &service{
		q:      dbq.New(db),
		keys:   authn.KeyStore(),
		issuer: issuer,
		now:    opts.Now,
	}
	if svc.now == nil {
		svc.now = func() time.Time { return time.Now().UTC() }
	}

	r := chi.NewRouter()
	r.Post("/activations", svc.activate)
	r.Post("/offline/activations", svc.offlineActivate)
	r.Group(func(r chi.Router) {
		r.Use(authn.Middleware)
		r.Post("/check-ins", svc.checkIn)
		r.Get("/licence", svc.getLicence)
	})
	return r
}

// newID generates a uuidv7 primary key.
func newID() string { return uuid.Must(uuid.NewV7()).String() }

// writeJSON writes v as the JSON response body.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr writes the {error, message} envelope.
func writeErr(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}
