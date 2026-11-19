// Package httpapi wires the portal HTTP router: middleware, the /healthz
// domain and the versioned /v1 mount point where domain packages each add
// a single r.Mount line.
package httpapi

import (
	"crypto/rand"
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/technofish-au/sp-portal/internal/accounts"
	"github.com/technofish-au/sp-portal/internal/billing"
	"github.com/technofish-au/sp-portal/internal/config"
	"github.com/technofish-au/sp-portal/internal/healthz"
	"github.com/technofish-au/sp-portal/internal/jobs"
	"github.com/technofish-au/sp-portal/internal/licensing"
	"github.com/technofish-au/sp-portal/internal/mailer"
	"github.com/technofish-au/sp-portal/internal/releases"
	"github.com/technofish-au/sp-portal/internal/version"
	"github.com/technofish-au/sp-portal/internal/webui"
)

// Deps are the cross-domain dependencies the router hands to domain
// Routes() constructors.
type Deps struct {
	DB     *sql.DB
	Logger *slog.Logger
	Cfg    config.Config

	Queue  *jobs.Queue
	Mailer mailer.Mailer

	// Resolved secrets (cli resolves the *_file config values; AuthSecret
	// falls back to an ephemeral random key when unset).
	AuthSecret          []byte
	AltchaSecret        []byte
	Stripe              billing.Client // nil = billing disabled
	StripeWebhookSecret string

	Licensing licensing.Options

	// DownloadSecret keys the HMAC signing release download URLs (empty
	// = ephemeral dev key). BundleIssuer signs generated offline
	// bundles (nil = embedded DEV issuer).
	DownloadSecret []byte
	BundleIssuer   *licensing.Issuer
}

// NewRouter builds the portal's HTTP handler.
//
// Domain layout: each internal/<domain> package exposes routes.go with a
// Routes() http.Handler; registering a domain is a single Mount line here
// so parallel waves don't collide on router wiring.
func NewRouter(deps Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(
		middleware.RequestID,
		requestLogger(deps.Logger),
		middleware.Recoverer,
		middleware.Timeout(60*time.Second),
	)

	// Unversioned infrastructure endpoints.
	r.Mount("/healthz", healthz.Routes(deps.DB, version.Get().Version))

	// accounts owns /v1/auth/* and /v1/organisations* under a single
	// wildcard mount; more specific mounts (e.g. /v1/billing) win.
	acct := accounts.NewMust(deps.DB, accounts.Options{
		Secret:           authSecret(deps),
		SessionTTL:       deps.Cfg.SessionTTL,
		SecureCookies:    deps.Cfg.SecureCookies,
		PublicBaseURL:    deps.Cfg.PublicBaseURL,
		AltchaSecret:     deps.AltchaSecret,
		AltchaMaxNumber:  deps.Cfg.AltchaMaxNumber,
		TrialDays:        deps.Cfg.TrialDays,
		TrialMaxMachines: deps.Cfg.TrialMaxMachines,
		Queue:            deps.Queue,
	})
	bill := billing.Deps{
		DB: deps.DB, Queue: deps.Queue, Log: deps.Logger,
		Client: deps.Stripe, WebhookSecret: deps.StripeWebhookSecret,
		PublicBaseURL: deps.Cfg.PublicBaseURL,
		Prices: map[string]string{
			"starter":    deps.Cfg.StripePriceStarter,
			"pro":        deps.Cfg.StripePricePro,
			"enterprise": deps.Cfg.StripePriceEnterprise,
		},
		AutomaticTax:  deps.Cfg.StripeAutomaticTax,
		PastDueGrace:  deps.Cfg.PastDueGrace,
		SweepInterval: deps.Cfg.SuspendSweepInterval,
	}

	// Stripe's webhook is unversioned (POST /stripe/webhook): signature
	// verify -> stripe_events row -> jobs row -> 200, worker does the rest.
	r.Mount("/stripe", billing.WebhookRoutes(bill))

	// The appliance apt repository lives at the root too (GET /apt/*
	// basic-auth per docs/fakeportal.md), not under /v1.
	relOpts := releases.Options{
		StorageRoot:     deps.Cfg.StorageDir,
		PublicBaseURL:   deps.Cfg.PublicBaseURL,
		DownloadSecret:  deps.DownloadSecret,
		DownloadURLTTL:  deps.Cfg.DownloadURLTTL,
		BundleSigner:    deps.BundleIssuer,
		MaxSkew:         deps.Cfg.InstAuthMaxSkew,
		RateLimitPerMin: deps.Cfg.InstAuthRateLimitPerMin,
	}
	r.Mount("/apt", releases.AptHandler(deps.DB, deps.Logger, relOpts))

	// Versioned API surface; domain packages mount one line each as waves
	// land (see api/openapi.yaml for the documented shape).
	r.Route("/v1", func(r chi.Router) {
		r.Mount("/", accounts.Routes(acct))
		r.Mount("/billing", billing.Routes(acct, bill))
		// r.Mount("/licences", licences.Routes(deps))
		// r.Mount("/instances", instances.Routes(deps))
		// Licensing owns /activations, /check-ins, /licence and
		// /offline/activations; it registers directly on this mux since
		// chi refuses two Mount("/") calls (accounts holds the root).
		licensing.Mount(r, deps.DB, deps.Logger, deps.Licensing)
		// Releases owns /admin/releases*, /admin/offline-bundles,
		// /admin/storage/prune, /releases/download-urls,
		// /releases/{id}/download and /support-bundles.
		releases.Mount(r, deps.DB, deps.Logger, acct, relOpts)
	})

	// The embedded web UI catches everything else (SPA fallback lives in
	// internal/webui).
	r.Mount("/", webui.Handler())
	return r
}

// authSecret returns the resolved auth secret or a per-process ephemeral
// one (documented dev mode: sessions reset on restart).
func authSecret(deps Deps) []byte {
	if len(deps.AuthSecret) > 0 {
		return deps.AuthSecret
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

// statusRecorder captures the response status for the request log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// requestLogger logs one line per request at info level.
func requestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, req)
			log.Info("http request",
				slog.String("method", req.Method),
				slog.String("path", req.URL.Path),
				slog.Int("status", rec.status),
				slog.Duration("duration", time.Since(start)),
				slog.String("remote", req.RemoteAddr),
				slog.String("request_id", middleware.GetReqID(req.Context())),
			)
		})
	}
}
