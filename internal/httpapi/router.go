// Package httpapi wires the portal HTTP router: middleware, the /healthz
// domain and the versioned /v1 mount point where domain packages each add
// a single r.Mount line.
package httpapi

import (
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/technofish-au/sp-portal/internal/healthz"
	"github.com/technofish-au/sp-portal/internal/licensing"
	"github.com/technofish-au/sp-portal/internal/version"
	"github.com/technofish-au/sp-portal/internal/webui"
)

// Deps are the cross-domain dependencies the router hands to domain
// Routes() constructors.
type Deps struct {
	DB        *sql.DB
	Logger    *slog.Logger
	Licensing licensing.Options
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

	// Versioned API surface; domain packages mount one line each as waves
	// land (see api/openapi.yaml for the documented shape).
	r.Route("/v1", func(r chi.Router) {
		// r.Mount("/organisations", organisations.Routes(deps))
		// r.Mount("/licences", licences.Routes(deps))
		// r.Mount("/instances", instances.Routes(deps))
		// r.Mount("/releases", releases.Routes(deps))
		// Licensing owns its own path set (/activations, /check-ins,
		// /licence, /offline/activations) so it mounts at the /v1 root;
		// chi prefers the more specific mounts above when they land.
		r.Mount("/", licensing.Routes(deps.DB, deps.Logger, deps.Licensing))
	})

	// The embedded web UI catches everything else (SPA fallback lives in
	// internal/webui).
	r.Mount("/", webui.Handler())
	return r
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
