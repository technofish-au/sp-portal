// Package healthz is the liveness/readiness domain: GET /healthz.
package healthz

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// pingTimeout bounds the database ping inside the health check.
const pingTimeout = 2 * time.Second

// Routes returns the /healthz handler set. The handler pings the database;
// it answers 200 {"status":"ok"} when the process is up and the database
// is reachable, 503 otherwise. deps may be nil for a pure-liveness check.
func Routes(db *sql.DB, ver string) http.Handler {
	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if db != nil {
			ctx, cancel := context.WithTimeout(req.Context(), pingTimeout)
			defer cancel()
			if err := db.PingContext(ctx); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"status": "unavailable",
					"detail": "database unreachable",
				})
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"version": ver,
		})
	})
	return r
}
