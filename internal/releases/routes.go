// Package releases is the release-catalogue domain (wave R5-4): the
// staff admin API for the release catalogue (register, publish,
// withdraw, security flag, storage prune), HMAC-signed artifact download
// URLs served with HTTP range support, the appliance apt repository, and
// the support-bundle upload leg. docs/fakeportal.md is the external
// contract for the appliance-facing endpoints.
package releases

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/accounts"
	"github.com/technofish-au/sp-portal/internal/audit"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/instauth"
	"github.com/technofish-au/sp-portal/internal/licensing"
)

// Options configures the domain; zero values take the dev defaults.
type Options struct {
	// StorageRoot is the resolved storage directory (internal/storage
	// layout — releases/, apt/, offline-bundles/, support-bundles/ must
	// already exist; storage.Ensure does that at startup).
	StorageRoot string
	// PublicBaseURL prefixes minted download URLs ("" = path-relative).
	PublicBaseURL string
	// DownloadSecret keys the download-URL HMAC; empty generates an
	// ephemeral key (minted URLs die with the process — dev only).
	DownloadSecret []byte
	// DownloadURLTTL bounds minted download URLs (default 15m).
	DownloadURLTTL time.Duration
	// BundleSigner signs generated offline bundles. Nil uses the
	// embedded DEV-ONLY issuer (licensing.DevIssuer).
	BundleSigner *licensing.Issuer
	// MaxSkew is the instance-auth timestamp window (default 10m).
	MaxSkew time.Duration
	// RateLimitPerMin bounds authenticated requests per instance
	// (default 60).
	RateLimitPerMin int
	// SupportBundleMaxBytes caps support-bundle uploads (default 64MiB).
	SupportBundleMaxBytes int64
	// SupportBundleTTL is the retention stamped on uploads (default 90d).
	SupportBundleTTL time.Duration
	// Now is the clock (tests).
	Now func() time.Time
}

// Defaults.
const (
	defaultDownloadTTL       = 15 * time.Minute
	defaultBundleMaxBytes    = 64 << 20
	defaultSupportBundleTTL  = 90 * 24 * time.Hour
	tokenKindRelease         = "release"
	tokenKindApt             = "apt"
	downloadTokenHashPurpose = "SP-DL-V1" // purpose line of the signed string (docs/fakeportal.md)
)

// service carries the handlers' dependencies.
type service struct {
	q      *dbq.Queries
	log    *slog.Logger
	authn  *instauth.Auth
	opts   Options
	signer *licensing.Issuer
	now    func() time.Time
}

// Routes returns the domain handler for standalone use (tests): all the
// /v1 paths plus the /apt tree, rooted as Mount/AptHandler would see
// them.
func Routes(db *sql.DB, logger *slog.Logger, acct *accounts.Service, opts Options) http.Handler {
	r := chi.NewRouter()
	Mount(r, db, logger, acct, opts)
	r.Mount("/apt", AptHandler(db, logger, opts))
	return r
}

// Mount registers the domain's /v1 routes directly on r (chi refuses two
// Mount("/") calls — accounts already holds the /v1 root, so the domain
// registers its own paths, same pattern as internal/licensing).
//
//	POST   /admin/releases                        staff session
//	GET    /admin/releases                        staff session
//	PATCH  /admin/releases/{releaseID}            staff session
//	POST   /admin/releases/{releaseID}/publish    staff session
//	POST   /admin/releases/{releaseID}/withdraw   staff session
//	POST   /admin/releases/{releaseID}/offline-bundle  staff session
//	GET    /admin/offline-bundles                 staff session
//	POST   /admin/storage/prune                   staff session
//	POST   /releases/download-urls                SP-Ed25519 instance auth
//	GET    /releases/{releaseID}/download         signed download token
//	POST   /support-bundles                       SP-Ed25519 instance auth
func Mount(r chi.Router, db *sql.DB, logger *slog.Logger, acct *accounts.Service, opts Options) {
	svc := newService(db, logger, opts)

	// Staff catalogue admin — session cookie + is_platform_admin.
	r.Group(func(r chi.Router) {
		r.Use(acct.SessionMiddleware())
		r.Use(accounts.RequireAuth)
		r.Use(svc.requireStaff)
		r.Post("/admin/releases", svc.registerRelease)
		r.Get("/admin/releases", svc.listReleases)
		r.Patch("/admin/releases/{releaseID}", svc.updateRelease)
		r.Post("/admin/releases/{releaseID}/publish", svc.publishRelease)
		r.Post("/admin/releases/{releaseID}/withdraw", svc.withdrawRelease)
		r.Post("/admin/releases/{releaseID}/offline-bundle", svc.generateBundle)
		r.Get("/admin/offline-bundles", svc.listBundles)
		r.Post("/admin/storage/prune", svc.pruneStorage)
	})

	// Appliance-facing endpoints (SP-Ed25519, same scheme as licensing).
	r.Group(func(r chi.Router) {
		r.Use(svc.authn.Middleware)
		r.Post("/releases/download-urls", svc.mintDownloadURL)
		r.Post("/support-bundles", svc.uploadSupportBundle)
	})

	// Signed-URL download: the t= token is the credential, so no session
	// or instance auth — the URL is the capability.
	r.Get("/releases/{releaseID}/download", svc.serveDownload)
}

// AptHandler serves the hosted apt repository at GET /apt/* with HTTP
// basic auth (download_tokens kind "apt" — minted by licensing at
// activation). Mounted at the router root, not under /v1.
func AptHandler(db *sql.DB, logger *slog.Logger, opts Options) http.Handler {
	svc := newService(db, logger, opts)
	r := chi.NewRouter()
	r.Get("/*", svc.serveApt)
	return r
}

// newService normalises Options into a service.
func newService(db *sql.DB, logger *slog.Logger, opts Options) *service {
	if opts.DownloadURLTTL <= 0 {
		opts.DownloadURLTTL = defaultDownloadTTL
	}
	if opts.SupportBundleMaxBytes <= 0 {
		opts.SupportBundleMaxBytes = defaultBundleMaxBytes
	}
	if opts.SupportBundleTTL <= 0 {
		opts.SupportBundleTTL = defaultSupportBundleTTL
	}
	if len(opts.DownloadSecret) == 0 {
		opts.DownloadSecret = ephemeralSecret()
		if logger != nil {
			logger.Warn("download_secret_file unset: ephemeral download-URL key — minted URLs die on restart (dev mode)")
		}
	}
	signer := opts.BundleSigner
	if signer == nil {
		var err error
		signer, err = licensing.DevIssuer()
		if err != nil {
			panic(err)
		}
		if logger != nil {
			logger.Warn("using embedded DEV bundle signing key — never for production",
				slog.String("kid", signer.KID()))
		}
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &service{
		q:   dbq.New(db),
		log: logger,
		authn: instauth.New(db, instauth.Options{
			MaxSkew:         opts.MaxSkew,
			RateLimitPerMin: opts.RateLimitPerMin,
			// Support-bundle uploads sign the whole body, so the auth
			// middleware's buffer must cover the upload cap.
			MaxBody: max(opts.SupportBundleMaxBytes, 1<<20),
			Now:     opts.Now,
		}),
		opts:   opts,
		signer: signer,
		now:    now,
	}
}

// requireStaff rejects non-staff sessions: the user must exist, be fully
// authenticated and carry users.is_platform_admin.
func (s *service) requireStaff(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := accounts.SessionFrom(r.Context())
		if !ok {
			writeErr(w, http.StatusUnauthorized, "not_authenticated", "sign-in required")
			return
		}
		if !sess.User.IsPlatformAdmin {
			writeErr(w, http.StatusForbidden, "forbidden", "platform admin required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// storagePath resolves a storage-root-relative path, refusing traversal
// outside root.
func (s *service) storagePath(sub, rel string) (string, bool) {
	return storageJoin(s.opts.StorageRoot, sub, rel)
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

// releaseView is the staff/customer view of a releases row.
func releaseView(rel dbq.Release) map[string]any {
	return map[string]any{
		"id":               rel.ID,
		"version":          rel.Version,
		"component":        rel.Component,
		"channel":          rel.Channel,
		"notes":            rel.Notes,
		"min_upgrade_from": rel.MinUpgradeFrom,
		"security":         rel.Security,
		"artifact_path":    rel.ArtifactPath,
		"sha256":           rel.Sha256,
		"size_bytes":       rel.SizeBytes,
		"published":        rel.PublishedAt != nil && rel.WithdrawnAt == nil,
		"published_at":     rel.PublishedAt,
		"withdrawn_at":     rel.WithdrawnAt,
		"created_at":       rel.CreatedAt,
	}
}

// logAudit appends an audit_log row for a staff action; failures are
// logged, not fatal (the state change already committed).
func (s *service) logAudit(r *http.Request, action, targetType, targetID string, detail any) {
	entry := audit.Entry{
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Detail:     detail,
		IP:         clientIP(r),
	}
	if sess, ok := accounts.SessionFrom(r.Context()); ok {
		entry.ActorUserID = sess.User.ID
		entry.ActorEmail = sess.User.Email
	}
	if err := audit.Write(r.Context(), s.q, entry); err != nil && s.log != nil {
		s.log.Warn("audit write failed",
			slog.String("action", action), slog.String("error", err.Error()))
	}
}

// clientIP returns the request's client IP for audit entries (direct
// peer only — forwarded headers are not trusted).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
