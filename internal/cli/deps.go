package cli

import (
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/technofish-au/sp-portal/internal/billing"
	"github.com/technofish-au/sp-portal/internal/config"
	"github.com/technofish-au/sp-portal/internal/httpapi"
	"github.com/technofish-au/sp-portal/internal/jobs"
	"github.com/technofish-au/sp-portal/internal/licensing"
	"github.com/technofish-au/sp-portal/internal/mailer"
	"github.com/technofish-au/sp-portal/internal/secrets"
)

// readSecret resolves an optional file-mounted secret (empty path →
// empty result, no error).
func readSecret(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	return secrets.ReadFile(path)
}

// buildDeps resolves the configured secrets and builds the cross-domain
// dependencies for the HTTP router.
func buildDeps(cfg config.Config, sqlDB *sql.DB, logger *slog.Logger) (httpapi.Deps, error) {
	authSecret, err := readSecret(cfg.AuthSecretFile)
	if err != nil {
		return httpapi.Deps{}, fmt.Errorf("auth secret: %w", err)
	}
	if len(authSecret) == 0 {
		logger.Warn("auth_secret_file unset: using ephemeral key — sessions and TOTP reset on restart (dev mode)")
	}
	altchaSecret, err := readSecret(cfg.AltchaSecretFile)
	if err != nil {
		return httpapi.Deps{}, fmt.Errorf("altcha secret: %w", err)
	}
	ml, err := mailer.New(cfg, logger)
	if err != nil {
		return httpapi.Deps{}, err
	}
	var stripe billing.Client
	if cfg.StripeSecretKeyFile != "" {
		key, err := secrets.ReadString(cfg.StripeSecretKeyFile)
		if err != nil {
			return httpapi.Deps{}, fmt.Errorf("stripe secret key: %w", err)
		}
		stripe = billing.NewStripeClient(key)
	}
	var whSecret string
	if cfg.StripeWebhookSecretFile != "" {
		s, err := secrets.ReadString(cfg.StripeWebhookSecretFile)
		if err != nil {
			return httpapi.Deps{}, fmt.Errorf("stripe webhook secret: %w", err)
		}
		whSecret = s
	}
	issuer, err := licenceIssuer(cfg, logger)
	if err != nil {
		return httpapi.Deps{}, fmt.Errorf("licence issuer: %w", err)
	}
	return httpapi.Deps{
		DB: sqlDB, Logger: logger, Cfg: cfg,
		Queue:               jobs.NewQueue(sqlDB),
		Mailer:              ml,
		AuthSecret:          authSecret,
		AltchaSecret:        altchaSecret,
		Stripe:              stripe,
		StripeWebhookSecret: whSecret,
		Licensing: licensing.Options{
			Issuer:          issuer,
			MaxSkew:         cfg.InstAuthMaxSkew,
			RateLimitPerMin: cfg.InstAuthRateLimitPerMin,
		},
	}, nil
}

// billingDeps builds the billing domain deps for the job worker (event
// processing works off stored payloads — no outbound Stripe calls needed,
// but prices/config still apply).
func billingDeps(cfg config.Config, sqlDB *sql.DB, logger *slog.Logger) billing.Deps {
	return billing.Deps{
		DB: sqlDB, Queue: jobs.NewQueue(sqlDB), Log: logger,
		PublicBaseURL: cfg.PublicBaseURL,
		Prices: map[string]string{
			"starter":    cfg.StripePriceStarter,
			"pro":        cfg.StripePricePro,
			"enterprise": cfg.StripePriceEnterprise,
		},
		AutomaticTax:  cfg.StripeAutomaticTax,
		PastDueGrace:  cfg.PastDueGrace,
		SweepInterval: cfg.SuspendSweepInterval,
	}
}
