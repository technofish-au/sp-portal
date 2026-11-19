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
	dlSecret, err := readSecret(cfg.DownloadSecretFile)
	if err != nil {
		return httpapi.Deps{}, fmt.Errorf("download secret: %w", err)
	}
	if len(dlSecret) == 0 {
		logger.Warn("download_secret_file unset: using ephemeral key — signed download URLs die on restart (dev mode)")
	}
	bundleIssuer, err := bundleIssuer(cfg, issuer, logger)
	if err != nil {
		return httpapi.Deps{}, fmt.Errorf("bundle signing key: %w", err)
	}
	return httpapi.Deps{
		DB: sqlDB, Logger: logger, Cfg: cfg,
		Queue:               jobs.NewQueue(sqlDB),
		Mailer:              ml,
		AuthSecret:          authSecret,
		AltchaSecret:        altchaSecret,
		Stripe:              stripe,
		StripeWebhookSecret: whSecret,
		DownloadSecret:      dlSecret,
		BundleIssuer:        bundleIssuer,
		Licensing: licensing.Options{
			Issuer:          issuer,
			MaxSkew:         cfg.InstAuthMaxSkew,
			RateLimitPerMin: cfg.InstAuthRateLimitPerMin,
		},
	}, nil
}

// bundleIssuer resolves the offline-bundle signing key: the configured
// file-mounted key under bundle_signing_kid, or — when no key file is
// set — the licence issuer (documented dev default; the licence key is
// already resolved by this point, including the embedded DEV fallback).
func bundleIssuer(cfg config.Config, licence *licensing.Issuer, logger *slog.Logger) (*licensing.Issuer, error) {
	if cfg.BundleSigningKeyFile == "" {
		logger.Info("bundle_signing_key_file unset; offline bundles signed by the licence issuer",
			slog.String("kid", licence.KID()))
		return licence, nil
	}
	contents, err := secrets.ReadString(cfg.BundleSigningKeyFile)
	if err != nil {
		return nil, err
	}
	return licensing.LoadIssuer(cfg.BundleSigningKID, contents)
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
