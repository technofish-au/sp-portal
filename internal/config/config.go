// Package config loads the sp-portal configuration with koanf.
//
// Sources, in increasing precedence (mirroring sp-server's internal/config):
//
//  1. built-in defaults,
//  2. an optional YAML file (PORTAL_CONFIG_FILE, default
//     /etc/sp-portal/portal.yaml; ignored if the default path doesn't exist,
//     an error if an explicitly configured file is missing),
//  3. PORTAL_* environment variables (PORTAL_ + the upper-cased YAML key).
//
// Load takes the environment lookup and file reader as functions, so tests
// never touch the real process environment or file system.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"

	"github.com/technofish-au/sp-portal/internal/logging"
)

// EnvPrefix prefixes every environment variable read by Load.
const EnvPrefix = "PORTAL_"

// EnvConfigFile names the YAML config file; DefaultConfigFile applies when unset.
const (
	EnvConfigFile     = "PORTAL_CONFIG_FILE"
	DefaultConfigFile = "/etc/sp-portal/portal.yaml"
)

// Config is the resolved portal configuration. The koanf tags are the YAML
// keys; the environment variable of a key is EnvPrefix + upper(key).
type Config struct {
	HTTPAddr string `koanf:"http_addr"`
	LogLevel string `koanf:"log_level"`

	// MariaDB connection. The unix socket is the default transport
	// (db_socket); setting db_host switches to TCP (db_host:db_port) and
	// the socket is ignored.
	DBName   string `koanf:"db_name"`
	DBUser   string `koanf:"db_user"`
	DBSocket string `koanf:"db_socket"`
	DBHost   string `koanf:"db_host"`
	DBPort   int    `koanf:"db_port"`
	// DBPassword is the inline password (dev convenience). Prefer
	// DBPasswordFile, a Podman-secret style file whose mode must be
	// 0400 or 0600; when set the file wins.
	DBPassword     string `koanf:"db_password"`
	DBPasswordFile string `koanf:"db_password_file"`

	DBMaxOpenConns    int           `koanf:"db_max_open_conns"`
	DBMaxIdleConns    int           `koanf:"db_max_idle_conns"`
	DBConnMaxLifetime time.Duration `koanf:"db_conn_max_lifetime"`

	// StorageDir is the on-disk storage root; subdirectories
	// (releases/, apt/, offline-bundles/, support-bundles/, exports/) are
	// created on startup by internal/storage.
	StorageDir string `koanf:"storage_dir"`

	// Job worker tunables.
	WorkerInterval     time.Duration `koanf:"worker_interval"`
	WorkerBatchSize    int           `koanf:"worker_batch_size"`
	WorkerStaleTimeout time.Duration `koanf:"worker_stale_timeout"`

	// PublicBaseURL is the externally reachable base of the service
	// (https://portal.example.com); used in email links and Stripe
	// redirect URLs.
	PublicBaseURL string `koanf:"public_base_url"`

	// Auth: auth_secret_file is a file-mounted secret (0400/0600) keying
	// session-cookie HMACs, email-verification tokens and TOTP secret
	// sealing. Empty generates an ephemeral key at startup — fine for dev
	// (sessions reset on restart) but production must set it.
	AuthSecretFile string        `koanf:"auth_secret_file"`
	SessionTTL     time.Duration `koanf:"session_ttl"`
	// SecureCookies sets the Secure attribute on session cookies; enable
	// when the portal is served over TLS.
	SecureCookies bool `koanf:"secure_cookies"`

	// Sign-up bot protection: ALTCHA (self-hosted proof-of-work, no
	// outbound calls). altcha_secret_file is the file-mounted HMAC key;
	// empty disables the widget entirely (dev bypass). altcha_max_number
	// bounds the proof-of-work difficulty.
	AltchaSecretFile string `koanf:"altcha_secret_file"`
	AltchaMaxNumber  int    `koanf:"altcha_max_number"`

	// Trial: sign-up creates a trial subscription valid trial_days days
	// and capped at trial_max_machines machines.
	TrialDays        int `koanf:"trial_days"`
	TrialMaxMachines int `koanf:"trial_max_machines"`

	// Billing: a subscription stuck in past_due for longer than
	// past_due_grace is suspended by the sweep that runs
	// every suspend_sweep_interval.
	PastDueGrace         time.Duration `koanf:"past_due_grace"`
	SuspendSweepInterval time.Duration `koanf:"suspend_sweep_interval"`

	// Outbound mail. smtp_host empty disables SMTP and logs messages
	// instead (dev default); point it at Mailpit in dev compose.
	SMTPHost         string `koanf:"smtp_host"`
	SMTPPort         int    `koanf:"smtp_port"`
	SMTPUser         string `koanf:"smtp_user"`
	SMTPPasswordFile string `koanf:"smtp_password_file"`
	SMTPStartTLS     bool   `koanf:"smtp_starttls"`
	MailFrom         string `koanf:"mail_from"`
	MailFromName     string `koanf:"mail_from_name"`

	// Stripe credentials are file-mounted secrets (same 0400/0600 rule as
	// db_password_file); empty disables Stripe integration.
	StripeSecretKeyFile     string `koanf:"stripe_secret_key_file"`
	StripeWebhookSecretFile string `koanf:"stripe_webhook_secret_file"`
	// Plan -> Stripe price id (price_...) for Checkout Sessions.
	StripePriceStarter    string `koanf:"stripe_price_starter"`
	StripePricePro        string `koanf:"stripe_price_pro"`
	StripePriceEnterprise string `koanf:"stripe_price_enterprise"`
	// StripeAutomaticTax turns on automatic_tax on Checkout Sessions and
	// invoices (requires Stripe Tax registration).
	StripeAutomaticTax bool `koanf:"stripe_automatic_tax"`
}

// defaults lists every key with its default value. It doubles as the list of
// keys looked up in the environment.
func defaults() map[string]any {
	return map[string]any{
		"http_addr":                  ":8080",
		"log_level":                  "info",
		"db_name":                    "portal",
		"db_user":                    "portal",
		"db_socket":                  "/run/mysqld/mysqld.sock",
		"db_host":                    "",
		"db_port":                    3306,
		"db_password":                "",
		"db_password_file":           "",
		"db_max_open_conns":          16,
		"db_max_idle_conns":          4,
		"db_conn_max_lifetime":       "5m",
		"storage_dir":                "/var/lib/sp-portal",
		"worker_interval":            "1s",
		"worker_batch_size":          32,
		"worker_stale_timeout":       "5m",
		"public_base_url":            "http://localhost:8080",
		"auth_secret_file":           "",
		"session_ttl":                "336h",
		"secure_cookies":             false,
		"altcha_secret_file":         "",
		"altcha_max_number":          50000,
		"trial_days":                 30,
		"trial_max_machines":         25,
		"past_due_grace":             "336h",
		"suspend_sweep_interval":     "1h",
		"smtp_host":                  "",
		"smtp_port":                  25,
		"smtp_user":                  "",
		"smtp_password_file":         "",
		"smtp_starttls":              false,
		"mail_from":                  "portal@serverperch.com",
		"mail_from_name":             "ServerPerch Portal",
		"stripe_secret_key_file":     "",
		"stripe_webhook_secret_file": "",
		"stripe_price_starter":       "",
		"stripe_price_pro":           "",
		"stripe_price_enterprise":    "",
		"stripe_automatic_tax":       false,
	}
}

// EnvVar returns the environment variable name for a YAML key.
func EnvVar(key string) string { return EnvPrefix + strings.ToUpper(key) }

// Load resolves the configuration. env looks up an environment variable
// ("" = unset); readFile reads the YAML file. Use LoadFromOS for the real
// process environment.
func Load(env func(string) string, readFile func(string) ([]byte, error)) (Config, error) {
	k := koanf.New(".")
	if err := k.Load(confmap.Provider(defaults(), "."), nil); err != nil {
		return Config{}, fmt.Errorf("config: defaults: %w", err)
	}
	if err := loadFile(k, env, readFile); err != nil {
		return Config{}, err
	}
	if err := k.Load(confmap.Provider(envValues(env), "."), nil); err != nil {
		return Config{}, fmt.Errorf("config: environment: %w", err)
	}
	cfg, err := unmarshal(k)
	if err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// LoadFromOS is Load with os.Getenv and os.ReadFile.
func LoadFromOS() (Config, error) { return Load(os.Getenv, os.ReadFile) }

func loadFile(k *koanf.Koanf, env func(string) string, readFile func(string) ([]byte, error)) error {
	path := strings.TrimSpace(env(EnvConfigFile))
	explicit := path != ""
	if !explicit {
		path = DefaultConfigFile
	}
	data, err := readFile(path)
	if err != nil {
		if !explicit && errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := k.Load(rawbytes.Provider(data), yaml.Parser()); err != nil {
		return fmt.Errorf("config: parse %s: %w", path, err)
	}
	return nil
}

// envValues collects the PORTAL_* variables for every known key. Blank
// values count as unset.
func envValues(env func(string) string) map[string]any {
	out := map[string]any{}
	for key := range defaults() {
		if v := strings.TrimSpace(env(EnvVar(key))); v != "" {
			out[key] = v
		}
	}
	return out
}

func unmarshal(k *koanf.Koanf) (Config, error) {
	var cfg Config
	err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{
		Tag: "koanf",
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook:       mapstructure.StringToTimeDurationHookFunc(),
			ErrorUnused:      true, // typos in the YAML file are errors
			WeaklyTypedInput: true, // env values are strings
			Result:           &cfg,
			TagName:          "koanf",
		},
	})
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// UseTCP reports whether the MariaDB connection uses TCP (db_host set)
// rather than the default unix socket.
func (c Config) UseTCP() bool { return strings.TrimSpace(c.DBHost) != "" }

// DBAddr returns the dial address for the configured transport: the
// host:port pair for TCP or the socket path for unix.
func (c Config) DBAddr() string {
	if c.UseTCP() {
		return net.JoinHostPort(c.DBHost, fmt.Sprintf("%d", c.DBPort))
	}
	return c.DBSocket
}

// Validate checks value ranges.
func (c Config) Validate() error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	if strings.TrimSpace(c.HTTPAddr) == "" {
		add("http_addr must not be empty")
	}
	if _, err := logging.ParseLevel(c.LogLevel); err != nil {
		add("log_level: %v", err)
	}
	if strings.TrimSpace(c.DBName) == "" {
		add("db_name must not be empty")
	}
	if strings.TrimSpace(c.DBUser) == "" {
		add("db_user must not be empty")
	}
	if c.UseTCP() {
		if c.DBPort < 1 || c.DBPort > 65535 {
			add("db_port must be between 1 and 65535")
		}
	} else if strings.TrimSpace(c.DBSocket) == "" {
		add("db_socket must not be empty (or set db_host for TCP)")
	}
	if c.DBMaxOpenConns < 1 {
		add("db_max_open_conns must be >= 1")
	}
	if c.DBMaxIdleConns < 0 || c.DBMaxIdleConns > c.DBMaxOpenConns {
		add("db_max_idle_conns must be >= 0 and <= db_max_open_conns")
	}
	if c.DBConnMaxLifetime < 0 {
		add("db_conn_max_lifetime must be >= 0")
	}
	if strings.TrimSpace(c.StorageDir) == "" {
		add("storage_dir must not be empty")
	}
	if c.WorkerInterval <= 0 {
		add("worker_interval must be positive")
	}
	if c.WorkerBatchSize < 1 {
		add("worker_batch_size must be >= 1")
	}
	if c.WorkerStaleTimeout <= 0 {
		add("worker_stale_timeout must be positive")
	}
	if strings.TrimSpace(c.PublicBaseURL) == "" {
		add("public_base_url must not be empty")
	}
	if c.SessionTTL <= 0 {
		add("session_ttl must be positive")
	}
	if c.AltchaMaxNumber < 1 {
		add("altcha_max_number must be >= 1")
	}
	if c.TrialDays < 1 {
		add("trial_days must be >= 1")
	}
	if c.TrialMaxMachines < 1 {
		add("trial_max_machines must be >= 1")
	}
	if c.PastDueGrace <= 0 {
		add("past_due_grace must be positive")
	}
	if c.SuspendSweepInterval <= 0 {
		add("suspend_sweep_interval must be positive")
	}
	if c.SMTPPort < 1 || c.SMTPPort > 65535 {
		add("smtp_port must be between 1 and 65535")
	}
	if len(errs) > 0 {
		return fmt.Errorf("config: %s", strings.Join(errs, "; "))
	}
	return nil
}
