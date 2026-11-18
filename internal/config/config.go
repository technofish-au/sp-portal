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

	// Stripe credentials are file-mounted secrets (same 0400/0600 rule as
	// db_password_file); empty disables Stripe integration.
	StripeSecretKeyFile     string `koanf:"stripe_secret_key_file"`
	StripeWebhookSecretFile string `koanf:"stripe_webhook_secret_file"`
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
		"stripe_secret_key_file":     "",
		"stripe_webhook_secret_file": "",
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
	if len(errs) > 0 {
		return fmt.Errorf("config: %s", strings.Join(errs, "; "))
	}
	return nil
}
