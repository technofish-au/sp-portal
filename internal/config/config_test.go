package config

import (
	"errors"
	"io/fs"
	"testing"
)

// envOf returns an env lookup over a map.
func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// noFile fails every read (no config file).
func noFile(string) ([]byte, error) { return nil, fs.ErrNotExist }

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(envOf(nil), noFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPAddr != ":8080" || cfg.DBName != "portal" || cfg.DBSocket == "" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.UseTCP() {
		t.Fatal("default transport must be the unix socket")
	}
	if got := cfg.DBAddr(); got != cfg.DBSocket {
		t.Fatalf("DBAddr = %q, want socket %q", got, cfg.DBSocket)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	cfg, err := Load(envOf(map[string]string{
		"PORTAL_HTTP_ADDR": ":9090",
		"PORTAL_DB_HOST":   "mariadb.internal",
		"PORTAL_DB_PORT":   "3307",
		"PORTAL_DB_NAME":   "portal_test",
	}), noFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPAddr != ":9090" || cfg.DBName != "portal_test" || cfg.DBPort != 3307 {
		t.Fatalf("env overrides not applied: %+v", cfg)
	}
	if !cfg.UseTCP() {
		t.Fatal("db_host must select TCP transport")
	}
	if got := cfg.DBAddr(); got != "mariadb.internal:3307" {
		t.Fatalf("DBAddr = %q", got)
	}
}

func TestLoadYAMLFile(t *testing.T) {
	yaml := []byte("http_addr: ':7070'\nworker_batch_size: 64\n")
	cfg, err := Load(envOf(map[string]string{EnvConfigFile: "/x/portal.yaml"}),
		func(path string) ([]byte, error) {
			if path != "/x/portal.yaml" {
				return nil, errors.New("unexpected path")
			}
			return yaml, nil
		})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPAddr != ":7070" || cfg.WorkerBatchSize != 64 {
		t.Fatalf("file values not applied: %+v", cfg)
	}
}

func TestLoadEnvBeatsFile(t *testing.T) {
	yaml := []byte("http_addr: ':7070'\n")
	cfg, err := Load(envOf(map[string]string{
		EnvConfigFile:      "/x/portal.yaml",
		"PORTAL_HTTP_ADDR": ":9090",
	}), func(string) ([]byte, error) { return yaml, nil })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPAddr != ":9090" {
		t.Fatalf("env must override file, got %q", cfg.HTTPAddr)
	}
}

func TestLoadMissingExplicitFileIsError(t *testing.T) {
	_, err := Load(envOf(map[string]string{EnvConfigFile: "/nope.yaml"}), noFile)
	if err == nil {
		t.Fatal("expected error for explicitly configured missing file")
	}
}

func TestLoadUnknownYAMLKeyIsError(t *testing.T) {
	yaml := []byte("nope: 1\n")
	_, err := Load(envOf(map[string]string{EnvConfigFile: "/x.yaml"}),
		func(string) ([]byte, error) { return yaml, nil })
	if err == nil {
		t.Fatal("expected error for unknown YAML key")
	}
}

func TestValidateErrors(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"bad db_port":   {"PORTAL_DB_HOST": "h", "PORTAL_DB_PORT": "0"},
		"bad log level": {"PORTAL_LOG_LEVEL": "chatty"},
		"zero batch":    {"PORTAL_WORKER_BATCH_SIZE": "0"},
	} {
		if _, err := Load(envOf(env), noFile); err == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}
}

func TestValidateEmptySocket(t *testing.T) {
	// An explicit empty db_socket (env blanks count as unset, so only the
	// YAML file can express it) with no db_host is an error.
	yaml := []byte("db_socket: ''\n")
	_, err := Load(envOf(map[string]string{EnvConfigFile: "/x.yaml"}),
		func(string) ([]byte, error) { return yaml, nil })
	if err == nil {
		t.Fatal("expected validation error")
	}
}
