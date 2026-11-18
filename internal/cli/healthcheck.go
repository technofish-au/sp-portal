package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// healthcheckTimeout bounds the whole healthcheck request.
const healthcheckTimeout = 5 * time.Second

// healthURL derives the loopback health URL from a listen address such as
// ":8080", "0.0.0.0:8080" or "127.0.0.1:9000".
func healthURL(addr string) (string, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid PORTAL_HTTP_ADDR %q: %w", addr, err)
	}
	if port == "" {
		return "", fmt.Errorf("invalid PORTAL_HTTP_ADDR %q: missing port", addr)
	}
	return "http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz", nil
}

// runHealthcheck is used by container HEALTHCHECKs: it exits 0 only if the
// local server answers 200 with {"status":"ok"}.
func runHealthcheck(ctx context.Context, stderr io.Writer) int {
	cfg, err := loadPortalConfig()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal healthcheck: %v\n", err)
		return ExitError
	}
	url, err := healthURL(cfg.HTTPAddr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal healthcheck: %v\n", err)
		return ExitError
	}
	if err := checkHealth(ctx, url); err != nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal healthcheck: %v\n", err)
		return ExitError
	}
	return ExitOK
}

func checkHealth(ctx context.Context, url string) error {
	ctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return fmt.Errorf("GET %s: invalid body: %w", url, err)
	}
	if body.Status != "ok" {
		return fmt.Errorf("GET %s: status %q", url, body.Status)
	}
	return nil
}
