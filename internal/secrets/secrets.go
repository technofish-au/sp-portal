// Package secrets reads secret values from file-mounted credentials
// (Podman secrets, docker secrets, systemd credentials). Secret values are
// never logged and never appear in error messages.
package secrets

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrMode means the secret file's permissions are too open; only 0400
// (secret mount, e.g. Podman/docker secrets) and 0600 (operator-managed
// file) are accepted.
var ErrMode = errors.New("insecure permissions")

// ReadFile reads the secret at path and returns its trimmed contents. The
// file must have mode 0400 or 0600 (Podman-secret style); any other
// permission bits are an error. The error never contains the secret value.
func ReadFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("secrets: stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("secrets: %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm != 0o400 && perm != 0o600 {
		return nil, fmt.Errorf("secrets: %w %s is %04o, want 0400 or 0600 (chmod 0400 %s)",
			ErrMode, path, perm, path)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil, fmt.Errorf("secrets: read %s: %w", path, err)
	}
	return data, nil
}

// ReadString is ReadFile with the surrounding whitespace trimmed, the
// common shape of single-line secret files. An empty result is an error.
func ReadString(path string) (string, error) {
	data, err := ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(data))
	clear(data)
	if s == "" {
		return "", fmt.Errorf("secrets: %s is empty", path)
	}
	return s, nil
}
