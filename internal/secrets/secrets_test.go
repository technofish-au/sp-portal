package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSecret(t *testing.T, mode os.FileMode, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadStringModes(t *testing.T) {
	for _, mode := range []os.FileMode{0o400, 0o600} {
		got, err := ReadString(writeSecret(t, mode, "  hunter2\n"))
		if err != nil {
			t.Fatalf("mode %04o: %v", mode, err)
		}
		if got != "hunter2" {
			t.Fatalf("mode %04o: got %q", mode, got)
		}
	}
}

func TestReadStringRejectsOpenModes(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o444, 0o777} {
		if _, err := ReadString(writeSecret(t, mode, "hunter2")); !errors.Is(err, ErrMode) {
			t.Fatalf("mode %04o: err = %v, want ErrMode", mode, err)
		}
	}
}

func TestReadStringEmptyIsError(t *testing.T) {
	if _, err := ReadString(writeSecret(t, 0o400, "  \n")); err == nil {
		t.Fatal("expected error for empty secret file")
	}
}

func TestErrorNeverContainsSecret(t *testing.T) {
	secret := "sup3r-s3cret-value"
	_, err := ReadFile(writeSecret(t, 0o644, secret))
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks secret value: %v", err)
	}
}
