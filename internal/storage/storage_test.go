package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureCreatesLayout(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nested", "data")
	abs, err := Ensure(root)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for _, sub := range Layout {
		st, err := os.Stat(filepath.Join(abs, sub))
		if err != nil || !st.IsDir() {
			t.Fatalf("%s missing: %v", sub, err)
		}
	}
	// Idempotent.
	if _, err := Ensure(root); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
}
