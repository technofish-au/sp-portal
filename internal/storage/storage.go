// Package storage owns the on-disk storage layout under the configured
// storage_dir. Subsystems address files relative to the root.
package storage

import (
	"fmt"
	"os"
	"path/filepath"
)

// Layout is the fixed set of subdirectories created under the storage root:
//
//	releases/         uploaded ServerPerch release artifacts
//	apt/              the hosted apt repository served to appliances
//	offline-bundles/  generated air-gapped install/update bundles
//	support-bundles/  appliance support-bundle uploads
//	exports/          generated data exports (licence/telemetry reports)
var Layout = []string{
	"releases",
	"apt",
	"offline-bundles",
	"support-bundles",
	"exports",
}

// Dir names one of the Layout subdirectories.
const (
	Releases       = "releases"
	Apt            = "apt"
	OfflineBundles = "offline-bundles"
	SupportBundles = "support-bundles"
	Exports        = "exports"
)

// dirPerm is the mode of the storage root and its subdirectories.
const dirPerm = 0o750

// Ensure creates the storage root and every Layout subdirectory (0750),
// idempotently. It returns the absolute root path.
func Ensure(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("storage: resolve %s: %w", root, err)
	}
	if err := os.MkdirAll(abs, dirPerm); err != nil {
		return "", fmt.Errorf("storage: create %s: %w", abs, err)
	}
	for _, sub := range Layout {
		if err := os.MkdirAll(filepath.Join(abs, sub), dirPerm); err != nil {
			return "", fmt.Errorf("storage: create %s/%s: %w", abs, sub, err)
		}
	}
	return abs, nil
}
