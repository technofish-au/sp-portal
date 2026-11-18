// Package version carries build metadata injected via -ldflags -X.
package version

import "fmt"

// Build metadata; set with -ldflags "-X .../version.Version=...".
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Info is the build metadata of the running binary.
type Info struct {
	Version string
	Commit  string
	Date    string
}

// Get returns the build metadata.
func Get() Info { return Info{Version: Version, Commit: Commit, Date: Date} }

func (i Info) String() string {
	return fmt.Sprintf("%s (commit %s, built %s)", i.Version, i.Commit, i.Date)
}
