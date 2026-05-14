// Package version exposes build metadata populated via -ldflags -X at build time.
package version

var (
	// Commit is the short git SHA the binary was built from. Defaults to "unknown"
	// when the binary is built without ldflags (e.g. plain `go build`).
	Commit = "unknown"

	// Date is the UTC timestamp the binary was built at, in RFC3339 format.
	Date = "unknown"
)

// Info captures the build metadata returned by the version API and shown in the UI.
type Info struct {
	Commit string `json:"commit"`
	Date   string `json:"date"`
}

// Get returns the current build metadata.
func Get() Info {
	return Info{Commit: Commit, Date: Date}
}

// String renders the version as a single human-readable line for startup logs.
func String() string {
	return "commit=" + Commit + " built=" + Date
}
