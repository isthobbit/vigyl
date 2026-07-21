package version

// These are set at build time via -ldflags.
// e.g. go build -ldflags "-X github.com/isthobbit/vigil/pkg/version.Version=1.0.0"
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)
