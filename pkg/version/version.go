package version

// These are set at build time via -ldflags.
// e.g. go build -ldflags "-X github.com/isthobbit/vigyl/pkg/version.Version=1.0.0"
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)
