package version

import (
	"fmt"
	"runtime/debug"
)


const featureFlags = "Pebble/Gob+PackedIdx"

// EngineVersion automatically detects the version from the Git tag.
func EngineVersion() string {
	version := "(devel)" // Fallback for local testing (go run .)

	// Ask the Go runtime: "What Git tag was I built with?"
	if info, ok := debug.ReadBuildInfo(); ok {
		// info.Main.Version is automatically filled by 'go install'
		if info.Main.Version != "" {
			version = info.Main.Version
		}
	}

	return fmt.Sprintf("%s (%s)", version, featureFlags)
}