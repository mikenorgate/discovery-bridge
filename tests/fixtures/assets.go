// Package fixtures supplies synthetic contract data to standalone test executables.
package fixtures

import "embed"

// Files keeps qualification independent of the source checkout and working directory.
// It is imported by tests only, and is excluded from release executables.
//
//go:embed *.json
var Files embed.FS
