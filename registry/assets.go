// Package registrydata contains pinned public Avahi and IANA registry assets.
package registrydata

import "embed"

// Files contains the registries, their manifest and the upstream license.
//
//go:embed service-types iana.csv manifest.json COPYING.avahi
var Files embed.FS
