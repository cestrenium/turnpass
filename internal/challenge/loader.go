package challenge

import (
	"fmt"
	"regexp"
	"strings"
)

// LoaderInfo holds the extracted information from the Turnstile loader script
// (api.js).
type LoaderInfo struct {
	// Build is the 12-character lowercase hex build hash (the "ch" property).
	Build string
	// Route is the single-letter challenge-platform route (e.g., "b", "g").
	Route string
	// Source is the raw loader script source.
	Source string
}

var (
	// Matches the "ch" property in an object literal: ch: "e694063b5082"
	rxLoaderBuild = regexp.MustCompile(`(?i)\bch\s*:\s*["']([0-9a-f]{12})["']`)
	// Matches a function call with a single lowercase letter argument
	// followed by a .New member access: f(..., "g", e.New, ...)
	// This identifies the challenge-platform route in the loader script.
	rxLoaderRoute = regexp.MustCompile(`\(\s*[^,)]*,\s*["']([a-z])["']\s*,\s*\w+\.New\b`)
)

// ParseLoaderScript extracts the build hash and challenge-platform route from
// the Turnstile loader script (api.js) source.
//
// The build hash is a 12-character lowercase hexadecimal string assigned to
// the "ch" property. The route is a single lowercase letter passed as an
// argument before a .New member access in a function call.
func ParseLoaderScript(source string) (*LoaderInfo, error) {
	info := &LoaderInfo{Source: source}

	// Extract the build hash.
	if m := rxLoaderBuild.FindStringSubmatch(source); len(m) >= 2 {
		info.Build = strings.ToLower(m[1])
	}
	if info.Build == "" {
		return nil, fmt.Errorf("loader script has no api.js build hash; is this really api.js?")
	}

	// Extract the challenge-platform route.
	if m := rxLoaderRoute.FindStringSubmatch(source); len(m) >= 2 {
		info.Route = m[1]
	}
	if info.Route == "" {
		return nil, fmt.Errorf("loader script names no challenge-platform route")
	}

	return info, nil
}
