// Package semver implements the minimal subset of semantic-version handling
// depguard needs: parsing and comparing npm version strings so the proxy can
// repoint dist-tags.latest at the newest *surviving* version after filtering.
//
// Deliberately not a full semver implementation (no ranges, no build metadata
// ordering) — depguard never resolves ranges itself; npm does that. We only
// need "which of these concrete versions is newest, preferring stable".
package semver

import (
	"strconv"
	"strings"
)

// Version is a parsed major.minor.patch with an optional prerelease tag.
type Version struct {
	Major, Minor, Patch int
	Pre                 string // empty = stable release
	Raw                 string
}

// Parse splits an npm version string into its numeric parts.
// Returns ok=false for anything that doesn't look like x.y.z[-pre].
func Parse(s string) (Version, bool) {
	v := Version{Raw: s}
	core := s
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		core = s[:i]
		if s[i] == '-' {
			v.Pre = s[i+1:]
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return v, false
	}
	var err error
	if v.Major, err = strconv.Atoi(parts[0]); err != nil {
		return v, false
	}
	if v.Minor, err = strconv.Atoi(parts[1]); err != nil {
		return v, false
	}
	if v.Patch, err = strconv.Atoi(parts[2]); err != nil {
		return v, false
	}
	return v, true
}

// Less reports whether a orders before b. Stable releases order after their
// own prereleases (1.0.0-rc1 < 1.0.0), matching semver §11.
func Less(a, b Version) bool {
	if a.Major != b.Major {
		return a.Major < b.Major
	}
	if a.Minor != b.Minor {
		return a.Minor < b.Minor
	}
	if a.Patch != b.Patch {
		return a.Patch < b.Patch
	}
	// Same core: prerelease < stable; two prereleases compare lexically (good enough).
	if a.Pre != b.Pre {
		if a.Pre == "" {
			return false
		}
		if b.Pre == "" {
			return true
		}
		return a.Pre < b.Pre
	}
	return false
}

// MaxStable returns the highest stable version in vs, falling back to the
// highest prerelease when no stable version survived filtering.
// Returns "" when vs is empty.
func MaxStable(vs []string) string {
	var bestStable, bestAny *Version
	for _, s := range vs {
		v, ok := Parse(s)
		if !ok {
			continue
		}
		vc := v
		if bestAny == nil || Less(*bestAny, vc) {
			bestAny = &vc
		}
		if vc.Pre == "" && (bestStable == nil || Less(*bestStable, vc)) {
			bestStable = &vc
		}
	}
	if bestStable != nil {
		return bestStable.Raw
	}
	if bestAny != nil {
		return bestAny.Raw
	}
	return ""
}
