// Package pyver holds the small PyPI naming/version helpers shared by the
// check path (freshness), the index proxy (registry) and sdist handling. It is
// deliberately not PEP 440: only plain dotted releases compare; anything else
// is "not stable" and callers skip it or ask the user to pin.
package pyver

import (
	"regexp"
	"strconv"
	"strings"
)

var nameSep = regexp.MustCompile(`[-_.]+`)

// NormalizeName is PEP 503 normalization: lowercase, runs of -_. → "-".
func NormalizeName(n string) string {
	return nameSep.ReplaceAllString(strings.ToLower(n), "-")
}

// Stable reports a plain release version: dot-separated digit runs only (no
// pre/dev/post/local/epoch markers).
func Stable(v string) bool {
	for _, part := range strings.Split(v, ".") {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return false
		}
	}
	return true
}

// Compare orders two Stable versions numerically, missing parts as 0
// (PEP 440: 1.0 == 1.0.0). Returns -1, 0 or 1.
func Compare(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Less reports a < b for two Stable versions.
func Less(a, b string) bool { return Compare(a, b) < 0 }

// FileVersion extracts the (lowercased) version from a distribution filename:
// wheel {dist}-{ver}(-{build})?-{py}-{abi}-{plat}.whl, or an sdist
// {name}-{ver}.tar.gz/.zip/.tar.bz2 (version after the LAST '-').
func FileVersion(fn string) (string, bool) {
	if base, ok := strings.CutSuffix(fn, ".whl"); ok {
		parts := strings.Split(base, "-")
		if (len(parts) != 5 && len(parts) != 6) || parts[1] == "" {
			return "", false
		}
		return strings.ToLower(parts[1]), true
	}
	for _, ext := range []string{".tar.gz", ".zip", ".tar.bz2"} {
		if base, ok := strings.CutSuffix(fn, ext); ok {
			i := strings.LastIndexByte(base, '-')
			if i <= 0 || i == len(base)-1 {
				return "", false
			}
			return strings.ToLower(base[i+1:]), true
		}
	}
	return "", false
}
