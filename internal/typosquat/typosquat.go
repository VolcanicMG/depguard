// Package typosquat is the NAME-level filter (DESIGN.md §6: typosquat /
// dependency confusion). The cooldown and advisory layers judge a version by
// its age and its CVE record; neither looks at the package NAME. But a whole
// class of supply-chain attacks is purely nominal — publish `lodahs` or
// `expresss` or a homoglyph `reаct` (Cyrillic 'а') and wait for a fat-finger
// or an autocomplete miss. This package catches those before the proxy ever
// serves the impostor's metadata.
//
// The check is deliberately conservative and curated, not statistical: with
// no download counts available offline we can't rank packages by popularity,
// so we ship a small hand-picked list of the highest-value impersonation
// targets and flag only very-close (single-edit) look-alikes plus any name
// carrying non-ASCII letters. A legitimate package that happens to sit one
// edit from a popular one (preact ↔ react) is allow-listed by name; anything
// else a user genuinely wants can be cleared with `allow:` in .guardrc.
package typosquat

import (
	"strings"
	"unicode"
)

// popular is the curated set of high-value impersonation targets. Keep it
// SMALL and high-traffic: every entry widens the single-edit blast radius, so
// only names worth squatting belong here. (Sorted for readability.)
var popular = map[string]bool{
	"async": true, "axios": true, "babel": true, "bcrypt": true,
	"chalk": true, "commander": true, "cross-env": true, "debug": true,
	"dotenv": true, "esbuild": true, "eslint": true, "express": true,
	"jest": true, "lodash": true, "minimist": true, "mocha": true,
	"moment": true, "mongoose": true, "next": true, "node-fetch": true,
	"nodemon": true, "prettier": true, "react": true, "react-dom": true,
	"redux": true, "request": true, "rimraf": true, "rollup": true,
	"semver": true, "typescript": true, "underscore": true, "uuid": true,
	"vite": true, "vue": true, "webpack": true, "yargs": true,
}

// known is the escape hatch for LEGITIMATE packages that sit one edit from a
// popular name and would otherwise be flagged. These are real, widely-used
// packages — not squats — so they're cleared globally rather than forcing
// every consumer to allow-list them. (preact is one insert from react, etc.)
var known = map[string]bool{
	"preact": true, // one insert from "react"
}

// Suspicion reports whether a package name looks like a typosquat or homoglyph
// attack, returning a human-readable reason when it does. Exact matches to a
// popular name (the real package) and entries on the known-good list are never
// flagged. Callers treat a true result as fail-closed: block the name and tell
// the human how to clear it if it was intentional.
func Suspicion(name string) (reason string, suspicious bool) {
	if name == "" {
		return "", false
	}

	// Non-ASCII letters in a package name are a near-certain homoglyph attack:
	// npm names are conventionally lowercase ASCII, and a Cyrillic/Greek
	// look-alike exists precisely to read as its ASCII twin. This fires
	// regardless of edit distance — the character itself is the tell.
	if r, ok := firstNonASCIILetter(name); ok {
		return "non-ASCII letter " + quoteRune(r) + " in package name (possible homoglyph of an ASCII name)", true
	}

	// Edit-distance check runs on the bare name (scope is a namespace and
	// far harder to squat than an unscoped name).
	bare := name
	if i := strings.LastIndex(bare, "/"); i >= 0 {
		bare = bare[i+1:]
	}
	if popular[bare] || known[bare] {
		return "", false
	}
	for p := range popular {
		// Length guard bounds the work and rejects obvious non-matches before
		// the O(n·m) distance computation.
		if abs(len(bare)-len(p)) > 1 {
			continue
		}
		if osaDistance(bare, p) == 1 {
			return "one edit from popular package " + quote(p) + " (possible typosquat)", true
		}
	}
	return "", false
}

// osaDistance is the optimal-string-alignment (restricted Damerau-Levenshtein)
// distance between a and b. Unlike plain Levenshtein it counts a transposition
// of two ADJACENT characters as a single edit, which is exactly the most
// common typosquat shape ("lodash" → "lodahs"). "Restricted" = no substring is
// edited more than once, which is fine at the distance-1 threshold we use.
func osaDistance(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	// Three rolling rows are enough for OSA (current, previous, prev-previous).
	prev2 := make([]int, lb+1)
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(
				curr[j-1]+1,    // insertion
				prev[j]+1,      // deletion
				prev[j-1]+cost, // substitution
			)
			// Adjacent transposition.
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				if t := prev2[j-2] + 1; t < curr[j] {
					curr[j] = t
				}
			}
		}
		prev2, prev, curr = prev, curr, prev2
	}
	return prev[lb]
}

// firstNonASCIILetter returns the first rune that is a letter outside ASCII —
// the homoglyph signal. Digits, '-', '.', '_', '@', '/' are legal name
// punctuation and ignored; only non-ASCII LETTERS are the tell.
func firstNonASCIILetter(s string) (rune, bool) {
	for _, r := range s {
		if r > unicode.MaxASCII && unicode.IsLetter(r) {
			return r, true
		}
	}
	return 0, false
}

func quote(s string) string { return "\"" + s + "\"" }

func quoteRune(r rune) string { return "'" + string(r) + "'" }

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func min3(a, b, c int) int { return min(a, min(b, c)) }
