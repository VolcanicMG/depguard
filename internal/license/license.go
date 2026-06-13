// Package license reads the declared license of each installed package and
// checks it against the repo's policy (.guardrc license-deny / license-allow).
// It's the compliance sibling of the security checks: not "is this malware?"
// but "are we allowed to ship this?". The license lives in each package's own
// package.json (the lockfile doesn't carry it), so this reads node_modules —
// and degrades gracefully (reporting, never silently passing) when the tree
// isn't installed. Zero-dep: encoding/json + strings.
package license

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"depguard/internal/lockfile"
)

// Violation is one installed package whose license the policy rejects.
type Violation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License string `json:"license"` // as declared, or "" when unknown/missing
	Reason  string `json:"reason"`  // "denied" or "not allowed"
}

// Result is the outcome of a license check over a dependency tree.
type Result struct {
	Violations []Violation
	// Degraded is true when node_modules was missing/unreadable for some or all
	// packages, so the result is INCOMPLETE — the caller must surface this and
	// must not treat a clean result as proof (the fail-open contract the other
	// checks use).
	Degraded bool
}

// pkgManifest is the slice of a package.json we read. `license` is usually a
// string ("MIT") but historically an object ({"type":"MIT"}); `licenses` is the
// deprecated array form ([{"type":"MIT"}, ...]). We tolerate all three.
type pkgManifest struct {
	License  json.RawMessage `json:"license"`
	Licenses json.RawMessage `json:"licenses"`
}

// readLicense returns the declared license string for an installed package, or
// "" if none could be determined. It handles the string, object, and array
// forms npm has used over the years.
func readLicense(pkgDir string) string {
	raw, err := os.ReadFile(filepath.Join(pkgDir, "package.json"))
	if err != nil {
		return ""
	}
	var m pkgManifest
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	// Modern: a bare string.
	var s string
	if len(m.License) > 0 && json.Unmarshal(m.License, &s) == nil && s != "" {
		return s
	}
	// Old object form: {"type": "MIT"}.
	var obj struct {
		Type string `json:"type"`
	}
	if len(m.License) > 0 && json.Unmarshal(m.License, &obj) == nil && obj.Type != "" {
		return obj.Type
	}
	// Deprecated array form: [{"type":"MIT"}, {"type":"Apache-2.0"}].
	var arr []struct {
		Type string `json:"type"`
	}
	if len(m.Licenses) > 0 && json.Unmarshal(m.Licenses, &arr) == nil {
		var types []string
		for _, a := range arr {
			if a.Type != "" {
				types = append(types, a.Type)
			}
		}
		if len(types) > 0 {
			return strings.Join(types, " OR ")
		}
	}
	return ""
}

// tokens splits an SPDX license expression into its identifier tokens, dropping
// the operators (AND/OR/WITH) and parentheses. "(MIT OR Apache-2.0)" → [MIT,
// Apache-2.0]. A plain id returns itself.
func tokens(expr string) []string {
	fields := strings.FieldsFunc(expr, func(r rune) bool {
		return r == ' ' || r == '(' || r == ')'
	})
	var out []string
	for _, f := range fields {
		switch strings.ToUpper(f) {
		case "AND", "OR", "WITH", "":
			continue
		}
		out = append(out, f)
	}
	return out
}

// inList reports whether id is in list (case-insensitive — SPDX ids are
// case-insensitive in practice for the common identifiers).
func inList(id string, list []string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), id) {
			return true
		}
	}
	return false
}

// Check evaluates every installed package against the deny/allow policy. deny
// is applied first (a denied license is always a violation); allow, when
// non-empty, additionally requires at least one declared license to be allowed.
// With both lists empty the gate is off and Check returns no violations.
func Check(dir string, entries []lockfile.Entry, deny, allow []string) Result {
	var res Result
	if len(deny) == 0 && len(allow) == 0 {
		return res // gate disabled — nothing to do
	}
	readable := 0
	for _, e := range entries {
		lic := readLicense(filepath.Join(dir, e.Path))
		if lic == "" {
			// Couldn't read a license. Distinguish "tree not installed" (the
			// package dir is absent → degraded) from "installed but no license
			// field" (a real unknown, which allowlist mode rejects).
			if _, err := os.Stat(filepath.Join(dir, e.Path)); err != nil {
				res.Degraded = true
				continue
			}
		} else {
			readable++
		}
		toks := tokens(lic)

		// Deny gate: any token on the deny list convicts.
		denied := false
		for _, t := range toks {
			if inList(t, deny) {
				res.Violations = append(res.Violations, Violation{e.Name, e.Version, lic, "denied"})
				denied = true
				break
			}
		}
		if denied {
			continue
		}
		// Allow gate (allowlist mode): violation unless SOME token is allowed.
		if len(allow) > 0 {
			ok := false
			for _, t := range toks {
				if inList(t, allow) {
					ok = true
					break
				}
			}
			if !ok {
				display := lic
				if display == "" {
					display = "(unknown)"
				}
				res.Violations = append(res.Violations, Violation{e.Name, e.Version, display, "not allowed"})
			}
		}
	}
	return res
}
