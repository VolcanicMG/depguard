// Package lockfile reads package-lock.json — depguard's source of truth for
// "what is actually installed" (DESIGN.md §10). No external database tracks
// projects; the lockfile is already version-controlled state.
package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Entry is one installed package with its on-disk location.
type Entry struct {
	Name    string
	Version string
	// Path is the lockfile key, relative to the repo root
	// ("node_modules/@scope/name", possibly nested).
	Path string
	// Resolved/Integrity mirror the lockfile fields (see Pkg).
	Resolved  string
	Integrity string
}

// Pkg is one installed name@version pair, location-independent. A dependency
// tree routinely holds SEVERAL versions of the same name (a transitive dep
// pinned differently in two branches of the graph), so anything that must
// vet every version — advisory and cooldown checks — keys on the pair, never
// on the name alone. Collapsing by name (the old behavior) silently dropped
// every duplicate version from those checks.
type Pkg struct {
	Name    string
	Version string
	// Resolved is the tarball URL npm recorded for this version. A value that
	// points OFF the configured registry is how a poisoned lockfile silently
	// redirects a fetch to an attacker host — so it's a checkable signal.
	Resolved string
	// Integrity is the Subresource-Integrity hash (sha512-...). Its ABSENCE on
	// a registry dep means npm can't verify the tarball — also checkable.
	Integrity string
}

// Key is the dedupe/identity key for a package version ("name@version").
func (p Pkg) Key() string { return p.Name + "@" + p.Version }

// InstalledPaths returns every dependency with its node_modules path —
// used to locate each package's real directory for script detection.
func InstalledPaths(dir string) ([]Entry, error) {
	byName, err := parse(dir)
	if err != nil {
		return nil, err
	}
	return byName, nil
}

// Installed returns every DISTINCT name@version in the repo's lockfile. The
// same pair appearing at multiple paths collapses to one Pkg, but two
// different versions of one name are BOTH returned — that's the whole point:
// advisory and cooldown checks must see every version, not just the last one
// written under a given name.
//
// It auto-detects the lockfile: package-lock.json (npm), then pnpm-lock.yaml,
// then yarn.lock. The check path (advisory/cooldown/integrity) thus covers all
// three package managers; `guard install` itself remains npm-shaped because it
// shells out to npm.
func Installed(dir string) ([]Pkg, error) {
	if raw, err := os.ReadFile(filepath.Join(dir, "package-lock.json")); err == nil {
		entries, perr := parseBytes(raw)
		if perr != nil {
			return nil, perr
		}
		return dedupe(entries), nil
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "pnpm-lock.yaml")); err == nil {
		return dedupePkgs(parsePnpm(raw)), nil
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "yarn.lock")); err == nil {
		return dedupePkgs(parseYarn(raw)), nil
	}
	return nil, os.ErrNotExist // no recognized lockfile — callers treat as "nothing to check"
}

// InstalledBytes parses lockfile content directly — used to diff the staged
// lockfile against the one in git HEAD without checking files out.
func InstalledBytes(raw []byte) ([]Pkg, error) {
	entries, err := parseBytes(raw)
	if err != nil {
		return nil, err
	}
	return dedupe(entries), nil
}

// dedupe flattens entries to distinct name@version pairs, preserving every
// distinct version of a name (only exact-pair duplicates from nested paths
// are merged). Output order is deterministic (sorted by key) so callers that
// print or diff it behave reproducibly.
func dedupe(entries []Entry) []Pkg {
	seen := map[string]bool{}
	var out []Pkg
	for _, e := range entries {
		p := Pkg{Name: e.Name, Version: e.Version, Resolved: e.Resolved, Integrity: e.Integrity}
		if seen[p.Key()] {
			continue
		}
		seen[p.Key()] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// dedupePkgs is dedupe for parsers (pnpm/yarn) that already produce []Pkg.
// Drops entries missing a version (malformed lines) and distinct-by-key sorts.
func dedupePkgs(in []Pkg) []Pkg {
	seen := map[string]bool{}
	var out []Pkg
	for _, p := range in {
		if p.Name == "" || p.Version == "" || seen[p.Key()] {
			continue
		}
		seen[p.Key()] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// parse reads and flattens the lockfile's packages map.
func parse(dir string) ([]Entry, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		return nil, err
	}
	return parseBytes(raw)
}

// parseBytes flattens raw lockfile JSON into entries.
func parseBytes(raw []byte) ([]Entry, error) {
	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		// v2/v3: "packages" keys are paths like "node_modules/@scope/name".
		Packages map[string]struct {
			Version   string `json:"version"`
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}
	if lock.Packages == nil {
		return nil, fmt.Errorf("package-lock.json v%d has no packages map (npm <7?)", lock.LockfileVersion)
	}

	var out []Entry
	for path, p := range lock.Packages {
		if path == "" || p.Version == "" {
			continue // "" is the root project itself
		}
		// The package name is everything after the LAST "node_modules/",
		// which handles nested deps like "node_modules/a/node_modules/b".
		idx := strings.LastIndex(path, "node_modules/")
		if idx < 0 {
			continue // workspaces/links — not registry packages
		}
		out = append(out, Entry{
			Name:      path[idx+len("node_modules/"):],
			Version:   p.Version,
			Path:      path,
			Resolved:  p.Resolved,
			Integrity: p.Integrity,
		})
	}
	return out, nil
}
