// Package lockfile reads package-lock.json — depguard's source of truth for
// "what is actually installed" (DESIGN.md §10). No external database tracks
// projects; the lockfile is already version-controlled state.
package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
	// Bundled mirrors Pkg.Bundled — this occurrence ships inside a parent tarball.
	Bundled bool
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
	// FromRegistry marks an entry the PARSER proved is a plain registry dep
	// even though the lockfile records no tarball URL (pnpm's normal shape).
	// Without it an empty Resolved is indistinguishable from an npm file:/link:
	// dep, which legitimately carries neither a host nor a hash — so the
	// integrity checks would have to skip both, and pnpm would go unchecked.
	FromRegistry bool
	// Conflict marks a name@version recorded at two lockfile paths with
	// DIFFERENT tarball URLs or integrity hashes. Dedupe keeps one of them, so
	// without this flag the disagreement — the signature of a hand-edited or
	// partially poisoned lockfile — would vanish silently.
	Conflict bool
	// Bundled: every occurrence of this name@version ships INSIDE a parent's
	// tarball, so npm records no URL and no hash for it — the parent's integrity
	// hash already covers the bytes. It is still installed code, so advisories,
	// the cooldown and the SBOM must see it; only the integrity gates skip it,
	// because it has nothing of its own to verify.
	Bundled bool
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
	pkgs, _, err := InstalledAt(dir, "")
	return pkgs, err
}

// lockfileNames is the search order for "which lockfile does this project use".
var lockfileNames = []string{"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}

// InstalledAt is Installed for a specific git ref: "" reads the WORKING TREE,
// ":" reads the index (what a commit would contain), and a sha reads that
// commit. The hooks need this because the working tree is not what git is about
// to record or transmit — checking it lets a staged-but-different lockfile
// through the gates entirely.
//
// It also returns how many lockfile entries the parser could not recognize, so
// the caller can report an incompletely-understood lockfile instead of quietly
// checking a subset of it.
func InstalledAt(dir, ref string) (pkgs []Pkg, skipped int, err error) {
	// Validate the ref ONCE. After this, a per-name lookup that fails means the
	// path is absent from an otherwise-fine ref — git reports that as exit 128
	// ("not a valid object name"), indistinguishable by exit code from a broken
	// repo, so the two have to be separated here instead.
	if ref != "" {
		if rerr := refUsable(dir, ref); rerr != nil {
			return nil, 0, rerr
		}
	}
	for _, name := range lockfileNames {
		raw, found, rerr := readLockfile(dir, ref, name)
		if rerr != nil {
			return nil, 0, rerr // a real failure — never mistake it for "no deps"
		}
		if !found {
			continue
		}
		return parseNamed(name, raw)
	}
	return nil, 0, os.ErrNotExist // no recognized lockfile — callers treat as "nothing to check"
}

// readLockfile reads one lockfile from the working tree (ref "") or from git.
// It separates CONFIRMED ABSENCE (found=false, err=nil — try the next name) from
// FAILURE (err non-nil). Treating every read error as absence meant an unreadable
// file, a broken git or a bad ref all ended as "no lockfile here — nothing to
// check": a silent all-clear from a check that never ran. The ref itself is
// validated by the caller (refUsable), so here a git miss means "no such path".
func readLockfile(dir, ref, name string) (raw []byte, found bool, err error) {
	if ref == "" {
		b, rerr := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(rerr) {
			return nil, false, nil
		}
		if rerr != nil {
			return nil, false, rerr
		}
		return b, true, nil
	}
	// A trailing ':' is already the separator ("" ref + ':' is git's spelling of
	// the index), so don't double it.
	spec := strings.TrimSuffix(ref, ":") + ":" + name
	if perr := exec.Command("git", "-C", dir, "cat-file", "-e", spec).Run(); perr != nil {
		return nil, false, nil // path not in this ref — try the next lockfile name
	}
	out, oerr := exec.Command("git", "-C", dir, "show", spec).Output()
	if oerr != nil {
		return nil, false, fmt.Errorf("git show %s: %w", spec, oerr)
	}
	return out, true, nil
}

// refUsable reports whether ref is something git can actually read from here, so
// a missing FILE can be told apart from a missing repo or a bogus ref. Both look
// like exit 128 from cat-file, and only one of them means "nothing to check".
func refUsable(dir, ref string) error {
	if ref == ":" {
		// The index exists whenever the repo does.
		if err := exec.Command("git", "-C", dir, "rev-parse", "--git-dir").Run(); err != nil {
			return fmt.Errorf("git rev-parse --git-dir: %w", err)
		}
		return nil
	}
	if err := exec.Command("git", "-C", dir, "rev-parse", "--verify", "--quiet", ref+"^{commit}").Run(); err != nil {
		return fmt.Errorf("git cannot resolve ref %q: %w", ref, err)
	}
	return nil
}

// parseNamed dispatches on the lockfile's FILENAME — the only thing that
// identifies the format when the bytes come from git rather than from disk.
func parseNamed(name string, raw []byte) (pkgs []Pkg, skipped int, err error) {
	switch filepath.Base(name) {
	case "pnpm-lock.yaml":
		p, n, perr := parsePnpm(raw)
		if perr != nil {
			return nil, 0, perr
		}
		return dedupePkgs(p), n, nil
	case "yarn.lock":
		p, n, perr := parseYarn(raw)
		if perr != nil {
			return nil, 0, perr
		}
		return dedupePkgs(p), n, nil
	default:
		entries, perr := parseBytes(raw)
		if perr != nil {
			return nil, 0, perr
		}
		return dedupe(entries), 0, nil
	}
}

// Union folds several snapshots (one per pushed ref) into one distinct
// name@version set. Unlike dedupe it does NOT derive conflicts: see mergeAcross.
func Union(sets ...[]Pkg) []Pkg {
	at := map[string]int{}
	var out []Pkg
	for _, set := range sets {
		for _, p := range set {
			if p.Name == "" || p.Version == "" {
				continue
			}
			if i, ok := at[p.Key()]; ok {
				mergeAcross(&out[i], p)
				continue
			}
			at[p.Key()] = len(out)
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// InstalledBytes parses lockfile content directly — used to diff the staged
// lockfile against the one in git HEAD without checking files out.
func InstalledBytes(raw []byte) ([]Pkg, error) {
	pkgs, _, err := parseNamed("package-lock.json", raw)
	return pkgs, err
}

// dedupe flattens entries to distinct name@version pairs, preserving every
// distinct version of a name (only exact-pair duplicates from nested paths
// are merged). Output order is deterministic (sorted by key) so callers that
// print or diff it behave reproducibly.
// A duplicate that DISAGREES about the tarball or hash sets Conflict on the
// survivor — the lockfile is inconsistent and the caller must gate on it.
func dedupe(entries []Entry) []Pkg {
	// Sort by lockfile path first: the map the entries came from has no order,
	// so without this the surviving record of a duplicate pair would vary run
	// to run — and with it the reported Resolved/Integrity.
	sorted := append([]Entry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	at := map[string]int{}
	var out []Pkg
	for _, e := range sorted {
		// FromRegistry stays false: an npm lockfile records the tarball URL for
		// real registry deps, so Resolved alone classifies these.
		p := Pkg{Name: e.Name, Version: e.Version, Resolved: e.Resolved, Integrity: e.Integrity, Bundled: e.Bundled}
		if i, ok := at[p.Key()]; ok {
			merge(&out[i], p)
			continue
		}
		at[p.Key()] = len(out)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// merge folds a duplicate record of the same name@version into the survivor.
// It is a UNION, not a first-wins pick: an omitted field is filled in from the
// duplicate. Resolved may legitimately be absent (pnpm records no tarball URL),
// so empty-vs-set is no contradiction there; Integrity may not (see below).
//
// Collapsing by "first wins" was a gate bypass. A crafted lockfile could add an
// information-EMPTY duplicate (`{"version":"6.0.0"}`) at a path that sorts
// first; the real record — the one with the evil tarball URL and the hash — was
// discarded, the survivor had neither, checkableDep went false, and BOTH
// integrity checks skipped the package while printing "integrity ok".
func merge(dst *Pkg, src Pkg) { mergeInto(dst, src, true) }

// mergeAcross folds a record from a DIFFERENT snapshot (another pushed ref) into
// the survivor. It unions the fields and carries over a conflict already found
// inside a ref, but derives no new ones: two lockfiles that are each internally
// consistent are allowed to disagree with each other. Branch A predating a hash
// that branch B added is ordinary history, not a corrupt lockfile — and since
// the conflict verdict is unwaivable, inventing one there is a dead end blaming
// a file that is fine.
func mergeAcross(dst *Pkg, src Pkg) { mergeInto(dst, src, false) }

func mergeInto(dst *Pkg, src Pkg, sameFile bool) {
	// A bundled occurrence has no fields of its own to compare: it is neither
	// unhashed nor in disagreement, its bytes just live in the parent's tarball.
	// When the other occurrence is standalone, the standalone one decides.
	dst.Conflict = dst.Conflict || src.Conflict // never lose a flag, whichever side is bundled
	if src.Bundled {
		return
	}
	if dst.Bundled {
		dst.Resolved, dst.Integrity, dst.Bundled = src.Resolved, src.Integrity, false
		dst.FromRegistry = dst.FromRegistry || src.FromRegistry
		dst.Conflict = dst.Conflict || src.Conflict
		return
	}
	if dst.Resolved == "" {
		dst.Resolved = src.Resolved
	} else if sameFile && src.Resolved != "" && src.Resolved != dst.Resolved {
		dst.Conflict = true
	}
	// Integrity is different from Resolved: a registry dep is hashed at EVERY
	// path it appears, so an occurrence without a hash is not "less information",
	// it is the unhashed finding. Filling it in from a sibling hid exactly that.
	// The value is still unioned so the survivor stays checkable, but the
	// disagreement is recorded.
	if dst.Integrity == "" && src.Integrity != "" {
		dst.Integrity = src.Integrity
		dst.Conflict = dst.Conflict || sameFile
	} else if sameFile && src.Integrity != dst.Integrity {
		dst.Conflict = true
	}
	// Either record proving this is a registry dep is enough to keep it in scope,
	// and a conflict seen in either input survives the fold.
	dst.FromRegistry = dst.FromRegistry || src.FromRegistry
	dst.Conflict = dst.Conflict || src.Conflict
}

// dedupePkgs is dedupe for parsers (pnpm/yarn) that already produce []Pkg.
// Drops entries missing a version (malformed lines) and distinct-by-key sorts.
func dedupePkgs(in []Pkg) []Pkg {
	at := map[string]int{}
	var out []Pkg
	for _, p := range in {
		if p.Name == "" || p.Version == "" {
			continue
		}
		if i, ok := at[p.Key()]; ok {
			merge(&out[i], p)
			continue
		}
		at[p.Key()] = len(out)
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
			// InBundle: this copy ships INSIDE its parent's tarball, so npm
			// records no resolved/integrity for it — the parent's hash already
			// covers the bytes.
			InBundle bool `json:"inBundle"`
			// Link: a symlink to a workspace or a local path; no registry
			// identity to check at all.
			Link bool `json:"link"`
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
		// A link is a symlink to a workspace or a local path: no registry
		// identity, nothing to inventory. Dropped.
		if p.Link {
			continue
		}
		// A bundled copy records neither a URL nor a hash by design — its bytes
		// ship inside the PARENT's hashed tarball. It is still installed code, so
		// it stays in the INVENTORY (advisories, cooldown, SBOM) and is marked
		// instead; only the integrity gates skip Bundled entries. Dropping it
		// outright hid the package from every check whenever no standalone
		// occurrence existed, and treating it as an ordinary hashless occurrence
		// made every bundling package's tree look self-contradictory — a verdict
		// that is unwaivable and whose advice ("npm install regenerates
		// consistent entries") reproduces the very same lockfile.
		//
		// inBundle is attacker-writable, so trust the SHAPE, not the flag: an
		// entry that claims inBundle but carries a fetchable resolved/integrity
		// is an ordinary entry and is checked like one.
		bundled := p.InBundle && p.Resolved == "" && p.Integrity == ""
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
			Bundled:   bundled,
		})
	}
	return out, nil
}
