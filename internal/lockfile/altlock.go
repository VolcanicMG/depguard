package lockfile

// Hand-rolled parsers for pnpm-lock.yaml and yarn.lock. depguard's zero-dep
// invariant rules out a YAML library, but we don't need general YAML: both
// formats are line-regular, and we only need name@version (+ integrity) for
// the advisory/cooldown/integrity checks — not the full dependency graph npm's
// own lockfile gives us. These are deliberately tolerant: an unrecognized line
// is skipped, never fatal, because a check must degrade gracefully.

import (
	"errors"
	"strings"
)

// lines splits a lockfile into lines, normalizing CRLF first. Without this a
// Windows-authored pnpm-lock.yaml left a '\r' on every line, so no key ended in
// ':' and the parser silently returned an EMPTY tree — an unchecked lockfile.
func lines(raw []byte) []string {
	return strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
}

// parsePnpm extracts installed packages from a pnpm-lock.yaml. It reads the
// `packages:` section, whose 2-space-indented keys are the package identities.
// Key shapes across pnpm versions: "lodash@4.17.21", "/lodash@4.17.21",
// "/@scope/name@1.0.0", optionally with a "(peer)" suffix.
//
// Every emitted entry is marked FromRegistry: splitPnpmKey only accepts a
// digit-leading version, so git/link/file deps never make it out of here. That
// marker is what lets the integrity checks flag a pnpm entry with no hash —
// pnpm normally records no tarball URL at all, so Resolved can't classify it.
// A non-registry `tarball:` in the resolution block IS captured into Resolved
// so the off-registry host check works too.
//
// It returns an error when a `packages:` section held content but NOTHING in it
// parsed as a package key: an empty result there means "we didn't understand
// this file", which must not be reported as "no dependencies to check".
func parsePnpm(raw []byte) ([]Pkg, int, error) {
	var out []Pkg
	curIdx := -1
	inPackages := false
	sawEntries := false
	skipped := 0
	for _, ln := range lines(raw) {
		if ln == "" {
			continue
		}
		// Top-level key (no indent) switches sections.
		if ln[0] != ' ' && ln[0] != '\t' {
			inPackages = strings.HasPrefix(ln, "packages:")
			curIdx = -1
			continue
		}
		if !inPackages {
			continue
		}
		sawEntries = true
		// A package key is indented exactly two spaces and ends with ':'.
		if strings.HasPrefix(ln, "  ") && !strings.HasPrefix(ln, "   ") && strings.HasSuffix(strings.TrimRight(ln, " "), ":") {
			key := strings.TrimSpace(ln)
			key = strings.TrimSuffix(key, ":")
			key = strings.Trim(key, "'\"")
			if name, ver, ok := splitPnpmKey(key); ok {
				out = append(out, Pkg{Name: name, Version: ver, FromRegistry: true})
				curIdx = len(out) - 1
			} else {
				if !knownNonRegistryKey(key) {
					skipped++ // a package key we did not understand — not a
					// non-registry dep we meant to drop
				}
				curIdx = -1
			}
			continue
		}
		// Deeper lines belong to the current package; grab its integrity and,
		// when the resolution names one, its tarball URL. Comments must not
		// supply values: full-line comments are skipped, and a trailing
		// comment is cut at " #" (YAML needs whitespace before '#', so a '#'
		// embedded in a value, e.g. a tarball URL fragment, survives).
		if curIdx >= 0 && !strings.HasPrefix(strings.TrimSpace(ln), "#") {
			content := ln
			if j := strings.Index(content, " #"); j >= 0 {
				content = content[:j]
			}
			if v, ok := pnpmField(content, "integrity"); ok {
				out[curIdx].Integrity = v
			}
			if v, ok := pnpmField(content, "tarball"); ok {
				out[curIdx].Resolved = v
			}
		}
	}
	if sawEntries && len(out) == 0 {
		return nil, 0, errors.New("unrecognized pnpm-lock.yaml packages format")
	}
	return out, skipped, nil
}

// knownNonRegistryKey reports whether a key splitPnpmKey rejected was one we
// MEANT to drop — a git/link/file/http dep, which carries no registry identity
// to check. Anything else is a shape we failed to understand, and silently
// checking the rest of the lockfile while dropping it is how coverage rots.
func knownNonRegistryKey(key string) bool {
	// These appear as a prefix ("github.com/…") or after the version separator
	// ("/local@link:../x"), so match anywhere. None of them can occur in a plain
	// "name@version" key: a package name carries no ':' and no bare '/'.
	for _, marker := range []string{"link:", "file:", "git+", "http:", "https:", "github.com/", "workspace:"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

// pnpmField pulls `key: value` out of a resolution line, stopping at the next
// ',' or '}' so a combined {integrity: ..., tarball: ...} block splits cleanly.
// The key must sit at a real field boundary — start-of-content, whitespace,
// '{' or ',' — so a crafted sibling like `notarball:` or `fakeintegrity:` can't
// be read as `tarball:`/`integrity:` and spoof a security value.
func pnpmField(ln, key string) (string, bool) {
	needle := key + ":"
	for from := 0; ; {
		rel := strings.Index(ln[from:], needle)
		if rel < 0 {
			return "", false
		}
		i := from + rel
		if i == 0 || isPnpmFieldBoundary(ln[i-1]) {
			val := ln[i+len(needle):]
			if j := strings.IndexAny(val, ",}"); j >= 0 {
				val = val[:j]
			}
			return strings.Trim(val, " '\""), true
		}
		from = i + 1
	}
}

// isPnpmFieldBoundary reports whether b can precede a field key on a resolution
// line (so the key isn't just a suffix of a longer, attacker-chosen field name).
func isPnpmFieldBoundary(b byte) bool {
	return b == ' ' || b == '\t' || b == '{' || b == ','
}

// splitPnpmKey turns a pnpm package key into (name, version), across every key
// shape pnpm has shipped:
//
//	v6+ (pnpm 8/9):  "lodash@4.17.21"   "/@scope/name@1.0.0"   "…@1.0.0(peer@2)"
//	v5  (pnpm 7):    "/lodash/4.17.21"  "/@scope/name/1.0.0"   "/lodash/4.17.21_react@17.0.0"
//
// The last '@' is tried FIRST, with the '/' shape as fallback, and both
// candidates must pass validPnpmName. Slash-first was wrong: it split
// "@scope/2fa@1.0.0" into name "@scope" / version "2fa@1.0.0" (the version is
// digit-leading, so nothing caught it) and that package then went entirely
// unchecked — a silent fail-open. The fallback still handles the v5 peer suffix,
// because "react-dom/18.2.0_react@18.2.0" fails the '@' attempt on its name
// (a bare '/') and only then reaches the '/' split.
func splitPnpmKey(key string) (name, version string, ok bool) {
	if i := strings.IndexByte(key, '('); i >= 0 {
		key = key[:i] // drop v6 peer-deps suffix
	}
	key = strings.TrimPrefix(key, "/")
	if at := strings.LastIndex(key, "@"); at > 0 {
		if n, v, ok := pnpmNameVersion(key[:at], key[at+1:]); ok {
			return n, v, true
		}
	}
	if sl := strings.LastIndex(key, "/"); sl > 0 {
		return pnpmNameVersion(key[:sl], key[sl+1:])
	}
	return "", "", false
}

// pnpmNameVersion validates a candidate split. The version must be digit-leading
// — that is what keeps git/link/file deps out of the registry-marked results —
// and a v5 "_peer@x" suffix is trimmed off it.
func pnpmNameVersion(name, version string) (string, string, bool) {
	if i := strings.IndexByte(version, '_'); i >= 0 {
		version = version[:i]
	}
	if version == "" || version[0] < '0' || version[0] > '9' || !validPnpmName(name) {
		return "", "", false
	}
	return name, version, true
}

// validPnpmName reports whether name is shaped like an npm package name: at most
// one '/', and only as a scope separator. Without this a pnpm GIT dep key
// ("github.com/user/repo/<sha>") whose sha happens to start with a digit parsed
// as a registry package — marked FromRegistry with no hash, so the unhashed gate
// blocked every commit in that repo.
func validPnpmName(name string) bool {
	if name == "" {
		return false
	}
	i := strings.IndexByte(name, '/')
	if i < 0 {
		return true
	}
	return name[0] == '@' && i > 1 && !strings.Contains(name[i+1:], "/")
}

// parseYarn extracts installed packages from a yarn.lock — both dialects:
//
//	classic (v1):  `  version "4.17.21"`     + `resolved` / `integrity`
//	berry  (v2+):  `  version: 4.17.21`      + `resolution:` / `checksum:`
//
// The field name is compared EXACTLY (modulo an optional trailing ':') — a
// HasPrefix check would let `integrity-x: …` masquerade as `integrity` and
// overwrite a real security value with a crafted one. Accepting only the bare
// form was itself a silent-drop bug: every berry entry writes `version:`, so
// nothing ever got a version and the whole lockfile parsed to zero packages.
//
// Berry's `checksum` is NOT an SRI hash (it is yarn's own "10c0/<hex>" cache
// key), so it is deliberately NOT mapped to Integrity — a berry entry carries no
// tarball URL either, so checkableDep leaves it out of the integrity gates. It
// still gets a name and a version, which is what the advisory and cooldown
// layers need.
//
// Like parsePnpm, it errors rather than returning an empty result when
// descriptor lines were present but NOTHING got a version: "we didn't understand
// this file" must never be reported as "no dependencies".
func parseYarn(raw []byte) ([]Pkg, int, error) {
	var out []Pkg
	curIdx := -1
	sawDescriptor := false
	for _, ln := range lines(raw) {
		if strings.TrimSpace(ln) == "" || strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		if ln[0] != ' ' && ln[0] != '\t' {
			// Descriptor line: take the first specifier, derive the name.
			desc := strings.TrimSuffix(strings.TrimSpace(ln), ":")
			first := strings.TrimSpace(strings.SplitN(desc, ",", 2)[0])
			first = strings.Trim(first, "\"")
			if first == "__metadata" {
				curIdx = -1 // berry's header block, not a package
				continue
			}
			sawDescriptor = true
			out = append(out, Pkg{Name: yarnName(first)})
			curIdx = len(out) - 1
			continue
		}
		if curIdx < 0 {
			continue
		}
		t := strings.TrimSpace(ln)
		field, val, _ := strings.Cut(t, " ")
		switch strings.TrimSuffix(field, ":") {
		case "version":
			out[curIdx].Version = strings.Trim(strings.TrimSpace(val), "\"")
		case "resolved":
			out[curIdx].Resolved = strings.Trim(strings.TrimSpace(val), "\"")
		case "integrity":
			out[curIdx].Integrity = strings.TrimSpace(val)
		}
	}
	if sawDescriptor && !anyVersioned(out) {
		return nil, 0, errors.New("unrecognized yarn.lock format (no entry carried a version)")
	}
	// A descriptor that never got a version is an entry we read but could not
	// identify — it drops out of every check, so the caller must be able to say so.
	skipped := 0
	for _, p := range out {
		if p.Version == "" {
			skipped++
		}
	}
	return out, skipped, nil
}

// anyVersioned reports whether at least one parsed entry got a version.
func anyVersioned(pkgs []Pkg) bool {
	for _, p := range pkgs {
		if p.Version != "" {
			return true
		}
	}
	return false
}

// yarnName extracts the package name from a yarn specifier like
// "lodash@^4.17.21" or "@scope/name@^1.0.0" — everything before the '@' that
// introduces the version range (the scope's leading '@' is not that one).
func yarnName(spec string) string {
	at := strings.LastIndex(spec, "@")
	if at <= 0 {
		return spec
	}
	return spec[:at]
}
