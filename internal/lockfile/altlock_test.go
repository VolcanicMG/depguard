package lockfile

import (
	"reflect"
	"strings"
	"testing"
)

// pnpm entries are registry deps by construction (splitPnpmKey only accepts a
// digit-leading version), so the parser must mark them FromRegistry — that
// marker is what makes the unhashed gate apply to a pnpm lockfile at all.
func TestParsePnpmMarksRegistryAndFields(t *testing.T) {
	raw := []byte(`lockfileVersion: '6.0'

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-abc}
    dev: false

  /evil@1.0.0:
    resolution: {tarball: https://evil.example/evil-1.0.0.tgz}
    dev: false

  /nohash@2.0.0:
    resolution: {}
    dev: false
`)
	got, _, err := parsePnpm(raw)
	if err != nil {
		t.Fatalf("parsePnpm: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("parsed %d packages, want 3: %+v", len(got), got)
	}
	byName := map[string]Pkg{}
	for _, p := range got {
		if !p.FromRegistry {
			t.Errorf("%s: FromRegistry = false, want true", p.Key())
		}
		byName[p.Name] = p
	}
	if got := byName["lodash"].Integrity; got != "sha512-abc" {
		t.Errorf("lodash integrity = %q, want %q", got, "sha512-abc")
	}
	if got := byName["evil"].Resolved; got != "https://evil.example/evil-1.0.0.tgz" {
		t.Errorf("evil resolved = %q, want the foreign tarball URL", got)
	}
	if got := byName["nohash"].Integrity; got != "" {
		t.Errorf("nohash integrity = %q, want empty (must reach the unhashed gate)", got)
	}
}

// A commented-out field must not supply the value — otherwise a poisoned
// lockfile could hide a missing hash behind `# integrity: sha512-…`.
func TestParsePnpmIgnoresComments(t *testing.T) {
	// x: full-line AND trailing comments must not supply values.
	// y: a '#' embedded in a value (no preceding space) is not a comment.
	raw := []byte("packages:\n  /x@1.0.0:\n    # integrity: sha512-fake\n    # tarball: https://evil.example/x.tgz\n    resolution: {} # integrity: sha512-fake2\n  /y@2.0.0:\n    resolution: {tarball: https://r.example/y.tgz#sha256=abc}\n")
	got, _, err := parsePnpm(raw)
	if err != nil {
		t.Fatalf("parsePnpm: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d, want 2", len(got))
	}
	if got[0].Integrity != "" || got[0].Resolved != "" {
		t.Errorf("comment supplied a field: %+v", got[0])
	}
	if got[1].Resolved != "https://r.example/y.tgz#sha256=abc" {
		t.Errorf("value-embedded '#' clipped: resolved = %q", got[1].Resolved)
	}
}

// A combined resolution block must split cleanly — the integrity value must not
// swallow the trailing tarball field.
func TestParsePnpmSplitsCombinedResolution(t *testing.T) {
	raw := []byte("packages:\n  /x@1.0.0:\n    resolution: {integrity: sha512-zzz, tarball: https://r.example/x.tgz}\n")
	got, _, err := parsePnpm(raw)
	if err != nil {
		t.Fatalf("parsePnpm: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("parsed %d, want 1", len(got))
	}
	if got[0].Integrity != "sha512-zzz" {
		t.Errorf("integrity = %q, want %q", got[0].Integrity, "sha512-zzz")
	}
	if got[0].Resolved != "https://r.example/x.tgz" {
		t.Errorf("resolved = %q", got[0].Resolved)
	}
}

// A crafted sibling field must NOT be read as a security value: `notarball:`
// ends in "tarball:" and `fakeintegrity:` ends in "integrity:", but neither
// sits at a field boundary, so a poisoned lockfile can't spoof Resolved/Integrity.
func TestParsePnpmRejectsUnanchoredFields(t *testing.T) {
	raw := []byte("packages:\n  /x@1.0.0:\n    resolution: {notarball: https://evil.example/x.tgz, fakeintegrity: sha512-evil}\n")
	got, _, err := parsePnpm(raw)
	if err != nil {
		t.Fatalf("parsePnpm: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("parsed %d, want 1", len(got))
	}
	if got[0].Resolved != "" {
		t.Errorf("notarball spoofed Resolved = %q, want empty", got[0].Resolved)
	}
	if got[0].Integrity != "" {
		t.Errorf("fakeintegrity spoofed Integrity = %q, want empty", got[0].Integrity)
	}
	// The real fields at a boundary must still parse.
	real := []byte("packages:\n  /y@2.0.0:\n    resolution: {integrity: sha512-real, tarball: https://r.example/y.tgz}\n")
	g2, _, err2 := parsePnpm(real)
	if err2 != nil {
		t.Fatalf("parsePnpm: %v", err2)
	}
	if g2[0].Integrity != "sha512-real" || g2[0].Resolved != "https://r.example/y.tgz" {
		t.Errorf("real fields at a boundary failed to parse: %+v", g2[0])
	}
}

// A crafted yarn field name (`integrity-ish: …`) must not overwrite integrity,
// while a real `integrity "…"` line still does.
func TestParseYarnRejectsUnanchoredFields(t *testing.T) {
	// Real integrity FIRST, crafted sibling LAST: with the old HasPrefix match,
	// last-write-wins would let integrity-ish clobber the real value.
	raw := []byte("lodash@^4.17.21:\n  version \"4.17.21\"\n  integrity sha512-real\n  integrity-ish sha512-evil\n")
	got, _, err := parseYarn(raw)
	if err != nil {
		t.Fatalf("parseYarn: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("parsed %d, want 1", len(got))
	}
	if got[0].Integrity != "sha512-real" {
		t.Errorf("integrity = %q, want %q (integrity-ish must not overwrite)", got[0].Integrity, "sha512-real")
	}
}

// npm's own parser must NOT set FromRegistry: an npm lockfile records the
// tarball URL for real registry deps, and file:/link: entries legitimately have
// neither a URL nor a hash.
func TestNpmEntriesAreNotMarkedFromRegistry(t *testing.T) {
	raw := []byte(`{"lockfileVersion":3,"packages":{
	  "":{"name":"root"},
	  "node_modules/lodash":{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz","integrity":"sha512-abc"},
	  "node_modules/local":{"version":"1.0.0","resolved":"../local","link":true}
	}}`)
	pkgs, err := InstalledBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if p.FromRegistry {
			t.Errorf("%s: FromRegistry = true, want false for npm entries", p.Key())
		}
	}
}

func TestParseYarnSetsResolved(t *testing.T) {
	raw := []byte("lodash@^4.17.21:\n  version \"4.17.21\"\n  resolved \"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz\"\n  integrity sha512-abc\n")
	got, _, err := parseYarn(raw)
	if err != nil {
		t.Fatalf("parseYarn: %v", err)
	}
	if len(got) != 1 || got[0].Resolved == "" || got[0].FromRegistry {
		t.Fatalf("unexpected yarn parse: %+v", got)
	}
}

// A CRLF pnpm-lock.yaml must parse identically to an LF one. It didn't: the
// trailing '\r' meant no key line ended in ':', so the parser returned an EMPTY
// tree and every dependency went unchecked — silently, with no error.
func TestParsePnpmCRLF(t *testing.T) {
	lf := "lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-abc}\n\n  /left-pad@1.3.0:\n    resolution: {integrity: sha512-def}\n"
	want, _, err := parsePnpm([]byte(lf))
	if err != nil {
		t.Fatalf("parsePnpm(LF): %v", err)
	}
	got, _, err := parsePnpm([]byte(strings.ReplaceAll(lf, "\n", "\r\n")))
	if err != nil {
		t.Fatalf("parsePnpm(CRLF): %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("CRLF parsed %d packages, want 2: %+v", len(got), got)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CRLF parse = %+v, want the LF result %+v", got, want)
	}
}

// A yarn.lock with CRLF line endings parses too.
func TestParseYarnCRLF(t *testing.T) {
	lf := "lodash@^4.17.21:\n  version \"4.17.21\"\n  integrity sha512-abc\n"
	got, _, err := parseYarn([]byte(strings.ReplaceAll(lf, "\n", "\r\n")))
	if err != nil {
		t.Fatalf("parseYarn: %v", err)
	}
	if len(got) != 1 || got[0].Name != "lodash" || got[0].Version != "4.17.21" {
		t.Fatalf("CRLF yarn parse = %+v, want lodash@4.17.21", got)
	}
	if got[0].Integrity != "sha512-abc" {
		t.Errorf("integrity = %q, want sha512-abc (a stray \\r would corrupt it)", got[0].Integrity)
	}
}

// A packages: section we could not read AT ALL is an error, not "no packages":
// reporting zero dependencies for a file we didn't understand is the same
// silent-pass bug as the CRLF one.
func TestParsePnpmUnrecognizedPackagesErrors(t *testing.T) {
	// A future key shape with no version anywhere in it.
	raw := []byte("lockfileVersion: '9.0'\n\npackages:\n\n  registry.example/some-future-shape:\n    kind: opaque\n")
	if got, _, err := parsePnpm(raw); err == nil {
		t.Fatalf("parsePnpm returned (%+v, nil), want an error for an unreadable packages section", got)
	}
}

// No packages: section at all is legitimately empty — no error.
func TestParsePnpmNoPackagesSection(t *testing.T) {
	got, _, err := parsePnpm([]byte("lockfileVersion: '6.0'\n\nsettings:\n  autoInstallPeers: true\n"))
	if err != nil || got != nil {
		t.Fatalf("parsePnpm(no packages) = (%+v, %v), want (nil, nil)", got, err)
	}
}

// pnpm 7 writes lockfileVersion 5.x, whose keys put the version after a SLASH
// with no '@' at all. Rejecting those made every package unparseable — and once
// the "unrecognized packages section" guard landed, that turned into a hard
// error on every commit in a pnpm-7 repo.
func TestSplitPnpmKeyV5AndV6(t *testing.T) {
	cases := []struct{ key, name, version string }{
		// v6 (pnpm 8)
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"/lodash@4.17.21", "lodash", "4.17.21"},
		{"/@scope/name@1.0.0", "@scope/name", "1.0.0"},
		{"/react-dom@18.2.0(react@18.2.0)", "react-dom", "18.2.0"},
		// v5 (pnpm 7)
		{"/lodash/4.17.21", "lodash", "4.17.21"},
		{"/@scope/name/1.0.0", "@scope/name", "1.0.0"},
		{"/react-dom/18.2.0_react@18.2.0", "react-dom", "18.2.0"},
		// A scoped package whose NAME starts with a digit: slash-first split it
		// into "@scope" / "2fa@1.0.0" — digit-leading, so it passed, and the real
		// package was never advisory- or cooldown-checked.
		{"@scope/2fa@1.0.0", "@scope/2fa", "1.0.0"},
		{"/@scope/2fa@1.0.0", "@scope/2fa", "1.0.0"},
	}
	for _, c := range cases {
		name, version, ok := splitPnpmKey(c.key)
		if !ok || name != c.name || version != c.version {
			t.Errorf("splitPnpmKey(%q) = (%q, %q, %v), want (%q, %q, true)", c.key, name, version, ok, c.name, c.version)
		}
	}
	// Non-registry keys must still be rejected — that rejection is what keeps
	// git/link deps out of the hash-checked set.
	// A git dep whose commit sha starts with a digit used to parse as a registry
	// package — FromRegistry with no hash, so the unhashed gate blocked every
	// commit in that repo.
	for _, bad := range []string{
		"github.com/foo/bar",
		"github.com/foo/bar/2b8b1c0e4d5a6f7890abcdef1234567890abcdef",
		"link:../local",
		"@scope/name",
	} {
		if _, _, ok := splitPnpmKey(bad); ok {
			t.Errorf("splitPnpmKey(%q) accepted a non-registry key", bad)
		}
	}
}

// A whole v5 lockfile parses rather than erroring out.
func TestParsePnpmV5Lockfile(t *testing.T) {
	raw := []byte("lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.21:\n    resolution: {integrity: sha512-abc}\n\n  /@scope/name/1.0.0:\n    resolution: {integrity: sha512-def}\n")
	got, _, err := parsePnpm(raw)
	if err != nil {
		t.Fatalf("parsePnpm(v5): %v", err)
	}
	if len(got) != 2 || got[0].Key() != "lodash@4.17.21" || got[1].Key() != "@scope/name@1.0.0" {
		t.Fatalf("v5 parse = %+v, want lodash@4.17.21 and @scope/name@1.0.0", got)
	}
}

// yarn berry writes `version: 4.17.21` (colon) instead of `version "4.17.21"`.
// Comparing the field exactly meant nothing got a version and the file parsed to
// ZERO dependencies — silently, the same class of bug as the pnpm CRLF one.
func TestParseYarnBerry(t *testing.T) {
	raw := []byte(`# This file is generated by running "yarn install"

__metadata:
  version: 8
  cacheKey: 10c0

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 10c0/abcdef
  languageName: node
  linkType: hard

"@types/node@npm:^20.0.0":
  version: 20.11.0
  resolution: "@types/node@npm:20.11.0"
  checksum: 10c0/123456
`)
	got, _, err := parseYarn(raw)
	if err != nil {
		t.Fatalf("parseYarn(berry): %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("berry parse returned %d entries, want 2: %+v", len(got), got)
	}
	if got[0].Name != "lodash" || got[0].Version != "4.17.21" {
		t.Errorf("entry 0 = %+v, want lodash@4.17.21", got[0])
	}
	if got[1].Name != "@types/node" || got[1].Version != "20.11.0" {
		t.Errorf("entry 1 = %+v, want @types/node@20.11.0", got[1])
	}
	// berry's checksum is yarn's own cache key, not an SRI hash — mapping it to
	// Integrity would be claiming a verification we did not do.
	if got[0].Integrity != "" {
		t.Errorf("berry checksum leaked into Integrity: %q", got[0].Integrity)
	}
	if checkable := got[0].FromRegistry || got[0].Resolved != ""; checkable {
		t.Error("a berry entry must fall outside the integrity gates, not gate as unhashed")
	}
}

// Classic v1 still parses (the colon-tolerance must not regress it).
func TestParseYarnClassicStillWorks(t *testing.T) {
	raw := []byte("lodash@^4.17.21:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n  integrity sha512-abc\n")
	got, _, err := parseYarn(raw)
	if err != nil {
		t.Fatalf("parseYarn(classic): %v", err)
	}
	if len(got) != 1 || got[0].Version != "4.17.21" || got[0].Integrity != "sha512-abc" {
		t.Fatalf("classic parse = %+v", got)
	}
}

// Descriptor lines we could not read at all is an error, not "no dependencies".
func TestParseYarnUnrecognizedErrors(t *testing.T) {
	raw := []byte("some-dep@^1.0.0:\n  someFutureField: 3\n  anotherField: x\n")
	if got, _, err := parseYarn(raw); err == nil {
		t.Fatalf("parseYarn = (%+v, nil), want an error when nothing carried a version", got)
	}
}

// A key the parser drops silently is a package that escapes EVERY check. Git and
// file deps are dropped on purpose; anything else is a shape we failed to read,
// and the caller has to be able to say how much of the lockfile it actually saw.
func TestParsePnpmCountsUnrecognizedEntries(t *testing.T) {
	raw := []byte("lockfileVersion: '6.0'\n\npackages:\n\n" +
		"  /lodash@4.17.21:\n    resolution: {integrity: sha512-abc}\n" +
		"  /local@link:../x:\n    resolution: {}\n" + // deliberate drop
		"  github.com/foo/bar/abcdef:\n    resolution: {}\n" + // deliberate drop
		"  some-future-shape-no-version:\n    resolution: {}\n") // NOT deliberate
	got, skipped, err := parsePnpm(raw)
	if err != nil {
		t.Fatalf("parsePnpm: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("parsed %d packages, want 1: %+v", len(got), got)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (git/link deps are intentional drops, the unknown shape is not)", skipped)
	}
}

// A yarn descriptor that never got a version drops out of every check too.
func TestParseYarnCountsVersionlessDescriptors(t *testing.T) {
	raw := []byte("lodash@^4.17.21:\n  version \"4.17.21\"\n  integrity sha512-abc\n\n" +
		"weird@^1.0.0:\n  someFutureField: 3\n")
	got, skipped, err := parseYarn(raw)
	if err != nil {
		t.Fatalf("parseYarn: %v", err)
	}
	if len(got) != 2 || skipped != 1 {
		t.Fatalf("parsed %d entries with skipped=%d, want 2 and 1: %+v", len(got), skipped, got)
	}
}

// A clean lockfile reports nothing skipped — the counter must not cry wolf.
func TestParsersCountZeroOnCleanLockfiles(t *testing.T) {
	pnpm := []byte("lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-abc}\n")
	if _, skipped, err := parsePnpm(pnpm); err != nil || skipped != 0 {
		t.Errorf("parsePnpm(clean) skipped = %d (err %v), want 0", skipped, err)
	}
	yarn := []byte("lodash@^4.17.21:\n  version \"4.17.21\"\n  integrity sha512-abc\n")
	if _, skipped, err := parseYarn(yarn); err != nil || skipped != 0 {
		t.Errorf("parseYarn(clean) skipped = %d (err %v), want 0", skipped, err)
	}
}
