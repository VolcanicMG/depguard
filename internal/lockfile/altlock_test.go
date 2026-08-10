package lockfile

import "testing"

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
	got := parsePnpm(raw)
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
	got := parsePnpm(raw)
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
	got := parsePnpm(raw)
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
	got := parseYarn(raw)
	if len(got) != 1 || got[0].Resolved == "" || got[0].FromRegistry {
		t.Fatalf("unexpected yarn parse: %+v", got)
	}
}
