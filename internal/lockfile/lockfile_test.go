package lockfile

import (
	"reflect"
	"testing"
)

// Two lockfile paths for the SAME name@version that disagree about the tarball
// or the hash must be flagged. Dedupe keeps one record, so without Conflict the
// disagreement — the signature of a hand-edited lockfile — vanished silently.
func TestDedupeFlagsConflictingDuplicates(t *testing.T) {
	entries := []Entry{
		{Name: "tar", Version: "6.0.0", Path: "node_modules/tar", Resolved: "https://registry.npmjs.org/tar.tgz", Integrity: "sha512-good"},
		{Name: "tar", Version: "6.0.0", Path: "node_modules/a/node_modules/tar", Resolved: "https://evil.example/tar.tgz", Integrity: "sha512-good"},
		{Name: "ms", Version: "2.0.0", Path: "node_modules/ms", Resolved: "https://registry.npmjs.org/ms.tgz", Integrity: "sha512-a"},
		{Name: "ms", Version: "2.0.0", Path: "node_modules/b/node_modules/ms", Resolved: "https://registry.npmjs.org/ms.tgz", Integrity: "sha512-DIFFERENT"},
	}
	got := dedupe(entries)
	if len(got) != 2 {
		t.Fatalf("dedupe returned %d pkgs, want 2: %+v", len(got), got)
	}
	for _, p := range got {
		if !p.Conflict {
			t.Errorf("%s: Conflict = false, want true", p.Key())
		}
	}
}

// Identical duplicates are the NORMAL shape of a nested tree — they must not
// be flagged, or every real lockfile would gate.
func TestDedupeIgnoresIdenticalDuplicates(t *testing.T) {
	e := Entry{Name: "ms", Version: "2.0.0", Resolved: "https://registry.npmjs.org/ms.tgz", Integrity: "sha512-a"}
	a, b := e, e
	a.Path, b.Path = "node_modules/ms", "node_modules/x/node_modules/ms"
	// A third record that merely OMITS a field carries less information, not a
	// contradiction.
	c := Entry{Name: "ms", Version: "2.0.0", Path: "node_modules/y/node_modules/ms"}
	got := dedupe([]Entry{a, b, c})
	if len(got) != 1 || got[0].Conflict {
		t.Fatalf("dedupe = %+v, want one non-conflicting ms@2.0.0", got)
	}
}

// The surviving record of a duplicate pair must be the same one every run —
// entries arrive from an unordered map, so without the path sort the reported
// Resolved/Integrity flapped between parses.
func TestDedupeDeterministic(t *testing.T) {
	entries := []Entry{
		{Name: "ms", Version: "2.0.0", Path: "node_modules/z/node_modules/ms", Integrity: "sha512-z"},
		{Name: "ms", Version: "2.0.0", Path: "node_modules/ms", Integrity: "sha512-a"},
	}
	want := dedupe(entries)
	if want[0].Integrity != "sha512-a" {
		t.Fatalf("survivor = %q, want the lowest path's record sha512-a", want[0].Integrity)
	}
	for i := 0; i < 20; i++ {
		entries[0], entries[1] = entries[1], entries[0] // input order must not matter
		if got := dedupe(entries); !reflect.DeepEqual(got, want) {
			t.Fatalf("dedupe not deterministic: %+v vs %+v", got, want)
		}
	}
}

// A crafted lockfile must not be able to DISARM the integrity gates by adding a
// duplicate that carries no information. With "first wins" collapsing, an
// info-empty record at a path that sorts first evicted the real one: the
// survivor had no URL and no hash, checkableDep went false, and the package was
// skipped by both integrity checks while the run printed "integrity ok".
func TestDedupeCannotBeDisarmedByEmptyDuplicate(t *testing.T) {
	entries := []Entry{
		// Sorts FIRST and says nothing.
		{Name: "tar", Version: "6.0.0", Path: "node_modules/a/node_modules/tar"},
		// The record that actually matters.
		{Name: "tar", Version: "6.0.0", Path: "node_modules/tar",
			Resolved: "https://evil.example/tar.tgz", Integrity: "sha512-evil"},
	}
	got := dedupe(entries)
	if len(got) != 1 {
		t.Fatalf("dedupe returned %d pkgs, want 1: %+v", len(got), got)
	}
	if got[0].Resolved != "https://evil.example/tar.tgz" || got[0].Integrity != "sha512-evil" {
		t.Fatalf("survivor = %+v, want the evil tarball/hash merged in (an empty duplicate must not erase them)", got[0])
	}
	if got[0].Conflict {
		t.Error("Conflict = true, but the empty record contradicts nothing")
	}
}

// The merge is order-independent: whichever record the sort puts first, the
// union is the same.
func TestMergeUnionIsOrderIndependent(t *testing.T) {
	full := Entry{Name: "tar", Version: "6.0.0", Resolved: "https://r/tar.tgz", Integrity: "sha512-a"}
	empty := Entry{Name: "tar", Version: "6.0.0"}
	// Only Path decides order, so give each arrangement both orderings.
	a, b := full, empty
	a.Path, b.Path = "node_modules/tar", "node_modules/z/node_modules/tar"
	c, d := empty, full
	c.Path, d.Path = "node_modules/tar", "node_modules/z/node_modules/tar"
	if !reflect.DeepEqual(dedupe([]Entry{a, b}), dedupe([]Entry{c, d})) {
		t.Error("merge result depends on which record sorts first")
	}
	if got := dedupe([]Entry{c, d}); got[0].Integrity != "sha512-a" {
		t.Errorf("integrity = %q, want it merged up from the later record", got[0].Integrity)
	}
}
