package lockfile

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
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
	got := dedupe([]Entry{a, b})
	if len(got) != 1 || got[0].Conflict {
		t.Fatalf("dedupe = %+v, want one non-conflicting ms@2.0.0", got)
	}
	// A record with no tarball URL is genuinely less information (pnpm records
	// none at all), so Resolved empty-vs-set must NOT contradict.
	noURL := Entry{Name: "ms", Version: "2.0.0", Path: "node_modules/y/node_modules/ms", Integrity: "sha512-a"}
	if got := dedupe([]Entry{a, noURL}); got[0].Conflict {
		t.Errorf("a missing Resolved was treated as a conflict: %+v", got[0])
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
	// The union keeps the entry checkable for the off-registry host; the missing
	// hash on the other occurrence is itself a finding, so this also conflicts.
	if !got[0].Conflict {
		t.Error("Conflict = false — one occurrence carried no hash, which is the unhashed finding, not a gap to fill")
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

// An npm registry dep is hashed at EVERY path it appears. So when one occurrence
// has an integrity hash and another does not, that is not "one record knows less"
// — it is the unhashed finding, on that path. Filling the gap in from the sibling
// made it vanish: the survivor looked fully hashed and the gate stayed quiet.
func TestMergeHashedVsUnhashedConflicts(t *testing.T) {
	hashed := Entry{Name: "tar", Version: "6.0.0", Path: "node_modules/tar",
		Resolved: "https://registry.npmjs.org/tar.tgz", Integrity: "sha512-a"}
	unhashed := Entry{Name: "tar", Version: "6.0.0", Path: "node_modules/x/node_modules/tar",
		Resolved: "https://registry.npmjs.org/tar.tgz"}
	for _, order := range [][]Entry{{hashed, unhashed}, {unhashed, hashed}} {
		got := dedupe(order)
		if len(got) != 1 {
			t.Fatalf("dedupe = %+v, want one entry", got)
		}
		if !got[0].Conflict {
			t.Errorf("hashed+unhashed occurrences did not conflict (order %q first): %+v", order[0].Path, got[0])
		}
		// Still checkable: the union keeps the hash we do have.
		if got[0].Integrity != "sha512-a" {
			t.Errorf("Integrity = %q, want the known hash kept", got[0].Integrity)
		}
	}
}

// Union folds the per-ref snapshots a multi-ref push produces into one set.
func TestUnion(t *testing.T) {
	a := []Pkg{{Name: "ms", Version: "2.0.0", Integrity: "sha512-a"}, {Name: "tar", Version: "6.0.0", Integrity: "sha512-t"}}
	b := []Pkg{{Name: "ms", Version: "2.0.0", Integrity: "sha512-a"}, {Name: "new", Version: "1.0.0", Integrity: "sha512-n"}}
	got := Union(a, b)
	var keys []string
	for _, p := range got {
		keys = append(keys, p.Key())
	}
	if !reflect.DeepEqual(keys, []string{"ms@2.0.0", "new@1.0.0", "tar@6.0.0"}) {
		t.Fatalf("Union keys = %v, want the distinct union, sorted", keys)
	}
	for _, p := range got {
		if p.Conflict {
			t.Errorf("%s: identical records across refs must not conflict", p.Key())
		}
	}
}

// parseNamed picks the parser from the FILENAME, which is the only format hint
// available when the bytes come from `git show` instead of from disk.
func TestParseNamedDispatch(t *testing.T) {
	pnpm := []byte("lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-abc}\n")
	yarn := []byte("lodash@^4.17.21:\n  version \"4.17.21\"\n  integrity sha512-abc\n")
	npm := []byte(`{"lockfileVersion":3,"packages":{"":{"name":"r"},"node_modules/lodash":{"version":"4.17.21","integrity":"sha512-abc"}}}`)
	for _, c := range []struct {
		name string
		raw  []byte
	}{{"pnpm-lock.yaml", pnpm}, {"yarn.lock", yarn}, {"package-lock.json", npm}} {
		got, _, err := parseNamed(c.name, c.raw)
		if err != nil {
			t.Errorf("parseNamed(%s): %v", c.name, err)
			continue
		}
		if len(got) != 1 || got[0].Key() != "lodash@4.17.21" {
			t.Errorf("parseNamed(%s) = %+v, want lodash@4.17.21", c.name, got)
		}
	}
	// Wrong parser for the bytes must error, not silently return nothing.
	if _, _, err := parseNamed("package-lock.json", pnpm); err == nil {
		t.Error("npm parser accepted a pnpm lockfile")
	}
}

// gitRepo makes a temp repo with an initial commit, returning its dir.
func gitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v unavailable: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	return dir
}

func npmLock(names ...string) string {
	out := `{"lockfileVersion":3,"packages":{"":{"name":"r"}`
	for _, n := range names {
		out += `,"node_modules/` + n + `":{"version":"1.0.0","resolved":"https://r/x.tgz","integrity":"sha512-a"}`
	}
	return out + "}}"
}

// The gates must judge what git is about to record, not what happens to be in
// the working tree. A staged lockfile that differs from the tree is exactly the
// case that slipped through: the tree looked clean, the commit did not.
func TestInstalledAtIndexAndCommit(t *testing.T) {
	dir := gitRepo(t)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	path := filepath.Join(dir, "package-lock.json")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(npmLock("committed"))
	git("add", "package-lock.json")
	git("commit", "-qm", "one")
	head, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.TrimSpace(string(head))

	write(npmLock("staged"))
	git("add", "package-lock.json")
	write(npmLock("worktree")) // tree now differs from BOTH index and HEAD

	keys := func(ref string) []string {
		t.Helper()
		pkgs, _, err := InstalledAt(dir, ref)
		if err != nil {
			t.Fatalf("InstalledAt(%q): %v", ref, err)
		}
		var out []string
		for _, p := range pkgs {
			out = append(out, p.Name)
		}
		return out
	}
	if got := keys(""); !reflect.DeepEqual(got, []string{"worktree"}) {
		t.Errorf(`InstalledAt("") = %v, want the working tree`, got)
	}
	if got := keys(":"); !reflect.DeepEqual(got, []string{"staged"}) {
		t.Errorf(`InstalledAt(":") = %v, want the STAGED lockfile`, got)
	}
	if got := keys(sha); !reflect.DeepEqual(got, []string{"committed"}) {
		t.Errorf("InstalledAt(<sha>) = %v, want the committed lockfile", got)
	}
	if _, _, err := InstalledAt(dir, "0000000000000000000000000000000000000000"); err == nil {
		t.Error("InstalledAt on a ref with no lockfile should report not-exist")
	}
}

// A pnpm/yarn snapshot must work from git too — the name dispatch is what makes
// that possible, since `git show` hands over bytes with no format hint.
func TestInstalledAtNonNpmLockfile(t *testing.T) {
	dir := gitRepo(t)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	lock := "lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-abc}\n"
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "pnpm-lock.yaml")
	pkgs, _, err := InstalledAt(dir, ":")
	if err != nil {
		t.Fatalf("InstalledAt(pnpm, index): %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Key() != "lodash@4.17.21" {
		t.Fatalf("staged pnpm snapshot = %+v, want lodash@4.17.21", pkgs)
	}
}

// npm records a bundled dependency as a SECOND entry for the same name@version
// with no resolved and no integrity — the bytes ship inside the parent's tarball,
// which is hashed. Reading that as "hashed at one path, hashless at another" made
// every bundling package's tree self-contradictory, and the conflict verdict is
// UNWAIVABLE: the repo became un-committable except with GUARD_SKIP, while the
// advice ("npm install regenerates consistent entries") reproduces it exactly.
func TestBundledAndLinkEntriesAreNotOccurrences(t *testing.T) {
	lock := []byte(`{"lockfileVersion":3,"packages":{
	  "":{"name":"root"},
	  "node_modules/bar":{"version":"1.2.3","resolved":"https://registry.npmjs.org/bar.tgz","integrity":"sha512-bar"},
	  "node_modules/foo/node_modules/bar":{"version":"1.2.3","inBundle":true},
	  "node_modules/mylib":{"version":"1.0.0","link":true},
	  "node_modules/foo":{"version":"2.0.0","resolved":"https://registry.npmjs.org/foo.tgz","integrity":"sha512-foo"}
	}}`)
	pkgs, _, err := parseNamed("package-lock.json", lock)
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]Pkg{}
	for _, p := range pkgs {
		byKey[p.Key()] = p
	}
	bar, ok := byKey["bar@1.2.3"]
	if !ok {
		t.Fatal("bar@1.2.3 missing entirely")
	}
	if bar.Conflict {
		t.Error("a bundled copy was read as a contradicting occurrence — this gate is unwaivable, so the repo could not be committed at all")
	}
	if bar.Integrity != "sha512-bar" {
		t.Errorf("Integrity = %q, want the real entry's hash", bar.Integrity)
	}
	if _, ok := byKey["mylib@1.0.0"]; ok {
		t.Error("a link: entry was kept — it has no registry identity to check")
	}
}

// ...and the crafted attack duplicate carries no inBundle, so it must still be
// caught. This is the line between the two: npm marks its own bundled copies.
func TestCraftedEmptyDuplicateStillConflicts(t *testing.T) {
	lock := []byte(`{"lockfileVersion":3,"packages":{
	  "":{"name":"root"},
	  "node_modules/a/node_modules/tar":{"version":"6.0.0"},
	  "node_modules/tar":{"version":"6.0.0","resolved":"https://evil.example/tar.tgz","integrity":"sha512-evil"}
	}}`)
	pkgs, _, err := parseNamed("package-lock.json", lock)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || !pkgs[0].Conflict {
		t.Fatalf("pkgs = %+v, want one CONFLICTING tar@6.0.0 (no inBundle marker = not npm's doing)", pkgs)
	}
}

// inBundle is a field anyone editing the lockfile can write. A genuine bundled
// copy records neither a URL nor a hash; an entry that claims the flag but still
// carries a fetchable resolved/integrity must stay visible to every gate.
func TestMarkedInBundleWithURLIsStillChecked(t *testing.T) {
	lock := []byte(`{"lockfileVersion":3,"packages":{
	  "":{"name":"root"},
	  "node_modules/tar":{"version":"6.0.0","inBundle":true,"resolved":"https://evil.example/tar.tgz","integrity":"sha512-evil"}
	}}`)
	pkgs, _, err := parseNamed("package-lock.json", lock)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Resolved != "https://evil.example/tar.tgz" {
		t.Fatalf("pkgs = %+v, want the URL-bearing entry kept despite inBundle", pkgs)
	}
}

// Two branches in one push are two independently consistent lockfiles. They are
// allowed to disagree — branch A predating a hash that branch B added is ordinary
// history. Deriving a conflict there produced an unwaivable dead end blaming a
// file that is fine.
func TestUnionDoesNotInventConflicts(t *testing.T) {
	a := []Pkg{{Name: "ms", Version: "2.0.0", Resolved: "https://r/ms.tgz"}}
	b := []Pkg{{Name: "ms", Version: "2.0.0", Resolved: "https://other/ms.tgz", Integrity: "sha512-b"}}
	got := Union(a, b)
	if len(got) != 1 {
		t.Fatalf("Union = %+v, want one entry", got)
	}
	if got[0].Conflict {
		t.Error("Union invented a conflict between two self-consistent lockfiles")
	}
	if got[0].Integrity != "sha512-b" {
		t.Errorf("Integrity = %q, want the known hash unioned in", got[0].Integrity)
	}
	// A conflict found INSIDE one ref is real and must survive the fold.
	flagged := []Pkg{{Name: "tar", Version: "6.0.0", Conflict: true}}
	plain := []Pkg{{Name: "tar", Version: "6.0.0"}}
	for _, order := range [][][]Pkg{{flagged, plain}, {plain, flagged}} {
		if u := Union(order...); !u[0].Conflict {
			t.Error("a real in-lockfile conflict was lost in the union")
		}
	}
}
