package approvals

import (
	"os"
	"path/filepath"
	"testing"
)

// An approval is a decision about CODE, not about a name. Binding it to the
// tarball hash is what stops a republished (or lockfile-repointed) version from
// inheriting a yes the human gave to different bytes.
func TestEntryAppliesTo(t *testing.T) {
	cases := []struct {
		name    string
		stored  string
		current string
		want    bool
	}{
		{"bound, unchanged", "sha512-a", "sha512-a", true},
		{"bound, tarball changed", "sha512-a", "sha512-b", false},
		{"bound, lockfile now unhashed", "sha512-a", "", false},
		{"legacy entry with no binding", "", "sha512-a", true},
	}
	for _, c := range cases {
		if got := (Entry{Integrity: c.stored}).AppliesTo(c.current); got != c.want {
			t.Errorf("%s: AppliesTo = %v, want %v", c.name, got, c.want)
		}
	}
}

// The integrity binding must survive a save/load round-trip, and an old file
// written without the field must still load and apply.
func TestIntegrityRoundTrip(t *testing.T) {
	dir := t.TempDir()
	f, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.Set("tar@6.0.0", ApprovedBoxed, "build", "sha512-abc")
	if err := f.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := got.Get("tar@6.0.0")
	if !ok || e.Integrity != "sha512-abc" || e.Decision != ApprovedBoxed {
		t.Fatalf("round-tripped entry = %+v, ok=%v", e, ok)
	}

	legacy := `{"schema":1,"packages":{"ms@2.0.0":{"decision":"approved-boxed","date":"2020-01-01T00:00:00Z"}}}`
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	old, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, _ = old.Get("ms@2.0.0")
	if !e.AppliesTo("sha512-whatever") {
		t.Error("a pre-integrity approval stopped applying — old files must keep working")
	}
}

// A legacy entry (no integrity) applies to any tarball forever. The first run
// that can see the real hash must pin it there — otherwise upgrading guard never
// actually buys the binding for already-approved packages.
func TestBindOnlyFillsAnEmptyBinding(t *testing.T) {
	f := &File{Schema: 1, Packages: map[string]Entry{
		"legacy@1.0.0": {Decision: ApprovedBoxed, Date: "2020-01-01T00:00:00Z", Note: "n"},
		"bound@1.0.0":  {Decision: ApprovedBoxed, Integrity: "sha512-old"},
	}}
	if !f.Bind("legacy@1.0.0", "sha512-new") {
		t.Fatal("Bind reported no change on a legacy entry")
	}
	e, _ := f.Get("legacy@1.0.0")
	if e.Integrity != "sha512-new" {
		t.Errorf("Integrity = %q, want sha512-new", e.Integrity)
	}
	if e.Decision != ApprovedBoxed || e.Date != "2020-01-01T00:00:00Z" {
		t.Errorf("Bind rewrote the decision itself: %+v", e)
	}
	// The note must say the hash was INFERRED — .guard-approvals is reviewed in
	// PRs, and an auto-bound entry must not look like a reviewed one.
	if e.Note != AutoBoundNote {
		t.Errorf("Note = %q, want the auto-bound marker", e.Note)
	}
	// An existing binding is a review decision, not bookkeeping — never clobber it.
	if f.Bind("bound@1.0.0", "sha512-new") {
		t.Error("Bind overwrote an existing binding")
	}
	if e, _ := f.Get("bound@1.0.0"); e.Integrity != "sha512-old" {
		t.Errorf("Integrity = %q, want the original sha512-old", e.Integrity)
	}
	// Nothing to bind to, or nothing recorded: no-ops.
	if f.Bind("legacy@1.0.0", "") || f.Bind("absent@1.0.0", "sha512-x") {
		t.Error("Bind reported a change for an empty hash or an unknown key")
	}
}
