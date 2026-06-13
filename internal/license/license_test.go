package license

import (
	"os"
	"path/filepath"
	"testing"

	"depguard/internal/lockfile"
)

func TestTokens(t *testing.T) {
	got := tokens("(MIT OR Apache-2.0)")
	if len(got) != 2 || got[0] != "MIT" || got[1] != "Apache-2.0" {
		t.Errorf("tokens = %v, want [MIT Apache-2.0]", got)
	}
	if got := tokens("GPL-3.0 WITH Classpath-exception-2.0"); len(got) != 2 {
		t.Errorf("WITH not stripped: %v", got)
	}
}

// installPkg writes a node_modules/<name>/package.json with the given raw
// license JSON value and returns the (dir, entry) to feed Check.
func installPkg(t *testing.T, dir, name, version, licenseJSON string) lockfile.Entry {
	t.Helper()
	pdir := filepath.Join(dir, "node_modules", name)
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"name":"` + name + `","version":"` + version + `","license":` + licenseJSON + `}`
	if err := os.WriteFile(filepath.Join(pdir, "package.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return lockfile.Entry{Name: name, Version: version, Path: "node_modules/" + name}
}

func TestDenyGate(t *testing.T) {
	dir := t.TempDir()
	e1 := installPkg(t, dir, "good", "1.0.0", `"MIT"`)
	e2 := installPkg(t, dir, "bad", "2.0.0", `"GPL-3.0"`)
	res := Check(dir, []lockfile.Entry{e1, e2}, []string{"GPL-3.0"}, nil)
	if len(res.Violations) != 1 || res.Violations[0].Name != "bad" || res.Violations[0].Reason != "denied" {
		t.Fatalf("deny gate = %+v, want one denied 'bad'", res.Violations)
	}
}

func TestAllowlistGate(t *testing.T) {
	dir := t.TempDir()
	e1 := installPkg(t, dir, "ok", "1.0.0", `"MIT"`)
	e2 := installPkg(t, dir, "weird", "1.0.0", `"WTFPL"`)
	e3 := installPkg(t, dir, "objform", "1.0.0", `{"type":"ISC"}`)
	res := Check(dir, []lockfile.Entry{e1, e2, e3}, nil, []string{"MIT", "ISC"})
	if len(res.Violations) != 1 || res.Violations[0].Name != "weird" || res.Violations[0].Reason != "not allowed" {
		t.Fatalf("allowlist gate = %+v, want one not-allowed 'weird'", res.Violations)
	}
}

func TestDisabledGate(t *testing.T) {
	dir := t.TempDir()
	e := installPkg(t, dir, "x", "1.0.0", `"GPL-3.0"`)
	if res := Check(dir, []lockfile.Entry{e}, nil, nil); len(res.Violations) != 0 {
		t.Errorf("empty policy should yield no violations, got %v", res.Violations)
	}
}

func TestDegradedWhenTreeMissing(t *testing.T) {
	dir := t.TempDir()
	// entry points at a node_modules path that doesn't exist on disk.
	e := lockfile.Entry{Name: "ghost", Version: "1.0.0", Path: "node_modules/ghost"}
	res := Check(dir, []lockfile.Entry{e}, []string{"GPL-3.0"}, nil)
	if !res.Degraded {
		t.Error("missing package dir should mark the result degraded")
	}
}
