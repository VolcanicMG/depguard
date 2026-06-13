package lockfile

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// a small npm v3 lockfile: root depends on express (direct); express → qs and
// body-parser; body-parser → qs too. lodash is a direct dep with no children.
const sampleLock = `{
  "lockfileVersion": 3,
  "packages": {
    "": { "dependencies": { "express": "^4.0.0", "lodash": "^4.0.0" }, "devDependencies": { "jest": "^29.0.0" } },
    "node_modules/express": { "version": "4.18.2", "dependencies": { "qs": "6.11.0", "body-parser": "1.20.1" } },
    "node_modules/body-parser": { "version": "1.20.1", "dependencies": { "qs": "6.11.0" } },
    "node_modules/qs": { "version": "6.11.0" },
    "node_modules/lodash": { "version": "4.17.21" },
    "node_modules/jest": { "version": "29.7.0" }
  }
}`

// writeLock drops sampleLock into a temp dir and returns the dir.
func writeLock(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestBuildGraphRootsAndVersions(t *testing.T) {
	g, err := BuildGraph(writeLock(t, sampleLock))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"express", "lodash", "jest"} {
		if !g.Roots[want] {
			t.Errorf("expected %q to be a root dependency", want)
		}
	}
	if g.Roots["qs"] {
		t.Error("qs is transitive, must not be a root")
	}
	if got := g.SortedVersions("qs"); !reflect.DeepEqual(got, []string{"6.11.0"}) {
		t.Errorf("qs versions = %v, want [6.11.0]", got)
	}
}

func TestPathsTransitive(t *testing.T) {
	g, err := BuildGraph(writeLock(t, sampleLock))
	if err != nil {
		t.Fatal(err)
	}
	paths := g.Paths("qs", 0)
	// qs is reachable two ways: express→qs and express→body-parser→qs.
	want := map[string]bool{
		"express › qs":               true,
		"express › body-parser › qs": true,
	}
	got := map[string]bool{}
	for _, p := range paths {
		got[join(p)] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("paths to qs = %v, want %v", got, want)
	}
}

func TestPathsDirectDep(t *testing.T) {
	g, _ := BuildGraph(writeLock(t, sampleLock))
	// lodash is direct: it's a root, and its only path is the root-only one.
	paths := g.Paths("lodash", 0)
	if len(paths) != 1 || len(paths[0]) != 1 || paths[0][0] != "lodash" {
		t.Errorf("lodash paths = %v, want [[lodash]]", paths)
	}
}

func TestPathsMaxCap(t *testing.T) {
	g, _ := BuildGraph(writeLock(t, sampleLock))
	if got := g.Paths("qs", 1); len(got) != 1 {
		t.Errorf("maxPaths=1 returned %d paths, want 1", len(got))
	}
}

func TestBuildGraphMissingLockfile(t *testing.T) {
	_, err := BuildGraph(t.TempDir())
	if !os.IsNotExist(err) {
		t.Errorf("expected os.ErrNotExist for missing lockfile, got %v", err)
	}
}

// join renders a path for comparison.
func join(p []string) string {
	out := ""
	for i, s := range p {
		if i > 0 {
			out += " › "
		}
		out += s
	}
	return out
}
