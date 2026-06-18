package secrets

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestMatchAny(t *testing.T) {
	patterns := []string{".env", ".env.*", "secrets/", "*.pem", "id_rsa"}
	cases := []struct {
		file string
		want bool
		pat  string // expected matching pattern (when want)
	}{
		{".env", true, ".env"},
		{"config/.env", true, ".env"},            // basename match
		{".env.local", true, ".env.*"},           // glob
		{".env.example", true, ".env.*"},          // documents: example is caught → waive it
		{"secrets/prod.key", true, "secrets/"},    // dir prefix
		{"secrets/sub/db.key", true, "secrets/"},  // dir prefix, nested
		{"deep/nested/server.pem", true, "*.pem"}, // basename glob across dirs
		{"id_rsa", true, "id_rsa"},
		{"src/index.js", false, ""},
		{"README.md", false, ""},
		{"environment.ts", false, ""}, // must NOT match ".env"
	}
	for _, c := range cases {
		pat, ok := matchAny(c.file, patterns)
		if ok != c.want {
			t.Errorf("matchAny(%q) = %v, want %v", c.file, ok, c.want)
			continue
		}
		if ok && pat != c.pat {
			t.Errorf("matchAny(%q) matched %q, want %q", c.file, pat, c.pat)
		}
	}
}

// TestFindOnlyTrackedOrStaged is the core promise: a tracked/staged secret is
// flagged, but an untracked one (git won't upload it) is not.
func TestFindOnlyTrackedOrStaged(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")

	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".env", "TOKEN=abc")           // will be staged → must be flagged
	write(".env.local", "TOKEN=xyz")     // left untracked → must NOT be flagged
	write("index.js", "console.log(1)")  // staged, but not a secret
	run("add", ".env", "index.js")

	got, err := Find(dir, []string{".env", ".env.*"})
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	var paths []string
	for _, m := range got {
		paths = append(paths, m.Path)
	}
	sort.Strings(paths)
	want := []string{".env"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("Find returned %v, want %v (untracked .env.local must be ignored)", paths, want)
	}
}

// TestFindEmptyPatternsInert: gate off when no patterns, even with a secret present.
func TestFindEmptyPatternsInert(t *testing.T) {
	dir := t.TempDir()
	if got, err := Find(dir, nil); err != nil || got != nil {
		t.Fatalf("Find(nil patterns) = (%v, %v), want (nil, nil)", got, err)
	}
}

// TestFindNonRepoErrors: outside a git repo, Find surfaces the git error so the
// caller can fail-open-and-log rather than silently pass.
func TestFindNonRepoErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Find(dir, []string{".env"}); err == nil {
		t.Fatal("Find in a non-git dir should return git's error, got nil")
	}
}
