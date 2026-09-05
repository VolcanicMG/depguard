package secrets

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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
		{"config/.env", true, ".env"},             // basename match
		{".env.local", true, ".env.*"},            // glob
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
	write(".env", "TOKEN=abc")          // will be staged → must be flagged
	write(".env.local", "TOKEN=xyz")    // left untracked → must NOT be flagged
	write("index.js", "console.log(1)") // staged, but not a secret
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

// The pre-push gate's whole point: a secret committed and then DELETED in a
// later commit is gone from the index — Find sees nothing — but it still rides
// the outgoing history to the remote. FindOutgoing is what catches it, and it's
// why `git rm --cached` is not the fix.
func TestFindOutgoingSeesDeletedSecretInHistory(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "README.md")
	run("commit", "-qm", "base")
	base, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	baseSHA := strings.TrimSpace(string(base))

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("TOKEN=abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", ".env")
	run("commit", "-qm", "oops")
	run("rm", "-q", ".env")
	run("commit", "-qm", "remove the secret")

	// The tree is clean now — that is exactly the false all-clear.
	if got, err := Find(dir, []string{".env"}); err != nil || len(got) != 0 {
		t.Fatalf("Find = (%v, %v), want no tree hits after the removal commit", got, err)
	}
	head, _ := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	got, err := FindOutgoing(dir, []string{".env"}, [][]string{{baseSHA + ".." + strings.TrimSpace(string(head))}})
	if err != nil {
		t.Fatalf("FindOutgoing: %v", err)
	}
	if len(got) != 1 || got[0].Path != ".env" {
		t.Fatalf("FindOutgoing = %+v, want one .env hit from the outgoing history", got)
	}
	if !got[0].History {
		t.Error("History = false — the report would tell the user to git rm --cached, which cannot help")
	}
}

// No patterns or no ranges: the gate is inert, never an error.
func TestFindOutgoingInert(t *testing.T) {
	dir := t.TempDir()
	if got, err := FindOutgoing(dir, nil, [][]string{{"a..b"}}); err != nil || got != nil {
		t.Errorf("FindOutgoing(no patterns) = (%v, %v), want (nil, nil)", got, err)
	}
	if got, err := FindOutgoing(dir, []string{".env"}, nil); err != nil || got != nil {
		t.Errorf("FindOutgoing(no ranges) = (%v, %v), want (nil, nil)", got, err)
	}
}

// A range git cannot read must surface as an ERROR, not as "no secrets". On a
// shallow clone the remote sha isn't present locally, so EVERY range fails —
// swallowing that returned a confident all-clear from a scan that never ran.
func TestFindOutgoingReportsUnreadableRange(t *testing.T) {
	dir := t.TempDir()
	if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Skipf("git unavailable: %v\n%s", err, out)
	}
	missing := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	got, err := FindOutgoing(dir, []string{".env"}, [][]string{{missing + "..HEAD"}})
	if err == nil {
		t.Fatalf("FindOutgoing = (%v, nil), want an error for a range git can't resolve", got)
	}
	if len(got) != 0 {
		t.Errorf("matches = %v, want none", got)
	}
}
