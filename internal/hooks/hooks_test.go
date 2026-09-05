package hooks

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A missing guard binary is fail-open by design, but it must be LOUD. Silence
// there meant a repo could look protected while every commit went unchecked.
func TestHookScriptsWarnWhenGuardMissing(t *testing.T) {
	for name, script := range map[string]string{"hookScript": hookScript, "hookAppend": hookAppend} {
		if !strings.Contains(script, "guard binary not found on PATH") {
			t.Errorf("%s: no warning for a missing guard binary", name)
		}
		if !strings.Contains(script, "check SKIPPED") {
			t.Errorf("%s: warning does not say the check was skipped", name)
		}
	}
	if !strings.Contains(hookScript, "\nelse\n") {
		t.Error("hookScript: missing else branch on the command -v guard test")
	}
}

// The shim written to a fresh .git/hooks must carry the warning too — the
// content, not just the constant, is what protects the repo.
func TestInstallHookWritesWarningShim(t *testing.T) {
	dir := t.TempDir()
	path, err := installHook(dir, "pre-commit")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "guard binary not found on PATH") {
		t.Errorf("installed shim %s lacks the missing-binary warning", filepath.Base(path))
	}
	if !hasCurrentShim(string(b)) {
		t.Errorf("fresh shim %s lacks the current managed marker", filepath.Base(path))
	}
}

// A fresh install carries the current marker; a re-run is a no-op (no duplicate
// block), and the reported state is "current".
func TestInstallHookIdempotent(t *testing.T) {
	dir := t.TempDir()
	if _, err := installHook(dir, "pre-commit"); err != nil {
		t.Fatal(err)
	}
	// Second run must report "already current" (empty path) and not duplicate.
	p, err := installHook(dir, "pre-commit")
	if err != nil {
		t.Fatal(err)
	}
	if p != "" {
		t.Errorf("re-init rewrote a current shim (path %q), want no-op", p)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "pre-commit"))
	if n := strings.Count(string(b), shimBegin); n != 1 {
		t.Errorf("shim block count = %d, want 1 (no duplicate on re-init)", n)
	}
}

// A STALE managed shim (older version marker) must be UPGRADED in place — this
// is the F3 fix: keying off "guard check" alone left old shims frozen forever.
func TestInstallHookUpgradesStaleShim(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pre-commit")
	stale := "#!/bin/sh\n" + shimBegin + "\n# depguard-shim-version: 1\nold guard check body\n" + shimEnd + "\n"
	if err := os.WriteFile(path, []byte(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := installHook(dir, "pre-commit"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	got := string(b)
	if !hasCurrentShim(got) {
		t.Error("stale shim was not upgraded to the current marker")
	}
	if strings.Contains(got, "# depguard-shim-version: 1") {
		t.Error("old version marker survived the upgrade")
	}
	if strings.Contains(got, "old guard check body") {
		t.Error("old shim body survived the upgrade")
	}
	if n := strings.Count(got, shimBegin); n != 1 {
		t.Errorf("shim block count = %d after upgrade, want 1", n)
	}
	if !strings.HasPrefix(got, "#!/bin/sh\n") {
		t.Error("upgrade dropped the shebang / preceding content")
	}
}

// A FOREIGN hook that merely mentions "guard check" (no managed marker) must be
// chained onto, never clobbered.
func TestInstallHookChainsOntoForeign(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pre-commit")
	foreign := "#!/bin/sh\n# my hook\nguard check # a hand-rolled call\n"
	if err := os.WriteFile(path, []byte(foreign), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := installHook(dir, "pre-commit"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	got := string(b)
	if !strings.Contains(got, "# my hook") || !strings.Contains(got, "a hand-rolled call") {
		t.Error("foreign hook content was clobbered")
	}
	if !hasCurrentShim(got) {
		t.Error("managed block was not chained onto the foreign hook")
	}
	// And a re-run is still idempotent (marker now present).
	p, _ := installHook(dir, "pre-commit")
	if p != "" {
		t.Errorf("re-init after chaining rewrote the hook (path %q), want no-op", p)
	}
}

// Installed marks a hook "current" only when it carries the current marker —
// the shared signal 'guard status' keys its protection verdict off (F4).
func TestInstalledReportsCurrentMarker(t *testing.T) {
	dir := t.TempDir()
	hookDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hookDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A stale (marker-less) hook that calls guard: present, but NOT current.
	if err := os.WriteFile(filepath.Join(hookDir, "pre-commit"), []byte("#!/bin/sh\nguard check\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A current managed shim for pre-push.
	if _, err := installHook(hookDir, "pre-push"); err != nil {
		t.Fatal(err)
	}
	st := Installed(dir)
	if !st.PreCommit || st.PreCommitCurrent {
		t.Errorf("pre-commit: present=%v current=%v, want present + NOT current", st.PreCommit, st.PreCommitCurrent)
	}
	if !st.PrePush || !st.PrePushCurrent {
		t.Errorf("pre-push: present=%v current=%v, want present + current", st.PrePush, st.PrePushCurrent)
	}
}

// The v3 shim tells guard WHICH git phase invoked it — that's what lets the
// pre-push check look at the outgoing commits instead of the working tree.
func TestShimIsPhaseAware(t *testing.T) {
	if !strings.Contains(shimBody, `--hook="${0##*/}"`) {
		t.Error("shim body does not pass --hook= (the check can't tell pre-commit from pre-push)")
	}
	if shimVersion != "3" {
		t.Errorf("shimVersion = %q, want 3 — a body change must bump it or installed shims never upgrade", shimVersion)
	}
}

// A v2 shim must UPGRADE to v3 in place, or every already-initialised repo keeps
// running a phase-blind check forever.
func TestInstallHookUpgradesV2ToV3(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pre-push")
	v2 := "#!/bin/sh\n" + shimBegin + "\n# depguard-shim-version: 2\nguard check --quiet --confirm\n" + shimEnd + "\n"
	if err := os.WriteFile(path, []byte(v2), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := installHook(dir, "pre-push"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), `--hook="${0##*/}"`) {
		t.Error("upgraded shim does not pass --hook=")
	}
	if strings.Contains(string(got), "# depguard-shim-version: 2") {
		t.Error("v2 marker survived the upgrade")
	}
}

// gitRepo makes a temp repo, optionally with core.hooksPath set.
func gitRepo(t *testing.T, hooksPath string) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v unavailable: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	if hooksPath != "" {
		run("config", "core.hooksPath", hooksPath)
	}
	return dir
}

// core.hooksPath is git's own override: a shim written anywhere else never runs.
// Install must follow it, and Installed must look in the SAME place — hard-coding
// .git/hooks in Installed made 'guard status' report protection that wasn't there.
func TestHookDirFollowsCoreHooksPath(t *testing.T) {
	dir := gitRepo(t, "myhooks")
	if err := os.MkdirAll(filepath.Join(dir, "myhooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, want := HookDir(dir), filepath.Join(dir, "myhooks"); got != want {
		t.Fatalf("HookDir = %q, want %q", got, want)
	}
	if _, err := Install(dir, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "myhooks", "pre-commit")); err != nil {
		t.Fatalf("Install did not write into core.hooksPath: %v", err)
	}
	st := Installed(dir)
	if !st.PreCommit || !st.PreCommitCurrent || !st.PrePush {
		t.Errorf("Installed missed the shims in core.hooksPath: %+v", st)
	}
}

// husky v9 points core.hooksPath at .husky/_ and REGENERATES that dir on every
// install — a shim there is wiped. Target its parent instead.
func TestHookDirHuskyUnderscoreUsesParent(t *testing.T) {
	dir := gitRepo(t, ".husky/_")
	if got, want := HookDir(dir), filepath.Join(dir, ".husky"); got != want {
		t.Errorf("HookDir = %q, want the .husky parent %q", got, want)
	}
}

// os.WriteFile does NOT change an existing file's permissions, so rewriting a
// 0644 hook left it non-executable — installed, and silently never run by git.
func TestInstallHookForcesExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no execute bit on windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "pre-commit")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := installHook(dir, "pre-commit"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&0o111 == 0 {
		t.Errorf("hook mode = %v, want the execute bits set", fi.Mode())
	}
}

// A non-executable shim is protection git skips in silence — 'guard status'
// must report it as absent, not installed.
func TestInstalledIgnoresNonExecutableHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no execute bit on windows")
	}
	dir := t.TempDir()
	hookDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hookDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := installHook(hookDir, "pre-commit"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(hookDir, "pre-commit"), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := Installed(dir); st.PreCommit || st.PreCommitCurrent {
		t.Errorf("non-executable hook reported as installed: %+v", st)
	}
}

// git resolves a relative core.hooksPath against the REPO ROOT. Resolving it
// against the process's cwd instead put the shim in a subdirectory git never
// reads — and made 'guard status' look for it there too.
func TestHookDirRelativePathResolvesFromRepoRoot(t *testing.T) {
	dir := gitRepo(t, "myhooks")
	sub := filepath.Join(dir, "packages", "app")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// git reports the toplevel through symlinks (macOS /var → /private/var), so
	// compare against what git itself says rather than the raw temp path.
	want := filepath.Join(repoRoot(dir), "myhooks")
	if got := HookDir(sub); got != want {
		t.Errorf("HookDir(subdir) = %q, want %q (relative hooksPath is repo-root relative)", got, want)
	}
}
