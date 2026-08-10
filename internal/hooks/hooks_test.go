package hooks

import (
	"os"
	"path/filepath"
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
