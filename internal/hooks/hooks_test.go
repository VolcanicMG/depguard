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
}
