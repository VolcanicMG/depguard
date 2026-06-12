package box

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestScrubbedEnv is the crown-jewel check: an uncontained script inherits a
// toolchain + home but NONE of the caller's secrets.
func TestScrubbedEnv(t *testing.T) {
	t.Setenv("NPM_TOKEN", "supersecret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "leakme")
	env := scrubbedEnv()

	joined := strings.Join(env, "\n")
	for _, bad := range []string{"NPM_TOKEN", "supersecret", "AWS_SECRET_ACCESS_KEY", "leakme"} {
		if strings.Contains(joined, bad) {
			t.Errorf("scrubbedEnv leaked %q: %v", bad, env)
		}
	}
	keys := map[string]bool{}
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			keys[kv[:i]] = true
		}
	}
	for _, want := range []string{"PATH", "HOME", "LANG", "TMPDIR"} {
		if !keys[want] {
			t.Errorf("scrubbedEnv missing required %q: %v", want, env)
		}
	}
	if len(env) != 4 {
		t.Errorf("scrubbedEnv should expose exactly 4 vars, got %d: %v", len(env), env)
	}
}

// TestSeccompProfileValid pins the profile: valid JSON, denies the keyring +
// io_uring + kernel-attack syscalls, and never denies what strace needs.
func TestSeccompProfileValid(t *testing.T) {
	var p struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Names  []string `json:"names"`
			Action string   `json:"action"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal([]byte(seccompProfile), &p); err != nil {
		t.Fatalf("seccompProfile is not valid JSON: %v", err)
	}
	denied := map[string]bool{}
	for _, s := range p.Syscalls {
		if s.Action == "SCMP_ACT_ERRNO" {
			for _, n := range s.Names {
				denied[n] = true
			}
		}
	}
	for _, want := range []string{"io_uring_setup", "keyctl", "add_key", "request_key", "bpf", "perf_event_open", "userfaultfd"} {
		if !denied[want] {
			t.Errorf("seccomp profile must deny %q", want)
		}
	}
	for _, keep := range []string{"ptrace", "process_vm_readv"} {
		if denied[keep] {
			t.Errorf("seccomp profile must NOT deny %q (breaks strace observation)", keep)
		}
	}
}

// TestSweepArtifacts confirms a stray pre-run backup is reclaimed.
func TestSweepArtifacts(t *testing.T) {
	dir := t.TempDir()
	bak := filepath.Join(dir, "node_modules", "foo", "bar.guard-backup")
	if err := os.MkdirAll(bak, 0o755); err != nil {
		t.Fatal(err)
	}
	if n := SweepArtifacts(dir); n < 1 {
		t.Errorf("expected to sweep >=1 artifact, got %d", n)
	}
	if _, err := os.Stat(bak); !os.IsNotExist(err) {
		t.Errorf(".guard-backup dir survived the sweep")
	}
}

func hasNpm() bool { _, err := exec.LookPath("npm"); return err == nil }

// TestRunUncontainedScrubsEnv runs a real script uncontained and proves both
// that it executed AND that a secret in the parent env did not leak into it.
func TestRunUncontainedScrubsEnv(t *testing.T) {
	if !hasNpm() {
		t.Skip("npm not on PATH")
	}
	t.Setenv("GUARD_LEAK_PROBE", "tok-should-not-leak")
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"name":"u","version":"1.0.0","scripts":{"postinstall":"node mark.js"}}`)
	writeFile(t, dir, "mark.js", `const fs=require('fs');fs.writeFileSync('marker.txt','ran');fs.writeFileSync('leak.txt',String(process.env.GUARD_LEAK_PROBE||''));`)

	res, err := RunUncontained(dir)
	if err != nil {
		t.Fatalf("RunUncontained: %v (out: %s)", err, res.Output)
	}
	if _, err := os.Stat(filepath.Join(dir, "marker.txt")); err != nil {
		t.Fatalf("script did not run (no marker); out=%s", res.Output)
	}
	leak, _ := os.ReadFile(filepath.Join(dir, "leak.txt"))
	if strings.Contains(string(leak), "tok-should-not-leak") {
		t.Errorf("uncontained env LEAKED the probe token: %q", leak)
	}
}
