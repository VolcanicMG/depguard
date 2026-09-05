package box

import (
	"encoding/json"
	"fmt"
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

func dockerUp() bool {
	rt := Runtime()
	return rt != "" && exec.Command(rt, "version").Run() == nil
}

// TestSweepContainersNoRuntime: a no-op without a container runtime.
func TestSweepContainersNoRuntime(t *testing.T) {
	if n := SweepContainers(""); n != 0 {
		t.Errorf("SweepContainers(\"\") = %d, want 0", n)
	}
}

// TestSweepContainersRemovesOrphan creates a stray depguard-run container and
// confirms the sweep force-removes it. Docker-gated.
func TestSweepContainersRemovesOrphan(t *testing.T) {
	rt := Runtime()
	if !dockerUp() {
		t.Skip("docker daemon not reachable")
	}
	name := fmt.Sprintf("depguard-run-test-%d", os.Getpid())
	// A created-but-not-started container off the box base image (already local).
	if err := exec.Command(rt, "create", "--name", name, buildImage, "true").Run(); err != nil {
		t.Skipf("could not create test container (image missing?): %v", err)
	}
	defer exec.Command(rt, "rm", "-f", name).Run() // belt-and-suspenders

	if n := SweepContainers(rt); n < 1 {
		t.Errorf("expected to sweep >=1 orphan, got %d", n)
	}
	out, _ := exec.Command(rt, "ps", "-aq", "--filter", "name="+name).Output()
	if strings.TrimSpace(string(out)) != "" {
		t.Error("orphan container survived the sweep")
	}
}

// capWriter keeps at most max bytes and says so — the container's pipes are
// attacker-controllable firehoses, so an unbounded host-side buffer was a
// memory-exhaustion lever. It must never report a short write: that would make
// the child see EPIPE and change the run we're observing.
func TestCapWriterTruncates(t *testing.T) {
	w := &capWriter{max: 10}
	for _, chunk := range []string{"12345", "67890", "overflow"} {
		n, err := w.Write([]byte(chunk))
		if err != nil || n != len(chunk) {
			t.Fatalf("Write(%q) = (%d, %v), want (%d, nil)", chunk, n, err, len(chunk))
		}
	}
	if got := w.String(); got != "1234567890" {
		t.Errorf("buffered %q, want the first 10 bytes", got)
	}
	if !w.truncated {
		t.Error("truncated = false after overflowing the cap")
	}
	small := &capWriter{max: 10}
	small.Write([]byte("short"))
	if small.truncated {
		t.Error("truncated = true for a write that fit")
	}
}

// verdict is the whole post-run observation decision. Traced may only be true
// when we hold a COMPLETE trace: a missing one (strace never ran) and a
// truncated one (we stopped reading) both mean we did not see everything.
func TestVerdict(t *testing.T) {
	clean := []byte("1 openat(AT_FDCWD, \"/app/package.json\", O_RDONLY) = 3\n1 +++ exited with 0 +++\n")
	cases := []struct {
		name            string
		raw             []byte
		truncated, want bool // want = Traced
	}{
		{"complete trace", clean, false, true},
		{"truncated trace", clean, true, false},
		{"empty trace", nil, false, false},
		{"whitespace-only trace", []byte("\n  \n"), false, false},
	}
	for _, c := range cases {
		traced, _, _, _ := verdict(c.raw, c.truncated, true, false)
		if traced != c.want {
			t.Errorf("%s: Traced = %v, want %v", c.name, traced, c.want)
		}
	}
	// Tracing not requested: never claim observation, whatever arrived.
	if traced, _, _, _ := verdict(clean, false, false, false); traced {
		t.Error("untraced run reported Traced = true")
	}
}

// A truncated trace is still PARSED: evidence already captured convicts even
// though the observation as a whole is incomplete.
func TestVerdictTruncatedStillConvicts(t *testing.T) {
	raw := []byte(`1 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0` + "\n")
	traced, findings, unsafe, _ := verdict(raw, true, true, false)
	if traced {
		t.Error("Traced = true on a truncated trace")
	}
	if !unsafe || len(findings) == 0 {
		t.Errorf("truncated trace dropped its evidence: unsafe=%v findings=%d", unsafe, len(findings))
	}
}

// restore is what makes "the output was discarded" real: the package dir comes
// back byte-for-byte from the pre-run backup.
func TestRestoreRollsBack(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "pkg")
	backupDir := pkgDir + ".guard-backup"
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, pkgDir, "index.js", "original")
	if err := os.CopyFS(backupDir, os.DirFS(pkgDir)); err != nil {
		t.Fatal(err)
	}
	writeFile(t, pkgDir, "index.js", "TAMPERED")
	writeFile(t, pkgDir, "dropper.sh", "curl evil")

	keep, err := restore(pkgDir, backupDir)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if keep {
		t.Error("keepBackup = true after a SUCCESSFUL restore — the backup would be left behind")
	}
	b, err := os.ReadFile(filepath.Join(pkgDir, "index.js"))
	if err != nil || string(b) != "original" {
		t.Errorf("index.js = %q (%v), want the pre-run content", b, err)
	}
	if _, err := os.Stat(filepath.Join(pkgDir, "dropper.sh")); !os.IsNotExist(err) {
		t.Error("a file the script wrote survived the rollback")
	}
}

// The trace must travel on the container's STDOUT — a pipe the traced script
// cannot reach (see TestObsImageMakesTracerNonDumpable) — with the script's own
// output pushed to stderr. A shared file in a bind mount was the old design and
// the script, running as the same uid, could truncate it.
func TestTracedScriptUsesStdoutPipe(t *testing.T) {
	if !strings.Contains(tracedScript("cd /app"), "-o /dev/stdout") {
		t.Error("strace does not write the trace to stdout")
	}
	if !strings.HasPrefix(tracedScript("cd /app"), "exec strace ") {
		t.Error("strace is not exec'd: a dumpable sh at PID 1 would hold the trace pipe as fd 1 and reopen /proc/1/fd/1 forgery")
	}
	if !strings.Contains(tracedScript("cd /app"), "exec 1>&2") {
		t.Error("the traced script's own stdout is not redirected to stderr — it would mix into the trace")
	}
}

// Summary is the only thing the human sees for a run that was NOT discarded, so
// it has to say when the observation was incomplete. Under `untraced-boxed: run`
// a script that floods syscalls to trip the trace cap is otherwise reported in
// exactly the same words as a fully watched clean run.
func TestSummaryFlagsIncompleteObservation(t *testing.T) {
	clean := Result{ExitCode: 0, Requested: true, Traced: true}
	if s := clean.Summary(); strings.Contains(s, "INCOMPLETE") || strings.Contains(s, "cap") {
		t.Errorf("a fully watched run should read clean, got %q", s)
	}
	// An untraced-by-design box never asked, so it must not cry incomplete.
	if s := (Result{}).Summary(); strings.Contains(s, "INCOMPLETE") {
		t.Errorf("an untraced run reported INCOMPLETE: %q", s)
	}
	blinded := Result{Requested: true, Traced: false, Truncated: []string{"trace"}}
	s := blinded.Summary()
	if !strings.Contains(s, "INCOMPLETE") {
		t.Errorf("Summary hid an unobserved run: %q", s)
	}
	if !strings.Contains(s, "size cap") {
		t.Errorf("Summary did not mention the size cap that blinded it: %q", s)
	}
}

// traceFixture builds a realistic `strace -f -q` trace: root pid 100 spawns 101,
// and each process ends with its own marker line.
func traceFixture(rootMarker, childMarker bool) []byte {
	s := "100 execve(\"/bin/sh\", [\"sh\"], 0x0) = 0\n" +
		"100 openat(AT_FDCWD, \"/app/package.json\", O_RDONLY) = 3\n" +
		"101 openat(AT_FDCWD, \"/tmp/build\", O_RDONLY) = 4\n"
	if childMarker {
		s += "101 +++ exited with 0 +++\n"
	}
	if rootMarker {
		s += "100 +++ exited with 0 +++\n"
	}
	return []byte(s)
}

// The tracee can kill its tracer (`kill -9 $PPID`). strace dies, its pipe closes,
// and the trace guard reads looks completely ordinary — non-empty, under the cap,
// nothing incriminating. The script is DETACHED by that kill, not stopped, so
// everything it does next is unseen. Only the root tracee's exit marker proves
// the observer outlived it.
func TestVerdictRequiresRootCompletionMarker(t *testing.T) {
	if traced, _, _, lost := verdict(traceFixture(true, true), false, true, false); !traced || lost {
		t.Errorf("complete trace: traced=%v observerLost=%v, want (true, false)", traced, lost)
	}
	// Tracer killed: no root marker at all.
	traced, _, _, lost := verdict(traceFixture(false, true), false, true, false)
	if traced {
		t.Error("a trace with no completion marker was accepted as fully observed")
	}
	if !lost {
		t.Error("observerLost = false, so nothing would tell the human the observer died")
	}
	// A child exiting first must NOT satisfy it — a script can arrange exactly
	// that before killing strace.
	if traced, _, _, _ := verdict(traceFixture(false, true), false, true, false); traced {
		t.Error("a CHILD pid's exit marker satisfied the root completion check")
	}
	// A root killed by a signal is still a proven ending.
	killed := []byte("100 execve(\"/bin/sh\", [\"sh\"], 0x0) = 0\n100 +++ killed by SIGKILL +++\n")
	if traced, _, _, _ := verdict(killed, false, true, false); !traced {
		t.Error("'+++ killed by SIGKILL +++' is a completion marker too")
	}
	// Real strace -f pads the pid to a column ("11    +++ exited"), not one
	// space — captured from a live depguard-box run; a single-space regex
	// classified EVERY genuine run as observer-lost.
	padded := []byte("11    execve(\"/usr/bin/sh\", [\"sh\", \"-c\", \"exec 1>&2; node -e 1\"], 0x7ffd /* 6 vars */) = 0\n12    +++ exited with 0 +++\n11    --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=12} ---\n11    +++ exited with 0 +++\n")
	if traced, _, _, lost := verdict(padded, false, true, false); !traced || lost {
		t.Errorf("column-padded live trace: traced=%v observerLost=%v, want (true, false)", traced, lost)
	}
	// Truncation is a different failure and must not be relabelled.
	if _, _, _, lost := verdict(traceFixture(true, true), true, true, false); lost {
		t.Error("a truncated trace was reported as a lost observer")
	}
}

// The trace must keep strace's exit lines, or there is no marker to check.
func TestTracedScriptKeepsExitMarkers(t *testing.T) {
	got := tracedScript("cd /app")
	if strings.Contains(got, "-qq") {
		t.Error("-qq suppresses the '+++ exited with N +++' lines the completion check needs")
	}
	if !strings.Contains(got, "-q ") {
		t.Errorf("expected -q in %q", got)
	}
}

// A lost observer has to be visible to the human under `untraced-boxed: run`,
// where the output is kept.
func TestSummaryFlagsLostObserver(t *testing.T) {
	s := Result{Requested: true, Traced: false, ObserverLost: true}.Summary()
	if !strings.Contains(s, "observer terminated") {
		t.Errorf("Summary hid a killed observer: %q", s)
	}
}

// If the rename fails, the package dir is already deleted and the backup is the
// ONLY surviving copy. The caller's deferred cleanup must be told to leave it —
// otherwise a recoverable error becomes data loss.
func TestRestoreKeepsBackupWhenRenameFails(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "pkg")
	backupDir := pkgDir + ".guard-backup"
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, backupDir, "index.js", "original")
	// pkgDir's PARENT is missing, so RemoveAll succeeds (nothing there) and the
	// rename into it cannot.
	missing := filepath.Join(root, "gone", "pkg")
	keep, err := restore(missing, backupDir)
	if err == nil {
		t.Fatal("restore into a missing parent succeeded, want an error")
	}
	if !keep {
		t.Fatal("keepBackup = false after a failed rename — the deferred cleanup would delete the only copy")
	}
	if !strings.Contains(err.Error(), backupDir) {
		t.Errorf("error = %q, want it to name where the pre-run copy survived", err)
	}
	if _, statErr := os.Stat(filepath.Join(backupDir, "index.js")); statErr != nil {
		t.Errorf("the backup itself is gone: %v", statErr)
	}
}

// The round-3 completion marker was FORGEABLE: a tracee knows its own pid, so it
// could write "<$$> +++ exited with 0 +++" into /proc/<tracer>/fd/1 and only then
// kill strace. What closes that is not a smarter parse — it is making the tracer
// non-dumpable, so /proc/<tracer>/ becomes root-only and the trace pipe is
// unreachable from the script's uid.
//
// Only the recipe is pinnable without Docker; the live behaviour (write → EACCES,
// read → EACCES, no inherited fd to the pipe) was verified by hand in the box.
func TestObsImageMakesTracerNonDumpable(t *testing.T) {
	if !strings.Contains(obsDockerfile, "chmod 0711 /usr/bin/strace") {
		t.Error("obsDockerfile does not make strace execute-only — /proc/<tracer>/fd stays writable by the tracee and the completion marker is forgeable")
	}
	// EnsureObsImage reuses any local image with this tag, so a recipe change
	// without a tag bump would leave every existing install on the old one.
	if obsImage == "depguard-box:1" {
		t.Error("obsImage still :1 — existing installs would keep the old, forgeable image")
	}
}

// Killing your own tracer has no build-time excuse, so that output is discarded
// under EVERY policy — including `untraced-boxed: run`, where an ordinarily
// unobserved run is kept.
func TestShouldDiscard(t *testing.T) {
	cases := []struct {
		name                                               string
		strict, requested, observed, lost, truncated, want bool
	}{
		{"observed, nothing to decide", true, true, true, false, false, false},
		{"untraced box never asked", true, false, false, false, false, false},
		{"unobserved under run → kept", false, true, false, false, false, false},
		{"unobserved under fail → discarded", true, true, false, false, false, true},
		{"observer killed under run → DISCARDED anyway", false, true, false, true, false, true},
		{"observer killed under fail → discarded", true, true, false, true, false, true},
		{"trace flooded past the cap under run → DISCARDED (same class as a kill)", false, true, false, false, true, true},
	}
	for _, c := range cases {
		if got := shouldDiscard(c.strict, c.requested, c.observed, c.lost, c.truncated); got != c.want {
			t.Errorf("%s: shouldDiscard(%v,%v,%v,%v) = %v, want %v",
				c.name, c.strict, c.requested, c.observed, c.lost, got, c.want)
		}
	}
}

// We kill the container ourselves at the wall-clock limit, so strace never gets
// to write its exit line. Blaming the script for that would put "observer
// terminated by the script" next to "box killed after 10m" on every slow build.
func TestVerdictTimeoutIsNotObserverLoss(t *testing.T) {
	noMarker := traceFixture(false, true)
	traced, _, _, lost := verdict(noMarker, false, true, true)
	if traced {
		t.Error("a timed-out run was reported as fully observed — we still did not see the end")
	}
	if lost {
		t.Error("our own timeout was blamed on the script as observer loss")
	}
	// Without the timeout, the same trace IS observer loss.
	if _, _, _, lost := verdict(noMarker, false, true, false); !lost {
		t.Error("a missing marker with no timeout should be observer loss")
	}
}
