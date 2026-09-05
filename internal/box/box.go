// Package box runs approved lifecycle scripts inside a sealed throwaway
// container — the cage + observation chamber of DESIGN.md §8.
//
// depguard does NOT reimplement sandboxing. It shells out to Docker/Podman
// with a locked-down invocation: no network, read-only image, only the one
// package directory mounted, all capabilities dropped, non-root. The
// container is destroyed after the run (--rm).
//
// Observation in this version = captured output + exit code + a before/after
// file diff of the package dir. Syscall-level tracing (eBPF/Falco) is a
// documented future layer, not silently faked.
package box

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"depguard/internal/trace"
)

// Resource caps for a boxed script run. A build legitimately needs CPU and
// memory; a miner or fork/zip bomb needs them WITHOUT bound. These ceilings
// are generous enough for node-gyp yet stop a script from pinning the host,
// and the wall-clock kill ends anything that just spins (a miner never exits).
const (
	boxMemory  = "2g"
	boxCPUs    = "2"
	boxTimeout = 10 * time.Minute
)

// buildImage is the container the script runs in. The full (non-slim) image
// ships python3/make/g++, which node-gyp builds need.
// Pinned by DIGEST, not tag: a tag can be re-pushed to point at different
// content; a digest cannot. Same reasoning as lockfile integrity hashes.
const buildImage = "node:20.20.2@sha256:8f693eaa7e0a8e71560c9a82b55fd54c2ae920a2ba5d2cde28bac7d1c01c9ba5"

// obsImage is the observation variant: buildImage + strace, built LOCALLY
// from signed Debian packages on first boxed run. Nothing is installed on
// the host and nothing is pulled from an unofficial source — the only
// network trust added is Debian's apt repos, signature-verified by apt.
//
// The tag is VERSIONED: EnsureObsImage reuses whatever is already local, so a
// change to obsDockerfile that isn't accompanied by a bump here would leave
// every existing install silently running the old recipe. :2 added the
// non-dumpable strace below; :3 tightened it from 0711 to 0111 so it holds for a
// box run as root too.
const obsImage = "depguard-box:3"

// obsDockerfile builds obsImage. Kept in source (not a file) so the binary
// stays self-contained and the recipe is reviewable right here.
//
// The chmod is load-bearing security, not tidiness. A traced script knows its
// own pid, so it can WRITE a forged completion marker into the trace
// ("printf '%d +++ exited with 0 +++' $$ > /proc/<tracer>/fd/1") and only then
// kill the tracer — defeating any check made on the trace's contents alone.
// Making the strace binary execute-only causes the kernel to mark the running
// strace process NON-DUMPABLE, which flips /proc/<tracer>/ to root:root
// dr-x------ so the tracee cannot reach the tracer's fds: writing is EACCES,
// reading is EACCES. Combined with the tracee holding no inherited fd to the
// trace pipe (`exec 1>&2` replaces fd 1, and strace's -o fd is CLOEXEC), the
// trace becomes genuinely write-unreachable — which is what makes the completion
// marker trustworthy.
//
// The mode is 0111, not 0711: with 0711 the OWNER keeps the read bit, so a box
// run as root (`sudo guard`, a root CI runner — the box runs as the INVOKING
// uid) left strace dumpable and the forgery worked again. At 0111 nobody has the
// read bit, and uid 0 inside the box has no CAP_DAC_OVERRIDE to bypass it
// (--cap-drop ALL), so the tracer is non-dumpable for every uid. The same
// cap-drop removes CAP_SYS_PTRACE, which ptrace_may_access would otherwise let
// root use to reach a non-dumpable process's /proc entries.
const obsDockerfile = `FROM ` + buildImage + `
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends strace && rm -rf /var/lib/apt/lists/*
RUN chmod 0111 /usr/bin/strace
`

// seccompProfile blocks the syscalls that would let a script either evade the
// strace observer or reach for kernel-attack surface, while leaving everything
// a normal build (and strace itself) needs alone.
//
//   - io_uring_*: network/file I/O submitted via io_uring is INVISIBLE to
//     strace's syscall tracing — a script could connect()/sendto() through a
//     ring and our observer would see nothing. Blocking it forces all I/O back
//     through observable syscalls.
//   - keyctl / add_key / request_key: the kernel keyring — credential storage a
//     build never touches. These need NO capability, so --cap-drop does not
//     cover them; blocking here removes a stash/read-keys avenue strace would
//     also not see clearly.
//   - bpf / perf_event_open / userfaultfd / kexec_*: kernel-attack surface a
//     build never needs.
//
// This stays a DENYLIST on an allow-by-default base rather than a full
// default-deny allowlist ON PURPOSE: a hand-rolled allowlist reliably breaks
// node-gyp across kernels/arches (the false-positive fatigue DESIGN.md §11b
// warns trains users to disable the tool), and the box's real containment
// (--cap-drop ALL, --network none, no-new-privileges, non-root) already
// neutralizes the capability-gated syscalls. We add the few no-cap-required
// dangerous ones explicitly.
//
// Deliberately NOT blocked: ptrace and process_vm_readv — strace uses those to
// read the tracee's string arguments (the DNS payloads we decode). The profile
// is allow-by-default layered on top of the box's real containment (--cap-drop
// ALL, --network none, no-new-privileges, non-root), so it only needs to add
// the few explicit denials above, not re-derive a full allowlist.
const seccompProfile = `{
  "defaultAction": "SCMP_ACT_ALLOW",
  "syscalls": [
    {
      "names": ["io_uring_setup","io_uring_enter","io_uring_register","keyctl","add_key","request_key","bpf","perf_event_open","userfaultfd","kexec_load","kexec_file_load"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    }
  ]
}`

// ensureSeccompProfile writes the profile to a stable temp path and returns it.
// On any failure it returns "" so the caller simply omits the seccomp arg —
// the box's other protections still hold (fail open on a non-critical extra).
func ensureSeccompProfile() string {
	path := filepath.Join(os.TempDir(), "depguard-seccomp.json")
	if err := os.WriteFile(path, []byte(seccompProfile), 0o644); err != nil {
		return ""
	}
	return path
}

// Runtime returns the available container runtime binary ("docker" or
// "podman"), or "" when neither exists — the §9 fallback trigger.
func Runtime() string {
	for _, bin := range []string{"docker", "podman"} {
		if _, err := exec.LookPath(bin); err == nil {
			return bin
		}
	}
	return ""
}

// EnsureObsImage makes sure the strace-equipped image exists locally,
// building it on first use. Returns (image, traced): when the build fails
// (offline machine, registry hiccup) it falls back to the plain digest-pinned
// image — the cage still holds, only the tracing is lost, and the caller
// warns about exactly that.
func EnsureObsImage(runtime string) (string, bool) {
	if exec.Command(runtime, "image", "inspect", obsImage).Run() == nil {
		return obsImage, true
	}
	fmt.Fprintln(os.Stderr, "guard: building observation image (one-time, needs network)...")
	build := exec.Command(runtime, "build", "-q", "-t", obsImage, "-")
	build.Stdin = strings.NewReader(obsDockerfile)
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "guard: ⚠ observation image build failed — scripts still run CAGED but UNTRACED")
		return buildImage, false
	}
	return obsImage, true
}

// ObsImageName is the tag of the locally-built observation image (for status
// and clean reporting).
func ObsImageName() string { return obsImage }

// RemoveObsImage deletes the locally-built observation image to reclaim its
// space. It is safe (and a no-op) when no runtime exists or the image is
// absent; returns whether anything was removed.
func RemoveObsImage(runtime string) (bool, error) {
	if runtime == "" {
		return false, nil
	}
	if exec.Command(runtime, "image", "inspect", obsImage).Run() != nil {
		return false, nil // not present
	}
	if out, err := exec.Command(runtime, "rmi", obsImage).CombinedOutput(); err != nil {
		return false, fmt.Errorf("removing %s: %s", obsImage, strings.TrimSpace(string(out)))
	}
	return true, nil
}

// SweepContainers force-removes any leftover depguard run containers. The normal
// path runs with --rm and force-removes on a timeout, so this only finds orphans
// from a hard-killed guard. Returns the count removed; a no-op without a runtime.
func SweepContainers(runtime string) int {
	if runtime == "" {
		return 0
	}
	out, err := exec.Command(runtime, "ps", "-aq", "--filter", "name=depguard-run-").Output()
	if err != nil {
		return 0
	}
	n := 0
	for _, id := range strings.Fields(string(out)) {
		if exec.Command(runtime, "rm", "-f", id).Run() == nil {
			n++
		}
	}
	return n
}

// SweepArtifacts removes on-disk leftovers a HARD-KILLED box run could leave
// behind — the normal run path already cleans these via defer, so this is the
// recovery hook for a guard process killed mid-run:
//   - "*.guard-backup" sibling dirs anywhere under node_modules (pre-run backups)
//   - "guard-obs-*" temp dirs (strace logs written by guard <= 1.1.0)
//   - the shared seccomp profile temp file
//
// Returns the count removed. Best-effort: an unremovable item is skipped, never
// fatal.
func SweepArtifacts(projectDir string) int {
	removed := 0
	nm := filepath.Join(projectDir, "node_modules")
	_ = filepath.WalkDir(nm, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && strings.HasSuffix(path, ".guard-backup") {
			if os.RemoveAll(path) == nil {
				removed++
			}
			return filepath.SkipDir
		}
		return nil
	})
	if entries, err := os.ReadDir(os.TempDir()); err == nil {
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "guard-obs-") {
				if os.RemoveAll(filepath.Join(os.TempDir(), e.Name())) == nil {
					removed++
				}
			}
		}
	}
	if os.Remove(filepath.Join(os.TempDir(), "depguard-seccomp.json")) == nil {
		removed++
	}
	return removed
}

// Result is what the box observed during one script run.
type Result struct {
	ExitCode int
	Output   string   // combined stdout+stderr from the container
	NewFiles []string // files created under the package dir (expected: build output)
	Modified []string // files changed under the package dir
	// Findings is the syscall-level evidence (empty when untraced).
	Findings []trace.Observation
	// Unsafe: the trace showed behavior with no legitimate build-time
	// explanation. The package dir has been restored to its pre-run state.
	Unsafe bool
	// Traced reports whether strace observation was COMPLETE for this run. A
	// missing or truncated trace clears it: we did not see everything.
	Traced bool
	// Requested records that tracing was ASKED for. Traced=false alone can't be
	// read as a problem (an untraced box never asked); the pair can.
	Requested bool
	// Discarded: the output was rolled back because the run could not be
	// observed and policy is strict. Not evidence of malice — evidence of a
	// blind spot.
	Discarded bool
	// Truncated names the host-side buffers that hit their cap, if any.
	Truncated []string
	// ObserverLost: the trace ended without the root tracee's exit marker — the
	// script very likely killed strace and kept running unwatched.
	ObserverLost bool
}

// Output and trace caps. The container's pipes are attacker-controllable
// firehoses; these bound what guard buffers in RAM. var so a test can trip them.
var (
	maxScriptOutput = 4 << 20  // 4 MiB of script stdout/stderr
	maxTraceBytes   = 64 << 20 // 64 MiB of strace lines
)

// capWriter is a bounded in-memory sink: it accepts every write so the child
// never blocks or sees EPIPE, but keeps at most max bytes and records that it
// dropped the rest.
type capWriter struct {
	max       int
	buf       []byte
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.max - len(w.buf); room > 0 {
		if len(p) <= room {
			w.buf = append(w.buf, p...)
		} else {
			w.buf = append(w.buf, p[:room]...)
			w.truncated = true
		}
	} else if len(p) > 0 {
		w.truncated = true
	}
	return len(p), nil
}

func (w *capWriter) String() string { return string(w.buf) }

// verdict turns the raw trace pipe into the observation verdict. It is the
// whole post-run decision, kept pure so every branch is testable without Docker.
//
// Traced is TRUE only when tracing was requested AND we hold a complete trace:
// an empty one (strace never ran — the container died first) and a truncated one
// (we stopped reading) both mean we did not see everything, so we must not claim
// we did. A truncated trace is still PARSED — evidence already captured convicts
// even though the observation is incomplete.
func verdict(traceBytes []byte, truncated, tracedRequested, timedOut bool) (traced bool, findings []trace.Observation, unsafe, observerLost bool) {
	if !tracedRequested || len(strings.TrimSpace(string(traceBytes))) == 0 {
		return false, nil, false, false
	}
	rep := trace.Parse(traceBytes)
	complete := traceComplete(traceBytes)
	// Three different reasons for a missing ending, and only one of them is the
	// script's doing:
	//   truncated → we stopped reading (our cap)
	//   timedOut  → WE killed the container at the wall-clock limit, so of course
	//               strace never got to write its exit line
	//   otherwise → nobody but the script can explain it
	// Traced is false in all three (we did not see the end); ObserverLost — which
	// discards output under every policy — is reserved for the last.
	return !truncated && complete, rep.Observations, rep.Unsafe, !truncated && !timedOut && !complete
}

// shouldDiscard decides whether the script's output survives the box.
//
// strict is `untraced-boxed: fail` — "I don't keep what I couldn't watch".
// observerLost overrides policy entirely: killing your own tracer has no
// build-time excuse, so that output is never kept, even under
// `untraced-boxed: run`. It is still not an auto-CONVICTION (the approval stands)
// — a hung build we killed ourselves can look similar from the outside, which is
// why the timeout is excluded from observerLost upstream.
func shouldDiscard(strict, tracedRequested, observed, observerLost, traceTruncated bool) bool {
	if !tracedRequested || observed {
		return false
	}
	// A killed observer and a flooded one are the same class: no build emits
	// 64 MiB of network/exec/open syscalls by accident, so neither gets to
	// keep its output — under ANY policy. Only an innocent gap (no strace
	// image) is left to the untraced-boxed setting.
	return strict || observerLost || traceTruncated
}

// rootPidRe grabs the pid `strace -f` prefixes every line with.
var rootPidRe = regexp.MustCompile(`(?m)^(\d+)\s`)

// traceComplete reports whether the trace proves the OBSERVER outlived the
// script it was observing.
//
// The tracee can kill its tracer — `kill -9 $PPID` from the install script.
// strace dies, its pipe closes, and what guard reads is a perfectly ordinary
// trace: non-empty, under the cap, nothing incriminating in it. The script is
// DETACHED by that kill, not stopped: everything it does afterwards is invisible
// and, without this check, accepted. So absence of evidence is not enough — the
// trace has to carry positive proof of a clean ending.
//
// That proof is strace's own exit line for the ROOT tracee (the pid on the first
// line): "<pid> +++ exited with N +++" or "<pid> +++ killed by SIGx +++". A child
// pid's marker will not do — a script can arrange for a child to exit before it
// kills the tracer.
func traceComplete(log []byte) bool {
	m := rootPidRe.FindSubmatch(log)
	if m == nil {
		return false // can't identify the root tracee → can't prove completion
	}
	done := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(string(m[1])) + `\s+\+\+\+ (?:exited with \d+|killed by SIG\w+)`)
	return done.Match(log)
}

// restore rolls the package dir back to its pre-run backup — what makes
// "the output was discarded" real rather than aspirational.
//
// keepBackup is true when the rename FAILED: the package dir is already gone and
// the backup is the only surviving copy, so the caller's deferred cleanup must
// not delete it. Removing it there would turn a recoverable error into data loss.
func restore(pkgDir, backupDir string) (keepBackup bool, err error) {
	if err := os.RemoveAll(pkgDir); err != nil {
		return false, fmt.Errorf("discarding box output: %w", err)
	}
	if err := os.Rename(backupDir, pkgDir); err != nil {
		return true, fmt.Errorf("restoring pre-run state: %w (pre-run copy preserved at %s)", err, backupDir)
	}
	return false, nil
}

// Run executes the package's install scripts inside the sealed container,
// under syscall observation when the strace image is available.
// projectDir is the repo root; relPath is the package's lockfile path
// ("node_modules/<name>", possibly nested).
//
// Mount layout: the project's node_modules is visible READ-ONLY (install
// scripts legitimately require sibling packages — esbuild resolves its
// platform binary package this way), and only the target package's own
// directory is writable. The box never sees the rest of the project, $HOME,
// or any secret. Network is fully off: a malicious script's exfil attempt
// fails AND — under strace — is captured as evidence with the destination.
//
// When the trace verdict is UNSAFE the package directory is rolled back to
// its pre-run state: the script's output never survives. strict does the same
// for a run we could not fully OBSERVE (untraced-boxed: fail) — not because the
// script misbehaved, but because we can't say that it didn't.
func Run(runtime, image string, traced, strict bool, projectDir, relPath string) (Result, error) {
	pkgDir := filepath.Join(projectDir, relPath)
	before, err := snapshot(pkgDir)
	if err != nil {
		return Result{}, err
	}

	// Pre-run backup as a SIBLING (same filesystem → atomic rename restore).
	// This is what makes "discard the output" real rather than aspirational.
	backupDir := pkgDir + ".guard-backup"
	if err := os.CopyFS(backupDir, os.DirFS(pkgDir)); err != nil {
		return Result{}, fmt.Errorf("pre-run backup: %w", err)
	}
	keepBackup := false
	defer func() {
		// No-op after a successful restore renames it away; skipped entirely
		// when the restore failed and this is the only copy left.
		if !keepBackup {
			os.RemoveAll(backupDir)
		}
	}()

	// Keep the node_modules dir name in the container path so Node's
	// upward require() resolution finds siblings naturally.
	workDir := "/app/" + filepath.ToSlash(relPath)

	// Run every install-phase script that exists, in npm's own order, using
	// npm itself inside the container so package.json semantics hold.
	script := `cd "$WORK" && for s in preinstall install postinstall; do npm run "$s" --if-present --foreground-scripts || exit $?; done`

	// Evidence path: strace writes the trace to the container's STDOUT, which
	// guard reads over a pipe, and the traced shell's own output is redirected to
	// stderr so the two streams never mix. A file in a shared bind mount was the
	// old design and was tamperable: the script runs as the same uid, so it could
	// truncate or rewrite its own trace, and an unreadable trace downgraded to
	// "untraced".
	//
	// The pipe is UNREACHABLE from the tracee, in both directions: it holds no
	// inherited fd to it (`exec 1>&2` replaces fd 1; strace's -o fd is CLOEXEC),
	// and /proc/<tracer>/fd is root-only because the image's strace is
	// execute-only, so the kernel marks the tracer non-dumpable (see
	// obsDockerfile). So the trace can be neither truncated NOR appended to —
	// which is precisely what makes the root-exit marker worth checking. Without
	// the exec-only binary the marker would be forgeable and this whole guarantee
	// would collapse.
	if traced {
		script = tracedScript(script)
	}

	// Name the container so a timed-out (SIGKILL'd) run can still be force-removed
	// below — --rm only fires on a clean CLI exit, not when we kill it.
	containerName := fmt.Sprintf("depguard-run-%d-%d", os.Getpid(), time.Now().UnixNano())
	args := []string{
		"run", "--rm", "--name", containerName,
		"--network", "none", // no phone line
		"--read-only",               // image is immutable
		"--tmpfs", "/tmp:size=512m", // scratch space
		"--tmpfs", "/home/node:size=64m", // npm wants a writable HOME for its cache
		"-e", "HOME=/home/node",
		"-e", "WORK=" + workDir,
		// Silence npm's own phone-home plumbing (update checks, audit,
		// funding) so the benign baseline produces ZERO network syscalls —
		// any DNS query that remains in the trace is the script's own doing.
		"-e", "npm_config_update_notifier=false",
		"-e", "npm_config_audit=false",
		"-e", "npm_config_fund=false",
		"-e", "CI=true",
		// Whole dep tree readable (sibling resolution), nothing else.
		"-v", filepath.Join(projectDir, "node_modules") + ":/app/node_modules:ro",
		// The nested rw bind overrides the ro parent for this one subtree:
		// the script can only write its own package.
		"-v", pkgDir + ":" + workDir + ":rw",
	}
	args = append(args,
		"-w", workDir,
		"--cap-drop", "ALL", // no special powers (own-child ptrace needs none); also drops CAP_DAC_OVERRIDE so even uid 0 cannot open the non-dumpable tracer's /proc fds — load-bearing for the trace-forgery defense
		"--security-opt", "no-new-privileges", // setuid binaries can't escalate
		"--pids-limit", "512", // fork bombs die at the fence
		"--memory", boxMemory, // OOM a memory bomb instead of the host
		"--memory-swap", boxMemory, // == memory ⇒ no swap escape hatch
		"--cpus", boxCPUs, // a miner can't peg every core
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
	)
	// Block io_uring &c. so a script can't do I/O the strace observer can't see.
	// Fail open if the profile can't be written — the cage still holds without it.
	if prof := ensureSeccompProfile(); prof != "" {
		args = append(args, "--security-opt", "seccomp="+prof)
	}
	args = append(args,
		image, "sh", "-c", script,
	)

	// Wall-clock kill: a script that just spins (a miner) never exits on its
	// own. On timeout the docker CLI is killed and the --rm container torn down.
	ctx, cancel := context.WithTimeout(context.Background(), boxTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, runtime, args...)
	// Both sinks are BOUNDED: a script that prints forever must not grow guard's
	// heap without limit. When untraced there is no separate trace stream, so
	// stdout and stderr both land in the output buffer as before.
	outBuf := &capWriter{max: maxScriptOutput}
	traceBuf := &capWriter{max: maxTraceBytes}
	if traced {
		cmd.Stdout, cmd.Stderr = traceBuf, outBuf
	} else {
		cmd.Stdout, cmd.Stderr = outBuf, outBuf
	}
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Fprintf(outBuf, "\nguard: box killed after %s wall-clock limit\n", boxTimeout)
		// The killed CLI may not have run --rm; make sure the container is gone.
		_ = exec.Command(runtime, "rm", "-f", containerName).Run()
	}

	res := Result{Output: outBuf.String(), Requested: traced}
	if outBuf.truncated {
		res.Truncated = append(res.Truncated, "output")
	}
	if traceBuf.truncated {
		res.Truncated = append(res.Truncated, "trace")
	}
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		res.ExitCode = exitErr.ExitCode()
	} else if runErr != nil {
		return res, fmt.Errorf("container launch failed: %w", runErr)
	}

	res.Traced, res.Findings, res.Unsafe, res.ObserverLost = verdict(traceBuf.buf, traceBuf.truncated, traced, ctx.Err() == context.DeadlineExceeded)

	// UNSAFE → the output is discarded: pre-run state comes back via rename.
	if res.Unsafe {
		res.Discarded = true
		keep, err := restore(pkgDir, backupDir)
		keepBackup = keep
		return res, err
	}
	// We asked to observe this run and couldn't, fully. The script is not
	// convicted — but unobserved output isn't accepted either.
	if shouldDiscard(strict, traced, res.Traced, res.ObserverLost, traceBuf.truncated) {
		res.Discarded = true
		keep, err := restore(pkgDir, backupDir)
		keepBackup = keep
		return res, err
	}

	// File diff: what did the script actually write? Build output in the
	// package dir is expected; that's all it CAN write — everything else
	// was never mounted.
	after, err := snapshot(pkgDir)
	if err != nil {
		return res, err
	}
	for path, sig := range after {
		old, existed := before[path]
		switch {
		case !existed:
			res.NewFiles = append(res.NewFiles, path)
		case old != sig:
			res.Modified = append(res.Modified, path)
		}
	}
	return res, nil
}

// tracedScript wraps the install-script command in strace. The trace goes to
// the container's STDOUT — a pipe the script cannot reach (see obsDockerfile) —
// and the script's own output is pushed to stderr so the two never mix. %network covers connect/sendto/recvfrom
// — destinations AND DNS payloads; openat covers file access; execve covers spawns.
func tracedScript(script string) string {
	// -q (not -qq) keeps strace's per-process exit lines. That is the ONLY
	// evidence that the observer outlived the script — see traceComplete.
	// `exec` makes strace PID 1. Without it Debian's dash (no single-command
	// exec optimization) sits at PID 1, dumpable, holding the trace pipe as
	// its fd 1 — and /proc/1/fd/1 forgery works (verified live). As PID 1
	// strace also gains the kernel's pid-namespace init protection: SIGKILL
	// from inside the namespace is dropped, so the tracer can't be killed.
	return `exec strace -f -q -e trace=%network,execve,openat -s 512 -o /dev/stdout sh -c 'exec 1>&2; ` + script + `'`
}

// scrubbedEnv is the minimal environment an uncontained script inherits: enough
// to find a toolchain and a home, but NONE of the caller's secrets. The human
// approved running the script, not handing it every API token in their shell —
// so a leaked $NPM_TOKEN / $AWS_SECRET_ACCESS_KEY / $GITHUB_TOKEN can't ride
// along. Kept separate so a test can assert exactly what does (and does not)
// pass through.
func scrubbedEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"LANG=" + os.Getenv("LANG"),
		"TMPDIR=" + os.TempDir(),
	}
}

// RunUncontained executes install scripts with NO sandbox — the §9
// warn-approve path only. The caller is responsible for having obtained
// explicit human approval before calling this.
//
// Even uncontained, the environment is scrubbed to the minimum a build needs:
// the human approved running the script, not handing it every API token
// sitting in their shell environment.
func RunUncontained(pkgDir string) (Result, error) {
	cmd := exec.Command("sh", "-c",
		`for s in preinstall install postinstall; do npm run "$s" --if-present --foreground-scripts || exit $?; done`)
	cmd.Dir = pkgDir
	cmd.Env = scrubbedEnv()
	// Bounded like the boxed path: an uncontained script's output is even less
	// trustworthy, so it must not sit in an unbounded host-side buffer either.
	outBuf := &capWriter{max: maxScriptOutput}
	cmd.Stdout, cmd.Stderr = outBuf, outBuf
	runErr := cmd.Run()
	res := Result{Output: outBuf.String()}
	if outBuf.truncated {
		res.Truncated = append(res.Truncated, "output")
	}
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		res.ExitCode = exitErr.ExitCode()
	} else if runErr != nil {
		return res, runErr
	}
	return res, nil
}

// snapshot maps relative path → "size:mtime" for every file under dir.
// Cheap change detection — content hashing would be overkill for a diff
// whose job is "did it write anything unexpected".
func snapshot(dir string) (map[string]string, error) {
	snap := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		snap[rel] = fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
		return nil
	})
	return snap, err
}

// Summary renders a short human-readable account of what the box observed.
//
// It says so LOUDLY when the observation was incomplete. A script can blind the
// observer on purpose — flood enough openat() calls and the trace hits its cap —
// and under `untraced-boxed: run` that run is still accepted. The least we owe
// the human is to not report it in the same words as a fully watched run.
func (r Result) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "exit %d, %d new file(s), %d modified", r.ExitCode, len(r.NewFiles), len(r.Modified))
	if len(r.Truncated) > 0 {
		fmt.Fprintf(&b, "; ⚠ %s output hit the size cap (trace cap %d MiB)", strings.Join(r.Truncated, "+"), maxTraceBytes>>20)
	}
	if r.ObserverLost {
		b.WriteString("; ⚠ observer terminated before the script finished (trace has no completion marker)")
	}
	if r.Requested && !r.Traced {
		b.WriteString("; ⚠ observation INCOMPLETE — this run was NOT fully watched")
	}
	return b.String()
}
