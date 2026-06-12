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
const obsImage = "depguard-box:1"

// obsDockerfile builds obsImage. Kept in source (not a file) so the binary
// stays self-contained and the recipe is reviewable right here.
const obsDockerfile = `FROM ` + buildImage + `
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends strace && rm -rf /var/lib/apt/lists/*
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

// SweepArtifacts removes on-disk leftovers a HARD-KILLED box run could leave
// behind — the normal run path already cleans these via defer, so this is the
// recovery hook for a guard process killed mid-run:
//   - "*.guard-backup" sibling dirs anywhere under node_modules (pre-run backups)
//   - "guard-obs-*" temp dirs (strace logs)
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
	// Traced reports whether strace observation was active for this run.
	Traced bool
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
// its pre-run state: the script's output never survives.
func Run(runtime, image string, traced bool, projectDir, relPath string) (Result, error) {
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
	defer os.RemoveAll(backupDir) // no-op after a restore renames it away

	// Keep the node_modules dir name in the container path so Node's
	// upward require() resolution finds siblings naturally.
	workDir := "/app/" + filepath.ToSlash(relPath)

	// Run every install-phase script that exists, in npm's own order, using
	// npm itself inside the container so package.json semantics hold.
	script := `cd "$WORK" && for s in preinstall install postinstall; do npm run "$s" --if-present --foreground-scripts || exit $?; done`

	// Observation dir: strace writes its log here; guard reads it after the
	// container is gone. Host-side temp, never inside the package dir (the
	// script can write there and must not be able to doctor its own trace
	// pre-emptively — see the tamper note in docs/CODEMAP.md).
	var obsDir string
	if traced {
		obsDir, err = os.MkdirTemp("", "guard-obs-")
		if err != nil {
			return Result{}, err
		}
		defer os.RemoveAll(obsDir)
		// %network covers connect/sendto/recvfrom — destinations AND DNS
		// payloads; openat covers file access; execve covers spawns.
		script = `strace -f -qq -e trace=%network,execve,openat -s 512 -o /obs/trace.log sh -c '` + script + `'`
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
	if traced {
		args = append(args, "-v", obsDir+":/obs:rw")
	}
	args = append(args,
		"-w", workDir,
		"--cap-drop", "ALL", // no special powers (own-child ptrace needs none)
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
	out, runErr := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		out = append(out, []byte(fmt.Sprintf("\nguard: box killed after %s wall-clock limit\n", boxTimeout))...)
		// The killed CLI may not have run --rm; make sure the container is gone.
		_ = exec.Command(runtime, "rm", "-f", containerName).Run()
	}

	res := Result{Output: string(out), Traced: traced}
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		res.ExitCode = exitErr.ExitCode()
	} else if runErr != nil {
		return res, fmt.Errorf("container launch failed: %w", runErr)
	}

	// Verdict from the syscall evidence.
	if traced {
		log, err := os.ReadFile(filepath.Join(obsDir, "trace.log"))
		if err == nil {
			rep := trace.Parse(log)
			res.Findings = rep.Observations
			res.Unsafe = rep.Unsafe
		} else {
			// No log at all (container died pre-strace): treat as untraced
			// rather than pretending we observed a clean run.
			res.Traced = false
		}
	}

	// UNSAFE → the output is discarded: pre-run state comes back via rename.
	if res.Unsafe {
		if err := os.RemoveAll(pkgDir); err != nil {
			return res, fmt.Errorf("discarding unsafe output: %w", err)
		}
		if err := os.Rename(backupDir, pkgDir); err != nil {
			return res, fmt.Errorf("restoring pre-run state: %w", err)
		}
		return res, nil
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
	out, runErr := cmd.CombinedOutput()
	res := Result{Output: string(out)}
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
func (r Result) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "exit %d, %d new file(s), %d modified", r.ExitCode, len(r.NewFiles), len(r.Modified))
	return b.String()
}
