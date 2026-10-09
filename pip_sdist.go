package main

// pip source distributions (DESIGN.md §8, pip): the twin of npm's
// scan → approve-once → box+trace → run. An sdist runs setup.py / a PEP 517
// backend at build time, and pip has no "download without executing" for one,
// so pip never touches an unapproved sdist: guard fetches its bytes itself
// (sha256-verified), scans them, asks once, and TRIAL-BUILDS it in the box
// purely for a verdict. Only a clean (or explicitly uncontained-approved) sdist
// is then handed to pip, which builds it again on the host for real.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"depguard/internal/approvals"
	"depguard/internal/box"
	"depguard/internal/config"
	"depguard/internal/pyver"
	"depguard/internal/registry"
	"depguard/internal/scanner"
	"depguard/internal/sdist"
	"depguard/internal/ui"
)

// exitError ends a pip install with a specific process exit code; msg "" means
// pip already said why.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// Seams for tests: pip, the container runtime and the trial build.
var (
	runPip = func(args []string) (tail string, code int) {
		buf := &tailBuffer{max: 64 << 10}
		cmd := exec.Command("pip", args...)
		cmd.Stdout, cmd.Stderr, cmd.Stdin = io.MultiWriter(os.Stdout, buf), io.MultiWriter(os.Stderr, buf), os.Stdin
		cmd.Env = pipEnv(os.Environ())
		err := cmd.Run()
		var ee *exec.ExitError
		switch {
		case err == nil:
			return string(buf.b), 0
		case errors.As(err, &ee):
			return string(buf.b), ee.ExitCode()
		default:
			return err.Error(), -1
		}
	}
	boxRuntime     = box.Runtime
	ensureObsImage = box.EnsureObsImage
	runPyBuild     = box.RunPyBuild
	// hostPython is the interpreter version pip installs into ("3.12"), from
	// `pip --version`; "" when unknown (every requires-python then fails closed).
	hostPython = func() string {
		cmd := exec.Command("pip", "--version")
		cmd.Env = pipEnv(os.Environ())
		out, _ := cmd.Output()
		if m := pipPythonRe.FindStringSubmatch(string(out)); m != nil {
			return m[1]
		}
		return ""
	}
)

var pipPythonRe = regexp.MustCompile(`\(python (\d+(?:\.\d+)*)\)`)

// constraintsFile is the guard-owned pip constraints file in the stash: one
// `name==version` per admitted sdist, passed to every pip call so pip can only
// pick the version guard trial-built.
const constraintsFile = "guard-constraints.txt"

// maxSdistRounds bounds the download → admit loop (one round per sdist pip
// turns out to need). var so a test can trip it cheaply.
var maxSdistRounds = 50

// maxSdistBytes caps one fetched sdist.
var maxSdistBytes int64 = 256 << 20

// pipValueOpts are pip options that consume the next argument.
var pipValueOpts = map[string]bool{"-r": true, "--requirement": true, "-c": true, "--constraint": true,
	"-t": true, "--target": true, "-i": true, "--index-url": true, "--extra-index-url": true,
	"-f": true, "--find-links": true, "--prefix": true, "--root": true, "-e": true, "--editable": true}

// pipDownloadArgs is the part of an install argv `pip download` understands:
// requirements, -r/-c files, --pre and --no-deps. Install-only options
// (--target, --upgrade, ...) stay for the final `pip install`.
func pipDownloadArgs(sub string, args []string) []string {
	var out []string
	if sub == "ci" {
		out = []string{"-r", "requirements.txt"}
	}
	keep := map[string]bool{"-r": true, "--requirement": true, "-c": true, "--constraint": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		opt, _, hasEq := strings.Cut(a, "=")
		switch {
		case keep[a] && i+1 < len(args):
			out = append(out, a, args[i+1])
			i++
		case hasEq && keep[opt], a == "--pre", a == "--no-deps":
			out = append(out, a)
		case pipValueOpts[a]:
			i++
		case !strings.HasPrefix(a, "-"):
			out = append(out, a)
		}
	}
	return out
}

// sdistRun is one install's sdist admission state.
type sdistRun struct {
	dir     string
	cfg     config.Config
	appr    *approvals.File
	index   string                    // the proxy's /simple/ URL
	blocked func() []registry.Blocked // what the proxy hid so far
	stash   string                    // pip download dest; the box's /stash
	client  *http.Client
	hostPy  *string // memoized hostPython()
}

func (r *sdistRun) constraints() string { return filepath.Join(r.stash, constraintsFile) }

// python returns the host interpreter version, asked once per run.
func (r *sdistRun) python() string {
	if r.hostPy == nil {
		v := hostPython()
		r.hostPy = &v
	}
	return *r.hostPy
}

// installPipSdists is installPip when sdists are allowed: resolve into a stash
// (wheels, plus each sdist only once it passed review + trial build), then
// install from that stash alone.
func installPipSdists(dir string, cfg config.Config, sub string, args []string, proxy *registry.PyPIProxy) error {
	for _, a := range args {
		if opt, _, _ := strings.Cut(a, "="); opt == "--no-binary" || opt == "--only-binary" {
			return &exitError{2, "guard install: " + opt + " is guard's call with --allow-sdist (each sdist is reviewed and trial-built first); drop it"}
		}
	}
	stash, err := os.MkdirTemp("", "guard-pip-stash-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stash)
	appr, err := approvals.Load(dir)
	if err != nil {
		return err
	}
	r := &sdistRun{dir: dir, cfg: cfg, appr: appr, index: proxy.URL(), blocked: proxy.BlockedVersions,
		stash: stash, client: &http.Client{Timeout: 60 * time.Second}}
	if err := r.resolve(pipDownloadArgs(sub, args)); err != nil {
		reportProxy(proxy)
		return err
	}
	if err := verifyStash(stash, appr); err != nil {
		return err
	}
	install := []string{"install", "--no-index", "--find-links", stash, "-c", r.constraints()}
	if sub == "ci" {
		install = append(install, "-r", "requirements.txt")
	}
	_, code := runPip(append(install, args...))
	reportProxy(proxy)
	if code != 0 {
		return &exitError{max(code, 1), ""}
	}
	return nil
}

// resolve downloads into the stash until pip is satisfied, admitting one sdist
// per round. pip only ever builds sdists that admit() let through.
func (r *sdistRun) resolve(reqArgs []string) error {
	if err := os.WriteFile(r.constraints(), nil, 0o644); err != nil {
		return err
	}
	approved := map[string]bool{}
	for round := 0; round < maxSdistRounds; round++ {
		args := []string{"download", "--dest", r.stash, "--index-url", r.index, "-c", r.constraints(), "--only-binary=:all:"}
		names := make([]string, 0, len(approved))
		for p := range approved {
			names = append(names, p)
		}
		sort.Strings(names)
		for _, p := range names {
			args = append(args, "--no-binary", p) // only these may come as source
		}
		out, code := runPip(append(args, reqArgs...))
		if code == 0 {
			return nil
		}
		pkg, spec, ok := sdist.NeedSdist(out)
		if !ok {
			return &exitError{max(code, 1), ""} // some other pip failure; it said why
		}
		for _, b := range r.blocked() {
			if b.Package == pkg {
				return &exitError{1, "pip found no installable version of " + pkg + " — see the hidden versions above"}
			}
		}
		if approved[pkg] {
			return &exitError{1, "pip still cannot resolve " + pkg + " after its sdist was approved"}
		}
		f, err := r.pickSdist(pkg, spec)
		if err != nil {
			return err
		}
		if err := r.admit(pkg, f); err != nil {
			return err
		}
		// Pin pip to the exact version that was reviewed and trial-built.
		cf, err := os.OpenFile(r.constraints(), os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_, werr := fmt.Fprintf(cf, "%s==%s\n", pkg, f.version)
		if cerr := cf.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return werr
		}
		approved[pkg] = true
	}
	return &exitError{1, fmt.Sprintf("gave up after %d source-distribution rounds", maxSdistRounds)}
}

// sdistFile is one sdist candidate from the (filtered) index page.
type sdistFile struct{ version, filename, url, sha256 string }

// pickSdist reads pkg's page THROUGH the proxy (so cooldown, OSV and the name
// gate apply) and returns the highest stable .tar.gz version satisfying spec.
func (r *sdistRun) pickSdist(pkg, spec string) (sdistFile, error) {
	req, err := http.NewRequest(http.MethodGet, r.index+pkg+"/", nil)
	if err != nil {
		return sdistFile{}, err
	}
	req.Header.Set("Accept", "application/vnd.pypi.simple.v1+json")
	resp, err := r.client.Do(req)
	if err != nil {
		return sdistFile{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return sdistFile{}, &exitError{1, fmt.Sprintf("index page for %s returned %d", pkg, resp.StatusCode)}
	}
	var page struct {
		Files []struct {
			Filename string            `json:"filename"`
			URL      string            `json:"url"`
			Hashes   map[string]string `json:"hashes"`
			Yanked   any               `json:"yanked"`
			Python   string            `json:"requires-python"`
		} `json:"files"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&page); err != nil {
		return sdistFile{}, fmt.Errorf("index page for %s: %w", pkg, err)
	}
	var best sdistFile
	tooNew, unknown := 0, 0
	for _, f := range page.Files {
		// ponytail: .tar.gz only (PEP 625); legacy .zip sdists are not scanned.
		v, ok := pyver.FileVersion(f.Filename)
		if !ok || !strings.HasSuffix(f.Filename, ".tar.gz") || !pyver.Stable(v) || (f.Yanked != nil && f.Yanked != false) {
			continue
		}
		sat, err := sdist.Satisfies(v, spec)
		if err != nil {
			return sdistFile{}, &exitError{2, fmt.Sprintf("can't evaluate %q for %s (%v) — pin %s to an exact version", spec, pkg, err, pkg)}
		}
		// pip skips a file the host interpreter can't use; so must guard, or the
		// version it trial-builds is not the one pip would pick.
		if sat && f.Python != "" {
			if fits, perr := sdist.Satisfies(r.python(), f.Python); perr != nil {
				unknown, sat = unknown+1, false // can't tell → skip (fail closed)
			} else if !fits {
				tooNew, sat = tooNew+1, false
			}
		}
		if sat && (best.version == "" || pyver.Less(best.version, v)) {
			best = sdistFile{v, f.Filename, f.URL, f.Hashes["sha256"]}
		}
	}
	if best.version == "" {
		msg := fmt.Sprintf("no source distribution of %s satisfies %q", pkg, spec)
		if tooNew+unknown > 0 {
			msg += fmt.Sprintf(" for python %q (%d skipped: requires-python not met, %d unevaluable)", r.python(), tooNew, unknown)
		}
		return sdistFile{}, &exitError{1, msg}
	}
	return best, nil
}

// admit decides one sdist: fetch + scan, the remembered or prompted decision,
// then a boxed trial build (or the explicitly approved uncontained path). nil
// means pip may build it on the host.
func (r *sdistRun) admit(pkg string, f sdistFile) error {
	tgz, err := sdist.Fetch(r.client, f.url, f.sha256, maxSdistBytes)
	if err != nil {
		return &exitError{1, fmt.Sprintf("%s %s: %v", pkg, f.version, err)}
	}
	rep, err := scanner.ScanSdist(tgz)
	if err != nil {
		return &exitError{1, fmt.Sprintf("%s: unreadable sdist: %v", f.filename, err)}
	}
	key, integrity := pkg+"@"+f.version, "sha256:"+strings.ToLower(f.sha256)

	entry, known := r.appr.Get(key)
	if known && !entry.AppliesTo(integrity) {
		fmt.Fprintf(os.Stderr, "guard: approval for %s was for a different sdist (hash changed) — re-review\n", key)
		known = false
	}
	if !known {
		if !stdinIsTTY() {
			// Never decide for the human; nothing is recorded. The report still
			// prints so the follow-up `guard approve` is an informed one.
			printScanReport(key, rep, true)
			return &exitError{1, fmt.Sprintf("%s needs a reviewed source build and no one is here to approve it — guard approve %s", key, key)}
		}
		d := promptApproval(key, rep, boxRuntime(), r.cfg, nil, true)
		r.appr.Set(key, d, "", integrity)
		if err := r.appr.Save(r.dir); err != nil {
			return err
		}
		entry = approvals.Entry{Decision: d}
	}
	// Pin an unbound approval (e.g. from `guard approve`) to these bytes.
	if r.appr.Bind(key, integrity) {
		if err := r.appr.Save(r.dir); err != nil {
			return err
		}
	}
	if entry.Decision == approvals.Denied {
		return &exitError{1, "source build denied: " + key}
	}
	if entry.Decision == approvals.ApprovedUncontained && !uncontainedAllowed(r.cfg) {
		return &exitError{1, key + " is approved-uncontained but no-container-fallback is 'fail' — refusing the unboxed build"}
	}

	b, err := sdist.BuildRequires(tgz)
	if err != nil {
		return &exitError{1, fmt.Sprintf("%s: %v", key, err)}
	}
	// pip's final --no-index install needs the build requirements in the stash
	// too; fetch them as wheels only, so this step executes nothing.
	if len(b.Requires) > 0 {
		args := append([]string{"download", "--dest", r.stash, "--index-url", r.index, "-c", r.constraints(), "--only-binary=:all:"}, b.Requires...)
		if out, code := runPip(args); code != 0 {
			return &exitError{1, fmt.Sprintf("a build dependency of %s has no wheel:\n%s", key, tail(out, 10))}
		}
	}
	if entry.Decision == approvals.ApprovedUncontained {
		fmt.Fprintf(os.Stderr, "guard: %s %s — building UNCONTAINED on this host (explicitly approved)\n", ui.Warn(), key)
		return nil
	}
	return r.trialBuild(key, f.filename, tgz)
}

// trialBuild runs the boxed, traced build of one approved sdist and turns the
// verdict into admit's answer. Unsafe evidence revokes the approval.
func (r *sdistRun) trialBuild(key, filename string, tgz []byte) error {
	runtime := boxRuntime()
	if runtime == "" {
		return &exitError{1, fmt.Sprintf("%s is approved for BOXED builds only and no container runtime is available — install docker/podman, or re-approve with: guard approve %s --uncontained", key, key)}
	}
	image, traced := ensureObsImage(runtime)
	if !traced && r.cfg.UntracedFail {
		return &exitError{1, key + " — the trial build would be UNTRACED and untraced-boxed is 'fail'"}
	}
	if err := os.WriteFile(filepath.Join(r.stash, filepath.Base(filename)), tgz, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "guard: %s — trial-building in the box (%s)...\n", key, runtime)
	res, err := runPyBuild(runtime, image, traced, r.cfg.UntracedFail, r.stash, filepath.Base(filename))
	if err != nil {
		return fmt.Errorf("%s trial build: %w", key, err)
	}
	if res.Unsafe {
		fmt.Fprintf(os.Stderr, "\nguard: %s %s behaved MALICIOUSLY in its trial build:\n", ui.Bad(), key)
		for _, o := range res.Findings {
			if o.Kind != "exec" {
				fmt.Fprintf(os.Stderr, "    [%s] %s\n", o.Kind, o.Detail)
			}
		}
		prev, _ := r.appr.Get(key)
		r.appr.Set(key, approvals.Denied, "auto-denied: unsafe behavior observed in box", prev.Integrity)
		if err := r.appr.Save(r.dir); err != nil {
			return err
		}
		return &exitError{1, key + " attempted malicious actions during its build — approval revoked, nothing installed"}
	}
	if res.Discarded {
		return &exitError{1, fmt.Sprintf("%s — trial build not fully observed (%s); not handing it to pip", key, res.Summary())}
	}
	if res.ExitCode != 0 {
		return &exitError{1, fmt.Sprintf("%s — trial build failed in the box (%s). Output tail:\n%s", key, res.Summary(), tail(res.Output, 15))}
	}
	fmt.Fprintf(os.Stderr, "guard: %s — trial build clean (%s)\n", key, res.Summary())
	return nil
}

// verifyStash is the last check before pip builds anything on the host: every
// sdist in the stash must be one a human approved (boxed or uncontained) for
// exactly these bytes. Anything else means pip got an sdist past the loop.
func verifyStash(stash string, appr *approvals.File) error {
	entries, err := os.ReadDir(stash)
	if err != nil {
		return err
	}
	for _, e := range entries {
		fn := e.Name()
		if !strings.HasSuffix(fn, ".tar.gz") && !strings.HasSuffix(fn, ".zip") {
			continue
		}
		bad := &exitError{1, "unapproved source distribution in the stash: " + fn}
		v, ok := pyver.FileVersion(fn)
		if !ok {
			return bad
		}
		base := strings.TrimSuffix(strings.TrimSuffix(fn, ".tar.gz"), ".zip")
		name := pyver.NormalizeName(base[:strings.LastIndexByte(base, '-')])
		b, err := os.ReadFile(filepath.Join(stash, fn))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		entry, known := appr.Get(name + "@" + v)
		approved := entry.Decision == approvals.ApprovedBoxed || entry.Decision == approvals.ApprovedUncontained
		if !known || !approved || entry.Integrity != "sha256:"+hex.EncodeToString(sum[:]) {
			return bad
		}
	}
	return nil
}
