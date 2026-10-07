package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"depguard/internal/approvals"
	"depguard/internal/box"
	"depguard/internal/config"
	"depguard/internal/registry"
	"depguard/internal/trace"
)

// sdistBytes builds a <name>-<ver>.tar.gz whose pyproject.toml declares requires.
func sdistBytes(t *testing.T, name, ver, requires string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	files := map[string]string{
		"pyproject.toml": "[build-system]\nrequires = [" + requires + "]\nbuild-backend = \"backend\"\nbackend-path = [\".\"]\n",
		"backend.py":     "def build_wheel(d, c=None, m=None): pass\n",
	}
	for fn, body := range files {
		tw.WriteHeader(&tar.Header{Name: name + "-" + ver + "/" + fn, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}) //nolint:errcheck
		tw.Write([]byte(body))                                                                                                     //nolint:errcheck
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// pypiUpstream serves Simple pages (sdists only, all 400 days old) and the
// sdist bytes; requires maps a project to its build requirements.
type pypiUpstream struct {
	srv   *httptest.Server
	files map[string][]byte // filename → bytes
}

// pyReq optionally maps "name@version" to that file's requires-python.
func newUpstream(t *testing.T, releases map[string][]string, requires map[string]string, pyReq ...map[string]string) *pypiUpstream {
	t.Helper()
	u := &pypiUpstream{files: map[string][]byte{}}
	old := time.Now().AddDate(0, 0, -400).UTC().Format(time.RFC3339)
	pages := map[string]string{}
	mux := http.NewServeMux()
	u.srv = httptest.NewServer(mux)
	t.Cleanup(u.srv.Close)
	for name, vers := range releases {
		var files []string
		for _, v := range vers {
			fn := strings.ReplaceAll(name, "-", "_") + "-" + v + ".tar.gz"
			b := sdistBytes(t, strings.ReplaceAll(name, "-", "_"), v, requires[name])
			u.files[fn] = b
			sum := sha256.Sum256(b)
			rp := ""
			if len(pyReq) > 0 && pyReq[0][name+"@"+v] != "" {
				rp = fmt.Sprintf(`,"requires-python":%q`, pyReq[0][name+"@"+v])
			}
			files = append(files, fmt.Sprintf(`{"filename":%q,"url":%q,"hashes":{"sha256":%q},"upload-time":%q%s}`,
				fn, u.srv.URL+"/files/"+fn, hex.EncodeToString(sum[:]), old, rp))
		}
		pages[name] = `{"meta":{"api-version":"1.1"},"name":"` + name + `","files":[` + strings.Join(files, ",") + `]}`
	}
	mux.HandleFunc("/simple/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/simple/"), "/")
		if p, ok := pages[name]; ok {
			fmt.Fprint(w, p)
			return
		}
		w.WriteHeader(404)
	})
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		w.Write(u.files[strings.TrimPrefix(r.URL.Path, "/files/")]) //nolint:errcheck
	})
	return u
}

func (u *pypiUpstream) integrity(fn string) string {
	sum := sha256.Sum256(u.files[fn])
	return "sha256:" + hex.EncodeToString(sum[:])
}

// harness wires a sdistRun to a real PyPI proxy over the upstream, with pip,
// the runtime and the trial build faked.
type harness struct {
	run     *sdistRun
	pip     [][]string
	builds  []string
	verdict box.Result
}

func newHarness(t *testing.T, u *pypiUpstream, cfg config.Config, pip func(args []string) (string, int)) *harness {
	t.Helper()
	cfg.PyPI = u.srv.URL
	if cfg.Cooldown == 0 {
		cfg.Cooldown = 14 * 24 * time.Hour
	}
	proxy, err := registry.StartPyPI(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxy.Stop)
	dir := t.TempDir()
	appr, _ := approvals.Load(dir)
	h := &harness{verdict: box.Result{Traced: true, Requested: true}}
	h.run = &sdistRun{dir: dir, cfg: cfg, appr: appr, index: proxy.URL(), blocked: proxy.BlockedVersions,
		stash: t.TempDir(), client: &http.Client{Timeout: 5 * time.Second}}
	oldPip, oldRT, oldImg, oldBuild, oldPy := runPip, boxRuntime, ensureObsImage, runPyBuild, hostPython
	t.Cleanup(func() {
		runPip, boxRuntime, ensureObsImage, runPyBuild, hostPython = oldPip, oldRT, oldImg, oldBuild, oldPy
	})
	hostPython = func() string { return "3.12" }
	runPip = func(args []string) (string, int) {
		h.pip = append(h.pip, args)
		return pip(args)
	}
	boxRuntime = func() string { return "docker" }
	ensureObsImage = func(string) (string, bool) { return "img", true }
	runPyBuild = func(rt, img string, traced, strict bool, stash, name string) (box.Result, error) {
		if _, err := os.Stat(filepath.Join(stash, name)); err != nil {
			return box.Result{}, fmt.Errorf("sdist not in stash: %v", err)
		}
		h.builds = append(h.builds, name)
		return h.verdict, nil
	}
	return h
}

func (h *harness) approve(t *testing.T, key string, d approvals.Decision, integrity string) {
	t.Helper()
	h.run.appr.Set(key, d, "", integrity)
}

// needs answers pip download with a "needs an sdist" failure for pkg until the
// download carries --no-binary pkg.
func needs(pkgs ...string) func([]string) (string, int) {
	return func(args []string) (string, int) {
		joined := " " + strings.Join(args, " ") + " "
		for _, p := range pkgs {
			if !strings.Contains(joined, " --no-binary "+p+" ") && strings.Contains(joined, " "+p+" ") {
				return "ERROR: Could not find a version that satisfies the requirement " + p + " (from versions: none)\nERROR: No matching distribution found for " + p + "\n", 1
			}
		}
		return "", 0
	}
}

func exitOf(t *testing.T, err error) *exitError {
	t.Helper()
	var ee *exitError
	if !errors.As(err, &ee) {
		t.Fatalf("want an exitError, got %v", err)
	}
	return ee
}

func TestSdistLoopWheelsOnly(t *testing.T) {
	h := newHarness(t, newUpstream(t, nil, nil), config.Defaults(), func([]string) (string, int) { return "", 0 })
	if err := h.run.resolve([]string{"requests"}); err != nil || len(h.pip) != 1 || len(h.builds) != 0 {
		t.Fatalf("err=%v pip=%v builds=%v", err, h.pip, h.builds)
	}
	if got := strings.Join(h.pip[0], " "); !strings.Contains(got, "download --dest "+h.run.stash+" --index-url "+h.run.index+" -c "+h.run.constraints()+" --only-binary=:all: requests") {
		t.Errorf("download argv = %s", got)
	}
}

func TestSdistLoopApprovedBoxedClean(t *testing.T) {
	u := newUpstream(t, map[string][]string{"src-pkg": {"1.0", "2.0", "3.0rc1"}}, nil)
	h := newHarness(t, u, config.Defaults(), needs("src-pkg"))
	h.approve(t, "src-pkg@2.0", approvals.ApprovedBoxed, "") // unbound: bound on first use
	if err := h.run.resolve([]string{"src-pkg"}); err != nil {
		t.Fatal(err)
	}
	if len(h.builds) != 1 || h.builds[0] != "src_pkg-2.0.tar.gz" {
		t.Errorf("builds = %v, want the highest stable sdist", h.builds)
	}
	if last := strings.Join(h.pip[len(h.pip)-1], " "); !strings.Contains(last, "--no-binary src-pkg") {
		t.Errorf("second download must allow the approved sdist: %s", last)
	}
	if e, _ := h.run.appr.Get("src-pkg@2.0"); e.Integrity != u.integrity("src_pkg-2.0.tar.gz") || e.Note != approvals.AutoBoundNote {
		t.Errorf("approval not bound to the sdist: %+v", e)
	}
}

func TestSdistLoopSpecPicksVersion(t *testing.T) {
	u := newUpstream(t, map[string][]string{"src-pkg": {"1.0", "1.5", "2.0"}}, nil)
	h := newHarness(t, u, config.Defaults(), func(args []string) (string, int) {
		if !strings.Contains(strings.Join(args, " "), "--no-binary src-pkg") {
			return "ERROR: No matching distribution found for src-pkg<2,>=1.1\n", 1
		}
		return "", 0
	})
	h.approve(t, "src-pkg@1.5", approvals.ApprovedBoxed, u.integrity("src_pkg-1.5.tar.gz"))
	if err := h.run.resolve([]string{"src-pkg>=1.1,<2"}); err != nil || len(h.builds) != 1 || h.builds[0] != "src_pkg-1.5.tar.gz" {
		t.Fatalf("err=%v builds=%v", err, h.builds)
	}
}

func TestSdistLoopRefusals(t *testing.T) {
	cases := []struct {
		name     string
		cfg      func(*config.Config)
		decision approvals.Decision // "" = no approval recorded
		pipOut   string             // first download output ("" → needs src-pkg)
		requires string
		verdict  box.Result
		blocked  bool
		code     int
		msg      string
	}{
		{name: "denied", decision: approvals.Denied, code: 1, msg: "source build denied: src-pkg@1.0"},
		{name: "unreviewed, no tty", code: 1, msg: "guard approve src-pkg@1.0"},
		{name: "uncontained refused by policy", decision: approvals.ApprovedUncontained,
			cfg: func(c *config.Config) { c.NoContainerFallback = config.FallbackFail }, code: 1, msg: "no-container-fallback is 'fail'"},
		{name: "build dep without a wheel", decision: approvals.ApprovedBoxed, requires: `"setuptools>=61"`, code: 1, msg: "build dependency of src-pkg@1.0 has no wheel"},
		{name: "blocked by the proxy", blocked: true, code: 1, msg: "see the hidden versions above"},
		{name: "unsafe trial build", decision: approvals.ApprovedBoxed, verdict: box.Result{Unsafe: true, Discarded: true, Traced: true, Requested: true,
			Findings: []trace.Observation{{Kind: trace.KindConnect, Detail: "203.0.113.1:80"}}}, code: 1, msg: "attempted malicious actions"},
		{name: "unobserved trial build", decision: approvals.ApprovedBoxed, verdict: box.Result{Discarded: true, Requested: true}, code: 1, msg: "not fully observed"},
		{name: "failed trial build", decision: approvals.ApprovedBoxed, verdict: box.Result{ExitCode: 1, Traced: true, Requested: true, Output: "boom"}, code: 1, msg: "trial build failed in the box"},
		{name: "other pip failure", pipOut: "ERROR: Could not install packages due to an OSError", code: 1, msg: ""},
		{name: "unsupported specifier", pipOut: "ERROR: No matching distribution found for src-pkg===1.0\n", code: 2, msg: "pin src-pkg to an exact version"},
		{name: "no sdist satisfies", pipOut: "ERROR: No matching distribution found for src-pkg>=9\n", code: 1, msg: `no source distribution of src-pkg satisfies ">=9"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := newUpstream(t, map[string][]string{"src-pkg": {"1.0"}}, map[string]string{"src-pkg": c.requires})
			cfg := config.Defaults()
			if c.cfg != nil {
				c.cfg(&cfg)
			}
			h := newHarness(t, u, cfg, func(args []string) (string, int) {
				if strings.Contains(strings.Join(args, " "), "setuptools") {
					return "ERROR: No matching distribution found for setuptools>=61\n", 1
				}
				if c.pipOut != "" {
					return c.pipOut, 1
				}
				return needs("src-pkg")(args)
			})
			if c.decision != "" {
				h.approve(t, "src-pkg@1.0", c.decision, u.integrity("src_pkg-1.0.tar.gz"))
			}
			if c.verdict.Requested {
				h.verdict = c.verdict
			}
			if c.blocked {
				h.run.blocked = func() []registry.Blocked {
					return []registry.Blocked{{Package: "src-pkg", Version: "1.0", Reason: "cooldown"}}
				}
			}
			ee := exitOf(t, h.run.resolve([]string{"src-pkg"}))
			if ee.code != c.code || !strings.Contains(ee.msg, c.msg) {
				t.Errorf("exit %d %q, want %d containing %q", ee.code, ee.msg, c.code, c.msg)
			}
		})
	}
}

// Unsafe evidence outranks the earlier yes: the approval flips to denied,
// bound to the same bytes, and is saved for teammates.
func TestSdistLoopUnsafeRevokesApproval(t *testing.T) {
	u := newUpstream(t, map[string][]string{"src-pkg": {"1.0"}}, nil)
	h := newHarness(t, u, config.Defaults(), needs("src-pkg"))
	integ := u.integrity("src_pkg-1.0.tar.gz")
	h.approve(t, "src-pkg@1.0", approvals.ApprovedBoxed, integ)
	h.verdict = box.Result{Unsafe: true, Discarded: true, Traced: true, Requested: true}
	h.run.resolve([]string{"src-pkg"}) //nolint:errcheck
	saved, _ := approvals.Load(h.run.dir)
	if e, _ := saved.Get("src-pkg@1.0"); e.Decision != approvals.Denied || e.Integrity != integ {
		t.Errorf("saved approval = %+v, want denied + bound", e)
	}
}

// A changed sdist (different hash) is not covered by the old approval.
func TestSdistLoopHashChangeReprompts(t *testing.T) {
	u := newUpstream(t, map[string][]string{"src-pkg": {"1.0"}}, nil)
	h := newHarness(t, u, config.Defaults(), needs("src-pkg"))
	h.approve(t, "src-pkg@1.0", approvals.ApprovedBoxed, "sha256:"+strings.Repeat("0", 64))
	if ee := exitOf(t, h.run.resolve([]string{"src-pkg"})); !strings.Contains(ee.msg, "guard approve src-pkg@1.0") || len(h.builds) != 0 {
		t.Errorf("stale approval honored: %q builds=%v", ee.msg, h.builds)
	}
}

func TestSdistLoopUncontainedAllowed(t *testing.T) {
	u := newUpstream(t, map[string][]string{"src-pkg": {"1.0"}}, nil)
	h := newHarness(t, u, config.Defaults(), needs("src-pkg"))
	h.approve(t, "src-pkg@1.0", approvals.ApprovedUncontained, u.integrity("src_pkg-1.0.tar.gz"))
	if err := h.run.resolve([]string{"src-pkg"}); err != nil || len(h.builds) != 0 {
		t.Errorf("err=%v builds=%v (uncontained must skip the box)", err, h.builds)
	}
}

func TestSdistLoopNoRuntime(t *testing.T) {
	u := newUpstream(t, map[string][]string{"src-pkg": {"1.0"}}, nil)
	h := newHarness(t, u, config.Defaults(), needs("src-pkg"))
	h.approve(t, "src-pkg@1.0", approvals.ApprovedBoxed, u.integrity("src_pkg-1.0.tar.gz"))
	boxRuntime = func() string { return "" }
	if ee := exitOf(t, h.run.resolve([]string{"src-pkg"})); !strings.Contains(ee.msg, "--uncontained") {
		t.Errorf("msg = %q", ee.msg)
	}
}

func TestSdistLoopStillUnresolvedAndCap(t *testing.T) {
	u := newUpstream(t, map[string][]string{"src-pkg": {"1.0"}, "other": {"1.0"}}, nil)
	h := newHarness(t, u, config.Defaults(), func([]string) (string, int) {
		return "ERROR: No matching distribution found for src-pkg\n", 1 // even after approval
	})
	h.approve(t, "src-pkg@1.0", approvals.ApprovedBoxed, u.integrity("src_pkg-1.0.tar.gz"))
	if ee := exitOf(t, h.run.resolve([]string{"src-pkg"})); !strings.Contains(ee.msg, "still cannot resolve src-pkg") {
		t.Errorf("msg = %q", ee.msg)
	}

	old := maxSdistRounds
	maxSdistRounds = 2
	defer func() { maxSdistRounds = old }()
	h = newHarness(t, u, config.Defaults(), needs("src-pkg", "other", "never-approved"))
	h.approve(t, "src-pkg@1.0", approvals.ApprovedBoxed, u.integrity("src_pkg-1.0.tar.gz"))
	h.approve(t, "other@1.0", approvals.ApprovedBoxed, u.integrity("other-1.0.tar.gz"))
	if ee := exitOf(t, h.run.resolve([]string{"src-pkg", "other", "never-approved"})); !strings.Contains(ee.msg, "gave up after 2") {
		t.Errorf("msg = %q", ee.msg)
	}
}

func TestPipDownloadArgs(t *testing.T) {
	for _, c := range []struct {
		sub, in, want string
	}{
		{"install", "requests --target /t -U", "requests"},
		{"install", "-r req.txt --requirement=b.txt -c c.txt pkg==1 --pre --no-deps --prefix /p", "-r req.txt --requirement=b.txt -c c.txt pkg==1 --pre --no-deps"},
		{"ci", "--target /t", "-r requirements.txt"},
		{"install", "", ""},
	} {
		if got := strings.Join(pipDownloadArgs(c.sub, strings.Fields(c.in)), " "); got != c.want {
			t.Errorf("pipDownloadArgs(%s, %q) = %q, want %q", c.sub, c.in, got, c.want)
		}
	}
}

// Each admitted sdist is pinned in the guard-owned constraints file, which every
// pip download carries — pip can only pick the version that was trial-built.
func TestSdistLoopConstraintsFile(t *testing.T) {
	u := newUpstream(t, map[string][]string{"src-pkg": {"1.0", "2.0"}, "other": {"3.0"}}, nil)
	h := newHarness(t, u, config.Defaults(), needs("src-pkg", "other"))
	h.approve(t, "src-pkg@2.0", approvals.ApprovedBoxed, u.integrity("src_pkg-2.0.tar.gz"))
	h.approve(t, "other@3.0", approvals.ApprovedBoxed, u.integrity("other-3.0.tar.gz"))
	if err := h.run.resolve([]string{"src-pkg", "other"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(h.run.constraints())
	if string(b) != "src-pkg==2.0\nother==3.0\n" {
		t.Errorf("constraints = %q", b)
	}
	for _, args := range h.pip {
		if !strings.Contains(strings.Join(args, " "), "-c "+h.run.constraints()) {
			t.Errorf("pip call without guard's constraints: %v", args)
		}
	}
}

// pickSdist skips files the host python can't use (or whose requires-python it
// can't evaluate), exactly as pip would.
func TestSdistLoopRequiresPython(t *testing.T) {
	u := newUpstream(t, map[string][]string{"src-pkg": {"1.0", "2.0", "3.0"}}, nil,
		map[string]string{"src-pkg@3.0": ">=3.13", "src-pkg@2.0": ">=3.8", "src-pkg@1.0": ">=3.8"})
	h := newHarness(t, u, config.Defaults(), needs("src-pkg"))
	h.approve(t, "src-pkg@2.0", approvals.ApprovedBoxed, u.integrity("src_pkg-2.0.tar.gz"))
	if err := h.run.resolve([]string{"src-pkg"}); err != nil || len(h.builds) != 1 || h.builds[0] != "src_pkg-2.0.tar.gz" {
		t.Fatalf("err=%v builds=%v, want 2.0 (3.0 needs python >=3.13, host is 3.12)", err, h.builds)
	}

	u = newUpstream(t, map[string][]string{"src-pkg": {"1.0"}}, nil, map[string]string{"src-pkg@1.0": ">=3.8.*"})
	h = newHarness(t, u, config.Defaults(), needs("src-pkg"))
	ee := exitOf(t, h.run.resolve([]string{"src-pkg"}))
	if !strings.Contains(ee.msg, "1 unevaluable") || len(h.builds) != 0 {
		t.Errorf("unevaluable requires-python must skip the file: %q", ee.msg)
	}
	// Unknown host python: every requires-python fails closed.
	h = newHarness(t, newUpstream(t, map[string][]string{"src-pkg": {"1.0"}}, nil, map[string]string{"src-pkg@1.0": ">=3.8"}), config.Defaults(), needs("src-pkg"))
	hostPython = func() string { return "" }
	if ee := exitOf(t, h.run.resolve([]string{"src-pkg"})); !strings.Contains(ee.msg, "unevaluable") {
		t.Errorf("unknown host python: %q", ee.msg)
	}
}

// Before the host install every sdist in the stash must be approved for exactly
// its bytes.
func TestVerifyStash(t *testing.T) {
	stash := t.TempDir()
	appr := &approvals.File{Schema: 1, Packages: map[string]approvals.Entry{}}
	write := func(fn, body string) string {
		if err := os.WriteFile(filepath.Join(stash, fn), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	write("dep-1.0-py3-none-any.whl", "wheel") // wheels are fine
	write(constraintsFile, "my-pkg==1.0\n")    // guard's own file
	appr.Set("my-pkg@1.0", approvals.ApprovedBoxed, "", write("My_Pkg-1.0.tar.gz", "good"))
	if err := verifyStash(stash, appr); err != nil {
		t.Fatalf("approved stash refused: %v", err)
	}
	write("other-2.0.tar.gz", "planted")
	if ee := exitOf(t, verifyStash(stash, appr)); !strings.Contains(ee.msg, "unapproved source distribution in the stash: other-2.0.tar.gz") {
		t.Errorf("planted sdist: %q", ee.msg)
	}
	os.Remove(filepath.Join(stash, "other-2.0.tar.gz"))
	write("My_Pkg-1.0.tar.gz", "swapped bytes")
	if ee := exitOf(t, verifyStash(stash, appr)); !strings.Contains(ee.msg, "My_Pkg-1.0.tar.gz") {
		t.Errorf("hash mismatch: %q", ee.msg)
	}
	appr.Set("my-pkg@1.0", approvals.Denied, "", write("My_Pkg-1.0.tar.gz", "good"))
	if err := verifyStash(stash, appr); err == nil {
		t.Error("a denied sdist passed the stash check")
	}
	appr.Set("my-pkg@1.0", approvals.ApprovedUncontained, "", write("My_Pkg-1.0.tar.gz", "good"))
	write("legacy-1.0.zip", "zip sdist")
	if err := verifyStash(stash, appr); err == nil {
		t.Error("an unapproved .zip sdist passed the stash check")
	}
}

func TestPipPythonRe(t *testing.T) {
	for out, want := range map[string]string{
		"pip 26.1.2 from /home/u/.local/lib/python3.12/site-packages/pip (python 3.12)\n": "3.12",
		"pip 22.3 from /venv/lib/python3.10/site-packages/pip (python 3.10.4)":            "3.10.4",
		"zsh: command not found: pip": "",
	} {
		got := ""
		if m := pipPythonRe.FindStringSubmatch(out); m != nil {
			got = m[1]
		}
		if got != want {
			t.Errorf("%q → %q, want %q", out, got, want)
		}
	}
}
