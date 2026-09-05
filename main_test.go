package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"depguard/internal/advisory"
	"depguard/internal/approvals"
	"depguard/internal/config"
	"depguard/internal/hooks"
	"depguard/internal/lockfile"
	"depguard/internal/registry"
	"depguard/internal/waivers"
)

// TestDominantBlockedReportsTrueCause pins the install-summary fix: when a
// package's versions are hidden for mixed reasons, the summary must surface the
// DOMINANT one, not an arbitrary first entry. (The nodemailer report blamed a
// 3-version cooldown when an OSV advisory had hidden 300 — misdiagnosing the
// cause.)
func TestDominantBlockedReportsTrueCause(t *testing.T) {
	bs := []registry.Blocked{
		{Package: "nodemailer", Version: "9.0.1", Reason: "published 13d ago, cooldown is 14d"},
		{Package: "nodemailer", Version: "6.10.1", Reason: "OSV advisory GHSA-p6gq-j5cr-w38f"},
		{Package: "nodemailer", Version: "5.0.0", Reason: "OSV advisory GHSA-rcmh-qjqh-p98v"},
		{Package: "nodemailer", Version: "4.0.0", Reason: "OSV advisory GHSA-48ww-j4fc-435p"},
	}
	got := dominantBlocked(bs)
	if cat := reasonCategory(got.Reason); cat != "advisory" {
		t.Fatalf("dominant reason = %q (category %q), want an advisory entry", got.Reason, cat)
	}
}

// TestReasonCategoryBuckets covers the category map the summary groups by.
func TestReasonCategoryBuckets(t *testing.T) {
	cases := map[string]string{
		"OSV advisory GHSA-xxxx":                                      "advisory",
		"published 2d ago, cooldown is 14d":                           "cooldown",
		"registry signature present but INVALID (possible tampering)": "signature",
		"no publish timestamp in registry time map":                   "no-timestamp",
	}
	for reason, want := range cases {
		if got := reasonCategory(reason); got != want {
			t.Errorf("reasonCategory(%q) = %q, want %q", reason, got, want)
		}
	}
}

func npmAvailable() bool { _, err := exec.LookPath("npm"); return err == nil }

// makeScriptPkg lays down node_modules/<name> with a marker-writing postinstall.
func makeScriptPkg(t *testing.T, projectDir, name string) string {
	t.Helper()
	rel := filepath.Join("node_modules", name)
	pdir := filepath.Join(projectDir, rel)
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "package.json"),
		[]byte(`{"name":"`+name+`","version":"1.0.0","scripts":{"postinstall":"node mark.js"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "mark.js"),
		[]byte(`require('fs').writeFileSync('marker.txt','ran');`), 0o644); err != nil {
		t.Fatal(err)
	}
	return rel
}

// TestRunApprovedNoRuntimeBoxedSkips is the fail-closed guarantee: an
// approved-BOXED script with no container runtime must be SKIPPED, never run
// bare.
func TestRunApprovedNoRuntimeBoxedSkips(t *testing.T) {
	dir := t.TempDir()
	rel := makeScriptPkg(t, dir, "boxedpkg")
	appr, _ := approvals.Load(dir)

	if err := runApproved("boxedpkg@1.0.0", dir, rel, approvals.ApprovedBoxed, "", "", false, config.Config{}, appr); err != nil {
		t.Fatalf("runApproved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, rel, "marker.txt")); !os.IsNotExist(err) {
		t.Errorf("approved-boxed script RAN with no runtime — must be skipped (fail closed)")
	}
}

// TestRunApprovedNoRuntimeUncontainedRuns: only an EXPLICIT approved-uncontained
// decision runs bare when there's no runtime.
func TestRunApprovedNoRuntimeUncontainedRuns(t *testing.T) {
	if !npmAvailable() {
		t.Skip("npm not on PATH")
	}
	dir := t.TempDir()
	rel := makeScriptPkg(t, dir, "uncpkg")
	appr, _ := approvals.Load(dir)

	if err := runApproved("uncpkg@1.0.0", dir, rel, approvals.ApprovedUncontained, "", "", false, config.Config{}, appr); err != nil {
		t.Fatalf("runApproved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, rel, "marker.txt")); err != nil {
		t.Errorf("approved-uncontained script did not run: %v", err)
	}
}

// TestGatherCheckSurfacesDegraded is the regression for the silent-swallow bug:
// when a registry fetch fails, gatherCheck must REPORT it in Degraded (a green
// result that hides an outage was the bug) while staying fail-open (OK true).
func TestGatherCheckSurfacesDegraded(t *testing.T) {
	dir := t.TempDir()
	// One package; empty resolved + present integrity so off-registry/unhashed
	// don't fire — only the freshness fetch failure remains to surface.
	lock := `{"lockfileVersion":3,"packages":{"node_modules/leftpad":{"version":"1.0.0","integrity":"sha512-x"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	// A loopback address with nothing listening: advisory is skipped (loopback),
	// and the freshness fetch is refused instantly (bind then close to guarantee
	// the port is dead).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()

	cfg := config.Config{Registry: "http://" + dead, Cooldown: 14 * 24 * time.Hour}
	res, err := gatherCheck(dir, cfg, true) // all=true: skip the git-diff scope
	if err != nil {
		t.Fatalf("gatherCheck: %v", err)
	}
	if len(res.Degraded) == 0 {
		t.Error("gatherCheck swallowed the registry fetch failure (Degraded empty) — a green result would hide the outage")
	}
	if !res.OK {
		t.Errorf("expected fail-open OK=true (no findings), got OK=false: %+v", res)
	}
}

// TestPartitionBySeverity locks the gating split that drives both the --json
// result and the human path: MAL-* and unknown always block, scored hits split
// at the threshold. (Severity classification itself is unit-tested in advisory.)
func TestPartitionBySeverity(t *testing.T) {
	hits := []advisory.Vuln{
		{ID: "MAL-2024-1", Severity: advisory.SevLow},     // malicious -> block
		{ID: "GHSA-crit", Severity: advisory.SevCritical}, // block
		{ID: "GHSA-high", Severity: advisory.SevHigh},     // block (at threshold)
		{ID: "GHSA-mod", Severity: advisory.SevModerate},  // warn
		{ID: "GHSA-low", Severity: advisory.SevLow},       // warn
		{ID: "GHSA-unk", Severity: advisory.SevUnknown},   // unknown -> block
	}
	blockers, warns := partitionBySeverity(hits, advisory.SevHigh)
	if len(blockers) != 4 {
		t.Errorf("blockers = %d, want 4 (MAL, crit, high, unknown)", len(blockers))
	}
	if len(warns) != 2 {
		t.Errorf("warnings = %d, want 2 (moderate, low)", len(warns))
	}
}

// TestCheckableDep pins which lockfile shapes the integrity gates apply to.
// The bug: pnpm records no tarball URL, so gating on Resolved alone skipped
// every pnpm entry — while npm file:/link: deps must STILL be exempt.
func TestCheckableDep(t *testing.T) {
	cases := []struct {
		name string
		p    lockfile.Pkg
		want bool
	}{
		{"npm registry tarball", lockfile.Pkg{Resolved: "https://registry.npmjs.org/a/-/a-1.tgz"}, true},
		{"npm link dep", lockfile.Pkg{Resolved: "../local"}, false},
		{"npm file dep", lockfile.Pkg{Resolved: "file:../local"}, false},
		{"git dep", lockfile.Pkg{Resolved: "git+ssh://git@github.com/a/b.git#deadbeef"}, false},
		{"npm entry with no resolved", lockfile.Pkg{}, false},
		{"pnpm registry entry (no URL)", lockfile.Pkg{FromRegistry: true}, true},
		{"pnpm entry with foreign tarball", lockfile.Pkg{FromRegistry: true, Resolved: "https://evil.example/x.tgz"}, true},
	}
	for _, c := range cases {
		if got := checkableDep(c.p); got != c.want {
			t.Errorf("%s: checkableDep = %v, want %v", c.name, got, c.want)
		}
	}
}

// End-to-end over the real check loop: a pnpm lockfile with a missing hash and
// a foreign tarball must both gate; the same run must not invent findings for
// a well-formed entry.
func TestCheckLockfileIntegrityCoversPnpm(t *testing.T) {
	dir := t.TempDir()
	lock := `lockfileVersion: '6.0'

packages:

  /good@1.0.0:
    resolution: {integrity: sha512-good}

  /nohash@1.0.0:
    resolution: {}

  /foreign@1.0.0:
    resolution: {integrity: sha512-x, tarball: https://evil.example/foreign.tgz}
`
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	wf, err := waivers.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Registry: "https://registry.npmjs.org"}
	err = checkLockfileIntegrity(worktreeSnapshot(dir), cfg, wf, true)
	if err == nil {
		t.Fatal("expected an integrity failure for the unhashed + off-registry pnpm entries")
	}
	if !strings.Contains(err.Error(), "1 off-registry") || !strings.Contains(err.Error(), "1 unhashed") {
		t.Errorf("error = %q, want exactly 1 off-registry and 1 unhashed", err)
	}
}

// An npm lockfile of link:/file: deps carries no hashes by design — the loop
// must not flag them.
func TestCheckLockfileIntegrityIgnoresLinkDeps(t *testing.T) {
	dir := t.TempDir()
	lock := `{"lockfileVersion":3,"packages":{
	  "":{"name":"root"},
	  "node_modules/local":{"version":"1.0.0","resolved":"../local","link":true},
	  "node_modules/tar":{"version":"2.0.0","resolved":"file:../tar.tgz"}
	}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	wf, err := waivers.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkLockfileIntegrity(worktreeSnapshot(dir), config.Config{Registry: "https://registry.npmjs.org"}, wf, true); err != nil {
		t.Errorf("link/file deps must not gate: %v", err)
	}
}

// protectionVerdict is the F4 decision core: 'guard status' may only claim
// "protected" when policy loads, a hook carries the CURRENT managed shim, AND
// guard is on PATH — a stale/foreign hook or a missing binary is degraded, with
// a specific reason.
func TestProtectionVerdict(t *testing.T) {
	current := hooks.InstalledState{PreCommit: true, PreCommitCurrent: true}
	stale := hooks.InstalledState{PreCommit: true} // present, no current marker
	cases := []struct {
		name        string
		st          hooks.InstalledState
		guardOnPath bool
		policyOK    bool
		wantOK      bool
		wantSubstr  string
	}{
		{"current marker + guard present", current, true, true, true, "protected"},
		{"no hook at all", hooks.InstalledState{}, true, true, false, "run 'guard init'"},
		{"stale/foreign hook", stale, true, true, false, "not depguard's current shim"},
		{"guard missing", current, false, true, false, "not on PATH"},
		{"invalid policy", current, true, false, false, "policy invalid"},
		// Present, current, but chained after a foreign `exit`: git runs the
		// file and never reaches depguard's block — must NOT read as protected.
		{"unreachable block", hooks.InstalledState{PreCommit: true, PreCommitCurrent: true, PreCommitUnreachable: true}, true, true, false, "UNREACHABLE"},
	}
	for _, c := range cases {
		ok, msg := protectionVerdict(c.st, c.guardOnPath, c.policyOK)
		if ok != c.wantOK {
			t.Errorf("%s: protected = %v, want %v (%q)", c.name, ok, c.wantOK, msg)
		}
		if !strings.Contains(msg, c.wantSubstr) {
			t.Errorf("%s: message %q lacks %q", c.name, msg, c.wantSubstr)
		}
	}
}

// ─── policy enforcement at run time (no-container-fallback) ──────────────────

// no-container-fallback: fail must be enforced at every RUN, not only when the
// approval was recorded. An approved-uncontained entry committed by a teammate
// on a Docker-less machine otherwise kept running bare in a repo that had since
// tightened the policy.
func TestUncontainedAllowed(t *testing.T) {
	if !uncontainedAllowed(config.Config{NoContainerFallback: config.FallbackWarnApprove}) {
		t.Error("warn-approve must permit an uncontained run")
	}
	if uncontainedAllowed(config.Config{NoContainerFallback: config.FallbackFail}) {
		t.Error("policy 'fail' must NOT permit an uncontained run")
	}
}

func TestRunApprovedUncontainedBlockedByPolicy(t *testing.T) {
	if !npmAvailable() {
		t.Skip("npm not on PATH")
	}
	dir := t.TempDir()
	rel := makeScriptPkg(t, dir, "failpkg")
	appr, _ := approvals.Load(dir)
	cfg := config.Config{NoContainerFallback: config.FallbackFail}

	if err := runApproved("failpkg@1.0.0", dir, rel, approvals.ApprovedUncontained, "", "", false, cfg, appr); err != nil {
		t.Fatalf("runApproved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, rel, "marker.txt")); !os.IsNotExist(err) {
		t.Error("an approved-uncontained script RAN under no-container-fallback: fail")
	}
}

// ─── install gate precedence (gates run before scripts) ──────────────────────

// installGates runs all three gates so each prints, then hands the exit code to
// the first one that tripped — the same precedence cmdCheck uses.
func TestFirstErrPrecedence(t *testing.T) {
	adv, integ, fresh := errors.New("advisory"), errors.New("integrity"), errors.New("freshness")
	cases := []struct {
		in   []error
		want error
	}{
		{[]error{adv, integ, fresh}, adv},
		{[]error{nil, integ, fresh}, integ},
		{[]error{nil, nil, fresh}, fresh},
		{[]error{nil, nil, nil}, nil},
	}
	for _, c := range cases {
		if got := firstErr(c.in...); got != c.want {
			t.Errorf("firstErr(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// ─── what `allow:` may and may not bypass ────────────────────────────────────

// `allow:` is a COOLDOWN escape hatch. It used to also silence the integrity
// gates, which is authority the generated .guardrc never claimed: an allowed
// package with no hash went unreported. Only internal-scopes — names DECLARED to
// live on a private registry — are exempt, and only from the host check.
func TestIntegrityGateAllowVsInternalScopes(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{
	  "":{"name":"root"},
	  "node_modules/@yourco/allowed":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a.tgz"},
	  "node_modules/@yourco/private":{"version":"2.0.0","resolved":"https://npm.yourco.internal/p.tgz","integrity":"sha512-p"},
	  "node_modules/@other/allowed-offreg":{"version":"3.0.0","resolved":"https://evil.example/o.tgz","integrity":"sha512-o"}
	}}`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	wf, err := waivers.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Registry:       "https://registry.npmjs.org",
		Allow:          []string{"@yourco/*", "@other/*"},
		InternalScopes: []string{"@yourco/private"},
	}
	err = checkLockfileIntegrity(worktreeSnapshot(dir), cfg, wf, true)
	if err == nil {
		t.Fatal("expected a gate: an allowed package with no hash and an allowed off-registry tarball")
	}
	// @other/allowed-offreg: allowed but NOT internal → its foreign host gates.
	if !strings.Contains(err.Error(), "1 off-registry") {
		t.Errorf("error = %q, want exactly 1 off-registry (@yourco/private is internal-scoped and exempt)", err)
	}
	// @yourco/allowed has no integrity → gates despite being allowed.
	if !strings.Contains(err.Error(), "1 unhashed") {
		t.Errorf("error = %q, want exactly 1 unhashed (allow must not silence the hash check)", err)
	}
}

// A lockfile that records one name@version at two paths with different tarballs
// contradicts itself — not waivable, because there is no single truth to waive.
func TestIntegrityGateFlagsConflictingEntries(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{
	  "":{"name":"root"},
	  "node_modules/tar":{"version":"6.0.0","resolved":"https://registry.npmjs.org/tar.tgz","integrity":"sha512-a"},
	  "node_modules/x/node_modules/tar":{"version":"6.0.0","resolved":"https://registry.npmjs.org/tar.tgz","integrity":"sha512-DIFFERENT"}
	}}`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	wf, err := waivers.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = checkLockfileIntegrity(worktreeSnapshot(dir), config.Config{Registry: "https://registry.npmjs.org"}, wf, true)
	if err == nil || !strings.Contains(err.Error(), "1 conflicting") {
		t.Fatalf("error = %v, want 1 conflicting entry reported", err)
	}
}

// ─── pre-push ref plumbing ───────────────────────────────────────────────────

// git feeds the pre-push hook "<local ref> <local sha> <remote ref> <remote sha>".
// A deleted ref (all-zero LOCAL sha) transmits nothing and must be dropped;
// an all-zero REMOTE sha means a new branch and must be kept.
func TestParsePushRefs(t *testing.T) {
	const zero = "0000000000000000000000000000000000000000"
	a := strings.Repeat("a", 40)
	b := strings.Repeat("b", 40)
	c := strings.Repeat("c", 40)
	d := strings.Repeat("d", 40)
	in := "refs/heads/main " + a + " refs/heads/main " + b + "\n" +
		"refs/heads/new " + c + " refs/heads/new " + zero + "\n" +
		"(delete) " + zero + " refs/heads/gone " + d + "\n" +
		"garbage\n"
	got := parsePushRefs(strings.NewReader(in))
	if len(got) != 2 {
		t.Fatalf("parsed %d refs, want 2 (the deletion and the garbage line drop): %+v", len(got), got)
	}
	if got[0].localSHA != a || got[0].remoteSHA != b {
		t.Errorf("ref[0] = %+v", got[0])
	}
	if got[1].localSHA != c || !isZeroSHA(got[1].remoteSHA) {
		t.Errorf("ref[1] = %+v, want the new-branch shape", got[1])
	}
}

// The rev selectors must cover exactly the commits being transmitted.
func TestOutgoingRevArgs(t *testing.T) {
	const zero = "0000000000000000000000000000000000000000"
	got := outgoingRevArgs([]pushRef{
		{localSHA: "local1", remoteSHA: "remote1"},
		{localSHA: "local2", remoteSHA: zero},
	}, "")
	// No remote name → exclude NOTHING and scan the whole branch. Excluding every
	// remote's commits would be the unsafe guess; a full scan is only slower.
	want := [][]string{{"remote1..local1"}, {"local2", "--not", "--remotes"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outgoingRevArgs = %v, want %v", got, want)
	}
}

// pushBaseRef picks what the freshness check compares AGAINST: the remote's
// state. Stub git so every branch is exercised without building repositories.
func TestPushBaseRef(t *testing.T) {
	const zero = "0000000000000000000000000000000000000000"
	orig := gitOutput
	defer func() { gitOutput = orig }()

	// Existing remote branch → the remote sha itself.
	if base, full := pushBaseRef("d", pushRef{localSHA: "L", remoteSHA: "R"}, ""); base != "R" || full {
		t.Errorf("existing branch: base=%q full=%v, want (R,false)", base, full)
	}

	// New branch → the parent of the OLDEST outgoing commit (rev-list is
	// newest-first, so that's the last line).
	gitOutput = func(dir string, args ...string) (string, error) {
		switch args[0] {
		case "rev-list":
			return "c3\nc2\nc1\n", nil
		case "rev-parse":
			return "parent\n", nil
		}
		return "", nil
	}
	if base, full := pushBaseRef("d", pushRef{localSHA: "L", remoteSHA: zero}, ""); base != "c1^" || full {
		t.Errorf("new branch: base=%q full=%v, want (c1^,false)", base, full)
	}

	// New branch with nothing outgoing → nothing to check.
	gitOutput = func(dir string, args ...string) (string, error) { return "", nil }
	if base, full := pushBaseRef("d", pushRef{localSHA: "L", remoteSHA: zero}, ""); base != "" || full {
		t.Errorf("nothing outgoing: base=%q full=%v, want (\"\",false)", base, full)
	}

	// Root commit (no parent) → no base at all, so the whole tree is new.
	gitOutput = func(dir string, args ...string) (string, error) {
		if args[0] == "rev-list" {
			return "root\n", nil
		}
		return "", errors.New("unknown revision")
	}
	if base, full := pushBaseRef("d", pushRef{localSHA: "L", remoteSHA: zero}, ""); base != "" || !full {
		t.Errorf("root commit: base=%q full=%v, want (\"\",true)", base, full)
	}
}

// refLockfile reads package-lock.json at an arbitrary ref without checking it
// out — the pre-push check needs the pushed snapshot, not the working tree.
func TestRefLockfile(t *testing.T) {
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v unavailable: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"r"},"node_modules/ms":{"version":"2.0.0","resolved":"https://registry.npmjs.org/ms.tgz","integrity":"sha512-a"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "package-lock.json")
	git("commit", "-qm", "lock")

	// The working tree moves on; the committed ref must not.
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"":{"name":"r"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, ok := refLockfile(dir, "HEAD")
	if !ok || len(pkgs) != 1 || pkgs[0].Key() != "ms@2.0.0" {
		t.Fatalf("refLockfile(HEAD) = (%+v, %v), want the committed ms@2.0.0", pkgs, ok)
	}
	if _, ok := refLockfile(dir, "does-not-exist"); ok {
		t.Error("refLockfile reported success for a missing ref")
	}
}

// newVersions is the "what does this change ADD" primitive both the HEAD diff
// and the pre-push diff use.
func TestNewVersions(t *testing.T) {
	base := []lockfile.Pkg{{Name: "ms", Version: "2.0.0"}, {Name: "tar", Version: "6.0.0"}}
	curr := []lockfile.Pkg{{Name: "ms", Version: "2.0.0"}, {Name: "tar", Version: "6.0.1"}, {Name: "new", Version: "1.0.0"}}
	got := newVersions(curr, base)
	if len(got) != 2 || got[0].Key() != "tar@6.0.1" || got[1].Key() != "new@1.0.0" {
		t.Fatalf("newVersions = %+v, want tar@6.0.1 and new@1.0.0 (a bumped version counts as new)", got)
	}
	if n := len(newVersions(base, base)); n != 0 {
		t.Errorf("newVersions(same) returned %d, want 0", n)
	}
}

// The end-to-end half of the dedupe-bypass fix: a crafted lockfile that pairs
// the real (evil) record with an information-EMPTY duplicate at a path that
// sorts FIRST must still gate. Before the merge, the empty record won the
// collapse, the survivor had no URL and no hash, checkableDep went false, and
// guard printed "lockfile integrity ok".
func TestIntegrityGateNotDisarmedByEmptyDuplicate(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{
	  "":{"name":"root"},
	  "node_modules/a/node_modules/tar":{"version":"6.0.0"},
	  "node_modules/tar":{"version":"6.0.0","resolved":"https://evil.example/tar.tgz","integrity":"sha512-evil"}
	}}`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	wf, err := waivers.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Registry: "https://registry.npmjs.org"}
	err = checkLockfileIntegrity(worktreeSnapshot(dir), cfg, wf, true)
	if err == nil {
		t.Fatal("integrity gate passed a tarball pointing off-registry — an empty duplicate disarmed it")
	}
	if !strings.Contains(err.Error(), "1 off-registry") {
		t.Errorf("error = %q, want the off-registry host reported", err)
	}
}

// A sha off the hook's stdin is concatenated into git ARGUMENTS, so it has to
// look like an object id. "--output=/tmp/x" is a perfectly good string until git
// reads it as a flag.
func TestParsePushRefsRejectsNonSHA(t *testing.T) {
	const good = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const zero = "0000000000000000000000000000000000000000"
	in := "refs/heads/a --output=/tmp/pwned refs/heads/a " + good + "\n" +
		"refs/heads/b " + good + " refs/heads/b --upload-pack=evil\n" +
		"refs/heads/c " + good + " refs/heads/c " + zero + "\n" +
		"refs/heads/d " + good + " refs/heads/d " + good + "\n"
	got := parsePushRefs(strings.NewReader(in))
	if len(got) != 2 {
		t.Fatalf("parsed %d refs, want 2 (both --flag shas rejected): %+v", len(got), got)
	}
	for _, r := range got {
		if strings.HasPrefix(r.localSHA, "-") || strings.HasPrefix(r.remoteSHA, "-") {
			t.Errorf("a flag-shaped sha survived: %+v", r)
		}
	}
	// sha256 object ids (64 hex) must still be accepted.
	long := strings.Repeat("a", 64)
	if n := len(parsePushRefs(strings.NewReader("refs/heads/x " + long + " refs/heads/x " + long + "\n"))); n != 1 {
		t.Errorf("sha256 ref lines parsed = %d, want 1", n)
	}
}

// A push can carry several refs. Checking only the first let a second branch
// smuggle a too-young version through the gate. Uses a real repo: the snapshots
// come from lockfile.InstalledAt, which shells out to git itself.
func TestPushNewVersionsUnionsAllRefs(t *testing.T) {
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Skipf("git %v unavailable: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	lock := func(names ...string) {
		t.Helper()
		body := `{"lockfileVersion":3,"packages":{"":{"name":"r"}`
		for _, n := range names {
			body += `,"node_modules/` + n + `":{"version":"1.0.0","resolved":"https://r/x.tgz","integrity":"sha512-a"}`
		}
		body += "}}"
		if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		git("add", "package-lock.json")
	}
	git("init", "-q")
	lock("old")
	git("commit", "-qm", "base")
	base := git("rev-parse", "HEAD")

	// Two branches off the same base, each adding a different package.
	git("checkout", "-qb", "a")
	lock("old", "fromA")
	git("commit", "-qm", "a")
	shaA := git("rev-parse", "HEAD")

	git("checkout", "-q", base)
	git("checkout", "-qb", "b")
	lock("old", "fromB")
	git("commit", "-qm", "b")
	shaB := git("rev-parse", "HEAD")

	pkgs, scope, ok := pushNewVersions(dir, []pushRef{
		{localSHA: shaA, remoteSHA: base},
		{localSHA: shaB, remoteSHA: base},
	}, "")
	if !ok {
		t.Fatal("pushNewVersions reported no npm snapshot, want ok")
	}
	var keys []string
	for _, p := range pkgs {
		keys = append(keys, p.Name)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, []string{"fromA", "fromB"}) {
		t.Fatalf("pushNewVersions = %v, want both refs' additions (fromA, fromB)", keys)
	}
	if !strings.Contains(scope, "this push adds") {
		t.Errorf("scope = %q", scope)
	}
}

// The --hook= phase must actually reach cmdCheck's logic, and an unknown phase
// must degrade to the plain check rather than breaking the hook.
func TestParseCheckArgsHookPhase(t *testing.T) {
	if _, _, _, _, hook, _ := parseCheckArgs([]string{"--quiet", "--confirm", "--hook=pre-push"}); hook != "pre-push" {
		t.Errorf("hook = %q, want pre-push", hook)
	}
	if _, _, _, _, hook, _ := parseCheckArgs([]string{"--hook=pre-commit"}); hook != "pre-commit" {
		t.Errorf("hook = %q, want pre-commit", hook)
	}
	if _, _, _, _, hook, _ := parseCheckArgs([]string{"--hook=post-merge"}); hook != "" {
		t.Errorf("unknown phase = %q, want it ignored", hook)
	}
	quiet, all, jsonOut, confirm, _, _ := parseCheckArgs([]string{"--quiet", "--all", "--json", "--confirm"})
	if !quiet || !all || !jsonOut || !confirm {
		t.Error("the existing flags regressed")
	}
}

// gatherCheck (the --json / MCP path) must apply the SAME allow/internal-scopes
// narrowing as the prose path — it had its own copy of the loop, and only the
// prose one was under test.
func TestGatherCheckAllowVsInternalScopes(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{
	  "":{"name":"root"},
	  "node_modules/@yourco/allowed":{"version":"1.0.0","resolved":"http://127.0.0.1:1/a.tgz"},
	  "node_modules/@yourco/private":{"version":"2.0.0","resolved":"https://npm.yourco.internal/p.tgz","integrity":"sha512-p"},
	  "node_modules/@other/allowed-offreg":{"version":"3.0.0","resolved":"https://evil.example/o.tgz","integrity":"sha512-o"}
	}}`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	// Loopback registry so the advisory lookup is skipped (those versions aren't
	// in OSV's public namespace anyway).
	cfg := config.Config{
		Registry:       "http://127.0.0.1:1",
		Allow:          []string{"@yourco/*", "@other/*"},
		InternalScopes: []string{"@yourco/private"},
	}
	res, err := gatherCheck(dir, cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.OffRegistry, []string{"@other/allowed-offreg@3.0.0"}) {
		t.Errorf("OffRegistry = %v, want only the allowed-but-not-internal package", res.OffRegistry)
	}
	if !reflect.DeepEqual(res.Unhashed, []string{"@yourco/allowed@1.0.0"}) {
		t.Errorf("Unhashed = %v, want the allowed package with no hash (allow must not silence it)", res.Unhashed)
	}
	if res.OK {
		t.Error("OK = true despite off-registry + unhashed findings")
	}
}

// `guard approve` binds the decision to the tarball in the lockfile. Tested via
// the extracted lookup (cmdApprove itself reads os.Getwd and writes files).
func TestLockedIntegrity(t *testing.T) {
	dir := t.TempDir()
	lock := `{"lockfileVersion":3,"packages":{
	  "":{"name":"root"},
	  "node_modules/tar":{"version":"6.0.0","resolved":"https://r/tar.tgz","integrity":"sha512-tar"}
	}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := lockedIntegrity(dir, "tar@6.0.0"); got != "sha512-tar" {
		t.Errorf("lockedIntegrity = %q, want sha512-tar", got)
	}
	// Approving ahead of an install must stay possible — the entry is just not
	// bound to any bytes yet.
	if got := lockedIntegrity(dir, "notinstalled@1.0.0"); got != "" {
		t.Errorf("lockedIntegrity(absent) = %q, want empty", got)
	}
	if got := lockedIntegrity(t.TempDir(), "tar@6.0.0"); got != "" {
		t.Errorf("lockedIntegrity(no lockfile) = %q, want empty", got)
	}
}

// A pnpm/yarn repo has no package-lock.json at any pushed commit. The pre-push
// scope must then fall BACK to the working-tree view, not check an empty set —
// otherwise switching package manager silently disables the cooldown gate on push.
func TestPushNewVersionsNoNpmSnapshot(t *testing.T) {
	orig := gitOutput
	defer func() { gitOutput = orig }()
	gitOutput = func(dir string, args ...string) (string, error) {
		return "", errors.New("path does not exist in HEAD")
	}
	pkgs, _, ok := pushNewVersions("d", []pushRef{{localSHA: "L1", remoteSHA: "R1"}}, "")
	if ok || len(pkgs) != 0 {
		t.Fatalf("pushNewVersions = (%v, ok=%v), want no snapshot so the caller falls back", pkgs, ok)
	}
}

// A tree-wide registry outage produces one warning PER PACKAGE. The hooks run
// with --quiet and the warning is printed regardless (green-but-incomplete must
// never look green), so the volume has to be handled here instead: one line per
// check, naming the count and an example.
func TestCollapse(t *testing.T) {
	if err := collapse(nil); err != nil {
		t.Errorf("collapse(nil) = %v, want nil", err)
	}
	if err := collapse([]string{"tar@6.0.0: timeout"}); err == nil || err.Error() != "tar@6.0.0: timeout" {
		t.Errorf("collapse(one) = %v, want the message verbatim", err)
	}
	err := collapse([]string{"a@1: timeout", "b@2: timeout", "c@3: timeout"})
	if err == nil {
		t.Fatal("collapse(many) = nil")
	}
	if !strings.Contains(err.Error(), "3 package(s)") {
		t.Errorf("collapse(many) = %q, want the COUNT so the scale is visible", err)
	}
	if !strings.Contains(err.Error(), "a@1: timeout") {
		t.Errorf("collapse(many) = %q, want an example cause", err)
	}
}

// A bare "0" is not a git object id. isZeroSHA is what decides "this side has
// nothing", so accepting junk there would drop or mis-scope a real ref.
func TestIsZeroSHALength(t *testing.T) {
	if isZeroSHA("0") || isZeroSHA("") || isZeroSHA(strings.Repeat("0", 39)) {
		t.Error("a short all-zero string was accepted as git's zero sha")
	}
	if !isZeroSHA(strings.Repeat("0", 40)) || !isZeroSHA(strings.Repeat("0", 64)) {
		t.Error("a real all-zero object id was rejected")
	}
}

// ─── round-5 pins ────────────────────────────────────────────────────────────

// The gates must judge what git is about to RECORD. Before this, a lockfile
// staged with an off-registry tarball passed every gate as long as the working
// tree copy was clean — `git add` then edit back, and the commit sails through.
func TestIntegrityGateUsesStagedSnapshot(t *testing.T) {
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v unavailable: %v\n%s", args, err, out)
		}
	}
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	clean := `{"lockfileVersion":3,"packages":{"":{"name":"r"},"node_modules/ms":{"version":"2.0.0","resolved":"https://registry.npmjs.org/ms.tgz","integrity":"sha512-a"}}}`
	evil := `{"lockfileVersion":3,"packages":{"":{"name":"r"},"node_modules/ms":{"version":"2.0.0","resolved":"https://evil.example/ms.tgz","integrity":"sha512-a"}}}`
	git("init", "-q")
	write(evil)
	git("add", "package-lock.json")
	write(clean) // working tree now looks innocent; the INDEX does not

	wf, err := waivers.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Registry: "https://registry.npmjs.org"}
	if err := checkLockfileIntegrity(worktreeSnapshot(dir), cfg, wf, true); err != nil {
		t.Fatalf("working tree is clean, should not gate: %v", err)
	}
	staged := hookSnapshot(dir, "pre-commit", nil)
	if err := checkLockfileIntegrity(staged, cfg, wf, true); err == nil {
		t.Fatal("the STAGED lockfile resolves off-registry and was not gated")
	}
}

// hookSnapshot picks the state each phase actually acts on.
func TestHookSnapshot(t *testing.T) {
	if got := hookSnapshot("d", "pre-commit", nil); !reflect.DeepEqual(got.refs, []string{":"}) {
		t.Errorf("pre-commit refs = %v, want the index", got.refs)
	}
	refs := []pushRef{{localSHA: "aaa"}, {localSHA: "bbb"}}
	if got := hookSnapshot("d", "pre-push", refs); !reflect.DeepEqual(got.refs, []string{"aaa", "bbb"}) {
		t.Errorf("pre-push refs = %v, want every pushed sha", got.refs)
	}
	// No phase, or pre-push run by hand with no refs, falls back to the tree.
	for _, c := range []struct {
		hook string
		refs []pushRef
	}{{"", nil}, {"pre-push", nil}} {
		if got := hookSnapshot("d", c.hook, c.refs); len(got.refs) != 0 {
			t.Errorf("hook %q refs = %v, want the working tree", c.hook, got.refs)
		}
	}
}

// A lockfile that EXISTS at the ref but cannot be parsed is not "no lockfile":
// the working-tree path fails closed on a parse error and the snapshot path must
// too, or an unparseable staged lockfile passes every gate.
func TestSnapshotPkgsFailsClosedOnParseError(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\npackages:\n  registry.example/some-future-shape:\n    resolution: {integrity: sha512-x}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "pnpm-lock.yaml")
	_, _, err := snapshot{dir: dir, refs: []string{":"}}.pkgs()
	if err == nil || os.IsNotExist(err) {
		t.Fatalf("staged unparseable lockfile: err = %v, want a parse error (not nil, not ErrNotExist)", err)
	}
}

// "Outgoing" is relative to the DESTINATION. --remotes excludes commits present
// on ANY remote, so a branch already pushed to a fork looked like nothing-new
// when first pushed to the real upstream — the exact case the gate exists for.
func TestOutgoingRevArgsScopedToRemote(t *testing.T) {
	const zero = "0000000000000000000000000000000000000000"
	refs := []pushRef{{localSHA: "local1", remoteSHA: zero}}
	if got := outgoingRevArgs(refs, "origin"); !reflect.DeepEqual(got, [][]string{{"local1", "--not", "--remotes=origin"}}) {
		t.Errorf("with a remote: %v, want it scoped to origin", got)
	}
	// No remote name (a pre-1.2.1 v3 shim, a URL push): keep the all-remotes
	// exclusion rather than a full-history scan, which would turn every not-yet
	// re-initialised repo's next push into a wall of historic findings.
	if got := outgoingRevArgs(refs, ""); !reflect.DeepEqual(got, [][]string{{"local1", "--not", "--remotes"}}) {
		t.Errorf("without a remote: %v, want the all-remotes fallback", got)
	}
	// An existing remote branch is already an exact range; the remote name adds
	// nothing there.
	known := []pushRef{{localSHA: "l", remoteSHA: "r"}}
	if got := outgoingRevArgs(known, "origin"); !reflect.DeepEqual(got, [][]string{{"r..l"}}) {
		t.Errorf("known branch: %v, want r..l", got)
	}
}

// The remote name reaches git's argv, so it is validated, not trusted.
func TestParseCheckArgsRemote(t *testing.T) {
	if _, _, _, _, _, r := parseCheckArgs([]string{"--remote=origin"}); r != "origin" {
		t.Errorf("remote = %q, want origin", r)
	}
	if _, _, _, _, _, r := parseCheckArgs([]string{"--remote=my/fork"}); r != "my/fork" {
		t.Errorf("slash-named remote (legal, glob-inert) = %q, want my/fork", r)
	}
	if _, _, _, _, _, r := parseCheckArgs([]string{"--remote=my-fork.2_x"}); r != "my-fork.2_x" {
		t.Errorf("remote = %q, want the punctuated name accepted", r)
	}
	for _, bad := range []string{"--remote=", "--remote=--upload-pack=evil", "--remote=a b", "--remote=$(x)"} {
		if _, _, _, _, _, r := parseCheckArgs([]string{bad}); r != "" {
			t.Errorf("%s: remote = %q, want it ignored", bad, r)
		}
	}
}

// Every return path out of gatherCheck must apply on-check-error. The "no
// lockfile" early return decided on secrets alone, so a repo with no deps could
// report ok:true after a check that never ran.
func TestFinalOKHonoursOnCheckError(t *testing.T) {
	degraded := CheckResult{Degraded: []string{"advisory check skipped"}}
	if !finalOK(degraded, config.Config{}) {
		t.Error("warn mode: a degraded-but-finding-free result should stay ok")
	}
	if finalOK(degraded, config.Config{OnCheckErrorFail: true}) {
		t.Error("fail mode: a check that could not complete must not report ok")
	}
	// Findings gate under either policy.
	if finalOK(CheckResult{Unhashed: []string{"a@1"}}, config.Config{}) {
		t.Error("an unhashed finding did not gate")
	}
	if finalOK(CheckResult{provenanceInvalid: 1}, config.Config{}) {
		t.Error("an invalid provenance attestation did not gate")
	}
	if !finalOK(CheckResult{}, config.Config{OnCheckErrorFail: true}) {
		t.Error("a clean, complete result should be ok in fail mode too")
	}
}

// A lockfile entry the parser could not read is a package that escapes every
// check. Under on-check-error: fail that has to gate, not pass quietly.
func TestGatePkgsReportsUnrecognizedEntries(t *testing.T) {
	dir := t.TempDir()
	lock := "lockfileVersion: '6.0'\n\npackages:\n\n" +
		"  /lodash@4.17.21:\n    resolution: {integrity: sha512-abc}\n" +
		"  some-future-shape:\n    resolution: {}\n"
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := worktreeSnapshot(dir)
	pkgs, degraded, err := gatePkgs(snap, config.Config{})
	if err != nil {
		t.Fatalf("gatePkgs: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("pkgs = %+v, want the one entry we could read", pkgs)
	}
	if degraded != nil {
		t.Errorf("warn mode gated: %v", degraded)
	}
	_, degraded, err = gatePkgs(snap, config.Config{OnCheckErrorFail: true})
	if err != nil {
		t.Fatal(err)
	}
	if degraded == nil {
		t.Fatal("on-check-error: fail did not gate on an unreadable lockfile entry")
	}
	if !strings.Contains(degraded.Error(), "lockfile parse") {
		t.Errorf("error = %q, want it to name the lockfile parse", degraded)
	}
	// A lockfile we fully understood reports nothing.
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "package-lock.json"),
		[]byte(`{"lockfileVersion":3,"packages":{"":{"name":"r"},"node_modules/ms":{"version":"2.0.0","integrity":"sha512-a"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, d, err := gatePkgs(worktreeSnapshot(clean), config.Config{OnCheckErrorFail: true}); err != nil || d != nil {
		t.Errorf("a fully-parsed lockfile reported degraded: %v (err %v)", d, err)
	}
}

// ─── round-7 pins ────────────────────────────────────────────────────────────

// pushRepo builds a repo with two branches off a shared base, each committing
// its own package-lock.json body. Returns (dir, base, shaA, shaB).
func pushRepo(t *testing.T, lockA, lockB string) (string, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Skipf("git %v unavailable: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		git("add", "package-lock.json")
	}
	clean := `{"lockfileVersion":3,"packages":{"":{"name":"r"},"node_modules/base":{"version":"1.0.0","resolved":"https://registry.npmjs.org/base.tgz","integrity":"sha512-base"}}}`
	git("init", "-q")
	write(clean)
	git("commit", "-qm", "base")
	base := git("rev-parse", "HEAD")

	git("checkout", "-qb", "a")
	write(lockA)
	git("commit", "-qm", "a")
	shaA := git("rev-parse", "HEAD")

	git("checkout", "-q", base)
	git("checkout", "-qb", "b")
	write(lockB)
	git("commit", "-qm", "b")
	shaB := git("rev-parse", "HEAD")
	return dir, base, shaA, shaB
}

// The integrity gate judges OCCURRENCES, so it must run per ref. Over the union,
// a clean branch A lends its hash to branch B's unhashed occurrence of the same
// name@version and the finding disappears from the push entirely.
func TestIntegrityGateRunsPerRef(t *testing.T) {
	hashed := `{"lockfileVersion":3,"packages":{"":{"name":"r"},"node_modules/ms":{"version":"2.0.0","resolved":"https://registry.npmjs.org/ms.tgz","integrity":"sha512-ms"}}}`
	unhashed := `{"lockfileVersion":3,"packages":{"":{"name":"r"},"node_modules/ms":{"version":"2.0.0","resolved":"https://registry.npmjs.org/ms.tgz"}}}`
	dir, _, shaA, shaB := pushRepo(t, hashed, unhashed)

	wf, err := waivers.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Registry: "https://registry.npmjs.org"}
	snap := hookSnapshot(dir, "pre-push", []pushRef{{localSHA: shaA}, {localSHA: shaB}})

	// The union hides it: branch A's hash covers branch B's occurrence.
	union, _, err := snap.pkgs()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range union {
		if p.Key() == "ms@2.0.0" && p.Integrity == "" {
			t.Fatal("fixture wrong: the union should have borrowed the hash")
		}
	}
	err = checkLockfileIntegrity(snap, cfg, wf, true)
	if err == nil {
		t.Fatal("the unhashed occurrence in the second pushed branch was not reported")
	}
	if !strings.Contains(err.Error(), "1 unhashed") {
		t.Errorf("error = %q, want the unhashed finding", err)
	}
}

// Same for an off-registry tarball in one branch of a multi-ref push.
func TestIntegrityGatePerRefOffRegistry(t *testing.T) {
	clean := `{"lockfileVersion":3,"packages":{"":{"name":"r"},"node_modules/ms":{"version":"2.0.0","resolved":"https://registry.npmjs.org/ms.tgz","integrity":"sha512-ms"}}}`
	evil := `{"lockfileVersion":3,"packages":{"":{"name":"r"},"node_modules/ms":{"version":"2.0.0","resolved":"https://evil.example/ms.tgz","integrity":"sha512-ms"}}}`
	dir, _, shaA, shaB := pushRepo(t, clean, evil)

	wf, err := waivers.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	snap := hookSnapshot(dir, "pre-push", []pushRef{{localSHA: shaA}, {localSHA: shaB}})
	err = checkLockfileIntegrity(snap, config.Config{Registry: "https://registry.npmjs.org"}, wf, true)
	if err == nil {
		t.Fatal("an off-registry tarball in the second pushed branch was not reported")
	}
	if !strings.Contains(err.Error(), "1 off-registry") {
		t.Errorf("error = %q, want the off-registry finding", err)
	}
}

// perRef keeps each ref's set separate and labels it; the union stays available
// for the name@version-only checks.
func TestSnapshotPerRef(t *testing.T) {
	a := `{"lockfileVersion":3,"packages":{"":{"name":"r"},"node_modules/fromA":{"version":"1.0.0","integrity":"sha512-a"}}}`
	b := `{"lockfileVersion":3,"packages":{"":{"name":"r"},"node_modules/fromB":{"version":"1.0.0","integrity":"sha512-b"}}}`
	dir, _, shaA, shaB := pushRepo(t, a, b)
	views, err := hookSnapshot(dir, "pre-push", []pushRef{{localSHA: shaA}, {localSHA: shaB}}).perRef()
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 2 {
		t.Fatalf("perRef returned %d views, want one per ref", len(views))
	}
	if views[0].label != shaA[:8] || views[1].label != shaB[:8] {
		t.Errorf("labels = %q/%q, want the short shas", views[0].label, views[1].label)
	}
	// The working tree collapses to a single labelled view.
	single, err := worktreeSnapshot(dir).perRef()
	if err != nil {
		t.Fatal(err)
	}
	if len(single) != 1 || single[0].label != "working tree" {
		t.Errorf("worktree perRef = %+v, want one 'working tree' view", single)
	}
}

// gatherCheck (--json / MCP) used lockfile.Installed, which DISCARDS the skipped
// count, so a partially-understood lockfile reported a clean result.
func TestGatherCheckRecordsPartialParse(t *testing.T) {
	dir := t.TempDir()
	lock := "lockfileVersion: '6.0'\n\npackages:\n\n" +
		"  /lodash@4.17.21:\n    resolution: {integrity: sha512-abc}\n" +
		"  some-future-shape:\n    resolution: {}\n"
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Registry: "http://127.0.0.1:1"}
	res, err := gatherCheck(dir, cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, d := range res.Degraded {
		if strings.Contains(d, "lockfile parse") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Degraded = %v, want the unrecognized-entry count recorded", res.Degraded)
	}
	// And under on-check-error: fail that must flip ok.
	cfg.OnCheckErrorFail = true
	res, err = gatherCheck(dir, cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Error("ok = true over a partial parse under on-check-error: fail")
	}
}
