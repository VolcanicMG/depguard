package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"depguard/internal/advisory"
	"depguard/internal/approvals"
	"depguard/internal/config"
	"depguard/internal/registry"
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
		"OSV advisory GHSA-xxxx":             "advisory",
		"published 2d ago, cooldown is 14d":  "cooldown",
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
