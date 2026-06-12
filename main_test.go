package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"depguard/internal/approvals"
	"depguard/internal/config"
)

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
