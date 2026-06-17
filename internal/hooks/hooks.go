// Package hooks installs the per-repo trigger points (DESIGN.md §3):
// git pre-commit / pre-push hooks and the optional CI workflow. All of them
// just call the globally installed `guard` binary — the repo holds only tiny
// shims, never the tool itself.
package hooks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// hookScript is the shim written to .git/hooks/. It re-checks the lockfile
// against advisory feeds on every commit/push — that's how a dep that "goes
// bad later" gets caught at your next action instead of by a daemon.
//
// GUARD_SKIP=1 bypasses just this check for one commit/push (e.g. an urgent
// hotfix). Unlike git --no-verify it skips depguard ALONE, leaving any other
// hooks intact. It lives in the shell shim on purpose: CI runs `guard check`
// directly, so no env var a contributor sets can weaken the PR gate.
const hookScript = `#!/bin/sh
# depguard shim — installed by 'guard init'. Calls the global guard binary.
# Bypass ONLY depguard for one commit/push:  GUARD_SKIP=1 git push
# (Unlike git --no-verify, this skips depguard alone — your other hooks still run.
# The bypass lives here in the local hook, NOT in the binary, so it can never
# weaken the CI gate, which calls 'guard check' directly.)
if [ -n "$GUARD_SKIP" ]; then
  echo "depguard: check skipped (GUARD_SKIP set)." >&2
  exit 0
fi
if command -v guard >/dev/null 2>&1; then
  guard check --quiet --confirm || {
    echo "depguard: advisory check failed (or warnings not accepted). Run 'guard check' for details." >&2
    echo "depguard: bypass once with GUARD_SKIP=1 (depguard only) or git --no-verify (all hooks)." >&2
    exit 1
  }
fi
`

// ciWorkflow is the optional PR gate: same check, blocks merge if a dep in
// the lockfile is now flagged. Runs only on pull_request — no schedules,
// consistent with "nothing runs in the background".
//
// The binary download is deliberately a FIXME, not a working default: a
// supply-chain guard must never bootstrap itself from an unpinned source.
// Fill in your release URL and checksum once, commit, done.
const ciWorkflow = `# depguard PR gate — installed by 'guard init --ci'.
# Blocks merge when an installed dependency is hit by a new advisory or a
# lockfile change introduces a version still inside the cooldown.
name: depguard
on: pull_request
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2 # guard check diffs the lockfile against the parent
      # FIXME(one-time setup): point at YOUR pinned guard release and its
      # checksum. Never use a floating tag here — this workflow guards your
      # supply chain and must not be a supply-chain risk itself.
      - name: Fetch guard binary (pinned)
        run: |
          echo "FIXME: download a pinned guard release, e.g.:" >&2
          echo "  curl -fsSLo guard https://YOUR-HOST/guard-vX.Y.Z-linux-amd64" >&2
          echo "  echo '<sha256>  guard' | sha256sum -c -" >&2
          echo "  chmod +x guard && sudo mv guard /usr/local/bin/" >&2
          exit 1
      - run: guard check
`

// hookAppend is chained onto an EXISTING hook (husky, lefthook, a hand-rolled
// one) instead of clobbering it — no shebang, because the file already has one.
const hookAppend = `
# depguard — appended by 'guard init' (chained onto your existing hook).
# Bypass ONLY depguard for one commit/push:  GUARD_SKIP=1 git push
if [ -n "$GUARD_SKIP" ]; then
  echo "depguard: check skipped (GUARD_SKIP set)." >&2
elif command -v guard >/dev/null 2>&1; then
  guard check --quiet --confirm || { echo "depguard: advisory check failed or warnings not accepted (bypass once with GUARD_SKIP=1)" >&2; exit 1; }
fi
`

// installHook writes the guard shim for hook phase h, or APPENDS to an existing
// hook rather than skipping it. Hook managers (husky &c.) own the file, so we
// chain onto them — the old behavior silently left those repos unprotected.
// Returns the path written/updated, or "" if it was already chained.
func installHook(hookDir, h string) (string, error) {
	path := filepath.Join(hookDir, h)
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if os.IsNotExist(err) {
		return path, os.WriteFile(path, []byte(hookScript), 0o755)
	}
	if strings.Contains(string(existing), "guard check") {
		return "", nil // already chained — don't double-append
	}
	content := string(existing)
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += hookAppend
	return path, os.WriteFile(path, []byte(content), 0o755)
}

// npmrcSettings are the npm-config keys depguard pins at the .npmrc level. This
// is the backstop for installs that DON'T go through guard: a teammate running
// plain `npm install` in this repo still gets these, because npm itself reads
// this file. Each entry carries the substring used to detect a pre-existing
// setting (so we never clobber a human's choice) and the block to append.
//
//	ignore-scripts=true  lifecycle scripts never auto-run; 'guard install'
//	                     handles approvals.
//	save-exact=true /    new deps are written at their exact resolved version
//	save-prefix=         (e.g. "react": "19.1.0"), never a "^"/"~" range — so a
//	                     version changes only when you deliberately bump it,
//	                     never silently on a later install. save-prefix= is the
//	                     belt-and-suspenders backstop if save-exact is unset.
var npmrcSettings = []struct{ key, block string }{
	{"ignore-scripts", "# depguard: never auto-run lifecycle scripts; 'guard install' handles approvals.\nignore-scripts=true\n"},
	{"save-exact", "# depguard: pin new deps to the exact installed version (no ^/~); bump manually.\nsave-exact=true\nsave-prefix=\n"},
}

// installNpmrc writes (or appends to) the repo's .npmrc so raw npm installs are
// also script-neutralized and version-pinned. Each setting is appended only if
// absent, so a human's existing choice for any one of them is left untouched.
// Returns true if anything was written.
func installNpmrc(dir string) (bool, error) {
	path := filepath.Join(dir, ".npmrc")
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	content := string(existing)
	wrote := false
	for _, s := range npmrcSettings {
		if strings.Contains(content, s.key) {
			continue // already configured (either value) — human's choice stands
		}
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		content += s.block
		wrote = true
	}
	if !wrote {
		return false, nil
	}
	return true, os.WriteFile(path, []byte(content), 0o644)
}

// Install writes the git hooks + .npmrc (always) and CI workflow (when ci is
// true). Returns a list of what it wrote for the init summary.
func Install(dir string, ci bool) ([]string, error) {
	var written []string

	if wrote, err := installNpmrc(dir); err != nil {
		return nil, err
	} else if wrote {
		written = append(written, ".npmrc (ignore-scripts + save-exact)")
	}

	// Prefer husky's hook dir when present: husky points core.hooksPath at
	// .husky, so anything we drop in .git/hooks would never fire there.
	hookDir := filepath.Join(dir, ".git", "hooks")
	if _, err := os.Stat(filepath.Join(dir, ".husky")); err == nil {
		hookDir = filepath.Join(dir, ".husky")
	}
	if _, err := os.Stat(hookDir); err != nil {
		return nil, fmt.Errorf("no %s here — run inside a git repo (or git init first)", filepath.Base(hookDir))
	}
	for _, h := range []string{"pre-commit", "pre-push"} {
		p, err := installHook(hookDir, h)
		if err != nil {
			return written, err
		}
		if p != "" {
			rel, _ := filepath.Rel(dir, p)
			written = append(written, rel)
		}
	}

	if ci {
		wfDir := filepath.Join(dir, ".github", "workflows")
		if err := os.MkdirAll(wfDir, 0o755); err != nil {
			return written, err
		}
		path := filepath.Join(wfDir, "depguard.yml")
		if _, err := os.Stat(path); err == nil {
			fmt.Fprintln(os.Stderr, "guard: .github/workflows/depguard.yml already exists, skipping")
		} else {
			if err := os.WriteFile(path, []byte(ciWorkflow), 0o644); err != nil {
				return written, err
			}
			written = append(written, ".github/workflows/depguard.yml")
		}
	}
	return written, nil
}

// InstalledState reports which guard-managed artifacts are present in dir — the
// raw material for `guard status`. Detection is by content marker (not mere
// existence), so a hand-removed or husky-chained hook is reported accurately.
type InstalledState struct {
	PreCommit  bool // .git/hooks/pre-commit calls guard
	PrePush    bool // .git/hooks/pre-push calls guard
	Npmrc      bool // .npmrc pins ignore-scripts=true
	CIWorkflow bool // .github/workflows/depguard.yml present
	Husky      bool // a .husky dir exists (hooks chain there instead of .git/hooks)
}

// Installed inspects dir for the artifacts `guard init` drops.
func Installed(dir string) InstalledState {
	var s InstalledState
	s.PreCommit = hookCallsGuard(filepath.Join(dir, ".git", "hooks", "pre-commit"))
	s.PrePush = hookCallsGuard(filepath.Join(dir, ".git", "hooks", "pre-push"))
	if b, err := os.ReadFile(filepath.Join(dir, ".npmrc")); err == nil {
		s.Npmrc = strings.Contains(string(b), "ignore-scripts=true")
	}
	if _, err := os.Stat(filepath.Join(dir, ".github", "workflows", "depguard.yml")); err == nil {
		s.CIWorkflow = true
	}
	if fi, err := os.Stat(filepath.Join(dir, ".husky")); err == nil && fi.IsDir() {
		s.Husky = true
	}
	return s
}

// hookCallsGuard reports whether the hook file at path exists and invokes guard.
func hookCallsGuard(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && strings.Contains(string(b), "guard check")
}
