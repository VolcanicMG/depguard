// Command guard is depguard's CLI — a local-first supply-chain guard for npm
// dependencies. See DESIGN.md for the full model. Quick map:
//
//	guard init [--ci]      drop .guardrc + git hooks (+ CI workflow) into a repo
//	guard install [args]   protected npm install through the ephemeral proxy
//	guard check [--quiet]  lockfile vs OSV advisories (what the hooks/CI run)
//	guard approve <pkg>    record a script decision without installing
//	guard version          print version
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"depguard/internal/advisory"
	"depguard/internal/approvals"
	"depguard/internal/box"
	"depguard/internal/config"
	"depguard/internal/freshness"
	"depguard/internal/hooks"
	"depguard/internal/lockfile"
	"depguard/internal/maintainer"
	"depguard/internal/registry"
	"depguard/internal/scanner"
	"depguard/internal/semver"
	"depguard/internal/tty"
)

const version = "0.5.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "install", "i":
		err = cmdInstall("install", os.Args[2:])
	case "ci":
		// npm ci installs exactly what the lockfile pins; the proxy filter is
		// moot (versions are fixed) but script neutralization + approvals +
		// advisory check all still apply.
		err = cmdInstall("ci", os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	case "scan":
		err = cmdScan(os.Args[2:])
	case "approve":
		err = cmdApprove(os.Args[2:])
	case "mcp":
		err = cmdMCP(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("guard", version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "guard:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `guard — supply-chain protection for npm installs

  guard init [--ci]               set up this repo (.guardrc, git hooks, CI gate)
  guard install [npm args...]     npm install, filtered + scripts neutralized
  guard check [--quiet] [--json]  re-check installed deps against advisories
  guard scan <dir> [--json]       static-scan one package dir (scripts, caps, injection)
  guard mcp                       run as an MCP server over stdio
  guard approve <name@version>    record a script approval (use --uncontained to
                                  allow running with no sandbox; --deny to refuse)
  guard version
`)
}

// ─── guard init ──────────────────────────────────────────────────────────────

// cmdInit drops the per-repo state: policy file + trigger shims (DESIGN.md §3, §10).
func cmdInit(args []string) error {
	ci := false
	for _, a := range args {
		if a == "--ci" {
			ci = true
		}
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}

	var wrote []string
	if err := config.WriteDefault(dir); err == nil {
		wrote = append(wrote, config.FileName)
	} else {
		fmt.Fprintln(os.Stderr, "guard:", err, "— keeping it")
	}
	hookFiles, err := hooks.Install(dir, ci)
	if err != nil {
		return err
	}
	wrote = append(wrote, hookFiles...)

	fmt.Println("depguard initialized:")
	for _, f := range wrote {
		fmt.Println("  +", f)
	}
	fmt.Println("\nNext: use 'guard install <pkg>' instead of 'npm install <pkg>'.")
	return nil
}

// ─── guard install ───────────────────────────────────────────────────────────

// cmdInstall is the protected install path — the whole §5–§9 flow:
// ephemeral proxy → npm with scripts neutralized → approval/box for the few
// script-bearing packages → advisory check on the result.
// npmCmd is "install" or "ci".
func cmdInstall(npmCmd string, npmArgs []string) error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	cfg, err := config.Load(dir)
	if err != nil {
		return err
	}
	appr, err := approvals.Load(dir)
	if err != nil {
		return err
	}

	// 1. Ephemeral proxy: exists only for this command (§5).
	proxy, err := registry.Start(cfg)
	if err != nil {
		return fmt.Errorf("start proxy: %w", err)
	}
	defer proxy.Stop()

	// 2. The real install, pointed at the proxy, lifecycle scripts OFF.
	// CLI flags beat any .npmrc, so a repo-level registry override can't
	// route around the filter.
	args := append([]string{npmCmd}, npmArgs...)
	args = append(args, "--registry="+proxy.URL())
	if cfg.IgnoreScripts {
		args = append(args, "--ignore-scripts")
	}
	npm := exec.Command("npm", args...)
	npm.Stdout, npm.Stderr, npm.Stdin = os.Stdout, os.Stderr, os.Stdin
	npmErr := npm.Run()

	// 3. Tell the human what the filter hid and why — even when npm failed,
	// because "all versions in cooldown" IS the explanation for the failure.
	if blocked := proxy.BlockedVersions(); len(blocked) > 0 {
		fmt.Fprintf(os.Stderr, "\nguard: filtered %d version(s):\n", len(blocked))
		byPkg := map[string][]registry.Blocked{}
		for _, b := range blocked {
			byPkg[b.Package] = append(byPkg[b.Package], b)
		}
		names := make([]string, 0, len(byPkg))
		for n := range byPkg {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			bs := byPkg[n]
			// One line per package, not per version — npm fetches metadata
			// for the whole tree and this list gets long.
			fmt.Fprintf(os.Stderr, "  %-30s %d version(s), e.g. %s (%s)\n",
				n, len(bs), bs[0].Version, bs[0].Reason)
		}
	}
	// Deprecated default-resolutions (informational, not a failure).
	if dep := proxy.DeprecatedVersions(); len(dep) > 0 {
		fmt.Fprintf(os.Stderr, "\nguard: %d package(s) resolve to a DEPRECATED version:\n", len(dep))
		for _, d := range dep {
			fmt.Fprintf(os.Stderr, "  %s@%s — %s\n", d.Package, d.Version, truncate(d.Reason, 80))
		}
	}
	if npmErr != nil {
		return fmt.Errorf("npm install failed: %w", npmErr)
	}

	// 4. Script-bearing packages: detect → approve → box (§7, §8).
	if cfg.IgnoreScripts {
		if err := handleScripts(dir, cfg, appr); err != nil {
			return err
		}
		// The ROOT project's own lifecycle scripts were also skipped by
		// --ignore-scripts, but they're the user's own committed code — the
		// thing depguard exists to protect, not protect against. Run them so
		// husky/patch-package-style setups keep working.
		if err := runRootScripts(dir); err != nil {
			return err
		}
	}

	// 5. Advisory re-check on the final lockfile (§3 layer 5).
	return checkAdvisories(dir, false)
}

// handleScripts finds every installed package that wanted to run a lifecycle
// script, and walks each through the ask-once approval flow.
func handleScripts(dir string, cfg config.Config, appr *approvals.File) error {
	entries, err := lockfile.InstalledPaths(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no lockfile (npm install with no package.json?) — nothing to do
		}
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	interactive := stdinIsTTY()
	runtime := box.Runtime()
	var skipped []string

	// The observation image is ensured lazily: most installs have no
	// script-bearing packages and should never pay for (or build) it.
	boxImage, boxTraced, boxReady := "", false, false
	ensureBox := func() {
		if !boxReady && runtime != "" {
			boxImage, boxTraced = box.EnsureObsImage(runtime)
			boxReady = true
		}
	}

	for _, e := range entries {
		pkgDir := filepath.Join(dir, e.Path)
		// Cheap gate first: one package.json read. The full capability sweep
		// only runs for the few packages that actually declare scripts —
		// otherwise installs with 1000+ deps would crawl.
		scripts, err := scanner.ReadScripts(pkgDir)
		if err != nil {
			continue // not unpacked (optional dep for another platform, etc.)
		}
		if len(scripts) == 0 {
			continue // ~90% of packages exit here: no scripts, nothing to decide
		}
		rep, err := scanner.ScanDir(pkgDir)
		if err != nil {
			continue
		}

		key := e.Name + "@" + e.Version
		entry, known := appr.Get(key)
		if known && entry.Decision == approvals.Denied {
			fmt.Fprintf(os.Stderr, "guard: %s — scripts denied previously, skipping\n", key)
			continue
		}

		if !known {
			if !interactive {
				// Never decide for the human in a non-interactive context;
				// surface it and move on (install still succeeds — §7).
				skipped = append(skipped, key)
				continue
			}
			// Capability diff vs the previous version (DESIGN §6), opt-in via
			// flag: new-network / new-fs. Best-effort — shown in the prompt so
			// the human sees what THIS update added before approving.
			var newCaps []scanner.Finding
			if cfg.Flagged("new-network") || cfg.Flagged("new-fs") {
				newCaps = priorCapabilityDiff(cfg, e.Name, e.Version, rep)
			}
			decision := promptApproval(key, rep, runtime, cfg, newCaps)
			appr.Set(key, decision, "")
			if err := appr.Save(dir); err != nil {
				return err
			}
			entry = approvals.Entry{Decision: decision}
			if decision == approvals.Denied {
				continue
			}
		}

		// Approved → run it, boxed when possible.
		ensureBox()
		if err := runApproved(key, dir, e.Path, entry.Decision, runtime, boxImage, boxTraced, cfg, appr); err != nil {
			return err
		}
	}

	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "\nguard: %d package(s) want install scripts but no one was here to approve:\n", len(skipped))
		for _, k := range skipped {
			fmt.Fprintln(os.Stderr, "   ", k)
		}
		fmt.Fprintln(os.Stderr, "  Approve interactively with: guard approve <name@version>")
	}
	return nil
}

// promptApproval shows the static scan verdict and asks the §7 question.
// The human sees what the script DOES before deciding — that's the whole point.
// newCaps holds capabilities this version added over the previous one (§6
// diff), shown prominently because "newly opened a socket" is higher signal
// than the absolute capability list.
func promptApproval(key string, rep scanner.Report, runtime string, cfg config.Config, newCaps []scanner.Finding) approvals.Decision {
	fmt.Printf("\n── %s wants to run install scripts ──\n", key)
	for phase, cmd := range rep.Scripts {
		fmt.Printf("   %s: %s\n", phase, truncate(cmd, 80))
	}
	if len(rep.Findings) > 0 {
		fmt.Println("   static scan:")
		for _, f := range rep.Findings {
			fmt.Printf("     [%s] %s (%s)\n", f.Severity, f.What, f.Where)
		}
	} else {
		fmt.Println("   static scan: no capability flags")
	}
	if len(newCaps) > 0 {
		fmt.Println("   ⚠ NEW since the previous version:")
		for _, f := range newCaps {
			fmt.Printf("     + [%s] %s\n", f.Severity, f.What)
		}
	}

	if runtime != "" {
		fmt.Printf("   Script would run BOXED: no network, package dir only (%s).\n", runtime)
		if promptYN("   Allow?") {
			return approvals.ApprovedBoxed
		}
		return approvals.Denied
	}

	// §9 warn-approve: no container runtime on this machine.
	if cfg.NoContainerFallback == config.FallbackFail {
		fmt.Println("   No container runtime and policy is 'fail' — denying.")
		return approvals.Denied
	}
	fmt.Println("   ⚠ No container runtime found (docker/podman).")
	fmt.Println("   Running this script means executing its code on your machine, UNCONTAINED.")
	if promptYN("   Run uncontained anyway?") {
		return approvals.ApprovedUncontained
	}
	return approvals.Denied
}

// runApproved executes an approved script with the strongest containment the
// decision and machine allow, and reports what the box observed (§8).
// An UNSAFE trace verdict converts the approval into an automatic denial:
// the evidence outranks the human's earlier yes.
func runApproved(key, projectDir, relPath string, d approvals.Decision, runtime, boxImage string, boxTraced bool, cfg config.Config, appr *approvals.File) error {
	pkgDir := filepath.Join(projectDir, relPath)
	switch {
	case runtime != "":
		// Fail-closed policy: if we can't observe the run (no strace image) and
		// the repo said it won't accept unobserved output, skip rather than run
		// caged-but-blind. Install still succeeds; the script just doesn't run.
		if !boxTraced && cfg.UntracedFail {
			fmt.Fprintf(os.Stderr, "guard: %s — boxed run would be UNTRACED and policy is 'fail' — skipping.\n", key)
			return nil
		}
		mode := "boxed+traced"
		if !boxTraced {
			mode = "boxed, UNTRACED"
		}
		fmt.Fprintf(os.Stderr, "guard: %s — running %s (%s)...\n", key, mode, runtime)
		res, err := box.Run(runtime, boxImage, boxTraced, projectDir, relPath)
		if err != nil {
			return fmt.Errorf("%s box run: %w", key, err)
		}
		if res.Unsafe {
			fmt.Fprintf(os.Stderr, "\nguard: ✗ %s behaved MALICIOUSLY in the box:\n", key)
			for _, f := range res.Findings {
				if f.Kind != "exec" { // execs are context; print the convictions
					fmt.Fprintf(os.Stderr, "    [%s] %s\n", f.Kind, f.Detail)
				}
			}
			fmt.Fprintln(os.Stderr, "guard: its output was DISCARDED (package dir restored) and the approval revoked.")
			// The denial is recorded in the committed approvals file, so the
			// evidence travels to every teammate and CI run.
			appr.Set(key, approvals.Denied, "auto-denied: unsafe behavior observed in box")
			if err := appr.Save(projectDir); err != nil {
				return err
			}
			return fmt.Errorf("%s attempted malicious actions during install", key)
		}
		fmt.Fprintf(os.Stderr, "guard: %s — %s\n", key, res.Summary())
		if res.ExitCode != 0 {
			// Network-needing builds fail in the box by design (no phone
			// line). Show the tail so the human can tell build-bug from
			// exfil attempt.
			fmt.Fprintf(os.Stderr, "guard: %s script failed in the box. Output tail:\n%s\n",
				key, tail(res.Output, 15))
		}
		return nil

	case d == approvals.ApprovedUncontained:
		// Explicit human approval recorded — the only path that runs bare.
		fmt.Fprintf(os.Stderr, "guard: %s — running UNCONTAINED (explicitly approved)...\n", key)
		res, err := box.RunUncontained(pkgDir)
		if err != nil {
			return fmt.Errorf("%s uncontained run: %w", key, err)
		}
		if res.ExitCode != 0 {
			fmt.Fprintf(os.Stderr, "guard: %s script failed. Output tail:\n%s\n", key, tail(res.Output, 15))
		}
		return nil

	default:
		// Approved-boxed but no runtime here (e.g. teammate had Docker,
		// this machine doesn't): fail closed, explain how to proceed.
		fmt.Fprintf(os.Stderr, "guard: %s approved for BOXED runs only and no container runtime is available — skipped.\n", key)
		fmt.Fprintf(os.Stderr, "guard: install docker/podman, or re-approve with: guard approve %s --uncontained\n", key)
		return nil
	}
}

// runRootScripts replays the root project's own lifecycle scripts — trusted
// code from the repo itself, run normally (not boxed). `prepare` is included
// here, unlike for registry deps: npm runs prepare for the ROOT project on
// install (husky and friends depend on that).
func runRootScripts(dir string) error {
	raw, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil // no root manifest — nothing to run
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(raw, &pkg) != nil {
		return nil
	}
	any := false
	for _, p := range []string{"preinstall", "install", "postinstall", "prepare"} {
		if _, ok := pkg.Scripts[p]; ok {
			any = true
			break
		}
	}
	if !any {
		return nil
	}
	fmt.Fprintln(os.Stderr, "guard: running the project's own lifecycle scripts (trusted)...")
	cmd := exec.Command("sh", "-c",
		`for s in preinstall install postinstall prepare; do npm run "$s" --if-present || exit $?; done`)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// ─── guard check ─────────────────────────────────────────────────────────────

// cmdCheck is the hook/CI trigger (§3): lockfile vs OSV advisory feed, plus
// cooldown re-verification on lockfile changes. The freshness half is what
// makes the hooks an ENFORCEMENT point: installs that bypassed guard (plain
// npm, a teammate without it) still can't push a too-young version past a
// commit or PR.
func cmdCheck(args []string) error {
	quiet, all, jsonOut := false, false, false
	for _, a := range args {
		switch a {
		case "--quiet":
			quiet = true
		case "--all":
			all = true // force full-tree freshness check, not just the git diff
		case "--json":
			jsonOut = true
		}
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	cfg, cfgErr := config.Load(dir)
	if cfgErr != nil {
		return cfgErr
	}

	// Machine-readable path: assemble the structured result and emit it, no
	// human prose. Same gather the MCP server uses, so the two never drift.
	if jsonOut {
		res, err := gatherCheck(dir, cfg, all)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return err
		}
		if !res.OK {
			return fmt.Errorf("guard check found issues")
		}
		return nil
	}
	advErr := checkAdvisories(dir, quiet)
	freshErr := checkFreshness(dir, quiet, all)
	intErr := checkLockfileIntegrity(dir, cfg, quiet)
	// Informational diff signals (never gate the commit/PR). Run here so a
	// new-deps heads-up rides the same `guard check` the hooks already run.
	if cfg.Flagged("new-deps") {
		reportNewDeps(dir, quiet)
	}
	if cfg.Flagged("new-maintainer") {
		checkMaintainers(dir, cfg, quiet)
	}
	// First gate to trip wins the exit code; all of them already printed.
	if advErr != nil {
		return advErr
	}
	if intErr != nil {
		return intErr
	}
	return freshErr
}

// CheckResult is the structured outcome of a `guard check` — the shape emitted
// by --json and returned by the MCP server's check tool.
type CheckResult struct {
	Advisories  []advisory.Vuln       `json:"advisories"`
	Cooldown    []freshness.Violation `json:"cooldownViolations"`
	OffRegistry []string              `json:"offRegistry"`
	Unhashed    []string              `json:"unhashed"`
	NewDeps     []string              `json:"newDeps"`
	Maintainers []maintainer.Change   `json:"maintainerChanges"`
	OK          bool                  `json:"ok"`
}

// gatherCheck runs every check over the lockfile and returns the structured
// result WITHOUT printing — the single source of truth behind both
// `guard check --json` and the MCP check tool. The human-prose path in
// cmdCheck stays separate (different output contract), but both read the same
// underlying internal packages.
func gatherCheck(dir string, cfg config.Config, all bool) (CheckResult, error) {
	var res CheckResult
	pkgs, err := lockfile.Installed(dir)
	if err != nil {
		if os.IsNotExist(err) {
			res.OK = true
			return res, nil
		}
		return res, err
	}
	if v, err := advisory.Check(pkgs); err == nil {
		res.Advisories = v
	}
	regHost := hostOf(cfg.Registry)
	for _, p := range pkgs {
		if cfg.Allowed(p.Name) || (!strings.HasPrefix(p.Resolved, "http://") && !strings.HasPrefix(p.Resolved, "https://")) {
			continue
		}
		if h := hostOf(p.Resolved); h != regHost && !isLoopbackHost(h) {
			res.OffRegistry = append(res.OffRegistry, p.Key())
		}
		if p.Integrity == "" {
			res.Unhashed = append(res.Unhashed, p.Key())
		}
	}
	fresh := pkgs
	if !all {
		if prev, ok := headLockfile(dir); ok {
			vetted := map[string]bool{}
			for _, p := range prev {
				vetted[p.Key()] = true
			}
			var add []lockfile.Pkg
			for _, p := range pkgs {
				if !vetted[p.Key()] {
					add = append(add, p)
					res.NewDeps = append(res.NewDeps, p.Key())
				}
			}
			fresh = add
		}
	}
	if viol, _ := freshness.Check(cfg.Registry, fresh, cfg.Cooldown, cfg.Allowed); len(viol) > 0 {
		res.Cooldown = viol
	}
	if cfg.Flagged("new-maintainer") {
		if ch, _ := maintainer.Check(cfg.Registry, pkgs, cfg.Allowed); len(ch) > 0 {
			res.Maintainers = ch
		}
	}
	res.OK = len(res.Advisories) == 0 && len(res.Cooldown) == 0 && len(res.OffRegistry) == 0 && len(res.Unhashed) == 0
	return res, nil
}

// checkLockfileIntegrity flags lockfile entries whose tarball resolves OFF the
// configured registry (a poisoned lockfile silently redirecting a fetch to an
// attacker host) or that carry no integrity hash (npm can't verify the
// download). Both are tamper signatures a hand-edited or malicious lockfile
// leaves behind. Allowlisted packages bypass — a deliberately alternate source
// is the human's call. Gates the check like the advisory layer.
func checkLockfileIntegrity(dir string, cfg config.Config, quiet bool) error {
	pkgs, err := lockfile.Installed(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	regHost := hostOf(cfg.Registry)
	var offReg, noHash []string
	for _, p := range pkgs {
		if cfg.Allowed(p.Name) {
			continue
		}
		// Only http(s) tarballs are comparable; git/file/link deps legitimately
		// resolve elsewhere and carry no registry host or integrity hash.
		if !strings.HasPrefix(p.Resolved, "http://") && !strings.HasPrefix(p.Resolved, "https://") {
			continue
		}
		if h := hostOf(p.Resolved); h != regHost && !isLoopbackHost(h) {
			offReg = append(offReg, fmt.Sprintf("%s — tarball host %q ≠ registry %q", p.Key(), h, regHost))
		}
		if p.Integrity == "" {
			noHash = append(noHash, p.Key())
		}
	}
	if len(offReg) == 0 && len(noHash) == 0 {
		if !quiet {
			fmt.Printf("guard: lockfile integrity ok (%d version(s)) ✓\n", len(pkgs))
		}
		return nil
	}
	if len(offReg) > 0 {
		fmt.Fprintf(os.Stderr, "guard: %d lockfile entr(ies) resolve OFF the configured registry:\n", len(offReg))
		for _, s := range offReg {
			fmt.Fprintln(os.Stderr, "  ", s)
		}
	}
	if len(noHash) > 0 {
		fmt.Fprintf(os.Stderr, "guard: %d registry entr(ies) carry NO integrity hash:\n", len(noHash))
		for _, s := range noHash {
			fmt.Fprintln(os.Stderr, "  ", s)
		}
	}
	fmt.Fprintln(os.Stderr, "guard: a tarball off-registry or without a hash can't be verified — allowlist in .guardrc if intentional")
	return fmt.Errorf("lockfile integrity check failed (%d off-registry, %d unhashed)", len(offReg), len(noHash))
}

// hostOf extracts the hostname from a URL, "" on parse failure.
func hostOf(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// isLoopbackHost reports whether h is a local address (test harnesses, local
// proxies) — never a wire-attack surface.
func isLoopbackHost(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

// priorCapabilityDiff fetches the highest published version strictly below
// `version` and reports the capabilities `current` adds over it (DESIGN §6).
// Best-effort: any network/parse failure yields no diff rather than blocking
// approval. The caller gates this on flag: new-network / new-fs.
func priorCapabilityDiff(cfg config.Config, name, version string, current scanner.Report) []scanner.Finding {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(cfg.Registry + "/" + url.PathEscape(name))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var doc struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if json.NewDecoder(resp.Body).Decode(&doc) != nil {
		return nil
	}
	all := make([]string, 0, len(doc.Versions))
	for v := range doc.Versions {
		all = append(all, v)
	}
	prev := priorVersion(version, all)
	if prev == "" {
		return nil
	}
	prevRep, err := scanner.FetchReport(client, cfg.Registry, name, prev)
	if err != nil {
		return nil
	}
	return scanner.DiffNew(prevRep, current)
}

// priorVersion returns the highest version in all that is strictly less than
// current, or "" when there's no predecessor (or current doesn't parse).
func priorVersion(current string, all []string) string {
	cur, ok := semver.Parse(current)
	if !ok {
		return ""
	}
	var best *semver.Version
	for _, v := range all {
		pv, ok := semver.Parse(v)
		if !ok || !semver.Less(pv, cur) {
			continue
		}
		if best == nil || semver.Less(*best, pv) {
			b := pv
			best = &b
		}
	}
	if best == nil {
		return ""
	}
	return best.Raw
}

// checkMaintainers surfaces publisher changes on installed versions — the
// account-takeover signal (DESIGN §6). Opt-in via `flag: new-maintainer`
// because it fetches a packument per package; informational, never gates.
func checkMaintainers(dir string, cfg config.Config, quiet bool) {
	pkgs, err := lockfile.Installed(dir)
	if err != nil {
		return
	}
	changes, warnings := maintainer.Check(cfg.Registry, pkgs, cfg.Allowed)
	for _, w := range warnings {
		if !quiet {
			fmt.Fprintln(os.Stderr, "guard: maintainer check skipped for", w)
		}
	}
	if len(changes) == 0 {
		if !quiet {
			fmt.Println("guard: no maintainer/publisher changes on installed versions ✓")
		}
		return
	}
	fmt.Fprintf(os.Stderr, "guard: %d installed version(s) changed publisher or republished after dormancy (verify — account-takeover signal):\n", len(changes))
	for _, c := range changes {
		switch {
		case c.PrevUser != "" && c.NewUser != "" && c.PrevUser != c.NewUser:
			fmt.Fprintf(os.Stderr, "  %s@%s — published by %q, previous version by %q", c.Name, c.Version, c.NewUser, c.PrevUser)
			if c.GapDays > 0 {
				fmt.Fprintf(os.Stderr, " (after %dd gap)", c.GapDays)
			}
			fmt.Fprintln(os.Stderr)
		default:
			fmt.Fprintf(os.Stderr, "  %s@%s — published after %dd dormancy\n", c.Name, c.Version, c.GapDays)
		}
	}
}

// reportNewDeps surfaces the packages a lockfile change ADDS to the tree
// versus git HEAD — the "new-deps" diff signal (DESIGN.md §10 `flag:`). It is
// purely informational: a heads-up that an update widened your dependency
// surface (the cheapest, highest-signal half of §6's capability diff), never a
// gate. Silent when there's no committed lockfile to diff against.
func reportNewDeps(dir string, quiet bool) {
	prev, ok := headLockfile(dir)
	if !ok {
		return // no HEAD lockfile to diff against — nothing to say
	}
	curr, err := lockfile.Installed(dir)
	if err != nil {
		return
	}
	had := map[string]bool{}
	for _, p := range prev {
		had[p.Key()] = true
	}
	var added []string
	for _, p := range curr {
		if !had[p.Key()] {
			added = append(added, p.Key()) // curr is already key-sorted
		}
	}
	if len(added) == 0 {
		if !quiet {
			fmt.Println("guard: no new dependencies vs HEAD ✓")
		}
		return
	}
	fmt.Fprintf(os.Stderr, "guard: this change adds %d package(s) to the tree:\n", len(added))
	for _, a := range added {
		fmt.Fprintln(os.Stderr, "   +", a)
	}
}

// checkFreshness re-applies the cooldown to versions already in the lockfile.
// Scope: only versions ADDED relative to git HEAD (each version gets checked
// once, at the commit that introduces it) — full tree with --all or when
// there's no git history to diff against.
func checkFreshness(dir string, quiet, all bool) error {
	cfg, err := config.Load(dir)
	if err != nil {
		return err
	}
	pkgs, err := lockfile.Installed(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	scope := "lockfile additions"
	if !all {
		if prev, ok := headLockfile(dir); ok {
			// Keep only versions not already present at HEAD. Keyed on
			// name@version (not name) so a NEW version of an existing package
			// is still vetted — each distinct version is checked once, at the
			// commit that introduces it.
			vetted := map[string]bool{}
			for _, p := range prev {
				vetted[p.Key()] = true
			}
			kept := pkgs[:0]
			for _, p := range pkgs {
				if !vetted[p.Key()] {
					kept = append(kept, p)
				}
			}
			pkgs = kept
		} else {
			scope = "full tree (no committed lockfile to diff against)"
		}
	} else {
		scope = "full tree (--all)"
	}
	if len(pkgs) == 0 {
		if !quiet {
			fmt.Println("guard: no new lockfile versions to cooldown-check ✓")
		}
		return nil
	}

	violations, warnings := freshness.Check(cfg.Registry, pkgs, cfg.Cooldown, cfg.Allowed)
	for _, w := range warnings {
		// Fail-open on per-package fetch errors, but loudly: a registry blip
		// must not block every commit in every repo.
		fmt.Fprintln(os.Stderr, "guard: freshness check skipped for", w)
	}
	if len(violations) == 0 {
		if !quiet {
			fmt.Printf("guard: %d version(s) cooldown-checked (%s), all clear ✓\n", len(pkgs), scope)
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "guard: %d version(s) inside the %s cooldown:\n", len(violations), cfg.Cooldown)
	for _, v := range violations {
		if v.Age == 0 {
			fmt.Fprintf(os.Stderr, "  %s@%s — no publish timestamp\n", v.Name, v.Version)
		} else {
			fmt.Fprintf(os.Stderr, "  %s@%s — published %dd ago\n", v.Name, v.Version, int(v.Age.Hours()/24))
		}
	}
	fmt.Fprintln(os.Stderr, "guard: wait out the cooldown, pin an older version, or allowlist in .guardrc")
	return fmt.Errorf("%d version(s) violate the cooldown", len(violations))
}

// headLockfile reads package-lock.json as committed at git HEAD.
// ok=false when there's no git repo, no HEAD, or no committed lockfile.
func headLockfile(dir string) ([]lockfile.Pkg, bool) {
	out, err := exec.Command("git", "-C", dir, "show", "HEAD:package-lock.json").Output()
	if err != nil {
		return nil, false
	}
	prev, err := lockfile.InstalledBytes(out)
	if err != nil {
		return nil, false
	}
	return prev, true
}

// checkAdvisories queries OSV for every installed version and fails when any
// advisory hits — the "installed last month, reported yesterday" recovery layer.
func checkAdvisories(dir string, quiet bool) error {
	pkgs, err := lockfile.Installed(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if !quiet {
				fmt.Println("guard: no package-lock.json here — nothing to check")
			}
			return nil
		}
		return err
	}
	vulns, err := advisory.Check(pkgs)
	if err != nil {
		// Advisory feed unreachable: report, don't block work on a network
		// blip. The cooldown + script layers still stand.
		fmt.Fprintln(os.Stderr, "guard: advisory check skipped:", err)
		return nil
	}
	if len(vulns) == 0 {
		if !quiet {
			fmt.Printf("guard: %d installed package(s), no advisory hits ✓\n", len(pkgs))
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "guard: %d advisory hit(s) on installed packages:\n", len(vulns))
	for _, v := range vulns {
		fmt.Fprintf(os.Stderr, "  %s@%s — %s: %s\n", v.Package, v.Version, v.ID, truncate(v.Summary, 100))
	}
	return fmt.Errorf("%d vulnerable package(s) installed", len(vulns))
}

// ─── guard scan ──────────────────────────────────────────────────────────────

// cmdScan static-scans a single package directory and prints its report —
// scripts, capability flags, and LLM-injection signals. The JSON form is the
// machine-readable primitive the MCP server and CI consume.
func cmdScan(args []string) error {
	jsonOut := false
	var path string
	for _, a := range args {
		switch {
		case a == "--json":
			jsonOut = true
		case !strings.HasPrefix(a, "-"):
			path = a
		}
	}
	if path == "" {
		return fmt.Errorf("usage: guard scan <package-dir> [--json]")
	}
	rep, err := scanner.ScanDir(path)
	if err != nil {
		return err
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	if len(rep.Scripts) > 0 {
		fmt.Println("install scripts:")
		for phase, cmd := range rep.Scripts {
			fmt.Printf("  %s: %s\n", phase, truncate(cmd, 100))
		}
	}
	if len(rep.Findings) == 0 {
		fmt.Println("guard: no capability/injection findings ✓")
		return nil
	}
	for _, f := range rep.Findings {
		fmt.Printf("[%s] %s (%s)\n", f.Severity, f.What, f.Where)
	}
	return nil
}

// ─── guard approve ───────────────────────────────────────────────────────────

// cmdApprove records a script decision outside the install flow — how CI
// skips get resolved and how teammates pre-approve for non-interactive runs.
func cmdApprove(args []string) error {
	var key string
	decision := approvals.ApprovedBoxed
	for _, a := range args {
		switch a {
		case "--uncontained":
			decision = approvals.ApprovedUncontained
		case "--deny":
			decision = approvals.Denied
		default:
			if strings.HasPrefix(a, "-") {
				return fmt.Errorf("unknown flag %s", a)
			}
			key = a
		}
	}
	if key == "" || !strings.Contains(key[1:], "@") {
		return fmt.Errorf("usage: guard approve <name@version> [--uncontained|--deny]")
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	appr, err := approvals.Load(dir)
	if err != nil {
		return err
	}
	appr.Set(key, decision, "recorded via guard approve")
	if err := appr.Save(dir); err != nil {
		return err
	}
	fmt.Printf("guard: %s → %s (saved to %s — commit it so the decision travels)\n",
		key, decision, approvals.FileName)
	return nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// stdinIsTTY reports whether a human is attached — the gate between
// "ask now" and "skip + tell them how to approve later" (§9).
// Delegates to the termios-based check: /dev/null masquerades as a char
// device and must not count as a human.
func stdinIsTTY() bool { return tty.IsTerminal() }

// promptYN asks a yes/no question, defaulting to NO — every unanswered or
// garbled response must land on the safe side.
func promptYN(q string) bool {
	fmt.Printf("%s [y/N] ", q)
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return false
	}
	ans := strings.ToLower(strings.TrimSpace(sc.Text()))
	return ans == "y" || ans == "yes"
}

// truncate shortens s for single-line display.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// tail returns the last n lines of s — enough output to diagnose a script
// failure without flooding the terminal.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return "    " + strings.Join(lines, "\n    ")
}
