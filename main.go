// Command guard is depguard's CLI — a local-first supply-chain guard for npm
// dependencies. See DESIGN.md for the full model. Quick map:
//
//	guard init [--ci]      drop .guardrc + git hooks (+ CI workflow) into a repo
//	guard install [args]   protected npm install through the ephemeral proxy
//	guard check [flags]    lockfile vs OSV advisories (what the hooks/CI run; --confirm prompts on warn-tier)
//	guard approve <pkg>    record a script decision without installing
//	guard ignore <id>      waive a reviewed check finding (.guard-ignores)
//	guard version          print version
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
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
	"depguard/internal/attestation"
	"depguard/internal/box"
	"depguard/internal/config"
	"depguard/internal/freshness"
	"depguard/internal/hooks"
	"depguard/internal/license"
	"depguard/internal/lockfile"
	"depguard/internal/maintainer"
	"depguard/internal/registry"
	"depguard/internal/sbom"
	"depguard/internal/scanner"
	"depguard/internal/semver"
	"depguard/internal/tty"
	"depguard/internal/ui"
	"depguard/internal/waivers"
)

const version = "0.9.0"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
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
	case "why":
		err = cmdWhy(os.Args[2:])
	case "sbom":
		err = cmdSbom(os.Args[2:])
	case "approve":
		err = cmdApprove(os.Args[2:])
	case "ignore":
		err = cmdIgnore(os.Args[2:])
	case "allow":
		err = cmdAllow(os.Args[2:])
	case "config":
		err = cmdConfig(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "clean":
		err = cmdClean(os.Args[2:])
	case "prewarm":
		err = cmdPrewarm(os.Args[2:])
	case "mcp":
		err = cmdMCP(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("guard", version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "guard:", err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `guard — supply-chain protection for npm installs

  guard init [--ci]               set up this repo (.guardrc, git hooks, CI gate)
  guard status                    is this repo protected? (policy, hooks, sandbox, decisions)
  guard install [npm args...]     npm install, filtered + scripts neutralized
  guard ci                        npm ci — lockfile-exact, same protections
  guard check [--quiet] [--json] [--confirm]  re-check installed deps (advisories, cooldown, integrity)
  guard scan <dir> [--json]       static-scan one package dir (scripts, caps, injection)
  guard why <package> [--all]     show which direct dep(s) pull a package in (npm lockfile)
  guard sbom [--spdx]             write an SBOM of installed deps to stdout (CycloneDX, or SPDX)
  guard mcp                       run as an MCP server over stdio
  guard approve <name@version>    record a script approval (--uncontained | --deny)
  guard ignore <issue-id>         waive a reviewed check finding (--reason, --expires, --list, --remove)
  guard allow <pattern>...        add a name/scope to .guardrc allow (bypass cooldown)
  guard config [get | set <k> <v>]  show or edit .guardrc policy
  guard prewarm                   build the sandbox image now (skip the first-run wait)
  guard clean [--image]           sweep stray containers/artifacts (--image also reclaims the image)
  guard help                      show this message
  guard version
`)
}

// cmdClean reclaims depguard's footprint: the locally-built observation image
// (`depguard-box`) and any on-disk leftovers a HARD-KILLED box run left behind
// (pre-run backups, strace temp dirs, the seccomp temp file). OFFLINE and
// idempotent — it removes nothing a future run can't rebuild, so it is always
// safe to run.
func cmdClean(args []string) error {
	removeImage := false
	for _, a := range args {
		if a == "--image" {
			removeImage = true
		}
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	runtime := box.Runtime()

	// Routine cleanup keeps the (expensive-to-rebuild) image so the next boxed
	// run stays instant: sweep orphaned containers (the normal path --rm's them;
	// this catches a crashed run) + on-disk leftovers.
	containers := box.SweepContainers(runtime)
	swept := box.SweepArtifacts(dir)
	fmt.Printf("%s swept %d stray container(s) + %d artifact(s)\n", ui.OK(), containers, swept)

	if !removeImage {
		fmt.Println(ui.Dim("  image kept — run `guard clean --image` to reclaim its ~1.6 GB"))
		return nil
	}

	// --image: also reclaim the observation image.
	removed, rmErr := box.RemoveObsImage(runtime)
	if rmErr != nil {
		fmt.Fprintln(os.Stderr, "guard:", rmErr)
	}
	switch {
	case runtime == "":
		fmt.Println(ui.Warn(), "no container runtime — could not remove the image")
	case removed:
		fmt.Println(ui.OK(), "removed observation image", box.ObsImageName())
	default:
		fmt.Println(ui.OK(), "observation image not present — nothing to remove")
	}
	return nil
}

// cmdPrewarm builds the sandbox (strace) image ahead of time so the FIRST boxed
// script run doesn't pay the one-time build. Needs a container runtime + network
// (the §9 box; pure-JS installs never touch it). Idempotent — a no-op if already
// built.
func cmdPrewarm(args []string) error {
	runtime := box.Runtime()
	if runtime == "" {
		return fmt.Errorf("no container runtime (docker/podman) found — install one first")
	}
	fmt.Println("guard: prewarming the sandbox image (one-time, needs network)...")
	if _, traced := box.EnsureObsImage(runtime); !traced {
		return fmt.Errorf("could not build the sandbox image %s (see output above)", box.ObsImageName())
	}
	fmt.Println(ui.OK(), "sandbox image ready:", box.ObsImageName())
	return nil
}

// ─── guard init ──────────────────────────────────────────────────────────────

// cmdInit drops the per-repo state: policy file + trigger shims (DESIGN.md §3, §10).
func cmdInit(args []string) error {
	ci, prebuildBox := false, false
	for _, a := range args {
		switch a {
		case "--ci":
			ci = true
		case "--prebuild-box":
			prebuildBox = true
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
	// Nudge committing only the repo-tracked policy files that actually landed —
	// the .git/hooks shims live inside .git (never committed), and the `wrote`
	// labels are display strings, not bare paths, so check the disk by name.
	var commit []string
	for _, f := range []string{config.FileName, ".npmrc", ".github/workflows/depguard.yml"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			commit = append(commit, f)
		}
	}
	if len(commit) > 0 {
		fmt.Println("\nCommit the policy so it travels with the repo + CI:")
		fmt.Printf("  git add %s && git commit -m \"chore: add depguard policy\"\n", strings.Join(commit, " "))
	}
	// --prebuild-box: build the sandbox image now so the first boxed run is
	// instant. Best-effort and OPT-IN — default init stays offline and never
	// needs docker (most repos have no script-bearing deps anyway).
	if prebuildBox {
		if rt := box.Runtime(); rt != "" {
			fmt.Println("\nguard: prebuilding the sandbox image (--prebuild-box)...")
			if _, traced := box.EnsureObsImage(rt); !traced {
				fmt.Fprintln(os.Stderr, "guard: ⚠ sandbox prebuild failed — it will build lazily on the first boxed run")
			}
		} else {
			fmt.Fprintln(os.Stderr, "guard: ⚠ --prebuild-box: no container runtime found; skipping")
		}
	}

	fmt.Println("\nNext steps:")
	fmt.Println("  1. use 'guard install <pkg>' instead of 'npm install <pkg>'")
	fmt.Println("  2. your commits & pushes now run 'guard check' automatically (the hooks above)")
	fmt.Println("  3. check protection anytime with 'guard status'")
	tip := "Optional: enable build-provenance + license gates in .guardrc (see the comments there)."
	if !ci {
		tip = "Optional: 'guard init --ci' adds a PR gate; provenance + license gates live in .guardrc."
	}
	fmt.Println(ui.Dim("  " + tip))
	return nil
}

// ─── guard install ───────────────────────────────────────────────────────────

// detectManager picks the package manager for an install from the lockfile
// present in dir: pnpm-lock.yaml -> pnpm, yarn.lock -> yarn, else npm (also the
// default in a fresh repo with no lockfile yet). Lockfile presence is each
// manager's own "this is a <mgr> project" signal, so we reuse it.
func detectManager(dir string) string {
	if _, err := os.Stat(filepath.Join(dir, "pnpm-lock.yaml")); err == nil {
		return "pnpm"
	}
	if _, err := os.Stat(filepath.Join(dir, "yarn.lock")); err == nil {
		return "yarn"
	}
	return "npm"
}

// installInvocation is how to run a protected install for one package manager:
// the binary, its args, and the registry-override env vars to append. Returned
// (not executed) by buildInstall so command construction is unit-testable
// without npm/pnpm/yarn installed.
type installInvocation struct {
	name string
	args []string
	env  []string
}

// buildInstall constructs the install invocation for mgr, pointing it at the
// ephemeral proxy. sub is "install" or "ci". "ci" maps to each manager's
// frozen-lockfile install (npm has a real `ci` subcommand; pnpm/yarn take
// `install --frozen-lockfile`). ignoreScripts adds --ignore-scripts, honored by
// all three.
func buildInstall(mgr, sub string, userArgs []string, proxyURL string, ignoreScripts bool) installInvocation {
	// Registry env covers managers that read it over their rc file: npm + pnpm
	// honor npm_config_registry; yarn berry honors YARN_NPM_REGISTRY_SERVER and
	// yarn classic YARN_REGISTRY. Set all so the override is generation-proof.
	regEnv := []string{
		"npm_config_registry=" + proxyURL,
		"YARN_NPM_REGISTRY_SERVER=" + proxyURL,
		"YARN_REGISTRY=" + proxyURL,
	}
	withScripts := func(args []string) []string {
		if ignoreScripts {
			return append(args, "--ignore-scripts")
		}
		return args
	}
	switch mgr {
	case "pnpm":
		args := frozenArgs(sub, userArgs)
		args = append(args, "--registry="+proxyURL) // pnpm accepts the flag too
		return installInvocation{"pnpm", withScripts(args), regEnv}
	case "yarn":
		// No --registry flag: yarn berry errors on unknown flags, so route via
		// env only (both generations honor the registry env vars above).
		return installInvocation{"yarn", withScripts(frozenArgs(sub, userArgs)), regEnv}
	default: // npm
		args := append([]string{sub}, userArgs...)
		args = append(args, "--registry="+proxyURL) // CLI flag beats any .npmrc
		return installInvocation{"npm", withScripts(args), regEnv}
	}
}

// frozenArgs builds [subcmd, userArgs...] for pnpm/yarn, mapping the npm-style
// "ci" to "install --frozen-lockfile" (the equivalent both managers use instead
// of a separate ci command).
func frozenArgs(sub string, userArgs []string) []string {
	if sub == "ci" {
		return append(append([]string{"install"}, userArgs...), "--frozen-lockfile")
	}
	return append([]string{sub}, userArgs...)
}

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

	// Detect the package manager from the lockfile so pnpm/yarn installs route
	// through the SAME ephemeral proxy as npm (§5). guard install used to be
	// npm-only at install time; now all three are cooldown-filtered. The boxed
	// lifecycle-script approval flow (§7–§8) stays npm-only — see the note after
	// the install.
	mgr := detectManager(dir)

	// 1. Ephemeral proxy: exists only for this command (§5).
	proxy, err := registry.Start(cfg)
	if err != nil {
		return fmt.Errorf("start proxy: %w", err)
	}
	defer proxy.Stop()

	// 2. The real install, pointed at the proxy, lifecycle scripts OFF. The
	// registry override goes in as a flag (npm/pnpm — CLI beats the rc file) AND
	// as env vars (yarn, which rejects an unknown --registry flag on berry but
	// honors YARN_NPM_REGISTRY_SERVER / YARN_REGISTRY over its rc), so a
	// repo-level registry setting can't route around the filter on any manager.
	inv := buildInstall(mgr, npmCmd, npmArgs, proxy.URL(), cfg.IgnoreScripts)
	pm := exec.Command(inv.name, inv.args...)
	pm.Stdout, pm.Stderr, pm.Stdin = os.Stdout, os.Stderr, os.Stdin
	pm.Env = append(os.Environ(), inv.env...)
	npmErr := pm.Run()

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
		return fmt.Errorf("%s %s failed: %w", inv.name, npmCmd, npmErr)
	}

	// 4. Script-bearing packages: detect → approve → box (§7, §8). This reads
	// package-lock.json to enumerate packages, so it's npm-only; under pnpm/yarn
	// scripts simply stayed disabled (--ignore-scripts above) and the lockfile
	// re-check below still runs over all three managers.
	if cfg.IgnoreScripts && mgr == "npm" {
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
	} else if cfg.IgnoreScripts && mgr != "npm" {
		fmt.Fprintf(os.Stderr,
			"guard: %s install ran with lifecycle scripts disabled. Boxed script\n"+
				"       approval is npm-only for now — if a dependency's postinstall is\n"+
				"       genuinely needed, review and run it manually. Lockfile re-checked below.\n",
			mgr)
	}

	// 5. Re-check the FINAL lockfile (§3 layer 5): advisories AND cooldown.
	// Both run so each prints its own findings; the advisory gate takes the
	// exit code first (matching cmdCheck's precedence). Freshness is re-applied
	// here so install-time enforcement matches `guard check`: a too-fresh
	// version that entered via a pinned lockfile (guard ci, or npm honoring an
	// existing pin) skips the proxy's packument filter and would otherwise only
	// be caught later at commit/push. Scope is git-diff (all=false) like the
	// hook, so only versions THIS install introduced are vetted.
	wf, err := waivers.Load(dir)
	if err != nil {
		return err
	}
	// Same severity tiering as 'guard check' (moderate/low warn, high+/MAL/unknown
	// block), but no interactive confirm here — install isn't the commit/push gate.
	advErr := checkAdvisories(dir, false, false, cfg.AdvisoryThreshold, wf)
	freshErr := checkFreshness(dir, false, false, wf)
	if advErr != nil {
		return advErr
	}
	return freshErr
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
		fmt.Println("   " + ui.Warn() + " NEW since the previous version:")
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
	fmt.Println("   " + ui.Warn() + " No container runtime found (docker/podman).")
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
			fmt.Fprintf(os.Stderr, "\nguard: %s %s behaved MALICIOUSLY in the box:\n", ui.Bad(), key)
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
	quiet, all, jsonOut, confirm := false, false, false, false
	for _, a := range args {
		switch a {
		case "--quiet":
			quiet = true
		case "--all":
			all = true // force full-tree freshness check, not just the git diff
		case "--json":
			jsonOut = true
		case "--confirm":
			// Interactive gate for warn-tier advisories: prompt on a terminal
			// before proceeding, recording acceptances. The git hooks pass this;
			// CI (no terminal) sees warnings print without prompting.
			confirm = true
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
	wf, err := waivers.Load(dir)
	if err != nil {
		return err
	}
	advErr := checkAdvisories(dir, quiet, confirm, cfg.AdvisoryThreshold, wf)
	freshErr := checkFreshness(dir, quiet, all, wf)
	intErr := checkLockfileIntegrity(dir, cfg, wf, quiet)
	licErr := checkLicenses(dir, cfg, wf, quiet)
	var provErr error
	if cfg.Flagged("provenance") {
		provErr = checkProvenance(dir, cfg, quiet)
	}
	// Informational diff signals (never gate the commit/PR). Run here so a
	// new-deps heads-up rides the same `guard check` the hooks already run.
	if cfg.Flagged("new-deps") {
		reportNewDeps(dir, quiet)
	}
	if cfg.Flagged("new-maintainer") {
		checkMaintainers(dir, cfg, quiet)
	}
	// One-line rollup so the overall verdict is scannable regardless of how many
	// checkers printed above (and lands as a single line in CI logs).
	if !quiet {
		printCheckSummary(dir, map[string]error{
			"advisories": advErr,
			"cooldown":   freshErr,
			"integrity":  intErr,
			"licenses":   licErr,
			"provenance": provErr,
		})
	}
	// First gate to trip wins the exit code; all of them already printed.
	if advErr != nil {
		return advErr
	}
	if intErr != nil {
		return intErr
	}
	if licErr != nil {
		return licErr
	}
	if provErr != nil {
		return provErr
	}
	return freshErr
}

// printCheckSummary prints the single-line verdict for guard check: the
// dependency count and either "no issues" or the list of gates that tripped.
// Skipped entirely when there's no lockfile (the checkers already said so).
func printCheckSummary(dir string, gates map[string]error) {
	pkgs, err := lockfile.Installed(dir)
	if err != nil {
		return // no lockfile / unreadable — the per-checker output already covered it
	}
	var tripped []string
	for name, gerr := range gates {
		if gerr != nil {
			tripped = append(tripped, name)
		}
	}
	sort.Strings(tripped) // deterministic order (map iteration is random)
	if len(tripped) == 0 {
		fmt.Printf("guard: %s %d dependency(s) checked — no issues\n", ui.OK(), len(pkgs))
		return
	}
	fmt.Fprintf(os.Stderr, "guard: %s %d dependency(s) — gating: %s\n", ui.Bad(), len(pkgs), strings.Join(tripped, ", "))
}

// CheckResult is the structured outcome of a `guard check` — the shape emitted
// by --json and returned by the MCP server's check tool.
type CheckResult struct {
	// Advisories are the BLOCKING advisory hits — severity at/above the
	// configured threshold, plus MAL-* and any unknown/unscored hit (fail
	// closed). These flip OK to false.
	Advisories []advisory.Vuln `json:"advisories"`
	// AdvisoryWarnings are hits BELOW the threshold (e.g. moderate/low when
	// threshold is high). Surfaced for visibility but never gate — OK ignores
	// them. On an interactive `guard check --confirm` the human is asked to
	// accept these before the commit/push proceeds.
	AdvisoryWarnings []advisory.Vuln       `json:"advisoryWarnings,omitempty"`
	Cooldown         []freshness.Violation `json:"cooldownViolations"`
	OffRegistry      []string              `json:"offRegistry"`
	Unhashed         []string              `json:"unhashed"`
	NewDeps          []string              `json:"newDeps"`
	Maintainers      []maintainer.Change   `json:"maintainerChanges"`
	License          []license.Violation   `json:"licenseViolations,omitempty"`
	Provenance       []attestation.Result  `json:"provenance,omitempty"`
	Waived           []string              `json:"waived,omitempty"`
	// Degraded names layers that could NOT run this check (e.g. OSV unreachable,
	// a registry fetch failed). The check stays fail-open — these don't flip OK —
	// but a non-empty Degraded means a green result is INCOMPLETE, not proven
	// clean. Surfacing it is what keeps --json/MCP from hiding an outage.
	Degraded []string `json:"degraded,omitempty"`
	OK       bool     `json:"ok"`
}

// ─── waiver identity + filtering ─────────────────────────────────────────────
//
// These build the stable, version-pinned ID under which a human waives a gating
// finding in .guard-ignores, and filter actively-waived findings out of the
// gates. They are the SINGLE source of truth for waiver IDs, shared by the
// human-prose path (cmdCheck's three checkers) and the structured path
// (gatherCheck / the MCP server), so the two never disagree about what is or
// isn't waived. The kind prefix keeps categories unambiguous; the name@version
// pin means a waiver lapses when the package moves — the new version is judged
// on its own (DESIGN.md §13).

// advisoryWaiverID is "advisory:<name>@<version>:<osv-id>".
func advisoryWaiverID(v advisory.Vuln) string {
	return fmt.Sprintf("advisory:%s@%s:%s", v.Package, v.Version, v.ID)
}

// cooldownWaiverID is "cooldown:<name>@<version>".
func cooldownWaiverID(v freshness.Violation) string {
	return fmt.Sprintf("cooldown:%s@%s", v.Name, v.Version)
}

// offRegistryWaiverID / unhashedWaiverID take a lockfile key ("name@version").
func offRegistryWaiverID(key string) string { return "off-registry:" + key }
func unhashedWaiverID(key string) string    { return "unhashed:" + key }

// licenseWaiverID is "license:<name>@<version>" — version-pinned like the rest,
// so the waiver lapses when the package moves (a new version is re-judged).
func licenseWaiverID(v license.Violation) string {
	return fmt.Sprintf("license:%s@%s", v.Name, v.Version)
}

// waiverReason renders " — <reason>" for display, or "" when none was given.
func waiverReason(e waivers.Entry) string {
	if e.Reason == "" {
		return ""
	}
	return " — " + e.Reason
}

// waivedActive reports whether id has an in-force (non-expired) waiver.
func waivedActive(wf *waivers.File, id string, now time.Time) bool {
	_, st := wf.Check(id, now)
	return st == waivers.Active
}

// activeAdvisories drops advisory hits an active waiver suppresses, recording
// each suppressed ID in *waived. Expired waivers do NOT suppress (fail closed).
func activeAdvisories(vulns []advisory.Vuln, wf *waivers.File, now time.Time, waived *[]string) []advisory.Vuln {
	var out []advisory.Vuln
	for _, v := range vulns {
		id := advisoryWaiverID(v)
		if waivedActive(wf, id, now) {
			*waived = append(*waived, id)
			continue
		}
		out = append(out, v)
	}
	return out
}

// activeCooldown is activeAdvisories for cooldown violations.
func activeCooldown(viol []freshness.Violation, wf *waivers.File, now time.Time, waived *[]string) []freshness.Violation {
	var out []freshness.Violation
	for _, v := range viol {
		id := cooldownWaiverID(v)
		if waivedActive(wf, id, now) {
			*waived = append(*waived, id)
			continue
		}
		out = append(out, v)
	}
	return out
}

// enrichSeverities populates each hit's Severity from OSV's per-vuln detail
// endpoint (querybatch carries none). Distinct ids are fetched once; a hit OSV
// could not score stays SevUnknown — which BLOCKS under the fail-closed policy,
// so a flaky detail fetch only ever makes the gate stricter.
func enrichSeverities(vulns []advisory.Vuln) []advisory.Vuln {
	if len(vulns) == 0 {
		return vulns
	}
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}
	sev := advisory.Severities(ids)
	for i := range vulns {
		if s, ok := sev[vulns[i].ID]; ok {
			vulns[i].Severity = s
		} else {
			vulns[i].Severity = advisory.SevUnknown
		}
	}
	return vulns
}

// partitionBySeverity splits enriched hits into blockers (gate the action) and
// warnings (surfaced, never gate) using each hit's Blocks(threshold) verdict.
func partitionBySeverity(vulns []advisory.Vuln, threshold advisory.Severity) (blockers, warnings []advisory.Vuln) {
	for _, v := range vulns {
		if v.Blocks(threshold) {
			blockers = append(blockers, v)
		} else {
			warnings = append(warnings, v)
		}
	}
	return blockers, warnings
}

// gatherCheck runs every check over the lockfile and returns the structured
// result WITHOUT printing — the single source of truth behind both
// `guard check --json` and the MCP check tool. The human-prose path in
// cmdCheck stays separate (different output contract), but both read the same
// underlying internal packages.
func gatherCheck(dir string, cfg config.Config, all bool) (CheckResult, error) {
	var res CheckResult
	wf, err := waivers.Load(dir)
	if err != nil {
		return res, err
	}
	now := time.Now()
	pkgs, err := lockfile.Installed(dir)
	if err != nil {
		if os.IsNotExist(err) {
			res.OK = true
			return res, nil
		}
		return res, err
	}
	// OSV is meaningless for a loopback/mock registry (those versions aren't in
	// OSV's public npm namespace) — same skip the proxy applies. For a real
	// registry, a lookup failure is recorded as DEGRADED rather than swallowed:
	// the advisory layer stays fail-open (an OSV outage must not block every
	// commit), but a green --json/MCP result can no longer hide that it didn't run.
	if !isLoopbackHost(hostOf(cfg.Registry)) {
		if v, err := advisory.Check(pkgs); err != nil {
			res.Degraded = append(res.Degraded, "advisory check skipped: "+err.Error())
		} else {
			active := activeAdvisories(v, wf, now, &res.Waived)
			active = enrichSeverities(active)
			// Split into blocking (>= threshold, or MAL-*/unknown) and warn-only
			// (below threshold). Only blockers flip OK; warnings are surfaced.
			res.Advisories, res.AdvisoryWarnings = partitionBySeverity(active, cfg.AdvisoryThreshold)
		}
	}
	regHost := hostOf(cfg.Registry)
	for _, p := range pkgs {
		if cfg.Allowed(p.Name) || (!strings.HasPrefix(p.Resolved, "http://") && !strings.HasPrefix(p.Resolved, "https://")) {
			continue
		}
		if h := hostOf(p.Resolved); h != regHost && !isLoopbackHost(h) {
			if id := offRegistryWaiverID(p.Key()); waivedActive(wf, id, now) {
				res.Waived = append(res.Waived, id)
			} else {
				res.OffRegistry = append(res.OffRegistry, p.Key())
			}
		}
		if p.Integrity == "" {
			if id := unhashedWaiverID(p.Key()); waivedActive(wf, id, now) {
				res.Waived = append(res.Waived, id)
			} else {
				res.Unhashed = append(res.Unhashed, p.Key())
			}
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
	viol, warns := freshness.Check(cfg.Registry, fresh, cfg.Cooldown, cfg.Allowed)
	if len(viol) > 0 {
		res.Cooldown = activeCooldown(viol, wf, now, &res.Waived)
	}
	// Per-package fetch failures are fail-open too — but recorded, not dropped.
	res.Degraded = append(res.Degraded, warns...)
	if cfg.Flagged("new-maintainer") {
		if ch, _ := maintainer.Check(cfg.Registry, pkgs, cfg.Allowed, nil); len(ch) > 0 {
			res.Maintainers = ch
		}
	}
	// License gate (no-op unless a deny/allow list is configured). Reads
	// node_modules; an absent tree is recorded as degraded, not a clean pass.
	if len(cfg.LicenseDeny) > 0 || len(cfg.LicenseAllow) > 0 {
		if entries, lerr := lockfile.InstalledPaths(dir); lerr == nil {
			lres := license.Check(dir, entries, cfg.LicenseDeny, cfg.LicenseAllow)
			if lres.Degraded {
				res.Degraded = append(res.Degraded, "license check incomplete: node_modules missing for some packages")
			}
			res.License = activeLicense(lres.Violations, wf, now, &res.Waived)
		}
	}
	// Build-provenance gate (flag-gated, opt-in). Only INVALID attestations gate;
	// verified/absent are informational. One registry fetch per package, so it's
	// off by default.
	invalidProv := 0
	if cfg.Flagged("provenance") {
		apkgs := make([]attestation.Pkg, 0, len(pkgs))
		for _, p := range pkgs {
			apkgs = append(apkgs, attestation.Pkg{Name: p.Name, Version: p.Version, Integrity: p.Integrity})
		}
		client := &http.Client{Timeout: 30 * time.Second}
		res.Provenance = attestation.Check(client, cfg.Registry, apkgs, cfg.Allowed, nil)
		for _, r := range res.Provenance {
			if r.Status == attestation.StatusInvalid {
				invalidProv++
			}
		}
	}
	// res.Advisories is blockers-only (warnings live in AdvisoryWarnings and do
	// not gate), so OK keys off it directly.
	res.OK = len(res.Advisories) == 0 && len(res.Cooldown) == 0 && len(res.OffRegistry) == 0 && len(res.Unhashed) == 0 && len(res.License) == 0 && invalidProv == 0
	return res, nil
}

// checkLockfileIntegrity flags lockfile entries whose tarball resolves OFF the
// configured registry (a poisoned lockfile silently redirecting a fetch to an
// attacker host) or that carry no integrity hash (npm can't verify the
// download). Both are tamper signatures a hand-edited or malicious lockfile
// leaves behind. Allowlisted packages bypass — a deliberately alternate source
// is the human's call. Gates the check like the advisory layer.
func checkLockfileIntegrity(dir string, cfg config.Config, wf *waivers.File, quiet bool) error {
	pkgs, err := lockfile.Installed(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	regHost := hostOf(cfg.Registry)
	now := time.Now()
	var offReg, noHash []string
	// waiveOrKeep routes one integrity finding: an active waiver suppresses it
	// (shown muted), an expired waiver re-gates it loudly, otherwise it gates.
	waiveOrKeep := func(id, display string, into *[]string) {
		e, st := wf.Check(id, now)
		switch st {
		case waivers.Active:
			if !quiet {
				fmt.Fprintf(os.Stderr, "guard: %s integrity waived %s%s\n", ui.Waived(), id, waiverReason(e))
			}
		case waivers.Expired:
			fmt.Fprintf(os.Stderr, "guard: %s integrity waiver EXPIRED (%s) for %s — re-review or renew\n", ui.Warn(), e.Expires, id)
			*into = append(*into, display)
		default:
			*into = append(*into, display)
		}
	}
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
			waiveOrKeep(offRegistryWaiverID(p.Key()),
				fmt.Sprintf("%s — tarball host %q ≠ registry %q", p.Key(), h, regHost), &offReg)
		}
		if p.Integrity == "" {
			waiveOrKeep(unhashedWaiverID(p.Key()), p.Key(), &noHash)
		}
	}
	if len(offReg) == 0 && len(noHash) == 0 {
		if !quiet {
			fmt.Printf("guard: lockfile integrity ok (%d version(s)) %s\n", len(pkgs), ui.OK())
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
	fmt.Fprintln(os.Stderr, "guard: a tarball off-registry or without a hash can't be verified — allowlist in .guardrc, or — if reviewed — guard ignore off-registry:<name>@<version> / unhashed:<name>@<version>")
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
	changes, warnings := maintainer.Check(cfg.Registry, pkgs, cfg.Allowed, progressPrinter("maintainers", quiet))
	for _, w := range warnings {
		if !quiet {
			fmt.Fprintln(os.Stderr, "guard: maintainer check skipped for", w)
		}
	}
	if len(changes) == 0 {
		if !quiet {
			fmt.Println("guard: no maintainer/publisher changes on installed versions " + ui.OK())
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
			fmt.Println("guard: no new dependencies vs HEAD " + ui.OK())
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
func checkFreshness(dir string, quiet, all bool, wf *waivers.File) error {
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
			fmt.Println("guard: no new lockfile versions to cooldown-check " + ui.OK())
		}
		return nil
	}

	violations, warnings := freshness.Check(cfg.Registry, pkgs, cfg.Cooldown, cfg.Allowed)
	for _, w := range warnings {
		// Fail-open on per-package fetch errors, but loudly: a registry blip
		// must not block every commit in every repo.
		fmt.Fprintln(os.Stderr, "guard: freshness check skipped for", w)
	}
	// Drop violations a human has reviewed and waived (still shown, muted); an
	// expired waiver re-gates and is reported.
	now := time.Now()
	var active []freshness.Violation
	for _, v := range violations {
		id := cooldownWaiverID(v)
		e, st := wf.Check(id, now)
		switch st {
		case waivers.Active:
			if !quiet {
				fmt.Fprintf(os.Stderr, "guard: %s cooldown waived %s%s\n", ui.Waived(), id, waiverReason(e))
			}
		case waivers.Expired:
			fmt.Fprintf(os.Stderr, "guard: %s cooldown waiver EXPIRED (%s) for %s — re-review or renew\n", ui.Warn(), e.Expires, id)
			active = append(active, v)
		default:
			active = append(active, v)
		}
	}
	if len(active) == 0 {
		if !quiet {
			fmt.Printf("guard: %d version(s) cooldown-checked (%s), all clear %s\n", len(pkgs), scope, ui.OK())
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "guard: %d version(s) inside the %s cooldown:\n", len(active), cfg.Cooldown)
	for _, v := range active {
		if v.Age == 0 {
			fmt.Fprintf(os.Stderr, "  %s@%s — no publish timestamp (unknown age)\n", v.Name, v.Version)
		} else {
			fmt.Fprintf(os.Stderr, "  %s@%s — published %dd ago, clears cooldown in %s\n",
				v.Name, v.Version, int(v.Age.Hours()/24), fmtRemaining(v.Remaining))
		}
	}
	fmt.Fprintln(os.Stderr, "guard: wait out the cooldown, pin an older version, allowlist in .guardrc, or — if reviewed — guard ignore cooldown:<name>@<version>")
	return fmt.Errorf("%d version(s) violate the cooldown", len(active))
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

// activeLicense drops license violations an active waiver suppresses, recording
// each suppressed ID in *waived. Mirrors activeAdvisories/activeCooldown.
func activeLicense(viol []license.Violation, wf *waivers.File, now time.Time, waived *[]string) []license.Violation {
	var out []license.Violation
	for _, v := range viol {
		id := licenseWaiverID(v)
		if waivedActive(wf, id, now) {
			*waived = append(*waived, id)
			continue
		}
		out = append(out, v)
	}
	return out
}

// checkLicenses gates on the .guardrc license policy (deny / allow lists). It's
// a no-op when neither list is set. Reads node_modules for each package's
// declared license; a missing tree DEGRADES the check (warned, never silently
// green) rather than gating. Non-waived violations fail the commit/PR.
func checkLicenses(dir string, cfg config.Config, wf *waivers.File, quiet bool) error {
	if len(cfg.LicenseDeny) == 0 && len(cfg.LicenseAllow) == 0 {
		return nil // gate disabled
	}
	entries, err := lockfile.InstalledPaths(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no npm lockfile — nothing to check
		}
		return err
	}
	res := license.Check(dir, entries, cfg.LicenseDeny, cfg.LicenseAllow)
	if res.Degraded && !quiet {
		fmt.Fprintf(os.Stderr, "guard: %s license check incomplete — node_modules missing for some packages (run an install first)\n", ui.Warn())
	}
	now := time.Now()
	var active []license.Violation
	for _, v := range res.Violations {
		id := licenseWaiverID(v)
		e, st := wf.Check(id, now)
		switch st {
		case waivers.Active:
			if !quiet {
				fmt.Fprintf(os.Stderr, "guard: %s license waived %s%s\n", ui.Waived(), id, waiverReason(e))
			}
		case waivers.Expired:
			fmt.Fprintf(os.Stderr, "guard: %s license waiver EXPIRED (%s) for %s — re-review or renew\n", ui.Warn(), e.Expires, id)
			active = append(active, v)
		default:
			active = append(active, v)
		}
	}
	if len(active) == 0 {
		if !quiet && len(res.Violations) == 0 {
			fmt.Printf("guard: license policy OK %s\n", ui.OK())
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "guard: %d license violation(s):\n", len(active))
	for _, v := range active {
		fmt.Fprintf(os.Stderr, "  %s@%s — %s (%s)\n", v.Name, v.Version, v.License, v.Reason)
	}
	fmt.Fprintf(os.Stderr, "guard: reviewed and accepting one? → guard ignore license:%s@%s --reason \"...\"\n",
		active[0].Name, active[0].Version)
	return fmt.Errorf("%d license violation(s)", len(active))
}

// checkProvenance verifies npm build-provenance (Sigstore) attestations for the
// installed packages — flag-gated ("provenance") and opt-in, because most
// packages don't publish attestations yet so an unconditional run would be
// noisy and slow (one registry fetch per package). A VERIFIED result reports
// the attested source repo; an INVALID one (attestation present but signature,
// cert chain, or digest binding failed) is a tamper signal that GATES. Absent
// attestations are not reported and never gate. Network errors fail open.
func checkProvenance(dir string, cfg config.Config, quiet bool) error {
	pkgs, err := lockfile.Installed(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	apkgs := make([]attestation.Pkg, 0, len(pkgs))
	for _, p := range pkgs {
		apkgs = append(apkgs, attestation.Pkg{Name: p.Name, Version: p.Version, Integrity: p.Integrity})
	}
	client := &http.Client{Timeout: 30 * time.Second}
	verified, invalid := 0, 0
	for _, r := range attestation.Check(client, cfg.Registry, apkgs, cfg.Allowed, progressPrinter("provenance", quiet)) {
		switch r.Status {
		case attestation.StatusVerified:
			verified++
			if !quiet {
				fmt.Printf("guard: %s provenance %s@%s ← %s\n", ui.OK(), r.Name, r.Version, r.Source)
			}
		case attestation.StatusInvalid:
			invalid++
			fmt.Fprintf(os.Stderr, "guard: %s provenance INVALID for %s@%s — %s\n", ui.Bad(), r.Name, r.Version, r.Reason)
		}
	}
	if !quiet && verified > 0 {
		fmt.Printf("guard: %d package(s) with verified build provenance %s\n", verified, ui.OK())
	}
	if invalid > 0 {
		return fmt.Errorf("%d package(s) with INVALID provenance attestation", invalid)
	}
	return nil
}

// checkAdvisories queries OSV for every installed version and fails when any
// advisory hits — the "installed last month, reported yesterday" recovery layer.
func checkAdvisories(dir string, quiet, confirm bool, threshold advisory.Severity, wf *waivers.File) error {
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
	// Partition into still-gating hits and the ones a human has reviewed and
	// waived in .guard-ignores. Waived hits are shown (muted) but never gate;
	// a lapsed waiver re-gates and is called out loudly.
	now := time.Now()
	var active []advisory.Vuln
	for _, v := range vulns {
		id := advisoryWaiverID(v)
		e, st := wf.Check(id, now)
		switch st {
		case waivers.Active:
			if !quiet {
				fmt.Fprintf(os.Stderr, "guard: %s advisory waived %s%s\n", ui.Waived(), id, waiverReason(e))
			}
		case waivers.Expired:
			fmt.Fprintf(os.Stderr, "guard: %s advisory waiver EXPIRED (%s) for %s — re-review or renew\n", ui.Warn(), e.Expires, id)
			active = append(active, v)
		default:
			active = append(active, v)
		}
	}
	if len(active) == 0 {
		if !quiet {
			fmt.Printf("guard: %d installed package(s), no advisory hits %s\n", len(pkgs), ui.OK())
		}
		return nil
	}
	// Score the live hits and split: at/above the threshold (plus MAL-* and any
	// unknown/unscored hit) BLOCKS; below the threshold WARNS (DESIGN.md §5).
	active = enrichSeverities(active)
	blockers, warns := partitionBySeverity(active, threshold)

	// Warnings are always shown and never gate on their own.
	if len(warns) > 0 {
		fmt.Fprintf(os.Stderr, "guard: %s %d advisory warning(s) below the %s threshold (not blocking):\n", ui.Warn(), len(warns), threshold)
		for _, v := range warns {
			fmt.Fprintf(os.Stderr, "  [%s] %s@%s — %s: %s\n", v.Severity, v.Package, v.Version, v.ID, truncate(v.Summary, 100))
		}
	}

	// Blockers gate unconditionally — the confirm flow does NOT apply to them.
	// (Accept a specific blocker deliberately with 'guard ignore'.)
	if len(blockers) > 0 {
		fmt.Fprintf(os.Stderr, "guard: %s %d blocking advisory hit(s) on installed packages:\n", ui.Bad(), len(blockers))
		for _, v := range blockers {
			fmt.Fprintf(os.Stderr, "  [%s] %s@%s — %s: %s\n", v.Severity, v.Package, v.Version, v.ID, truncate(v.Summary, 100))
		}
		fmt.Fprintf(os.Stderr, "guard: reviewed and accepting one? → guard ignore advisory:%s@%s:%s --reason \"...\"\n",
			blockers[0].Package, blockers[0].Version, blockers[0].ID)
		return fmt.Errorf("%d vulnerable package(s) installed", len(blockers))
	}

	// Only warnings remain. Without --confirm (a direct 'guard check' or CI),
	// they were printed above and don't gate — proceed.
	if !confirm || len(warns) == 0 {
		return nil
	}
	// Interactive --confirm: ask before proceeding, and record acceptances so
	// the human can later see what was waved through and when.
	accepted, interactive, err := confirmThroughWarnings(dir, warns, wf)
	if err != nil {
		return err
	}
	if !interactive {
		// No terminal to ask at (CI, a piped hook): warnings print, action proceeds.
		return nil
	}
	if !accepted {
		return fmt.Errorf("commit/push aborted — %d advisory warning(s) not accepted", len(warns))
	}
	return nil
}

// confirmThroughWarnings asks, on the controlling terminal, whether to proceed
// past warn-tier advisory hits. On "yes" it records each as a waiver in
// .guard-ignores — both the audit trail of what was accepted (and when) and the
// thing that suppresses the same hit on later runs. interactive is false when
// there is no terminal to ask at (CI, a piped hook); the caller then proceeds
// without recording. Reads /dev/tty directly, not stdin, because a git hook's
// stdin carries ref data, not the keyboard.
func confirmThroughWarnings(dir string, warns []advisory.Vuln, wf *waivers.File) (accepted, interactive bool, err error) {
	// Note: open /dev/tty (the controlling terminal) rather than reading os.Stdin
	// like promptYN does — a git hook's stdin is ref data or /dev/null, not the
	// keyboard. A failed open means "no terminal" (CI), the non-interactive path.
	ttyf, e := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if e != nil {
		return false, false, nil // no terminal — caller proceeds, no record
	}
	defer ttyf.Close()
	fmt.Fprintf(ttyf, "\nguard: accept the %d warning advisory(ies) above and proceed? [y/N] ", len(warns))
	line, _ := bufio.NewReader(ttyf).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		reason := "accepted " + time.Now().UTC().Format("2006-01-02") + " via guard check --confirm"
		for _, v := range warns {
			if e := wf.Set(advisoryWaiverID(v), reason, ""); e != nil {
				return false, true, e
			}
		}
		if e := wf.Save(dir); e != nil {
			return false, true, e
		}
		fmt.Fprintf(ttyf, "guard: recorded %d acceptance(s) in %s\n", len(warns), waivers.FileName)
		return true, true, nil
	default:
		fmt.Fprintln(ttyf, "guard: not accepted — aborting.")
		return false, true, nil
	}
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
		fmt.Println("guard: no capability/injection findings " + ui.OK())
		return nil
	}
	for _, f := range rep.Findings {
		fmt.Printf("[%s] %s (%s)\n", f.Severity, f.What, f.Where)
	}
	return nil
}

// ─── guard approve ───────────────────────────────────────────────────────────

// cmdWhy explains why a package is present: it prints the dependency path(s)
// from a direct dependency down to the named package — the first question when
// `guard check` flags a transitive dep you don't recognize ("which of MY deps
// dragged this in?"). The graph is name-level (versions are reported in the
// header but not used for routing), and npm-only: pnpm/yarn lockfiles don't
// carry a graph we parse zero-dep, so those users get a clear message.
//
// Accepts a bare name or "name@version" (the version is ignored for routing).
// Without --all it caps output at whyMaxPaths to keep deep graphs readable.
func cmdWhy(args []string) error {
	const whyMaxPaths = 20
	target, maxPaths := "", whyMaxPaths
	for _, a := range args {
		switch {
		case a == "--all":
			maxPaths = 0 // uncapped
		case strings.HasPrefix(a, "-"):
			// ignore unknown flags — keep the surface forgiving
		case target == "":
			target = a
		}
	}
	if target == "" {
		return fmt.Errorf("usage: guard why <package> [--all]")
	}
	if at := strings.LastIndex(target, "@"); at > 0 { // tolerate name@version
		target = target[:at]
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	g, err := lockfile.BuildGraph(dir)
	if os.IsNotExist(err) {
		return fmt.Errorf("guard why needs an npm package-lock.json (pnpm/yarn dependency graphs aren't supported)")
	}
	if err != nil {
		return err
	}

	versions := g.SortedVersions(target)
	if len(versions) == 0 && !g.Roots[target] {
		fmt.Printf("%s %s is not in the lockfile (not installed)\n", ui.Warn(), target)
		return nil
	}
	if len(versions) > 0 {
		fmt.Printf("%s %s @ %s\n", ui.OK(), target, strings.Join(versions, ", "))
	} else {
		fmt.Printf("%s %s\n", ui.OK(), target)
	}
	if g.Roots[target] {
		fmt.Printf("  %s direct dependency of this project\n", ui.Dim("•"))
	}

	// Only multi-hop paths are interesting; the root-only path restates the
	// "direct dependency" line above.
	var shown [][]string
	for _, p := range g.Paths(target, maxPaths) {
		if len(p) > 1 {
			shown = append(shown, p)
		}
	}
	if len(shown) == 0 {
		if !g.Roots[target] {
			fmt.Printf("  %s present but not reachable from any direct dependency (orphaned lockfile entry)\n", ui.Dim("•"))
		}
		return nil
	}
	fmt.Printf("  pulled in by:\n")
	for _, p := range shown {
		fmt.Println("    " + strings.Join(p, " › "))
	}
	if maxPaths > 0 && len(shown) >= maxPaths {
		fmt.Printf("  %s\n", ui.Dim(fmt.Sprintf("(showing first %d paths — run with --all for every path)", maxPaths)))
	}
	return nil
}

// cmdSbom writes a Software Bill of Materials for the installed dependency set
// to stdout — an audit/compliance artifact straight from the lockfile depguard
// already trusts as its source of truth. Default format is CycloneDX 1.5 JSON;
// --spdx switches to SPDX 2.3 JSON. Works for any lockfile lockfile.Installed
// understands (npm/pnpm/yarn).
func cmdSbom(args []string) error {
	format := "cyclonedx"
	for _, a := range args {
		switch a {
		case "--spdx":
			format = "spdx"
		case "--cyclonedx":
			format = "cyclonedx"
		}
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	pkgs, err := lockfile.Installed(dir)
	if os.IsNotExist(err) {
		return fmt.Errorf("no lockfile found (package-lock.json / pnpm-lock.yaml / yarn.lock) — nothing to bill")
	}
	if err != nil {
		return err
	}
	meta := sbom.Meta{ToolVersion: version}
	meta.Name, meta.Version = projectMeta(dir)

	var out []byte
	if format == "spdx" {
		out, err = sbom.SPDX(meta, pkgs)
	} else {
		out, err = sbom.CycloneDX(meta, pkgs)
	}
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

// projectMeta reads name+version from the repo's package.json, falling back to
// the directory's base name when there's no manifest (a bare lockfile).
func projectMeta(dir string) (name, ver string) {
	name = filepath.Base(dir)
	if raw, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil {
		var pj struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(raw, &pj) == nil {
			if pj.Name != "" {
				name = pj.Name
			}
			ver = pj.Version
		}
	}
	return name, ver
}

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

// ─── guard ignore ────────────────────────────────────────────────────────────

// cmdIgnore manages .guard-ignores — the per-issue waivers that stop a REVIEWED
// finding from gating commit/push/PR/CI (DESIGN.md §13). It is deliberately
// low-friction (one ID waives one finding — copy the `guard ignore …` line
// `guard check` prints for the finding you accept) but purposeful: the ID is
// pinned to an exact name@version + kind, and a --reason / --expires are
// encouraged so the waiver is auditable and self-retiring.
//
//	guard ignore <issue-id> [--reason "..."] [--expires 30d|YYYY-MM-DD]
//	guard ignore --list
//	guard ignore --remove <issue-id>
func cmdIgnore(args []string) error {
	var id, reason, expires string
	list, remove := false, false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "--list":
			list = true
		case "--remove", "--rm":
			remove = true
		case "--reason":
			if i+1 >= len(args) {
				return fmt.Errorf("--reason needs a value")
			}
			i++
			reason = args[i]
		case "--expires", "--expire":
			if i+1 >= len(args) {
				return fmt.Errorf("--expires needs a value (e.g. 30d or 2026-07-01)")
			}
			i++
			expires = args[i]
		default:
			if strings.HasPrefix(a, "-") {
				return fmt.Errorf("unknown flag %s", a)
			}
			id = a
		}
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	wf, err := waivers.Load(dir)
	if err != nil {
		return err
	}

	if list {
		ids := wf.IDs()
		if len(ids) == 0 {
			fmt.Println("guard: no waivers recorded (.guard-ignores is empty)")
			return nil
		}
		now := time.Now()
		fmt.Printf("guard: %d waiver(s) in %s:\n", len(ids), waivers.FileName)
		for _, w := range ids {
			e, st := wf.Check(w, now)
			tag := "active"
			if st == waivers.Expired {
				tag = "EXPIRED"
			}
			exp := "never"
			if e.Expires != "" {
				exp = e.Expires
			}
			fmt.Printf("  [%s] %s  (expires: %s)%s\n", tag, w, exp, waiverReason(e))
		}
		return nil
	}

	if id == "" {
		return fmt.Errorf("usage: guard ignore <issue-id> [--reason \"...\"] [--expires 30d|YYYY-MM-DD]\n" +
			"       guard ignore --list\n" +
			"       guard ignore --remove <issue-id>")
	}
	if !validWaiverID(id) {
		return fmt.Errorf("unrecognized issue id %q — expected one of: "+
			"advisory:<name>@<version>:<osv-id>, cooldown:<name>@<version>, "+
			"off-registry:<name>@<version>, unhashed:<name>@<version>", id)
	}

	if remove {
		if !wf.Remove(id) {
			return fmt.Errorf("no waiver for %q", id)
		}
		if err := wf.Save(dir); err != nil {
			return err
		}
		fmt.Printf("guard: removed waiver %s (commit %s)\n", id, waivers.FileName)
		return nil
	}

	if err := wf.Set(id, reason, expires); err != nil {
		return err
	}
	if err := wf.Save(dir); err != nil {
		return err
	}
	note := ""
	if reason == "" {
		note = " — no reason given; add --reason so the next reviewer knows why"
	}
	fmt.Printf("guard: waived %s (saved to %s — commit it so the waiver travels)%s\n", id, waivers.FileName, note)
	return nil
}

// validWaiverID checks the kind prefix so a typo'd id (which would silently
// never match any finding) is rejected at write time rather than rotting in the
// file. It validates the SHAPE, not that a matching finding currently exists —
// you may pre-empt a finding you expect.
func validWaiverID(id string) bool {
	for _, prefix := range []string{"advisory:", "cooldown:", "off-registry:", "unhashed:", "license:"} {
		if strings.HasPrefix(id, prefix) && len(id) > len(prefix) {
			return true
		}
	}
	return false
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

// ─── guard status ────────────────────────────────────────────────────────────

// cmdStatus answers "is this repo actually protected, right now?" on one screen:
// policy, the committed files, the trigger hooks, the sandbox runtime, and the
// recorded decisions. It is read-only and OFFLINE (no registry/OSV calls), so it
// is safe and instant to run anytime. Color is decoration — every state is also a
// word, so it reads fine piped or under NO_COLOR.
func cmdStatus(args []string) error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	fmt.Printf("%s · %s\n\n", ui.Bold("depguard status"), dir)

	row := func(label, val string) { fmt.Printf("  %-22s %s\n", label, val) }
	have := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	fileState := func(name string) string {
		if !have(name) {
			return ui.Dim("— absent")
		}
		if gitTracked(dir, name) {
			return ui.OK() + " present, tracked"
		}
		return ui.Warn() + " present, NOT committed"
	}

	// Policy
	cfg, cfgErr := config.Load(dir)
	fmt.Println(ui.Bold("policy") + " (.guardrc)")
	switch {
	case cfgErr != nil:
		row("status", ui.Red("✗ invalid: ")+cfgErr.Error())
	case !have(config.FileName):
		row("status", ui.Dim("— using built-in defaults (run 'guard init')"))
	default:
		row("status", ui.OK()+" loaded")
	}
	row("cooldown", fmtCooldown(cfg.Cooldown))
	row("ignore-scripts", fmt.Sprintf("%v", cfg.IgnoreScripts))
	row("allow", listOrNone(cfg.Allow))
	row("internal-scopes", listOrNone(cfg.InternalScopes))
	row("fallback", string(cfg.NoContainerFallback))
	row("flags", listOrNone(cfg.Flag))
	row("license-deny", listOrNone(cfg.LicenseDeny))
	row("license-allow", listOrNone(cfg.LicenseAllow))
	row("provenance", boolState(cfg.Flagged("provenance"), "on", "off (add 'provenance' to flag: to enable)"))

	// Files
	fmt.Println("\n" + ui.Bold("protection files"))
	row(".guardrc", fileState(config.FileName))
	row(".npmrc", npmrcState(dir))
	row(".guard-approvals", fileState(approvals.FileName))
	row(".guard-ignores", fileState(waivers.FileName))

	// Triggers
	fmt.Println("\n" + ui.Bold("triggers"))
	st := hooks.Installed(dir)
	row("pre-commit hook", boolState(st.PreCommit, "installed", "not installed (guard init)"))
	row("pre-push hook", boolState(st.PrePush, "installed", "not installed (guard init)"))
	row("CI PR gate", boolState(st.CIWorkflow, "installed", "not installed (guard init --ci)"))
	if st.Husky {
		row("husky", ui.OK()+" detected (depguard chained onto it)")
	}

	// Sandbox
	fmt.Println("\n" + ui.Bold("sandbox (the box)"))
	if rt := box.Runtime(); rt != "" {
		row("runtime", ui.OK()+" "+rt+ui.Dim("  (obs image builds on first approved script)"))
	} else {
		row("runtime", ui.Warn()+" none — approved builds follow '"+string(cfg.NoContainerFallback)+"'")
	}

	// Decisions
	fmt.Println("\n" + ui.Bold("decisions"))
	row("approvals", approvalSummary(dir))
	row("waivers", waiverSummary(dir))

	// Tools
	fmt.Println("\n" + ui.Bold("tools"))
	row("npm", lookState("npm"))
	row("git", lookState("git"))

	// Verdict — protected means policy loads AND at least one local gate fires.
	fmt.Println()
	if cfgErr == nil && (st.PreCommit || st.PrePush) {
		fmt.Println(ui.Green("→ this repo is protected ") + ui.OK())
	} else {
		fmt.Println(ui.Yellow("→ not fully set up — run 'guard init'"))
	}
	return nil
}

// fmtCooldown renders a duration as "Nd" when it's a whole number of days,
// else the Go duration string — matching how .guardrc is written.
func fmtCooldown(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	}
	return d.String()
}

// progressPrinter returns a (done,total) callback that redraws "label N/M" on a
// single stderr line for liveness during slow per-package network checks, or
// nil when output is quiet or not a TTY (so piped/CI logs stay clean). It emits
// the closing newline itself once done reaches total.
func progressPrinter(label string, quiet bool) func(done, total int) {
	if quiet || !tty.IsTerminalFd(os.Stderr.Fd()) {
		return nil
	}
	return func(done, total int) {
		fmt.Fprintf(os.Stderr, "\rguard: %s %d/%d ", label, done, total)
		if done >= total {
			fmt.Fprintln(os.Stderr)
		}
	}
}

// fmtRemaining renders a cooldown ETA in friendly, rounded-UP units so we never
// under-promise when a version clears: hours under a day, whole days otherwise.
func fmtRemaining(d time.Duration) string {
	if d <= 0 {
		return "moments"
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("~%dh", int((d+time.Hour-1)/time.Hour))
	}
	return fmt.Sprintf("~%dd", int((d+24*time.Hour-1)/(24*time.Hour)))
}

// listOrNone joins a list for display, dimmed "(none)" when empty.
func listOrNone(xs []string) string {
	if len(xs) == 0 {
		return ui.Dim("(none)")
	}
	return strings.Join(xs, ", ")
}

// boolState renders an on/off trigger row.
func boolState(on bool, yes, no string) string {
	if on {
		return ui.OK() + " " + yes
	}
	return ui.Dim("— " + no)
}

// npmrcState reports whether .npmrc pins ignore-scripts + save-exact and is
// committed.
func npmrcState(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, ".npmrc"))
	if err != nil {
		return ui.Dim("— absent")
	}
	s := string(b)
	if !strings.Contains(s, "ignore-scripts=true") {
		return ui.Warn() + " present, ignore-scripts NOT set"
	}
	if !strings.Contains(s, "save-exact=true") {
		return ui.Warn() + " ignore-scripts set, save-exact NOT set"
	}
	if gitTracked(dir, ".npmrc") {
		return ui.OK() + " ignore-scripts + save-exact set, tracked"
	}
	return ui.Warn() + " ignore-scripts + save-exact set, NOT committed"
}

// lookState reports whether a binary is on PATH.
func lookState(bin string) string {
	if _, err := exec.LookPath(bin); err == nil {
		return ui.OK() + " found"
	}
	return ui.Warn() + " not on PATH"
}

// gitTracked reports whether name is a committed file in dir's repo. False when
// there's no git, no repo, or the file isn't tracked — all "not committed".
func gitTracked(dir, name string) bool {
	err := exec.Command("git", "-C", dir, "ls-files", "--error-unmatch", name).Run()
	return err == nil
}

// approvalSummary counts recorded script decisions by kind.
func approvalSummary(dir string) string {
	appr, err := approvals.Load(dir)
	if err != nil || len(appr.Packages) == 0 {
		return ui.Dim("(none)")
	}
	var boxed, unc, denied int
	for _, e := range appr.Packages {
		switch e.Decision {
		case approvals.ApprovedBoxed:
			boxed++
		case approvals.ApprovedUncontained:
			unc++
		case approvals.Denied:
			denied++
		}
	}
	return fmt.Sprintf("%d (%d boxed, %d uncontained, %d denied)", len(appr.Packages), boxed, unc, denied)
}

// waiverSummary counts active vs expired waivers, flagging expiries loudly.
func waiverSummary(dir string) string {
	wf, err := waivers.Load(dir)
	if err != nil || len(wf.Ignores) == 0 {
		return ui.Dim("(none)")
	}
	now := time.Now()
	var active, expired int
	for _, id := range wf.IDs() {
		if _, s := wf.Check(id, now); s == waivers.Expired {
			expired++
		} else {
			active++
		}
	}
	out := fmt.Sprintf("%d active", active)
	if expired > 0 {
		out += ", " + ui.Yellow(fmt.Sprintf("%d EXPIRED", expired)) + " " + ui.Warn() + " (guard ignore --list)"
	}
	return out
}

// ─── guard allow ─────────────────────────────────────────────────────────────

// cmdAllow adds a name/scope to .guardrc's allow list — the command form of the
// cooldown-bypass escape hatch (and the clear for a typosquat name block), so a
// human doesn't hand-edit YAML. Symmetric with guard ignore: edits a committed
// file, dedups, tells you to commit.
func cmdAllow(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: guard allow <pattern>...  (e.g. @yourco/*)")
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	for _, pat := range args {
		added, err := config.AddAllow(dir, pat)
		if err != nil {
			return err
		}
		if added {
			fmt.Printf("guard: allow += %s  (saved to %s — commit it)\n", pat, config.FileName)
		} else {
			fmt.Printf("guard: %s is already allowed\n", pat)
		}
	}
	return nil
}

// ─── guard config ────────────────────────────────────────────────────────────

// cmdConfig shows the effective policy (get/list) or edits one key (set). Every
// set is validated against the same rules Load() enforces, so a command can't
// write a value a later run would reject.
func cmdConfig(args []string) error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	switch {
	case len(args) == 0, args[0] == "get", args[0] == "list":
		cfg, err := config.Load(dir)
		if err != nil {
			return err
		}
		printConfig(cfg)
		return nil
	case args[0] == "set":
		if len(args) < 3 {
			return fmt.Errorf("usage: guard config set <key> <value>")
		}
		key, value := args[1], strings.Join(args[2:], " ")
		canon, err := config.SetValue(dir, key, value)
		if err != nil {
			return err
		}
		fmt.Printf("guard: %s = %s  (saved to %s — commit it)\n", key, canon, config.FileName)
		return nil
	default:
		return fmt.Errorf("usage: guard config [get | set <key> <value>]")
	}
}

// printConfig prints the effective policy (defaults merged with .guardrc).
func printConfig(cfg config.Config) {
	fmt.Printf("cooldown:              %s\n", fmtCooldown(cfg.Cooldown))
	fmt.Printf("ignore-scripts:        %v\n", cfg.IgnoreScripts)
	fmt.Printf("no-container-fallback: %s\n", cfg.NoContainerFallback)
	fmt.Printf("registry:              %s\n", cfg.Registry)
	fmt.Printf("allow:                 %s\n", listOrNone(cfg.Allow))
	fmt.Printf("internal-scopes:       %s\n", listOrNone(cfg.InternalScopes))
	fmt.Printf("flag:                  %s\n", listOrNone(cfg.Flag))
	fmt.Printf("advisory-threshold:    %s\n", cfg.AdvisoryThreshold)
}
