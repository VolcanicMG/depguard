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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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
	"depguard/internal/secrets"
	"depguard/internal/semver"
	"depguard/internal/tty"
	"depguard/internal/ui"
	"depguard/internal/waivers"
)

const version = "1.2.1"

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
	case "secret-add":
		err = cmdSecretAdd(os.Args[2:])
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
  guard check [--quiet] [--json] [--confirm]  re-check repo (advisories, cooldown, integrity, secret files)
  guard scan <dir> [--json]       static-scan one package dir (scripts, caps, injection)
  guard why <package> [--all]     show which direct dep(s) pull a package in (npm lockfile)
  guard sbom [--spdx]             write an SBOM of installed deps to stdout (CycloneDX, or SPDX)
  guard mcp                       run as an MCP server over stdio
  guard approve <name@version>    record a script approval (--uncontained | --deny)
  guard ignore <issue-id>         waive a reviewed check finding (--reason, --expires, --list, --remove)
  guard allow <pattern>...        add a name/scope to .guardrc allow (bypass cooldown)
  guard secret-add <pattern>...   add a file/dir pattern to .guardrc secret-paths (never-commit gate)
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
	hookFiles, hookWarnings, err := hooks.Install(dir, ci)
	if err != nil {
		return err
	}
	wrote = append(wrote, hookFiles...)
	for _, w := range hookWarnings {
		fmt.Fprintf(os.Stderr, "guard: %s %s\n", ui.Warn(), w)
	}

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
			// for the whole tree and this list gets long. Report the DOMINANT
			// reason, not an arbitrary first entry: a package's versions are
			// usually hidden for one reason (a wide advisory range, or "all in
			// cooldown"), and blaming the wrong one misleads diagnosis.
			ex := dominantBlocked(bs)
			fmt.Fprintf(os.Stderr, "  %-30s %d version(s), e.g. %s (%s)\n",
				n, len(bs), ex.Version, ex.Reason)
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

	// 4. Lockfile gates BEFORE any script replay (§3 layer 5). node_modules is
	// already on disk, but nothing has EXECUTED yet — so a tree that fails the
	// advisory, integrity or cooldown gate never gets to run a postinstall.
	// Running these after the scripts (the old order) meant the gate reported on
	// code that had already had its say. Scope is git-diff like the hook, so only
	// versions THIS install introduced are cooldown-vetted.
	wf, err := waivers.Load(dir)
	if err != nil {
		return err
	}
	if err := installGates(dir, cfg, wf); err != nil {
		return err
	}

	// 5. Script-bearing packages: detect → approve → box (§7, §8). This reads
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

	return nil
}

// installGates runs the lockfile gates `guard install` applies to the freshly
// resolved tree, in cmdCheck's order so both commands agree on which finding
// owns the exit code. All three run (each prints its own findings); the first
// one to have tripped decides the error.
//
// Freshness is re-applied here so install-time enforcement matches
// `guard check`: a too-fresh version that entered via a pinned lockfile
// (guard ci, or npm honoring an existing pin) skips the proxy's packument
// filter and would otherwise only be caught later at commit/push. There is no
// interactive confirm — install isn't the commit/push gate.
func installGates(dir string, cfg config.Config, wf *waivers.File) error {
	// The freshly resolved tree IS the working tree here — nothing is staged or
	// pushed yet, so there is no other snapshot to judge.
	snap := worktreeSnapshot(dir)
	advErr := checkAdvisories(snap, cfg, false, false, wf)
	intErr := checkLockfileIntegrity(snap, cfg, wf, false)
	licErr := checkLicenses(snap, cfg, wf, false)
	var provErr error
	if cfg.Flagged("provenance") {
		provErr = checkProvenance(snap, cfg, false)
	}
	freshErr := checkFreshness(snap, cfg, false, false, false, wf, nil, "")
	// Same precedence as cmdCheck, so both commands agree on which finding owns
	// the exit code.
	return firstErr(advErr, intErr, licErr, provErr, freshErr)
}

// firstErr returns the first non-nil error, preserving gate precedence when
// every gate has already run and printed.
func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// reasonCategory collapses a proxy block reason to a stable category so the
// install summary can report WHY most of a package's versions were hidden.
// The raw reasons vary per version (cooldown days, OSV ids), so we bucket them.
func reasonCategory(r string) string {
	switch {
	case strings.HasPrefix(r, "OSV advisory"):
		return "advisory"
	case strings.Contains(r, "cooldown is"):
		return "cooldown"
	case strings.Contains(r, "signature"):
		return "signature"
	case strings.Contains(r, "no publish timestamp"):
		return "no-timestamp"
	default:
		return r
	}
}

// dominantBlocked picks a representative Blocked from a package's filtered
// versions: the first entry of the largest reason-category. Versions are usually
// hidden for one dominant reason (a wide advisory range, or "all in cooldown"),
// so surfacing an arbitrary first entry misreports the cause — e.g. blaming
// cooldown when an OSV advisory hid most versions. Ties break by category name
// for deterministic output.
func dominantBlocked(bs []registry.Blocked) registry.Blocked {
	counts := map[string]int{}
	rep := map[string]registry.Blocked{}
	for _, b := range bs {
		k := reasonCategory(b.Reason)
		counts[k]++
		if _, ok := rep[k]; !ok {
			rep[k] = b
		}
	}
	top := ""
	for k := range counts {
		if top == "" || counts[k] > counts[top] || (counts[k] == counts[top] && k < top) {
			top = k
		}
	}
	return rep[top]
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
		if known && !entry.AppliesTo(e.Integrity) {
			// The decision was about bytes that are no longer what will run.
			fmt.Fprintf(os.Stderr, "guard: approval for %s was for a different tarball (integrity changed) — re-review\n", key)
			known = false
		}
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
			appr.Set(key, decision, "", e.Integrity)
			if err := appr.Save(dir); err != nil {
				return err
			}
			entry = approvals.Entry{Decision: decision}
			if decision == approvals.Denied {
				continue
			}
		}

		// Bind a legacy (unbound) approval to the tarball it is about to run, so
		// from here on a changed tarball re-prompts instead of inheriting the yes.
		if appr.Bind(key, e.Integrity) {
			if err := appr.Save(dir); err != nil {
				return err
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
		res, err := box.Run(runtime, boxImage, boxTraced, cfg.UntracedFail, projectDir, relPath)
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
			// Keep the tarball binding: the denial is about THESE bytes.
			prev, _ := appr.Get(key)
			appr.Set(key, approvals.Denied, "auto-denied: unsafe behavior observed in box", prev.Integrity)
			if err := appr.Save(projectDir); err != nil {
				return err
			}
			return fmt.Errorf("%s attempted malicious actions during install", key)
		}
		if res.Discarded {
			// Not a conviction — a blind spot. The script may well have been
			// fine; we just can't say so, so we don't keep what we couldn't watch.
			if res.ObserverLost {
				// This one has no build-time excuse, so it is discarded under
				// EVERY policy, not just untraced-boxed: fail.
				fmt.Fprintf(os.Stderr, "guard: %s — observer was terminated by the script — output DISCARDED (%s).\n",
					key, res.Summary())
			} else if slices.Contains(res.Truncated, "trace") {
				fmt.Fprintf(os.Stderr, "guard: %s — the script flooded the trace past its cap — output DISCARDED (%s).\n",
					key, res.Summary())
			} else {
				fmt.Fprintf(os.Stderr, "guard: %s — output DISCARDED: observation incomplete (%s) and untraced-boxed is 'fail'.\n",
					key, res.Summary())
			}
			return nil
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
		// Policy is checked at RUN time, not just when the approval was recorded:
		// an entry approved on a machine that had no Docker must not keep running
		// bare after the repo tightened no-container-fallback to 'fail'.
		if !uncontainedAllowed(cfg) {
			fmt.Fprintf(os.Stderr, "guard: %s is approved-uncontained but no-container-fallback policy is 'fail' — skipping the uncontained run.\n", key)
			return nil
		}
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

// uncontainedAllowed reports whether policy permits running a script with NO
// sandbox at all. Consulted at every uncontained run and before recording an
// uncontained approval, so the two can't disagree.
func uncontainedAllowed(cfg config.Config) bool {
	return cfg.NoContainerFallback != config.FallbackFail
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
	quiet, all, jsonOut, confirm, hook, remote := parseCheckArgs(args)
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
	// At pre-push git feeds the hook "<local ref> <local sha> <remote ref>
	// <remote sha>" lines on stdin, which the shim passes straight through.
	// They name what is actually being TRANSMITTED — the only correct snapshot
	// for the secret and freshness gates at this phase. No lines (someone ran
	// the command by hand) falls back to the working-tree view.
	// Only read stdin when it is actually a pipe. Run by hand on a terminal,
	// --hook=pre-push would otherwise block forever waiting for ref lines.
	var refs []pushRef
	if hook == "pre-push" && !stdinIsTTY() {
		refs = parsePushRefs(os.Stdin)
	}
	// Every lockfile gate judges the SAME snapshot: the index at pre-commit, the
	// pushed commits at pre-push, the working tree otherwise.
	snap := hookSnapshot(dir, hook, refs)
	if len(snap.refs) > 0 && !quiet {
		if _, _, err := snap.pkgs(); err != nil && os.IsNotExist(err) {
			if _, werr := lockfile.Installed(dir); werr == nil {
				fmt.Fprintf(os.Stderr, "guard: note — no lockfile in the %s; the working tree has one that is not being %s.\n",
					snap.label, map[bool]string{true: "committed", false: "pushed"}[hook == "pre-commit"])
			}
		}
	}
	warnUnknownRemote(refs, remote)
	secErr := checkSecrets(dir, cfg, wf, quiet, refs, remote)
	advErr := checkAdvisories(snap, cfg, quiet, confirm, wf)
	freshErr := checkFreshness(snap, cfg, quiet, all, confirm, wf, refs, remote)
	intErr := checkLockfileIntegrity(snap, cfg, wf, quiet)
	licErr := checkLicenses(snap, cfg, wf, quiet)
	var provErr error
	if cfg.Flagged("provenance") {
		provErr = checkProvenance(snap, cfg, quiet)
	}
	// Informational diff signals (never gate the commit/PR). Run here so a
	// new-deps heads-up rides the same `guard check` the hooks already run.
	if cfg.Flagged("new-deps") {
		reportNewDeps(dir, quiet)
	}
	var maintErr error
	if cfg.Flagged("new-maintainer") {
		maintErr = checkMaintainers(dir, cfg, quiet)
	}
	// One-line rollup so the overall verdict is scannable regardless of how many
	// checkers printed above (and lands as a single line in CI logs).
	if !quiet {
		printCheckSummary(dir, map[string]error{
			"secrets":     secErr,
			"advisories":  advErr,
			"cooldown":    freshErr,
			"integrity":   intErr,
			"licenses":    licErr,
			"provenance":  provErr,
			"maintainers": maintErr,
		})
	}
	// First gate to trip wins the exit code; all of them already printed. Secrets
	// lead — an uploaded credential is the highest-stakes, least-recoverable miss.
	if secErr != nil {
		return secErr
	}
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
	if freshErr != nil {
		return freshErr
	}
	return maintErr
}

// parseCheckArgs pulls the flags out of `guard check`'s argv. Split out so the
// --hook= phase wiring is testable without running the whole command.
//
// An unrecognized --hook= value yields "" rather than an error: a future shim
// naming a phase this binary doesn't know must degrade to the plain check, not
// break every commit in the repo.
func parseCheckArgs(args []string) (quiet, all, jsonOut, confirm bool, hook, remote string) {
	for _, a := range args {
		switch {
		case a == "--quiet":
			quiet = true
		case a == "--all":
			all = true // force full-tree freshness check, not just the git diff
		case a == "--json":
			jsonOut = true
		case a == "--confirm":
			// Interactive gate for warn-tier advisories: prompt on a terminal
			// before proceeding, recording acceptances. The git hooks pass this;
			// CI (no terminal) sees warnings print without prompting.
			confirm = true
		case strings.HasPrefix(a, "--hook="):
			switch v := strings.TrimPrefix(a, "--hook="); v {
			case "pre-commit", "pre-push":
				hook = v
			}
		case strings.HasPrefix(a, "--remote="):
			// git hands the pre-push hook the remote NAME as $1. It scopes
			// "what is outgoing" to the destination actually being pushed to.
			// Anything not shaped like a remote name is ignored — it reaches
			// git's argv.
			if v := strings.TrimPrefix(a, "--remote="); remoteNameRe.MatchString(v) {
				remote = v
			}
		}
	}
	return
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
	// Conflicting are name@version pairs the lockfile records at two paths with
	// DIFFERENT tarballs or hashes. The lockfile contradicts itself, so no
	// single answer about what will be installed is trustworthy — not waivable.
	Conflicting []string            `json:"conflicting,omitempty"`
	NewDeps     []string            `json:"newDeps"`
	Maintainers []maintainer.Change `json:"maintainerChanges"`
	License     []license.Violation `json:"licenseViolations,omitempty"`
	// Secrets are files matching a secret-paths pattern that are staged or already
	// tracked by git — a HARD block (like a critical advisory). These flip OK.
	Secrets    []secrets.Match      `json:"secrets,omitempty"`
	Provenance []attestation.Result `json:"provenance,omitempty"`
	Waived     []string             `json:"waived,omitempty"`
	// Degraded names layers that could NOT run this check (e.g. OSV unreachable,
	// a registry fetch failed). The check stays fail-open — these don't flip OK —
	// but a non-empty Degraded means a green result is INCOMPLETE, not proven
	// clean. Surfacing it is what keeps --json/MCP from hiding an outage.
	Degraded []string `json:"degraded,omitempty"`
	OK       bool     `json:"ok"`
	// provenanceInvalid counts INVALID attestations; unexported because the
	// details already ride in Provenance and only the verdict needs the count.
	provenanceInvalid int
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

// secretWaiverID is "secret:<repo-relative-path>" — waives a deliberate match
// (e.g. ".env.example" caught by ".env.*", or a fixture). Keyed on the path, not
// a version: the file either should ship or shouldn't.
func secretWaiverID(path string) string { return "secret:" + path }

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

// finalOK is the ONE place the overall verdict is computed, so every return path
// out of gatherCheck agrees. The early "no lockfile" return used to decide on
// secrets alone, which quietly ignored on-check-error: fail with a non-empty
// Degraded — a repo with no deps could report ok:true after a check that did not
// run.
func finalOK(res CheckResult, cfg config.Config) bool {
	if cfg.OnCheckErrorFail && len(res.Degraded) > 0 {
		return false // a check that could not COMPLETE is not a pass
	}
	return len(res.Advisories) == 0 && len(res.Cooldown) == 0 && len(res.OffRegistry) == 0 &&
		len(res.Unhashed) == 0 && len(res.Conflicting) == 0 && len(res.License) == 0 &&
		len(res.Secrets) == 0 && res.provenanceInvalid == 0
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
	// Secret-file gate runs FIRST and independent of the lockfile: it inspects
	// git's tracked/staged set, not node_modules, so it must gate even in a repo
	// with no dependencies. A git error means "no upload surface to assert about"
	// — recorded as degraded, never silently treated as a leak.
	if len(cfg.SecretPaths) > 0 {
		if m, serr := secrets.Find(dir, cfg.SecretPaths); serr != nil {
			res.Degraded = append(res.Degraded, "secret-paths check skipped: "+serr.Error())
		} else {
			for _, hit := range m {
				if waivedActive(wf, secretWaiverID(hit.Path), now) {
					res.Waived = append(res.Waived, secretWaiverID(hit.Path))
					continue
				}
				res.Secrets = append(res.Secrets, hit)
			}
		}
	}
	// InstalledAt, not Installed: the skipped-entry count is part of the answer.
	// Installed discards it, so a partially-understood lockfile never reached
	// res.Degraded and --json/MCP reported a clean result over a partial parse.
	pkgs, skipped, err := lockfile.InstalledAt(dir, "")
	if err != nil {
		if os.IsNotExist(err) {
			// No deps to vet, but a tracked secret still gates.
			res.OK = finalOK(res, cfg)
			return res, nil
		}
		return res, err
	}
	if skipped > 0 {
		res.Degraded = append(res.Degraded,
			fmt.Sprintf("lockfile parse: %d unrecognized entr(ies) skipped", skipped))
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
		if p.Conflict {
			res.Conflicting = append(res.Conflicting, p.Key())
		}
		if !checkableDep(p) {
			continue
		}
		// Only internal-scope names are exempt from the host check: they are
		// DECLARED to come from a private registry. `allow:` is a cooldown
		// escape hatch and buys nothing here.
		if hasTarballURL(p) && !cfg.Internal(p.Name) {
			if h := hostOf(p.Resolved); h != regHost && !isLoopbackHost(h) {
				if id := offRegistryWaiverID(p.Key()); waivedActive(wf, id, now) {
					res.Waived = append(res.Waived, id)
				} else {
					res.OffRegistry = append(res.OffRegistry, p.Key())
				}
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
		ch, mwarns := maintainer.Check(cfg.Registry, pkgs, cfg.Allowed, nil)
		if len(ch) > 0 {
			res.Maintainers = ch
		}
		// Fail-open per package, but recorded: a green result must not hide
		// that the publisher comparison never ran for some of the tree.
		res.Degraded = append(res.Degraded, mwarns...)
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
	// Build-provenance gate (flag-gated, opt-in). Only INVALID attestations gate.
	// A DEGRADED result is a check that could not complete, so it joins
	// res.Degraded like every other failed lookup — and therefore obeys
	// on-check-error via the OK computation below, instead of the JSON/MCP path
	// reporting ok:true while the text path gates. One registry fetch per
	// package, so it's off by default.
	invalidProv := 0
	if cfg.Flagged("provenance") {
		apkgs := make([]attestation.Pkg, 0, len(pkgs))
		for _, p := range pkgs {
			apkgs = append(apkgs, attestation.Pkg{Name: p.Name, Version: p.Version, Integrity: p.Integrity})
		}
		client := &http.Client{Timeout: 30 * time.Second}
		res.Provenance = attestation.Check(client, cfg.Registry, apkgs, cfg.Internal, nil)
		degradedProv := 0
		for _, r := range res.Provenance {
			switch r.Status {
			case attestation.StatusInvalid:
				invalidProv++
			case attestation.StatusDegraded:
				degradedProv++
			}
		}
		if degradedProv > 0 {
			res.Degraded = append(res.Degraded, fmt.Sprintf("provenance check incomplete: %d package(s) could not be verified", degradedProv))
		}
	}
	// res.Advisories is blockers-only (warnings live in AdvisoryWarnings and do
	// not gate), so OK keys off it directly.
	res.provenanceInvalid = invalidProv
	res.OK = finalOK(res, cfg)
	return res, nil
}

// checkLockfileIntegrity flags lockfile entries whose tarball resolves OFF the
// configured registry (a poisoned lockfile silently redirecting a fetch to an
// attacker host) or that carry no integrity hash (npm can't verify the
// download). Both are tamper signatures a hand-edited or malicious lockfile
// leaves behind, as is the same name@version recorded twice with DIFFERENT
// tarballs or hashes (Conflict). Only internal-scope names are exempt from the
// host check — they are declared to live on a private registry. `allow:` is a
// cooldown escape hatch and exempts NOTHING here. Gates like the advisory layer.
func checkLockfileIntegrity(snap snapshot, cfg config.Config, wf *waivers.File, quiet bool) error {
	// PER REF, not over the union: an occurrence-level finding belongs to the
	// lockfile it appears in. Unioning first let a clean branch in the same push
	// lend its hash (or its registry host) to a bad occurrence in another.
	views, err := snap.perRef()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var degraded error
	total, skipped := 0, 0
	for _, v := range views {
		total += len(v.pkgs)
		skipped += v.skipped
	}
	if skipped > 0 {
		degraded = cfg.Degrade("lockfile parse",
			fmt.Errorf("%d unrecognized entr(ies) skipped in the %s", skipped, snap.label))
	}
	// Only label findings by ref when there is more than one to tell apart.
	label := func(v refPkgs, key string) string {
		if len(views) < 2 {
			return key
		}
		return v.label + ": " + key
	}
	regHost := hostOf(cfg.Registry)
	now := time.Now()
	var offReg, noHash, conflict []string
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
	for _, v := range views {
		for _, p := range v.pkgs {
			// Not waivable: a self-contradicting lockfile has to be fixed, not
			// accepted — we can't say which of the two records will win.
			if p.Conflict {
				conflict = append(conflict, label(v, p.Key()))
			}
			// A bundled copy has no tarball of its own: its bytes are covered by
			// the parent's hash. Nothing here to verify, so nothing to report.
			if p.Bundled || !checkableDep(p) {
				continue
			}
			// The host comparison needs an actual tarball URL; pnpm normally
			// records none, and those entries are still hash-checked below.
			if hasTarballURL(p) && !cfg.Internal(p.Name) {
				if h := hostOf(p.Resolved); h != regHost && !isLoopbackHost(h) {
					waiveOrKeep(offRegistryWaiverID(p.Key()),
						label(v, fmt.Sprintf("%s — tarball host %q ≠ registry %q", p.Key(), h, regHost)), &offReg)
				}
			}
			if p.Integrity == "" {
				waiveOrKeep(unhashedWaiverID(p.Key()), label(v, p.Key()), &noHash)
			}
		}
	}
	if len(offReg) == 0 && len(noHash) == 0 && len(conflict) == 0 {
		if !quiet && degraded == nil {
			fmt.Printf("guard: lockfile integrity ok (%d version(s), %s) %s\n", total, snap.label, ui.OK())
		}
		return degraded
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
	if len(conflict) > 0 {
		fmt.Fprintf(os.Stderr, "guard: %d version(s) appear with conflicting tarball/integrity values:\n", len(conflict))
		for _, s := range conflict {
			fmt.Fprintln(os.Stderr, "  ", s)
		}
		fmt.Fprintln(os.Stderr, "guard: fix the lockfile — `npm install` regenerates consistent entries; review the diff before committing. Not waivable.")
	}
	if len(offReg) > 0 || len(noHash) > 0 {
		fmt.Fprintln(os.Stderr, "guard: a tarball off-registry or without a hash can't be verified — mark private scopes with internal-scopes in .guardrc, or — if reviewed — guard ignore off-registry:<name>@<version> / unhashed:<name>@<version>")
	}
	return fmt.Errorf("lockfile integrity check failed (%d off-registry, %d unhashed, %d conflicting)", len(offReg), len(noHash), len(conflict))
}

// maxPackumentBytes caps bytes read from a registry packument (see
// internal/freshness). var so a test can lower it cheaply.
var maxPackumentBytes int64 = 128 << 20 // 128 MiB

// hasTarballURL reports whether the entry records an http(s) tarball — the only
// shape whose host is comparable against the configured registry.
func hasTarballURL(p lockfile.Pkg) bool {
	return strings.HasPrefix(p.Resolved, "http://") || strings.HasPrefix(p.Resolved, "https://")
}

// checkableDep reports whether the lockfile integrity gates apply to an entry.
// git/file/link deps legitimately carry no registry host and no hash, so they
// are exempt — but a pnpm entry (FromRegistry, usually with no Resolved at all)
// IS a registry dep and must still be hash-checked.
func checkableDep(p lockfile.Pkg) bool { return p.FromRegistry || hasTarballURL(p) }

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
	// Capped like every other registry read; truncation surfaces as a decode
	// error, which yields no diff (the caller's fail-open path).
	if json.NewDecoder(io.LimitReader(resp.Body, maxPackumentBytes)).Decode(&doc) != nil {
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
// It returns an error only under on-check-error: fail, when a publisher lookup
// could not complete — the CHANGES themselves are a signal to verify, never a
// gate (a legitimate maintainer handover looks identical to a takeover).
func checkMaintainers(dir string, cfg config.Config, quiet bool) error {
	pkgs, err := lockfile.Installed(dir)
	if err != nil {
		return nil
	}
	changes, warnings := maintainer.Check(cfg.Registry, pkgs, cfg.Allowed, progressPrinter("maintainers", quiet))
	degraded := cfg.Degrade("maintainer check", collapse(warnings))
	if len(changes) == 0 {
		if !quiet {
			fmt.Println("guard: no maintainer/publisher changes on installed versions " + ui.OK())
		}
		return degraded
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
	return degraded
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
// Which versions count as "new" depends on the PHASE:
//
//	--all       the full tree.
//	pre-push    what the pushed commits ADD over the remote side (refs non-empty).
//	otherwise   what the working tree ADDS over git HEAD.
//
// The pre-push case is the one that matters for enforcement: after a commit the
// working tree and HEAD agree, so a too-young version that got committed anyway
// (GUARD_SKIP, or a teammate without guard) is invisible to a HEAD diff yet is
// exactly what the push transmits. Comparing against the remote catches it.
// npm-only — the ref snapshots come from package-lock.json.
func checkFreshness(snap snapshot, cfg config.Config, quiet, all, confirm bool, wf *waivers.File, refs []pushRef, remote string) error {
	dir := snap.dir
	pkgs, _, err := snap.pkgs()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	scope := "lockfile additions"
	scoped := false
	if all {
		scope, scoped = "full tree (--all)", true
	} else if len(refs) > 0 {
		// One push can carry several refs (`git push --all`, or two branches at
		// once). Each has its own snapshot and its own base, so vet the UNION of
		// what they add — checking only the first would let a second branch
		// smuggle a too-young version through.
		//
		// ok is false when no pushed commit had a package-lock.json at all (a
		// pnpm/yarn repo): fall through to the working-tree view rather than
		// checking nothing.
		if np, s, ok := pushNewVersions(dir, refs, remote); ok {
			pkgs, scope, scoped = np, s, true
		}
	}
	if !scoped {
		if len(refs) > 0 {
			scope = "working tree vs HEAD (no npm lockfile in the pushed commits)"
		}
		if prev, ok := headLockfile(dir); ok {
			pkgs = newVersions(pkgs, prev)
		} else {
			scope = "full tree (no committed lockfile to diff against)"
		}
	}
	if len(pkgs) == 0 {
		if !quiet {
			fmt.Println("guard: no new lockfile versions to cooldown-check " + ui.OK())
		}
		return nil
	}

	violations, warnings := freshness.Check(cfg.Registry, pkgs, cfg.Cooldown, cfg.Allowed)
	// Per-package fetch errors are fail-open by default (a registry blip must
	// not block every commit in every repo) — but always loud, and gating under
	// on-check-error: fail. Collapsed to ONE line: a tree-wide registry outage
	// produces one warning per package, and hundreds of them is how a warning
	// stops being read.
	degraded := cfg.Degrade("freshness check", collapse(warnings))
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
		return degraded
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
	// Interactive gate (the git hooks pass --confirm; CI/no-terminal does not):
	// offer to accept all and waive, or auto-pin each package to its latest
	// version past the cooldown and reinstall. With no terminal we fall through to
	// the hard block below — install enforcement and CI stay strict.
	if confirm {
		resolved, interactive, cerr := confirmCooldown(dir, cfg, active, wf)
		if cerr != nil {
			return cerr
		}
		if interactive {
			if resolved {
				return nil
			}
			return fmt.Errorf("commit/push aborted — %d version(s) inside the cooldown not accepted", len(active))
		}
	}
	fmt.Fprintln(os.Stderr, "guard: wait out the cooldown, pin an older version, allowlist in .guardrc, or — if reviewed — guard ignore cooldown:<name>@<version>")
	return fmt.Errorf("%d version(s) violate the cooldown", len(active))
}

// confirmCooldown is the interactive cooldown gate (the --confirm path). On the
// controlling terminal it offers three choices for the too-fresh versions:
//
//	[a] accept all      record a cooldown waiver for each and proceed
//	[p] pin & reinstall rewrite package.json's DIRECT deps to each package's
//	                    latest version past the cooldown, reinstall, re-verify
//	[N] abort
//
// interactive is false when there's no terminal (CI, a piped hook) — the caller
// then falls through to the hard block. Reads /dev/tty, not stdin: a git hook's
// stdin carries ref data, not the keyboard (mirrors confirmThroughWarnings).
func confirmCooldown(dir string, cfg config.Config, active []freshness.Violation, wf *waivers.File) (resolved, interactive bool, err error) {
	ttyf, e := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if e != nil {
		return false, false, nil // no terminal — caller hard-blocks
	}
	defer ttyf.Close()

	// One registry fetch per package to name the concrete pin target up front, so
	// the human chooses with the real version in hand rather than a guess.
	safe := map[string]string{}
	for _, v := range active {
		if s, e := freshness.LatestSafe(cfg.Registry, v.Name, cfg.Cooldown); e == nil && s != "" {
			safe[v.Name] = s
		}
	}
	fmt.Fprintln(ttyf, "guard: cooldown options —")
	for _, v := range active {
		if s := safe[v.Name]; s != "" {
			fmt.Fprintf(ttyf, "  %s@%s  → latest past cooldown: %s\n", v.Name, v.Version, s)
		} else {
			fmt.Fprintf(ttyf, "  %s@%s  (no version past the cooldown yet)\n", v.Name, v.Version)
		}
	}
	fmt.Fprint(ttyf, "Choose: [a] accept all (waive)  [p] pin & reinstall  [N] abort: ")
	line, _ := bufio.NewReader(ttyf).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "a", "accept":
		reason := "accepted " + time.Now().UTC().Format("2006-01-02") + " via guard check --confirm"
		for _, v := range active {
			if e := wf.Set(cooldownWaiverID(v), reason, ""); e != nil {
				return false, true, e
			}
		}
		if e := wf.Save(dir); e != nil {
			return false, true, e
		}
		fmt.Fprintf(ttyf, "guard: recorded %d cooldown acceptance(s) in %s\n", len(active), waivers.FileName)
		return true, true, nil
	case "p", "pin":
		if e := pinAndReinstall(dir, cfg, active, safe, ttyf); e != nil {
			fmt.Fprintln(ttyf, "guard: pin failed:", e)
			return false, true, nil // failed pin = not resolved; caller aborts
		}
		return true, true, nil
	default:
		fmt.Fprintln(ttyf, "guard: not accepted — aborting.")
		return false, true, nil
	}
}

// pinAndReinstall rewrites package.json so each cooldown-violating DIRECT
// dependency points at its latest version past the cooldown (from safe), then
// re-runs the install through guard's ephemeral proxy to refresh the lockfile.
// Transitive violations (not named in package.json) can't be pinned directly —
// they're reported; the reinstall may still resolve them to an older survivor.
// Errors if nothing could be pinned, the reinstall fails, or a violation
// survives the reinstall.
func pinAndReinstall(dir string, cfg config.Config, active []freshness.Violation, safe map[string]string, out io.Writer) error {
	pinned, unpinnable, err := pinPackageJSON(dir, active, safe)
	if err != nil {
		return err
	}
	if len(pinned) == 0 {
		return fmt.Errorf("no DIRECT dependency to pin (%d transitive — update the dep that pulls them in, or wait out the cooldown)", len(unpinnable))
	}
	for name, ver := range pinned {
		fmt.Fprintf(out, "guard: pinned %s → %s in package.json\n", name, ver)
	}
	for _, n := range unpinnable {
		fmt.Fprintf(out, "guard: %s is transitive — not pinned directly; reinstall may still drop it\n", n)
	}
	// Reinstall through the proxy so the (older) versions are fetched under the
	// same cooldown/advisory protections; lifecycle scripts stay off.
	proxy, err := registry.Start(cfg)
	if err != nil {
		return fmt.Errorf("start proxy: %w", err)
	}
	defer proxy.Stop()
	inv := buildInstall(detectManager(dir), "install", nil, proxy.URL(), cfg.IgnoreScripts)
	cmd := exec.Command(inv.name, inv.args...)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = out, out
	cmd.Env = append(os.Environ(), inv.env...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reinstall failed: %w", err)
	}
	fmt.Fprintln(out, "guard: reinstalled, lockfile refreshed.")
	// Re-verify: a pin that didn't actually clear every violation must NOT report
	// success (a transitive dep can drag a too-fresh version back in).
	pkgs, err := lockfile.Installed(dir)
	if err != nil {
		return err
	}
	if viol, _ := freshness.Check(cfg.Registry, pkgs, cfg.Cooldown, cfg.Allowed); len(viol) > 0 {
		return fmt.Errorf("%d version(s) still inside the cooldown after reinstall", len(viol))
	}
	return nil
}

// pinPackageJSON rewrites dir/package.json so each violating DIRECT dependency
// is set to its safe[name] version, returning what it pinned and which names it
// couldn't (transitive, or no safe version). The edit is a string replacement
// (setDepVersion), not a JSON re-encode, so the committed file's formatting and
// key order survive. The file is written only if at least one dep was pinned.
func pinPackageJSON(dir string, active []freshness.Violation, safe map[string]string) (pinned map[string]string, unpinnable []string, err error) {
	path := filepath.Join(dir, "package.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var pj struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		return nil, nil, fmt.Errorf("parse package.json: %w", err)
	}
	direct := func(name string) bool {
		_, a := pj.Dependencies[name]
		_, b := pj.DevDependencies[name]
		_, c := pj.OptionalDependencies[name]
		return a || b || c
	}
	pinned = map[string]string{}
	content := string(data)
	seen := map[string]bool{}
	for _, v := range active {
		if seen[v.Name] {
			continue // one pin per package even if several versions violate
		}
		seen[v.Name] = true
		s := safe[v.Name]
		if s == "" || !direct(v.Name) {
			unpinnable = append(unpinnable, v.Name)
			continue
		}
		if next, ok := setDepVersion(content, v.Name, s); ok {
			content = next
			pinned[v.Name] = s
		} else {
			unpinnable = append(unpinnable, v.Name)
		}
	}
	if len(pinned) == 0 {
		return pinned, unpinnable, nil
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return nil, nil, err
	}
	return pinned, unpinnable, nil
}

// setDepVersion rewrites the version value of dependency name in package.json
// text, preserving every other byte (a targeted string edit, not a JSON
// re-encode — so a committed file's layout, key order, and spacing are
// untouched). Returns the new text and whether it changed.
func setDepVersion(content, name, version string) (string, bool) {
	re := regexp.MustCompile(`("` + regexp.QuoteMeta(name) + `"\s*:\s*")[^"]*(")`)
	if !re.MatchString(content) {
		return content, false
	}
	return re.ReplaceAllString(content, "${1}"+version+"${2}"), true
}

// headLockfile reads package-lock.json as committed at git HEAD.
// ok=false when there's no git repo, no HEAD, or no committed lockfile.
func headLockfile(dir string) ([]lockfile.Pkg, bool) { return refLockfile(dir, "HEAD") }

// refLockfile parses package-lock.json as it exists at a git ref — "HEAD", a
// sha, or "<sha>^" — without checking anything out. npm-only: InstalledBytes
// reads npm's lockfile shape, so pnpm/yarn repos fall back to the full tree.
// snapshot names the lockfile state a set of gates must judge. The working tree
// is NOT that state during a hook: at pre-commit git records the INDEX, and at
// pre-push it transmits the pushed COMMITS. Checking the tree instead let a
// staged-but-different lockfile through every gate.
type snapshot struct {
	dir string
	// refs are git refs to read the lockfile from — ":" is the index, a sha is
	// that commit. Empty means the working tree.
	refs []string
	// label says which snapshot this is, for the checkers' own output.
	label string
}

// worktreeSnapshot is the plain "what is on disk" view — `guard check` run by
// hand, `guard install`, and the --json/MCP path.
func worktreeSnapshot(dir string) snapshot { return snapshot{dir: dir, label: "working tree"} }

// hookSnapshot picks the state the named git phase is actually about to act on.
func hookSnapshot(dir, hook string, refs []pushRef) snapshot {
	switch {
	case hook == "pre-commit":
		return snapshot{dir: dir, refs: []string{":"}, label: "staged lockfile"}
	case hook == "pre-push" && len(refs) > 0:
		var shas []string
		for _, r := range refs {
			shas = append(shas, r.localSHA)
		}
		return snapshot{dir: dir, refs: shas, label: "pushed commits"}
	default:
		return worktreeSnapshot(dir)
	}
}

// pkgs returns the distinct name@version set for this snapshot — the union
// across refs when a push carries several — plus how many lockfile entries the
// parsers could not recognize.
//
// A ref with no lockfile at all is skipped rather than fatal (a branch that
// predates the lockfile); os.ErrNotExist comes back only when NO ref had one.
// refPkgs is one ref's own package set — the view the OCCURRENCE-level gates
// need. Integrity and provenance judge a specific tarball at a specific path, so
// they must not see the union: a clean branch A lends its hash to branch B's
// unhashed occurrence and the finding disappears from the push.
type refPkgs struct {
	ref     string
	label   string
	pkgs    []lockfile.Pkg
	skipped int
}

// perRef returns each ref's package set separately, in ref order. For the
// working tree (or a single ref) that is one entry, so the loop collapses.
func (s snapshot) perRef() ([]refPkgs, error) {
	if len(s.refs) == 0 {
		p, n, err := lockfile.InstalledAt(s.dir, "")
		if err != nil {
			return nil, err
		}
		return []refPkgs{{label: s.label, pkgs: p, skipped: n}}, nil
	}
	var out []refPkgs
	for _, ref := range s.refs {
		p, n, err := lockfile.InstalledAt(s.dir, ref)
		if os.IsNotExist(err) {
			continue // this ref carries no lockfile; others may
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ref, err)
		}
		out = append(out, refPkgs{ref: ref, label: refLabel(ref, s.label), pkgs: p, skipped: n})
	}
	if len(out) == 0 {
		return nil, os.ErrNotExist
	}
	return out, nil
}

// refLabel names a ref in a finding. Only worth a short sha; the full one is
// noise on every line.
func refLabel(ref, fallback string) string {
	if ref == "" || ref == ":" {
		return fallback
	}
	if len(ref) > 8 {
		return ref[:8]
	}
	return ref
}

func (s snapshot) pkgs() ([]lockfile.Pkg, int, error) {
	if len(s.refs) == 0 {
		return lockfile.InstalledAt(s.dir, "")
	}
	var sets [][]lockfile.Pkg
	skipped := 0
	for _, ref := range s.refs {
		p, n, err := lockfile.InstalledAt(s.dir, ref)
		if os.IsNotExist(err) {
			continue // this ref carries no lockfile; others may
		}
		if err != nil {
			// A lockfile that EXISTS but can't be parsed is not "nothing to
			// check" — fail closed like the working-tree path does.
			return nil, 0, fmt.Errorf("%s: %w", ref, err)
		}
		sets = append(sets, p)
		skipped += n
	}
	if len(sets) == 0 {
		return nil, 0, os.ErrNotExist
	}
	return lockfile.Union(sets...), skipped, nil
}

// gatePkgs is the shared front door for every lockfile gate: the snapshot's
// package set, with an unreadable-entry count reported through the
// on-check-error policy so a partially-understood lockfile can gate.
func gatePkgs(s snapshot, cfg config.Config) ([]lockfile.Pkg, error, error) {
	pkgs, skipped, err := s.pkgs()
	if err != nil {
		return nil, nil, err
	}
	var degraded error
	if skipped > 0 {
		degraded = cfg.Degrade("lockfile parse",
			fmt.Errorf("%d unrecognized entr(ies) skipped in the %s", skipped, s.label))
	}
	return pkgs, degraded, nil
}

func refLockfile(dir, ref string) ([]lockfile.Pkg, bool) {
	prev, _, err := lockfile.InstalledAt(dir, ref)
	if err != nil {
		return nil, false
	}
	return prev, true
}

// collapse turns a list of per-package failure messages into ONE error naming
// the count and the first cause, or nil when there were none. Fail-open layers
// report per package; printing all of them buries the signal.
func collapse(warnings []string) error {
	switch len(warnings) {
	case 0:
		return nil
	case 1:
		return errors.New(warnings[0])
	default:
		return fmt.Errorf("%d package(s), e.g. %s", len(warnings), warnings[0])
	}
}

// newVersions returns the entries of curr whose name@version is absent from
// base — each distinct version is checked once, at the change that adds it.
func newVersions(curr, base []lockfile.Pkg) []lockfile.Pkg {
	vetted := map[string]bool{}
	for _, p := range base {
		vetted[p.Key()] = true
	}
	var out []lockfile.Pkg
	for _, p := range curr {
		if !vetted[p.Key()] {
			out = append(out, p)
		}
	}
	return out
}

// gitOutput runs a git command in dir and returns its stdout. A func var so the
// ref-selection logic below is testable without building repositories.
var gitOutput = func(dir string, args ...string) (string, error) {
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
	return string(out), err
}

// pushRef is one "<local ref> <local sha> <remote ref> <remote sha>" line git
// writes to a pre-push hook's stdin.
type pushRef struct{ localRef, localSHA, remoteRef, remoteSHA string }

// isZeroSHA reports git's all-zero sha, which means "this side has nothing":
// on the local side a ref being DELETED, on the remote side a branch that does
// not exist there yet.
// A bare "0" is not a git object id — the length has to be right too, or a
// junk field would be read as "this side has nothing".
func isZeroSHA(s string) bool {
	return len(s) >= 40 && len(s) <= 64 && strings.Trim(s, "0") == ""
}

// remoteNameRe is what we accept as a git remote name. The value arrives from
// the hook's argv and is passed back to git, so it is validated, not trusted.
var remoteNameRe = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`) // `/` is legal in a remote name and inert in a --remotes= glob

// isSHA validates an object id from the hook's stdin: 40 hex (sha1) to 64 hex
// (sha256), nothing else. These values are concatenated into git ARGUMENTS, so
// an unvalidated one is an argument-injection surface — "--output=…" is a
// perfectly good string until git reads it as a flag.
func isSHA(s string) bool {
	if len(s) < 40 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// parsePushRefs reads the ref lines git feeds the pre-push hook (guard inherits
// that stdin through the shim). Deletions carry nothing to check and are dropped;
// malformed lines are skipped rather than fatal.
func parsePushRefs(r io.Reader) []pushRef {
	var out []pushRef
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		// Drop deletions (nothing to check) and anything whose object ids don't
		// look like object ids — they end up as git arguments.
		if len(f) < 4 || isZeroSHA(f[1]) || !isSHA(f[1]) || !(isSHA(f[3]) || isZeroSHA(f[3])) {
			continue
		}
		out = append(out, pushRef{localRef: f[0], localSHA: f[1], remoteRef: f[2], remoteSHA: f[3]})
	}
	return out
}

// outgoingRevArgs turns pushed refs into git-log revision selectors covering
// exactly the commits the push transmits: a "<remote>..<local>" range for a
// branch the remote already has, and "<local> --not --remotes" for a new one
// (everything reachable from it that no remote branch already holds).
func outgoingRevArgs(refs []pushRef, remote string) [][]string {
	var out [][]string
	for _, r := range refs {
		if isZeroSHA(r.remoteSHA) {
			out = append(out, append([]string{r.localSHA}, notArgs(remote)...))
		} else {
			out = append(out, []string{r.remoteSHA + ".." + r.localSHA})
		}
	}
	return out
}

// notRemotes excludes what the DESTINATION already has. Scoping to the named
// remote matters: "--remotes" excludes commits present on ANY remote, so a
// branch already pushed to a fork would be treated as nothing-new when pushed to
// the real upstream for the first time — the exact case a review gate must catch.
//
// With no remote name — a pre-1.2.1 (v3) shim that passes no --remote, a URL
// push, or a hook chain that consumed $1 — we fall back to excluding what is on
// ANY remote. Excluding nothing would be safer in theory but turns the next push
// of every not-yet-re-initialised repo into a full-history secret scan and a
// full-tree cooldown sweep, which reads as guard breaking; warnUnknownRemote
// tells the user how to get the precise scope instead.
//
// When the named remote simply has no tracking refs yet, --remotes=<name>
// matches nothing and the whole branch history is scanned — the conservative
// outcome for a genuinely new destination.
func notRemotes(remote string) []string {
	if remote == "" {
		return []string{"--remotes"}
	}
	return []string{"--remotes=" + remote}
}

// warnUnknownRemote explains the wider scope once per check run.
var warnedUnknownRemote bool

func warnUnknownRemote(refs []pushRef, remote string) {
	if remote != "" || len(refs) == 0 || warnedUnknownRemote {
		return
	}
	warnedUnknownRemote = true
	fmt.Fprintln(os.Stderr, "guard: push destination unknown (old hook shim?) — outgoing scope is 'not on any remote'; re-run 'guard init' to scope it to the destination.")
}

// notArgs builds the "--not <exclusions>" tail.
func notArgs(remote string) []string {
	return append([]string{"--not"}, notRemotes(remote)...)
}

// pushBaseRef picks the freshness comparison base for one pushed ref: the state
// the REMOTE already has, so "new" means "new to the remote", not "new to my
// working tree". For a branch the remote knows, that's its sha. For a new branch
// it's the parent of the oldest outgoing commit.
//
// Returns ("", false) when nothing is outgoing, and ("", true) when there is no
// base at all (a root commit) — then the whole tree counts as new.
func pushBaseRef(dir string, r pushRef, remote string) (base string, full bool) {
	if !isZeroSHA(r.remoteSHA) {
		return r.remoteSHA, false
	}
	out, err := gitOutput(dir, append([]string{"rev-list", r.localSHA}, notArgs(remote)...)...)
	if err != nil {
		return "", true
	}
	commits := strings.Fields(out)
	if len(commits) == 0 {
		return "", false // already on a remote — nothing to check
	}
	oldest := commits[len(commits)-1]
	if _, err := gitOutput(dir, "rev-parse", "--verify", "--quiet", oldest+"^"); err != nil {
		return "", true // root commit, no parent
	}
	return oldest + "^", false
}

// pushNewVersions returns the lockfile versions a push ADDS, unioned across
// every pushed ref, plus a human scope label. For each ref the "current"
// snapshot is the commit being pushed (not the working tree) and the base is
// whatever the remote already has (pushBaseRef). A ref with no base at all — a
// root commit — makes the whole of that snapshot new.
//
// ok is false when NO pushed commit carried a package-lock.json — a pnpm/yarn
// repo, where these snapshots don't exist. The caller then falls back to the
// working-tree scope instead of silently checking an empty set.
func pushNewVersions(dir string, refs []pushRef, remote string) (pkgs []lockfile.Pkg, scope string, ok bool) {
	seen := map[string]bool{}
	var out []lockfile.Pkg
	scope = "nothing outgoing"
	sawSnapshot := false
	for _, r := range refs {
		cur, ok := refLockfile(dir, r.localSHA)
		if !ok {
			continue // no npm lockfile at that commit — nothing to compare
		}
		sawSnapshot = true
		base, full := pushBaseRef(dir, r, remote)
		add := cur
		switch {
		case full:
			scope = "full tree (no reachable base for the pushed commits, npm lockfile only)"
		case base == "":
			continue // this ref is already on a remote
		default:
			if prev, ok := refLockfile(dir, base); ok {
				add = newVersions(cur, prev)
				if scope == "nothing outgoing" {
					scope = "versions this push adds (npm lockfile only)"
				}
			} else {
				scope = "full tree (no lockfile on the remote side)"
			}
		}
		for _, p := range add {
			if !seen[p.Key()] {
				seen[p.Key()] = true
				out = append(out, p)
			}
		}
	}
	return out, scope, sawSnapshot
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
func checkLicenses(snap snapshot, cfg config.Config, wf *waivers.File, quiet bool) error {
	dir := snap.dir
	if len(cfg.LicenseDeny) == 0 && len(cfg.LicenseAllow) == 0 {
		return nil // gate disabled
	}
	// The license gate is WORKING-TREE shaped, unavoidably: it reads each
	// package's own package.json out of node_modules, and node_modules only ever
	// reflects the tree. Pairing a staged or pushed lockfile's paths with
	// on-disk files would just report "incomplete" for every entry that differs.
	// So this one gate ignores snap and reads the tree — declared here and in
	// DESIGN §3 rather than silently approximated.
	entries, err := lockfile.InstalledPaths(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no npm lockfile — nothing to check
		}
		return err
	}
	res := license.Check(dir, entries, cfg.LicenseDeny, cfg.LicenseAllow)
	var degraded error
	if res.Degraded {
		// An absent node_modules means we could not read some declared licenses
		// — same "the check didn't run" shape as an OSV outage, same policy.
		degraded = cfg.Degrade("license check",
			errors.New("node_modules missing for some packages (run an install first)"))
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
		if !quiet && len(res.Violations) == 0 && degraded == nil {
			fmt.Printf("guard: license policy OK %s\n", ui.OK())
		}
		return degraded
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
// attestations are not reported and never gate. A fetch/parse that couldn't
// complete is reported as DEGRADED (visible, never gating) — distinct from a
// clean "none published" so a transient/hostile failure isn't read as absence.
func checkProvenance(snap snapshot, cfg config.Config, quiet bool) error {
	// Per ref like the integrity gate: an attestation is bound to a specific
	// tarball HASH, so a union that borrowed a hash from another ref would verify
	// the wrong bytes.
	views, err := snap.perRef()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	seen := map[string]bool{}
	var apkgs []attestation.Pkg
	for _, v := range views {
		for _, p := range v.pkgs {
			// Same identity the attestation binds to; fetch each once.
			k := p.Key() + "|" + p.Integrity
			if seen[k] {
				continue
			}
			seen[k] = true
			apkgs = append(apkgs, attestation.Pkg{Name: p.Name, Version: p.Version, Integrity: p.Integrity})
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	verified, invalid, degraded := 0, 0, 0
	for _, r := range attestation.Check(client, cfg.Registry, apkgs, cfg.Internal, progressPrinter("provenance", quiet)) {
		switch r.Status {
		case attestation.StatusVerified:
			verified++
			if !quiet {
				fmt.Printf("guard: %s provenance %s@%s ← %s\n", ui.OK(), r.Name, r.Version, r.Source)
			}
		case attestation.StatusInvalid:
			invalid++
			fmt.Fprintf(os.Stderr, "guard: %s provenance INVALID for %s@%s — %s\n", ui.Bad(), r.Name, r.Version, r.Reason)
		case attestation.StatusDegraded:
			degraded++
			if !quiet {
				// Fail-open: a fetch/parse that couldn't complete is NOT a tamper
				// signal and never gates — but say so, don't read it as "none".
				fmt.Fprintf(os.Stderr, "guard: %s provenance check degraded for %s@%s — %s\n", ui.Warn(), r.Name, r.Version, r.Reason)
			}
		}
	}
	if !quiet && verified > 0 {
		fmt.Printf("guard: %d package(s) with verified build provenance %s\n", verified, ui.OK())
	}
	if invalid > 0 {
		return fmt.Errorf("%d package(s) with INVALID provenance attestation", invalid)
	}
	if degraded > 0 {
		return cfg.Degrade("provenance check", fmt.Errorf("%d package(s) could not be verified", degraded))
	}
	return nil
}

// checkAdvisories queries OSV for every installed version and fails when any
// advisory hits — the "installed last month, reported yesterday" recovery layer.
func checkAdvisories(snap snapshot, cfg config.Config, quiet, confirm bool, wf *waivers.File) error {
	dir := snap.dir
	threshold := cfg.AdvisoryThreshold
	pkgs, degraded, err := gatePkgs(snap, cfg)
	if err != nil {
		if os.IsNotExist(err) {
			if !quiet {
				fmt.Printf("guard: no lockfile in the %s — nothing to check\n", snap.label)
			}
			return nil
		}
		return err
	}
	_ = degraded // reported once, by the integrity gate
	vulns, err := advisory.Check(pkgs)
	if err != nil {
		// Advisory feed unreachable: report, don't block work on a network blip
		// (the cooldown + script layers still stand) — unless on-check-error is
		// 'fail', where an unproven tree stops the commit instead.
		return cfg.Degrade("advisory check", err)
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

// checkSecrets is the commit/push gate for credential files (DESIGN.md §11). It
// hard-blocks — like a critical advisory, with no interactive bypass — when a
// file matching a secret-paths pattern is staged or already tracked by git, so a
// secret can't be uploaded. A git error (not a repo, git missing) is fail-open
// and logged: there's no upload surface to assert about. A deliberate match is
// waived per-path with 'guard ignore secret:<path>'.
func checkSecrets(dir string, cfg config.Config, wf *waivers.File, quiet bool, refs []pushRef, remote string) error {
	if len(cfg.SecretPaths) == 0 {
		return nil
	}
	matches, err := secrets.Find(dir, cfg.SecretPaths)
	if err != nil {
		// Fail-open + loud by default, consistent with the advisory/freshness
		// network paths: a missing git binary or non-repo must not wedge every
		// check. Gates under on-check-error: fail.
		return cfg.Degrade("secret-paths check", err)
	}
	// At pre-push the tree is not the upload surface: a secret committed and
	// then deleted is absent from ls-files but still rides the outgoing history.
	// Merge those hits in, keeping the history flag so the remediation advice
	// can say "rewrite + rotate", not "git rm --cached".
	var histErr error
	if len(refs) > 0 {
		hist, herr := secrets.FindOutgoing(dir, cfg.SecretPaths, outgoingRevArgs(refs, remote))
		// A range we could not read is "I did not look", not "nothing there" —
		// a shallow clone fails every range. Report it (and gate under
		// on-check-error: fail) while still using whatever we did find.
		histErr = cfg.Degrade("outgoing-history secret scan", herr)
		have := map[string]bool{}
		for _, m := range matches {
			have[m.Path] = true
		}
		for _, m := range hist {
			if !have[m.Path] {
				matches = append(matches, m)
			}
		}
	}
	now := time.Now()
	var active []secrets.Match
	for _, m := range matches {
		id := secretWaiverID(m.Path)
		e, st := wf.Check(id, now)
		switch st {
		case waivers.Active:
			if !quiet {
				fmt.Fprintf(os.Stderr, "guard: %s secret-path waived %s%s\n", ui.Waived(), id, waiverReason(e))
			}
		case waivers.Expired:
			fmt.Fprintf(os.Stderr, "guard: %s secret-path waiver EXPIRED (%s) for %s — re-review or renew\n", ui.Warn(), e.Expires, id)
			active = append(active, m)
		default:
			active = append(active, m)
		}
	}
	if len(active) == 0 {
		if !quiet && histErr == nil {
			fmt.Printf("guard: no secret files staged or tracked %s\n", ui.OK())
		}
		return histErr
	}
	fmt.Fprintf(os.Stderr, "guard: %s %d secret file(s) would be committed/pushed:\n", ui.Bad(), len(active))
	inHistory := false
	for _, m := range active {
		where := ""
		if m.History {
			where, inHistory = "  [committed in outgoing history]", true
		}
		fmt.Fprintf(os.Stderr, "  %s  (matched secret-paths %q)%s\n", m.Path, m.Pattern, where)
	}
	fmt.Fprintln(os.Stderr, "guard: untrack it first — git rm --cached <file> (and add it to .gitignore).")
	if inHistory {
		fmt.Fprintln(os.Stderr, "guard: a file marked [committed in outgoing history] is ALREADY in a commit you are pushing —")
		fmt.Fprintln(os.Stderr, "guard: deleting it now does not take it back. Rewrite the history (git rebase -i / filter-repo) AND rotate the credential.")
	}
	fmt.Fprintf(os.Stderr, "guard: a deliberate file? → guard ignore secret:%s --reason \"...\"\n", active[0].Path)
	return fmt.Errorf("%d secret file(s) staged or tracked", len(active))
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
	cfg, err := config.Load(dir)
	if err != nil {
		return err
	}
	if decision == approvals.ApprovedUncontained && !uncontainedAllowed(cfg) {
		return fmt.Errorf("no-container-fallback is 'fail' in %s — refusing to record an uncontained approval (it would never run anyway)", config.FileName)
	}
	appr, err := approvals.Load(dir)
	if err != nil {
		return err
	}
	// Bind the decision to the tarball currently in the lockfile, so it lapses
	// if the bytes behind this name@version ever change.
	appr.Set(key, decision, "recorded via guard approve", lockedIntegrity(dir, key))
	if err := appr.Save(dir); err != nil {
		return err
	}
	fmt.Printf("guard: %s → %s (saved to %s — commit it so the decision travels)\n",
		key, decision, approvals.FileName)
	return nil
}

// lockedIntegrity returns the integrity hash the lockfile records for a
// "name@version" key, or "" when the package isn't in this project's lockfile
// (approving ahead of an install stays possible — the entry just isn't bound).
func lockedIntegrity(dir, key string) string {
	entries, err := lockfile.InstalledPaths(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.Name+"@"+e.Version == key {
			return e.Integrity
		}
	}
	return ""
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
			"off-registry:<name>@<version>, unhashed:<name>@<version>, "+
			"license:<name>@<version>, secret:<path>", id)
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
	for _, prefix := range []string{"advisory:", "cooldown:", "off-registry:", "unhashed:", "license:", "secret:"} {
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
	row("on-check-error", boolState(cfg.OnCheckErrorFail, "fail", "warn"))
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
	row("pre-commit hook", hookRow(st.PreCommit, st.PreCommitCurrent, st.PreCommitUnreachable))
	row("pre-push hook", hookRow(st.PrePush, st.PrePushCurrent, st.PrePushUnreachable))
	rel, relErr := filepath.Rel(dir, st.HookDir)
	if relErr != nil {
		rel = st.HookDir
	}
	row("hook dir", ui.Dim(rel))
	row("CI PR gate", boolState(st.CIWorkflow, "installed", "not installed (guard init --ci)"))
	if st.Husky {
		if st.HuskyInactive {
			row("husky", ui.Warn()+" .husky present but core.hooksPath is unset — git uses .git/hooks, not husky")
		} else {
			row("husky", ui.OK()+" detected (depguard chained onto it)")
		}
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

	// Verdict — "protected" means policy loads, a hook carries depguard's CURRENT
	// managed shim, AND the guard binary resolves. A stale/foreign hook or a
	// missing binary is only PARTIAL protection, so the verdict says which.
	fmt.Println()
	_, guardErr := exec.LookPath("guard")
	if ok, msg := protectionVerdict(st, guardErr == nil, cfgErr == nil); ok {
		fmt.Println(ui.Green("→ "+msg+" ") + ui.OK())
	} else {
		fmt.Println(ui.Yellow("→ " + msg))
	}
	return nil
}

// hookRow renders a hook trigger row, distinguishing a current managed shim from
// a stale/foreign one that mentions guard but lacks the current marker.
func hookRow(present, current, unreachable bool) string {
	switch {
	case !present:
		return ui.Dim("— not installed (guard init)")
	case unreachable:
		return ui.Warn() + " installed but UNREACHABLE (hook exits before depguard's block)"
	case !current:
		return ui.Warn() + " present, stale shim — run 'guard init' to refresh"
	default:
		return ui.OK() + " installed"
	}
}

// protectionVerdict decides the one-line 'guard status' conclusion from the hook
// state, whether guard is on PATH, and whether policy loaded. Pure (no I/O) so
// the F4 degraded/stale/missing-binary cases are unit-testable without stdout
// capture. Returns (protected, message).
func protectionVerdict(st hooks.InstalledState, guardOnPath, policyOK bool) (bool, string) {
	switch {
	case !policyOK:
		return false, "not fully set up — policy invalid; fix .guardrc"
	case !(st.PreCommit || st.PrePush):
		return false, "not fully set up — run 'guard init'"
	case st.PreCommitUnreachable || st.PrePushUnreachable:
		return false, "degraded — depguard's block is installed but UNREACHABLE: the hook it was chained onto exits first; move the depguard block above that exit"
	case !(st.PreCommitCurrent || st.PrePushCurrent):
		return false, "degraded — a hook exists but is not depguard's current shim; run 'guard init' to refresh"
	case !guardOnPath:
		return false, "degraded — guard is not on PATH, so the hooks can't run; install the guard binary"
	default:
		return true, "this repo is protected"
	}
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

// cmdSecretAdd APPENDS one or more patterns to the secret-paths gate without
// restating the existing list — the convenience counterpart to `guard config set
// secret-paths …` (which replaces it). Mirrors cmdAllow.
func cmdSecretAdd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: guard secret-add <pattern>...  (e.g. .env \"secrets/\" \"*.pem\")")
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	for _, pat := range args {
		added, err := config.AddSecretPath(dir, pat)
		if err != nil {
			return err
		}
		if added {
			fmt.Printf("guard: secret-paths += %s  (saved to %s — commit it)\n", pat, config.FileName)
		} else {
			fmt.Printf("guard: %s is already a secret-path\n", pat)
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
