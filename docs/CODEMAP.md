# depguard — Code Map

Where everything lives, what calls what, and where to make which kind of change.
Companion to [DESIGN.md](DESIGN.md) (the *why*) and [README.md](../README.md) (the *how to use*).

> **Before you finish a change, update the docs.** [CLAUDE.md](../CLAUDE.md) maps every
> `.md` file to what triggers an edit (change a flag → README; change a layer guarantee →
> DESIGN + README; move a file → this code map).

## Layout

```
 depguard/
 ├── main.go                     CLI dispatch + the install/check orchestration
 ├── mcp.go                      `guard mcp`: stdio JSON-RPC MCP server (zero-dep)
 ├── go.mod                      module def — ZERO dependencies, on purpose
 ├── .github/workflows/
 │   └── release.yml            CI: cross-compile + publish binaries on a vX.Y.Z tag
 ├── internal/
 │   ├── config/config.go        .guardrc policy: parse, defaults, validation
 │   ├── approvals/approvals.go  .guard-approvals: ask-once script decisions
 │   ├── waivers/waivers.go      .guard-ignores: reviewed-finding waivers (suppress check gates)
 │   ├── ui/ui.go                tiny NO_COLOR-aware ANSI color helper (status + check glyphs)
 │   ├── registry/proxy.go       ephemeral filtering proxy (cooldown + typosquat +
 │   │                           OSV + signature + dependency-confusion gates)
 │   ├── scanner/scanner.go      static scan: scripts + capability + LLM-injection
 │   ├── scanner/tarball.go      scan a published tarball → capability diff
 │   ├── typosquat/typosquat.go  name-level filter: Damerau-1 + homoglyph
 │   ├── provenance/provenance.go npm ECDSA dist.signature verification (stdlib)
 │   ├── attestation/attestation.go npm build-provenance: Sigstore/SLSA DSSE + Fulcio chain + digest bind (flag:)
 │   ├── maintainer/maintainer.go publisher-change / account-takeover detection
 │   ├── freshness/freshness.go  cooldown re-check on lockfile versions + LatestSafe (pin target)
 │   ├── secrets/secrets.go      secret-file gate: git staged/tracked vs secret-paths globs
 │   ├── license/license.go      license-deny/allow gate on installed deps' SPDX ids
 │   ├── advisory/osv.go         OSV.dev known-bad feed client (Check = batch ids;
 │   │                           Severities = per-vuln detail for tiering; Blocks)
 │   ├── box/box.go              docker/podman sealed+traced+seccomp script runner
 │   ├── trace/trace.go          strace-log → evidence + safe/unsafe verdict
 │   ├── hooks/hooks.go          git hooks (chains onto husky), .npmrc, CI writers
 │   ├── lockfile/lockfile.go    package-lock.json reader (source of truth)
 │   ├── lockfile/altlock.go     pnpm-lock.yaml + yarn.lock parsers (check path)
 │   ├── lockfile/graph.go       package-lock graph rebuild for `guard why` (parent→child edges)
 │   ├── sbom/sbom.go            CycloneDX 1.5 / SPDX 2.3 SBOM renderer (`guard sbom`)
 │   ├── semver/semver.go        minimal version compare (dist-tag repointing)
 │   └── tty/                    "is a human attached?" (termios; /dev/null lies)
 ├── assets/                     README images (committed)
 │   ├── depguard.png            project logo (README header)
 │   └── depguard-*.svg          generated infographics (why/pipeline/layers/commands/different)
 ├── docs/                       deep docs (linked from README)
 │   ├── CODEMAP.md              this file
 │   ├── DESIGN.md               the agreed design contract
 │   └── SETUP.md                step-by-step per-repo onboarding + tips
 ├── demo/                       runnable live demo (safe; unroutable doc IPs)
 │   ├── packages.mjs            the cast: benign, false-positive, exfil, etc.
 │   └── run.mjs                 narrates guard handling each, asserts outcomes
 └── test/                       vitest black-box e2e suite (runs the real binary)
     ├── helpers/registry.mjs    mock npm registry w/ fabricated publish ages
     ├── helpers/tar.mjs         hand-rolled USTAR+gzip (zero test deps)
     ├── helpers/run.mjs         temp projects + binary spawner
     └── *.test.mjs              cooldown / additions / scripts / init / secrets suites
```

## Flow: `guard install` (and `guard ci`)

```
 main.cmdInstall
   │
   ├─ config.Load ──────────── .guardrc (validates registry is https/loopback)
   ├─ approvals.Load ───────── .guard-approvals
   │
   ├─ registry.Start ───────── proxy on 127.0.0.1:random, THIS command only
   │     └─ servePackument → rewrite():  allowlist bypass → typosquat/homoglyph
   │                          NAME gate (empties versions, fail closed) →
   │                          cooldown filter + dist-tags.latest repoint
   │                          (semver.MaxStable); fails CLOSED on rewrite errors
   │
   ├─ exec npm install/ci ──── --registry=proxy --ignore-scripts (flags win over .npmrc)
   ├─ report proxy.BlockedVersions()
   │
   ├─ handleScripts            for each lockfile entry (lockfile.InstalledPaths):
   │     ├─ scanner.ReadScripts ── cheap gate: ~90% exit here (no scripts)
   │     ├─ scanner.ScanDir ────── full capability sweep, script-bearing only
   │     ├─ approvals.Get / promptApproval (tty.IsTerminal gates the ask)
   │     ├─ box.EnsureObsImage ─── lazy: builds strace image on first script
   │     └─ runApproved
   │           ├─ box.Run ──────────── docker: net=none, ro tree, own dir rw,
   │           │     │                 cap-drop ALL, no-new-privileges,
   │           │     │                 pids-limit, digest-pinned image,
   │           │     │                 strace -f over network/openat/execve
   │           │     ├─ trace.Parse ── log → observations + Unsafe verdict
   │           │     └─ Unsafe? ────── pkg dir RESTORED from pre-run backup,
   │           │                       approval auto-flipped to Denied (committed)
   │           ├─ box.RunUncontained ─ ONLY if explicitly approved; env scrubbed
   │           └─ skip + explain ───── approved-boxed but no runtime here
   │
   ├─ runRootScripts ───────── the repo's OWN lifecycle scripts (trusted, incl. prepare)
   └─ checkAdvisories ──────── advisory.Check (OSV batch) on the final lockfile,
                              then enrichSeverities + partitionBySeverity (tiering)
```

## Flow: `guard check` (what hooks + CI run)

```
 main.cmdCheck (--confirm enables the interactive warn-tier accept flow)
   ├─ checkAdvisories ── lockfile.Installed → advisory.Check (OSV)
   │                     fail-open on network errors (loud warning)
   │                     → enrichSeverities (advisory.Severities, per-vuln detail)
   │                     → partitionBySeverity: blockers gate, warns don't
   │                     → confirmThroughWarnings (--confirm, /dev/tty): on "yes"
   │                       records acceptances via waivers.Set → .guard-ignores
   └─ checkFreshness ─── scope = lockfile versions ADDED since git HEAD
                         (headLockfile via `git show`; --all = full tree)
                         → freshness.Check: publish dates from registry,
                           violations fail the commit/PR; allowlist skipped
```

Every gating finding is first run through `.guard-ignores` (`internal/waivers`): an
actively-waived `<kind>:<name>@<version>` is shown muted and does **not** gate; an
expired waiver re-gates (fail closed). The same filter runs inside `gatherCheck`, so
`--json` / MCP (`CheckResult.waived`) agree with the human output.

This is the enforcement point for installs that **bypassed guard** (plain npm,
npx, a teammate without it): the bad version can reach node_modules, but not
the shared history.

## Flow: `guard init`

```
 main.cmdInit
   ├─ config.WriteDefault ── .guardrc (refuses to overwrite)
   └─ hooks.Install
        ├─ installNpmrc ──── ignore-scripts=true (appends; never duplicates,
        │                    never overrides an existing human choice)
        ├─ pre-commit/pre-push shims → call global `guard check --quiet`
        └─ --ci: .github/workflows/depguard.yml (deliberate FIXME — you must
                 pin YOUR release URL + checksum; no floating tags)
```

## Where to change what

| Change | Touch |
|---|---|
| New version-filter rule | `registry/proxy.go` `rewrite()` — add a filter, keep fail-closed |
| Typosquat list / distance rule | `typosquat/typosquat.go` (`popular`, `known`, `Suspicion`) |
| New static-scan capability signal | `scanner/scanner.go` `capabilityPatterns` table |
| New LLM-injection signal | `scanner/scanner.go` `injectionPatterns` / `isBidiControl` / `isZeroWidth` |
| New MCP tool | `mcp.go` `toolDefs()` + `callTool()` — keep the untrusted-data banner |
| Signature/keyring behavior | `provenance/provenance.go`; wired in `proxy.go` `rewrite()` |
| Maintainer-change heuristic | `maintainer/maintainer.go` `changesFor()` |
| Build-provenance verification | `attestation/attestation.go` (DSSE + Fulcio chain + digest bind); gated by `flag: provenance`, wired in `main.go` `checkProvenance` |
| License-policy gate | `license/license.go` (SPDX deny/allow); wired in `main.go` `checkLicenses` |
| SBOM output (CycloneDX / SPDX) | `sbom/sbom.go`; `main.go` `cmdSBOM` |
| `guard why` dependency graph | `lockfile/graph.go` (`BuildGraph` / `Paths`); `main.go` `cmdWhy` |
| Another lockfile format | `lockfile/altlock.go` + dispatch in `lockfile.go` `Installed()` |
| New `.guardrc` key | `config/config.go` `Load()` switch + `WriteDefault` starter |
| Secret-file gate behavior | `secrets/secrets.go` (`Find` / `matchAny` / `gitFiles`); wired in `main.go` `checkSecrets` + `gatherCheck` |
| Cooldown accept-all / auto-pin | `main.go` `confirmCooldown` / `pinAndReinstall` / `pinPackageJSON` / `setDepVersion`; pin target from `freshness.LatestSafe` |
| New waiver-id kind | `main.go` `validWaiverID` + a `<kind>WaiverID` helper |
| Append-to-a-list command | `config.AddSecretPath` / `AddAllow` (Load → dedup → SetValue); `main.go` `cmdSecretAdd` / `cmdAllow` + dispatch case |
| Box hardening / seccomp | `box/box.go` `Run()` args + `seccompProfile` |
| New dynamic (syscall) signal | `trace/trace.go` — add a matcher; convict only on no-build-excuse behavior |
| Box hardening / different runtime | `box/box.go` `Run()` arg list; image digest + obs Dockerfile at top |
| Demo scenarios | `demo/packages.mjs` (entry + `expect` + `why`) |
| Policy file keys | `config/config.go` `Load()` switch + `WriteDefault` starter |
| New CLI command | `main.go` dispatch switch + a `cmdX` func |
| Waiver kind / ID scheme | `internal/waivers/waivers.go` + `main.go` `*WaiverID` helpers + `validWaiverID` |
| `guard status` rows | `main.go` `cmdStatus` (+ `hooks.Installed`, `box.Runtime`) — read-only, OFFLINE |
| Editable `.guardrc` key (allow/config) | `config/config.go` `canonicalValue` + `writeKeyLine`; surfaced by `cmdAllow`/`cmdConfig` |
| Terminal color | `internal/ui/ui.go` (gate = NO_COLOR + both streams TTY) |
| Approval semantics | `approvals/approvals.go` (decisions) + `main.go` `promptApproval`/`runApproved` |
| Hook/CI behavior | `hooks/hooks.go` (the shims) — they only ever call `guard check` |
| Another ecosystem (PyPI) | new siblings of `registry`/`lockfile`/`scanner`; `main.go` orchestration is npm-shaped today |

## Invariants — do not break

1. **Zero Go dependencies.** The guard must not be attackable through its own supply chain.
2. **Fail closed in the filter path** (proxy rewrite errors, missing timestamps); **fail open with loud warnings in the check path** (registry/OSV blips must not block every commit).
3. **Nothing persistent.** No daemon, no schedule; the proxy dies with the command.
4. **Never auto-run an unvetted script** — non-interactive contexts skip and explain, never decide.
5. **Prompts default to NO** (EOF, garbage input → deny).
6. **Approvals/policy are committed files** — changes are PR-reviewable security decisions.
7. **The trace convicts only on no-build-excuse behavior** (network reach-out, real-secret access). Spawns and writes are context, never convictions — false positives train humans to disable the tool. New `trace` matchers must hold this line.
8. **The strace log is written to a host-side temp dir** (`/obs`), never inside the package's writable mount — the traced script must not be able to doctor its own evidence.

## Generated reference

A per-package symbol index (types + funcs with `file:line`), auto-generated from a
stdlib-only Go AST walk, used to live here. It drifted out of sync with the source
(line numbers and the package list go stale on every edit), so it was removed rather
than left misleading — regenerate it from the current tree if you want it back. The
hand-written map above (layout, flows, where-to-change, invariants) is the durable,
maintained reference.
