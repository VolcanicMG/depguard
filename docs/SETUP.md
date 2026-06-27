# depguard — Setup

Getting depguard protecting a repo, end to end — plus the tips that make it quiet
and unannoying in day-to-day use. For the *why* behind each layer see
[DESIGN.md](DESIGN.md); for the command reference see [README.md](../README.md).

```
 ① install the binary ONCE on the machine        (global, signed, zero-dep)
 ② guard init  in each repo                       (drops policy + hooks, commit them)
 ③ use guard install / guard ci instead of npm    (filtered + scripts neutralized)
 ④ hooks + CI run guard check on commit/push/PR    (catch deps that go bad later)
 ⑤ tune .guardrc + waive reviewed findings          (keep it quiet, stay honest)
```

---

## 0. Prerequisites

| Need | Why | Note |
|---|---|---|
| Go 1.26.4 | build the binary (once) | only the person *building* needs it; end users get the binary |
| git | hooks + the `guard check` HEAD-diff | a repo without git still works, just no commit-diff scoping |
| Docker or Podman | the box (run approved build scripts sandboxed + traced) | **optional** — every other layer works without it (see §5) |

Zero npm packages are involved in installing depguard — on purpose. A tool that
guards the npm ecosystem must not be installed *through* it.

---

## 1. Install the binary (once per machine)

**Prebuilt:** grab a binary for your OS/arch from the [Releases](https://github.com/VolcanicMG/depguard/releases) page and verify it against `SHA256SUMS` — then skip to §2. To build from source:

```sh
cd /path/to/depguard
go build -o guard .            # zero dependencies
sudo mv guard /usr/local/bin/  # or anywhere on your PATH
guard version                  # -> guard 1.0.0
```

On this machine Go lives at `~/.local/go/bin/go` (not on PATH), so:

```sh
~/.local/go/bin/go build -o guard .
```

That single binary is all an end user ever needs. Sign/checksum it if you
distribute it to a team (the CI gate, §6, will ask for a pinned URL + checksum).

### Cross-compiling for another OS/arch

depguard is pure Go (no cgo), so you can build for any target from any machine —
`CGO_ENABLED=0` is implied when `GOOS` differs:

| Target | Command |
|--------|---------|
| macOS (Apple silicon) | `GOOS=darwin GOARCH=arm64 go build -o guard .` |
| macOS (Intel) | `GOOS=darwin GOARCH=amd64 go build -o guard .` |
| Windows | `GOOS=windows GOARCH=amd64 go build -o guard.exe .` |
| Linux (x86-64) | `GOOS=linux GOARCH=amd64 go build -o guard .` |
| Linux (arm64) | `GOOS=linux GOARCH=arm64 go build -o guard .` |

The core (proxy, cooldown, OSV, scan, `why`, `sbom`, license, provenance) runs on
all of them. **Script sandboxing** additionally needs Docker/Podman — and because
`strace` + seccomp run *inside* the Linux container (not on the host), it works on
macOS and Windows hosts too; without a runtime it follows `no-container-fallback`
(§5). Git hooks are `sh` shims: native on macOS/Linux, Git-for-Windows' bash on
Windows.

---

## 2. Initialize a repo

```sh
cd your-project
guard init          # local protection (hooks + policy + .npmrc)
guard init --ci     # ALSO writes a GitHub Actions PR gate (.github/workflows/depguard.yml)
```

`guard init` is idempotent-ish: it **refuses to overwrite** an existing `.guardrc`
and never clobbers a human-edited `.npmrc` (it appends, never duplicates). What
lands:

```
 your-project/
 ├── .guardrc            ◄ policy (cooldown, scopes, fallback) — COMMIT IT
 ├── .npmrc              ◄ ignore-scripts=true (raw `npm install` can't run scripts) + save-exact=true (deps pinned, no ^/~)
 ├── .git/hooks/         ◄ pre-commit + pre-push shims that call the global `guard check`
 └── .github/workflows/  ◄ (--ci only) the PR gate template — see §6
```

`.guard-approvals` and `.guard-ignores` are created the first time you approve a
script or waive a finding — they don't exist until needed.

### Commit the state

```sh
git add .guardrc .npmrc            # + .guard-approvals / .guard-ignores once they exist
git commit -m "chore: add depguard policy"
```

These travel with the repo so every teammate and CI share one policy. They are
**security decisions** — review changes to them in PRs.

---

## 3. Daily workflow

| Instead of… | Run | What it does |
|---|---|---|
| `npm install <pkg>` | `guard install <pkg>` | filters versions through the ephemeral proxy (cooldown, typosquat, OSV, signature), neutralizes scripts, re-checks the final lockfile |
| `npm ci` | `guard ci` | lockfile-exact install with the same script-neutralization + approval + advisory checks |
| (manual audit) | `guard check [--all] [--json]` | what the hooks/CI run: advisories + cooldown + lockfile integrity |
| (inspect one dep) | `guard scan <dir> [--json]` | static scan of one package: scripts, capabilities, LLM/agent-injection signals |
| (is it set up?) | `guard status` | **offline** health screen: policy, files, hooks, sandbox, decisions (incl. expired waivers) |
| (edit policy) | `guard allow <scope>` · `guard config set <k> <v>` | change `.guardrc` via a command instead of hand-editing YAML |

First protected install:

```sh
guard install lodash
#  → npm only ever sees versions older than the cooldown; it picks a safe one
#  → if a package wants to run a setup script, you're asked once (remembered in
#    .guard-approvals); with Docker present it runs sandboxed + strace-traced
```

### The local escape hatch

A commit/push hook can be skipped for **one** action — depguard only, so any
co-located lint/format hooks still run:

```sh
GUARD_SKIP=1 git push       # skips depguard's hook for this push only
```

This lives in the shell shim, never in the binary, so it cannot weaken the CI
gate — CI calls `guard check` directly and ignores the env var.

---

## 4. Tune the policy (`.guardrc`)

`guard init` writes a fully-commented starter. The knobs you'll actually touch:

```yaml
cooldown: 14d                      # min age a version must reach before npm sees it
ignore-scripts: true               # never auto-run lifecycle scripts (the default; keep it)
allow: ["@yourco/*"]               # YOUR scopes bypass the cooldown (you publish them)
internal-scopes: ["@yourco/*"]     # MUST come from a private registry — blocked from public (confusion guard)
no-container-fallback: warn-approve # no Docker? warn + ask (CI fails closed unless pre-approved) | or: fail
flag: [new-deps, new-maintainer, provenance]  # extra opt-in signals guard check surfaces (see below)
advisory-threshold: high           # lowest advisory severity that BLOCKS; below it warns | critical|high|moderate|low
untraced-boxed: run                # box can't build the strace image? run caged-but-unwatched | or: fail
secret-paths: [".env", ".env.*", "secrets/", "*.pem"]  # files that must NEVER be committed/pushed (off by default)
license-deny: ["GPL-3.0", "AGPL-3.0"]   # SPDX ids to BLOCK on installed deps (off by default; deny applied first)
# license-allow: ["MIT", "Apache-2.0", "ISC", "BSD-3-Clause"]  # allowlist mode: ONLY these pass (stricter — pick one mode)
# registry: https://registry.npmjs.org   # upstream; must be https (loopback http ok for tests)
```

Tips:

- **Edit policy by command, not by hand:** `guard allow @yourco/*` appends to the
  allow list; `guard config set cooldown 7d` (or `flag`, `registry`, …) sets a key —
  both validate before writing and tell you to commit. `guard config get` prints the
  effective policy. Hand-editing `.guardrc` still works for anything fancier.
- **`allow:` is the cooldown bypass, not a trust-everything switch.** Use it for
  scopes you publish yourself; waiting out a cooldown on your own package is
  pointless. It also clears a typosquat/homoglyph **name** block (the only escape
  for that fail-closed gate).
- **`internal-scopes:` + `allow:` together** for your private scopes: bypass the
  cooldown *and* refuse to resolve them from the public registry.
- **`flag:` is opt-in extra signal.** `new-deps` (on by default) lists packages a
  lockfile change adds — cheap, non-blocking. `new-maintainer` flags publisher
  changes / long-dormancy republishes (account-takeover fingerprint). `provenance`
  verifies a package's npm build-provenance attestation (Sigstore/SLSA — DSSE
  signature, Fulcio cert chain, tarball-digest binding) and blocks a tampered
  claim. Both `new-maintainer` and `provenance` fetch per package, so they're off
  by default.
- **`license-deny:` / `license-allow:` gate dependency licenses.** Deny-list SPDX
  ids (`GPL-3.0`, `AGPL-3.0`, …) to BLOCK installed packages that declare them, or
  switch to allowlist mode with `license-allow:` so only the listed licenses pass
  (deny is applied first). Off by default; both read each installed package's
  declared license, so they need `node_modules` present.
- **`advisory-threshold:` grades advisories.** Hits at/above it BLOCK; below it
  WARN. Default `high` (critical+high block, moderate+low warn). `MAL-*`
  malicious-package hits and advisories OSV couldn't score **always** block,
  whatever the threshold (fail closed). On a commit/push at a terminal the hook
  runs `guard check --confirm`: it lists any warnings and asks before proceeding,
  and recording your acceptance writes a waiver into `.guard-ignores` so it's
  auditable later. CI (no terminal) never prompts — warnings print, blockers gate.
- **`secret-paths:` stops YOUR secrets from leaking.** List the files that must
  never reach the remote (`.env`, `secrets/`, `*.pem`, keys). If any matching file
  is staged or already tracked by git, `guard check` HARD-BLOCKS the commit/push —
  same weight as a critical advisory — so the secret can't be uploaded. Untracked /
  gitignored files are ignored (git wouldn't push them); a file already committed
  keeps blocking until you `git rm --cached` it (and rotate the secret). A
  deliberate match (`.env.example`) is waived with `guard ignore secret:<path>`.
  The list is fully yours to extend — nothing is baked in. `guard secret-add
  "*.pem" "secrets/"` APPENDS patterns without restating the list (the convenience
  twin of `guard config set secret-paths …`, which replaces it).
- **A cooldown hit at a terminal is recoverable in place.** On a commit/push the
  hook's `guard check --confirm` offers, over all violations at once: **[a] accept
  all** (waive them) or **[p] pin & reinstall** — drop each direct dep to its
  latest version past the cooldown, reinstall, and re-verify. CI keeps the strict
  block; pinning never happens unattended.
- **A typo in a bool fails closed.** `ignore-scripts: tru` errors out rather than
  silently disabling script neutralization. A typo'd `advisory-threshold` errors
  the same way (it never silently arms an unknown level). Unknown keys warn
  (likely a misspelt known key).

---

## 5. The box (running approved build scripts)

Native packages (`better-sqlite3`, `bcrypt`, esbuild, puppeteer…) need their
build script. depguard runs **only approved** scripts, and only inside a sandbox:

```
 Docker/Podman present → script runs: no network, read-only tree, only its own
                         dir writable, cap-drop ALL, no-new-privileges, pids/mem
                         capped, strace watching syscalls. A connect() to a real
                         host or a read of ~/.ssh auto-convicts: output discarded,
                         approval auto-revoked (and the revocation is committed).
 No container runtime  → no-container-fallback policy:
                           warn-approve → warn + ask; CI fails closed unless the
                                          decision is already in .guard-approvals
                           fail         → always skip the script
```

Tips:

- **No Docker is fine** for pure-JS dependency trees (~90%+ have no scripts).
  Cooldown, scan, advisory, integrity all still run. You only feel the gap when an
  *approved native build* must run.
- **Pre-approve for CI** locally so a vetted package builds non-interactively:
  `guard approve better-sqlite3@11.0.0` (add `--uncontained` to allow a bare run
  where there's no sandbox, or `--deny` to refuse). Commit `.guard-approvals`.
- **`untraced-boxed: fail`** for shops that won't accept output they couldn't
  observe (the strace image failed to build, e.g. offline).
- **An uncontained run is still env-scrubbed** — even when you approve a bare run
  (no sandbox), the script inherits only `PATH`/`HOME`/`LANG`/`TMPDIR`, never the
  API tokens in your shell. It's damage limitation, not containment.
- **Skip the first-run wait with `guard prewarm`** — builds the sandbox (strace)
  image ahead of time so the first approved native build isn't slow. Or pass
  `--prebuild-box` to `guard init`. Needs docker + network; pure-JS installs
  never touch it.
- **Tidy up with `guard clean`** — sweeps stray containers + any backup/trace
  leftovers from a hard-killed run, KEEPING the image so the next boxed run stays
  instant. `guard clean --image` also removes the ~1.6 GB image (it rebuilds
  lazily next time). Offline and idempotent.

---

## 6. CI gate (`--ci`)

`guard init --ci` writes `.github/workflows/depguard.yml` as a **deliberate
FIXME** — it refuses to run until you pin a real release:

1. Build + publish a `guard` binary as a release artifact.
2. Edit the workflow: set the release **URL** and its **sha256 checksum** (no
   floating tags — the gate must not pull an unpinned binary).
3. Commit. The PR check now runs `guard check` and blocks merge on a flagged dep.

This closes the "a teammate without depguard adds a bad dep" gap: the bad version
can reach their `node_modules`, but not past the merge gate.

---

## 7. Waiving a reviewed finding (`.guard-ignores`)

`guard check` gates on advisories, cooldown, lockfile integrity, and secret files.
When you've **reviewed** a finding and accept it, waive that one issue so it stops
holding up commits/PRs — without weakening the check for anything else.

```sh
guard check
#  ...prints, under each gating finding, the exact line to waive it, e.g.:
#  → guard ignore cooldown:lodash@4.17.21 --reason "..."

guard ignore cooldown:lodash@4.17.21 --reason "vendored fork, vetted" --expires 90d
guard ignore --list                       # active / EXPIRED, with reasons
guard ignore --remove cooldown:lodash@4.17.21
```

How to think about it:

- **One waiver = one finding**, pinned to an exact `name@version` + kind. IDs:
  `cooldown:<name>@<version>`, `secret:<path>`, `off-registry:<name>@<version>`,
  `unhashed:<name>@<version>`, `advisory:<name>@<version>:<osv-id>`.
- **It lapses when the package moves.** A new version is a new finding — you'll be
  asked to review it fresh. A waiver can't silently cover a version nobody saw.
- **`--expires` makes it self-retiring.** `30d` (relative) or `2026-09-01`
  (absolute). An expired waiver re-gates (fail closed) and is reported loudly.
- **Add a `--reason`.** It's optional but it's the audit trail the next reviewer
  reads. Commit `.guard-ignores` so the waiver + reason travel.
- **Not for name blocks.** A typosquat/confusion block is cleared with `allow:` in
  `.guardrc`, not a waiver — clearing a fail-closed block is a different decision.

---

## 8. Agents / MCP

Expose the scanners to an AI agent over stdio:

```sh
guard mcp        # tools: scan_package, check_dependencies
```

Every result is wrapped as **untrusted data**, and the scanner flags
prompt-injection prose, Trojan-Source bidi chars, and zero-width hiding in a
package's files — so an agent reviewing your deps treats a package's text as data,
not instructions.

---

## 9. Verify it's working

```sh
guard status                # offline: policy, files, hooks, sandbox, decisions — "protected ✓" or "run guard init"
guard check                 # clean tree -> "no advisory hits ✓ / cooldown ✓ / integrity ✓"
guard install left-pad      # a fresh version is hidden by the cooldown; npm picks an older one
git commit                  # the pre-commit hook runs guard check; a flagged dep blocks it
```

Run the bundled live demo (safe — uses unroutable doc IPs) to watch every layer
fire: `node demo/run.mjs` ([demo/README.md](../demo/README.md)).

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `guard check` blocks on a dep you trust | review it, then `guard ignore <id> --reason "…"` (the exact line is printed under the finding) |
| Cooldown blocks your own package | add its scope to `allow:` in `.guardrc` |
| Approved native build won't run | no container runtime → see `no-container-fallback` (§5); pre-approve with `guard approve` for CI |
| Hook blocks an urgent push | `GUARD_SKIP=1 git push` (this push only; CI still enforces) |
| `unknown key "…" (ignored)` warning | a misspelt `.guardrc` key — fix the spelling |
| `ignore-scripts …: expected true or false` | a typo'd bool fails closed by design; correct the value |
| pnpm / yarn project | `guard install` proxies all three managers (auto-detected); boxed **script approval** is npm-only, so under pnpm/yarn scripts stay disabled and the lockfile is re-checked |
| Waiver isn't suppressing | it may have **expired** (`guard ignore --list` shows EXPIRED) or the package version changed (re-waive the new `name@version`) |
| `Text file busy` overwriting `guard` | the MCP server (`guard mcp`) is running — unlink first, it won't disturb the live process: `sudo rm -f /usr/local/bin/guard && sudo cp guard /usr/local/bin/guard` |
