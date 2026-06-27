<div align="center">

<img src="depguard.png" alt="depguard — protect against supply-chain attacks" width="440">

<br>

![Go](https://img.shields.io/badge/Go-1.26.4-00ADD8?logo=go&logoColor=white)
![dependencies](https://img.shields.io/badge/dependencies-zero-2ea44f)
![version](https://img.shields.io/badge/version-0.9.0-2ea44f)
![platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-555)
![local-first](https://img.shields.io/badge/local--first-no%20cloud%20%C2%B7%20no%20telemetry-2ea44f)
![license](https://img.shields.io/badge/license-Apache%202.0-blue)

**Your next `npm install` is the easiest way into your machine. depguard closes it.**

One signed binary · zero dependencies · nothing running in the background.
Protection fires only when *you* act — install, commit, PR.

</div>

---

## Contents

- [Why](#why) · [How it works](#how-it-works) · [Quickstart](#quickstart)
- [The five layers](#the-five-layers) · [What each layer stops](#what-each-layer-stops)
- [Command reference](#command-reference) · [Per-repo files](#per-repo-files-commit-them) · [Waiving a finding](#waiving-a-reviewed-finding)
- [How it's different](#how-its-different) · [Honest limits](#honest-limits)
- [Tests](#tests) · [Docs](#docs)

## Why

Modern supply-chain attacks don't exploit your code — they *become* your code:

```
 a maintainer account gets phished ──► a "patch" version ships malware
 you typo one letter ──────────────► lodahs installs a credential stealer
 any dep's postinstall script ─────► arbitrary code runs on YOUR machine, as YOU
 a dep you installed last month ───► flagged malicious next week — who tells you?
```

Audits and scanners react *after* the damage. depguard sits in the install path
and makes the malicious version something npm **never even sees**.

> **Not installed through npm — on purpose.** A security tool that ships through
> the ecosystem it protects is itself a supply-chain target. depguard's binary
> lives on your machine; only policy lives in your repo (committed files — no
> accounts, no cloud, no telemetry).

## How it works

A package's full journey — from `guard install` through every layer to a trusted merge:

<div align="center">
  <img src="depguard-pipeline.svg" alt="depguard package lifecycle: guard install → name gate → cooldown + OSV filter → npm resolves → lifecycle scripts? → scan + box + strace → commit/PR re-check → merged. Blocked or contained at each layer." width="860">
</div>

<details><summary><b>Text version of the flow</b></summary>

```
 guard install lodash
       │
       ▼
 ┌─────────────────────────────┐
 │ ephemeral proxy (this cmd   │  versions younger than the cooldown are
 │ only) filters what npm SEES │  invisible → npm picks a safe one itself
 └─────────────────────────────┘
       │  --ignore-scripts: lifecycle scripts never auto-run
       │  save-exact: new deps pinned to the exact version (no ^/~)
       ▼
 script-bearing packages (the few) → static scan shown → you approve once
       │                              → script runs BOXED + TRACED (docker:
       │                                no network, read-only tree, own dir
       │                                writable, strace watching syscalls)
       │                              → exfil/secret-access attempt? output
       │                                discarded, approval auto-revoked
       ▼
 OSV advisory check on the final lockfile
```

</details>

See it live: `node demo/run.mjs` ([demo/README.md](demo/README.md)).

## Quickstart

```sh
# 1. Build the binary once per machine (Go 1.26.4, zero dependencies)
go build -o guard .
sudo mv guard /usr/local/bin/      # or anywhere on your PATH

# 2. Protect a repo
cd your-project
guard init                          # drops .guardrc, .npmrc, pre-commit/pre-push hooks
guard install lodash                # instead of npm install
```

End users need only the compiled binary — never Go, never npm packages. Full
onboarding, cross-compiling, tuning, and troubleshooting: **[docs/SETUP.md](docs/SETUP.md)**.

## The five layers

Defense in depth — five independent layers, no single one claimed to certify a
package clean:

```
 ① AVOID        cooldown + advisory filtering — risky versions become invisible
 ② CATCH        static scan — scripts, capabilities, obfuscation, injection prose
 ③ NEUTRALIZE   ignore-scripts by default — untrusted setup code never auto-runs
 ④ CONTAIN      approved scripts run boxed (no network, no secrets) + syscall-traced
 ⑤ RECOVER      every commit/PR re-checks the lockfile against fresh advisories
```

The *why* and the per-layer guarantees: **[docs/DESIGN.md](docs/DESIGN.md)** (the contract).

## What each layer stops

Defense in depth — but the layers don't all fire at once. Each acts at a specific
moment, grouped here by **when** it runs.

### ① At install · name & version safety — *before npm even resolves*

`guard install` / `guard ci`, via the ephemeral proxy:

| Layer | Stops |
|---|---|
| Typosquat / homoglyph name gate | impostor names before any metadata is served: one-edit look-alikes (`lodahs`, `expresss`) and non-ASCII homoglyphs (`reаct`) — blocked fail-closed, cleared via `allow:` |
| Dependency-confusion gate | `internal-scopes` names blocked from resolving against the public registry |
| Cooldown (default 14d) | freshly-published malicious versions (most are yanked in days) — risky versions made invisible to npm |
| OSV at resolve time | known-bad versions dropped *before* npm resolves (not just flagged after) |
| Registry signature verification | a version whose npm ECDSA signature is present-but-invalid (registry/account tampering the integrity hash can't catch) |
| Exact version pinning (`.npmrc` `save-exact`) | silent range drift — a later `npm install` pulling a freshly-compromised `^`/`~` patch you never chose; deps stay at the version you vetted until you bump manually |

### ② At install · lifecycle scripts — *only the few packages that ship them*

| Layer | Stops |
|---|---|
| Ignore-scripts (`guard` + `.npmrc`) | install-time code execution — the #1 npm attack vector — even via plain npm |
| Static scan at approval | informed yes/no: network, child_process, secret paths, eval — **plus LLM/agent-injection** (prompt-injection prose, Trojan-Source bidi chars, zero-width hiding) in README/markdown/code, for when an agent reviews your deps |
| Boxed + traced script run | exfil from approved scripts: no network, no secrets, digest-pinned image, no-new-privileges, pids-limit, **seccomp** (blocks io_uring + the kernel keyring + bpf/perf) — **and strace watches syscalls**, so a connect() to a real host or a read of `/root/.ssh` auto-convicts, discards the output, and revokes the approval. The container is named + force-removed on a timeout; `guard prewarm` builds the image ahead of the first run and `guard clean --image` reclaims it |

### ③ On commit / push / PR — *`guard check`, run by the git hooks & CI gate*

Catches deps that go bad *after* you installed them — and your own secrets on the way out:

| Layer | Stops |
|---|---|
| `guard check` (advisories + cooldown re-check) | newly-reported advisories (graded by severity: high+/`MAL-*`/unscored **block**, moderate/low **warn** — tune with `advisory-threshold`) AND cooldown violations across **every distinct version** in the tree, entered via *any* install path; `flag: new-deps` also reports packages a change adds. At a terminal (`--confirm`, which the hooks pass) a cooldown hit offers **accept-all** (waive every violation) or **pin & reinstall** (drop each direct dep to its latest version past the cooldown, then re-verify); CI keeps the strict block |
| Lockfile integrity check | entries whose tarball resolves off-registry or carry no integrity hash (poisoned lockfile) |
| Secret-file gate (opt-in) | **your own** credential files (`.env`, `secrets/`, `*.pem`, keys) staged or already tracked by git — hard-blocks commit/push (leads the exit-code precedence) so they never reach the remote (`secret-paths` in .guardrc); waive a deliberate file with `guard ignore secret:<path>` |
| License-policy gate (opt-in) | installed packages under a denied — or, in allowlist mode, non-allowed — license (`license-deny` / `license-allow` in .guardrc) |

### ④ Opt-in deeper trust checks — *`flag:`, fetched per package (too heavy for every commit)*

| Layer | Stops |
|---|---|
| Build-provenance attestation | a published Sigstore/SLSA attestation that fails to verify — DSSE signature, Fulcio cert chain, or tarball-digest binding — i.e. a tampered provenance claim (`flag: [provenance]`) |
| Maintainer-change | publisher changes / long-dormancy republishes on installed versions — the account-takeover fingerprint |

`guard check` scopes the cooldown re-check to lockfile versions **added since git
HEAD** — each version is vetted once, at the commit that introduces it. `--all`
forces a full-tree sweep.

The OSV advisory and registry-cooldown lookups are **fail-open**: a network blip
or an OSV outage must not block every commit, so the check never *gates* on them.
But it is never silent about it — the prose output warns (`advisory check
skipped: …`), and `guard check --json` (and the MCP `check_dependencies` tool)
list what couldn't run in a **`degraded`** array. A `degraded` result with
`ok: true` means *no findings were seen, but some layers didn't run* — treat it as
"incomplete," not "proven clean." CI that wants to be strict can fail on a
non-empty `degraded`.

## Command reference

<div align="center">
  <img src="depguard-commands.svg" alt="depguard command reference: setup (init, status), install (install, ci), audit (check, scan, why, sbom), decisions & waivers (approve, ignore, allow, secret-add), config & maintenance (config, prewarm, clean, mcp)" width="900">
</div>

<details><summary><b>Full reference with every flag (copy-paste)</b></summary>

```sh
# ── Setup ──────────────────────────────────────────────────
guard init [--ci] [--prebuild-box]   # drop .guardrc, .npmrc, git hooks (--ci adds a PR gate;
                                     #   --prebuild-box builds the sandbox image now)
guard status                         # offline read: policy, hooks, sandbox, recorded decisions
#   bypass a hook once (depguard only, other hooks still run): GUARD_SKIP=1 git push

# ── Install · instead of npm ───────────────────────────────
guard install <pkg>                  # protected install through the cooldown proxy
guard ci                             # lockfile-exact install (npm ci), same protections

# ── Audit ──────────────────────────────────────────────────
guard check [--all] [--json] [--confirm]   # advisories + cooldown + integrity + secrets (hooks run this)
guard scan <dir> [--json]            # static-scan one package dir (scripts, caps, injection)
guard why <pkg> [--all]              # which direct dep(s) pull a package in (npm lockfile)
guard sbom [--spdx]                  # write an SBOM (CycloneDX, or SPDX) to stdout

# ── Decisions & waivers ────────────────────────────────────
guard approve <name@version> [--uncontained|--deny]            # script decisions
guard ignore <issue-id> [--reason ".."] [--expires 30d]        # waive a REVIEWED finding (--list, --remove)
guard allow <pattern>...             # add a name/scope to .guardrc allow (bypass cooldown)
guard secret-add <pattern>...        # append a file/dir pattern to secret-paths (never-commit gate)

# ── Config & maintenance ───────────────────────────────────
guard config [get | set <k> <v>]     # show or edit .guardrc policy
guard prewarm                        # build the sandbox image now so the first boxed run isn't slow
guard clean [--image]                # sweep stray containers + run artifacts (--image reclaims the image)
guard mcp                            # MCP server over stdio (tools: scan_package, check_dependencies)
```

</details>

Run `guard status` anytime for an offline, instant read on whether the repo is
protected — policy, the committed files, hooks, sandbox runtime, and recorded
approvals/waivers (it flags expired ones). Output is colorized on a terminal and
respects `NO_COLOR`.

## Per-repo files (commit them)

| File | Holds |
|---|---|
| `.guardrc` | policy: cooldown, allowed scopes, fallback mode, advisory severity threshold, secret-file paths — **review changes in PRs** (it controls the filter) |
| `.guard-approvals` | ask-once script decisions — **review changes in PRs** (they're security decisions) |
| `.guard-ignores` | reviewed-finding waivers — one per issue, version-pinned + optional expiry — **review changes in PRs** |
| `.npmrc` | `ignore-scripts=true` (even raw `npm install` can't run scripts) + `save-exact=true` (new deps pinned to the exact installed version — no `^`/`~`) |

## Waiving a reviewed finding

`guard check` gates commit / push / PR / CI on advisories, cooldown, lockfile
integrity, and secret files. When you have **reviewed** a specific finding and
accept it, waive that one issue so it stops gating — without weakening the check
for anything else:

```sh
guard check                       # prints the exact `guard ignore …` line per finding
guard ignore cooldown:lodash@4.17.21 --reason "vendored fork, vetted" --expires 90d
guard ignore secret:.env.example  --reason "template, no real secret"   # deliberate match
guard ignore --list               # every waiver, tagged active / EXPIRED
guard ignore --remove cooldown:lodash@4.17.21
```

A waiver is **purposeful, not a blanket off-switch**: it is pinned to an exact
`name@version` + finding-kind, so it lapses the moment the package moves to a new
version (which is then judged on its own). `--expires` makes it self-retiring — an
expired waiver re-gates (fail closed) and is reported. Waivers live in the
committed `.guard-ignores`, so the decision *and its reason* travel to teammates
and CI as reviewable evidence. (The install-time **name** gate — typosquat /
dependency-confusion — is escaped with `allow:` in `.guardrc`, not here.) Full
mechanics: [docs/SETUP.md](docs/SETUP.md).

## How it's different

Most tools in this space **report** — they tell you, after the fact, that
something you already installed is bad. depguard sits *in the install path* and
makes the bad version one npm never resolves in the first place.

| You might use… | What it does | Where depguard differs |
|---|---|---|
| **Dependabot / `npm audit`** | alert on known CVEs *after* install, from a public advisory DB | filters bad versions out **before npm resolves**, and adds a **cooldown** that stops day-zero malware no advisory has named yet |
| **Snyk / socket.dev** | cloud service scans your manifest, dashboards + per-seat pricing, your dep graph leaves the building | **local-first, zero cloud, zero telemetry, no accounts** — state is committed files; nothing about your repo is uploaded |
| **Lockfile pinning / `npm ci`** | reproducible installs of whatever you already trusted — including a version poisoned before you pinned it | re-checks the locked versions against fresh advisories on **every commit/PR**, and verifies registry signatures + lockfile integrity |
| **`--ignore-scripts` by hand** | blocks *all* lifecycle scripts; native packages break, so teams turn it back off | ignore-by-default **plus** an ask-once approval that runs the few real build scripts **boxed and syscall-traced** — protection without the breakage |
| **OS sandboxes / per-OS jails** | contain script execution, but per-OS, escapable, complex to set up | a digest-pinned container that both **cages and observes** (strace convicts on exfil intent) — and when no runtime exists, every other layer still works |
| **Scanner-only tools** | flag suspicious *static* patterns; obfuscation hides from a code reader | pairs static signals with **dynamic syscall evidence** — you can hide a `connect()` from a reader, not from the trace |

## Honest limits

No layer claims 100%. Each raises attacker cost; together they close the gaps the
others leave.

- **Runtime malice is out of scope** — a dep that behaves badly when your app runs
  in production needs different tooling.
- The box needs Docker/Podman; without one, approved scripts follow the
  `no-container-fallback` policy (warn-then-approve; CI fails closed). Uncontained
  runs get a scrubbed environment (PATH/HOME/LANG only) — damage limitation, not
  containment.
- Static scan is signals, not proof — that's why approved scripts still run boxed
  and traced.
- Syscall observation uses `strace` inside the box (built locally from signed
  Debian packages — nothing installed on the host). It catches network reach-out,
  DNS queries, secret-path access, and process spawns. A kernel-level eBPF/Falco
  upgrade stays future work; if the strace image can't be built (offline), scripts
  still run CAGED but UNTRACED, and guard says so.
- A `.bin` entry from a malicious package still executes when *invoked* — install
  protection can't help once you run the code on purpose.
- `guard install` routes **npm, pnpm, and yarn** through the cooldown proxy
  (manager auto-detected from the lockfile). The **boxed lifecycle-script
  approval** flow stays npm-only — under pnpm/yarn scripts simply stay disabled
  (`--ignore-scripts`) and the lockfile re-check still runs.
- Signature verification **blocks only present-but-invalid** signatures; unsigned
  versions pass, because most of the ecosystem still is. Maintainer-change, the
  per-version capability diff, and build-provenance are **opt-in** (`flag:`) — they
  fetch per package, too heavy to run on every commit by default.
- Build-provenance verification checks the **DSSE signature, the Fulcio cert chain
  to a pinned Sigstore root, and the subject↔tarball digest binding**, then reports
  the attested source repo. It does **not** yet verify Rekor transparency-log
  inclusion, the SCT, or rotate trust roots via TUF — a green result is a high bar,
  not the full Sigstore guarantee.
- The MCP server returns scan/check results wrapped as **untrusted data**; an agent
  must still be told (as the banner says) not to follow instructions embedded in a
  package's files.

## Tests

Black-box e2e suite in `test/` — vitest spawns the **real compiled binary**
against a mock npm registry with fabricated publish dates, so the cooldown is
tested deterministically and nothing touches registry.npmjs.org. Plus Go unit
tests (`~/.local/go/bin/go test ./...`).

```sh
cd test
npm install          # vitest only; the harness itself adds zero other deps
npm test             # builds the binary (globalSetup), runs the e2e suite
```

What the suite proves, file by file: [test/README.md](test/README.md).

## Docs

| Doc | For | Covers |
|---|---|---|
| **[docs/DESIGN.md](docs/DESIGN.md)** | the contract — the *why* | goals/non-goals, the layered threat model, each layer's guarantee, design stance |
| **[docs/SETUP.md](docs/SETUP.md)** | onboarding | step-by-step setup **& cross-compiling**, `.guardrc` tuning, waiving findings, troubleshooting |
| **[docs/CODEMAP.md](docs/CODEMAP.md)** | contributors — the *where* | file/dir layout, what calls what, where to make which kind of change |
| [demo/README.md](demo/README.md) | demo runners | demo commands, scenario cast, safety guarantees |
| [test/README.md](test/README.md) | test authors | how the black-box suite runs, the mock-registry trick |

## License

[Apache 2.0](LICENSE) © 2026 Ethan Hoff — see [NOTICE](NOTICE).
