# depguard — Sales Pitch

**Your next `npm install` is the easiest way into your machine. depguard closes it.**

One signed binary. Zero dependencies. Nothing running in the background.
Protection fires only when *you* act — install, commit, PR.

---

## The problem (30 seconds)

Modern supply-chain attacks don't exploit your code — they *become* your code:

```
 a maintainer account gets phished ──► a "patch" version ships malware
 you typo one letter ──────────────► lodahs installs a credential stealer
 any dep's postinstall script ─────► arbitrary code runs on YOUR machine, as YOU
 a dep you installed last month ───► flagged malicious next week — who tells you?
```

Audits and scanners react *after* the damage. depguard sits in the install path
and makes the malicious version something npm **never even sees**.

## The product

A local-first guard for npm installs — defense in depth, five independent layers:

```
 ① AVOID        cooldown + advisory filtering — risky versions become invisible
 ② CATCH        static scan — scripts, capabilities, obfuscation, injection prose
 ③ NEUTRALIZE   ignore-scripts by default — untrusted setup code never auto-runs
 ④ CONTAIN      approved scripts run boxed (no network, no secrets) + syscall-traced
 ⑤ RECOVER      every commit/PR re-checks the lockfile against fresh advisories
```

Not installed through npm — a security tool must not ship through the ecosystem
it protects. The binary lives on your machine; only policy lives in your repo.

## Features

**The ephemeral proxy** — `guard install` spins up a per-command localhost proxy
that rewrites what npm sees: versions younger than the cooldown (default 14d)
vanish, OSV-flagged versions vanish, `latest` repoints to the newest safe
release. npm resolves normally and picks a safe version *itself* — no errors,
no friction, no daemon left running.

**Name-level gates, fail closed** — one-edit typosquats (`lodahs`, `expresss`),
non-ASCII homoglyphs (`reаct` with a Cyrillic а), and dependency-confusion
(internal scopes resolving against the public registry) are blocked before any
metadata is served.

**Scripts neutralized, then earned back** — `ignore-scripts` everywhere (guard
writes it into `.npmrc`, so even raw `npm install` can't run setup code). The
few packages that genuinely need a build step ask **once**, with a static scan
in front of the prompt. Answers are committed and travel with the team.

**The observation chamber** — approved scripts run in a docker box: no network,
read-only tree, capabilities dropped, digest-pinned image — with `strace`
watching every syscall. A `connect()` to a real host or a read of `~/.ssh`
auto-convicts: output discarded, approval revoked, evidence committed.

**Trust intelligence** — registry ECDSA signature verification, maintainer-change
detection (the account-takeover fingerprint), per-version capability diffs
("this patch release added a socket"), lockfile-integrity checks for poisoned
entries, and an LLM-injection sweep (prompt-injection prose, Trojan-Source bidi,
zero-width hiding) for the era when an *agent* reviews your deps.

## Services & surfaces

| Surface | What you get |
|---|---|
| `guard install` / `guard ci` | protected installs — the proxy, the filters, the box |
| `guard check [--json]` | on-demand audit: advisories, cooldown, integrity — across npm, pnpm, and yarn lockfiles |
| `guard scan <dir> [--json]` | static-scan any package dir; JSON for CI and agents |
| git hooks + CI gate | `guard init` drops pre-commit/pre-push hooks and an optional PR check — a teammate's bad dep never merges |
| `guard mcp` | MCP server over stdio (`scan_package`, `check_dependencies`) — your AI agents get the same protection, with every result wrapped as untrusted data |

Per-repo state is just three committed files (`.guardrc`, `.guard-approvals`,
your lockfile). No accounts, no cloud, no telemetry, no external database.

## How it's different

Most tools in this space **report** — they tell you, after the fact, that
something you already installed is bad. depguard sits *in the install path* and
makes the bad version one npm never resolves in the first place.

| You might use… | What it does | Where depguard differs |
|---|---|---|
| **Dependabot / `npm audit`** | alert on known CVEs *after* install, from a public advisory DB | filters bad versions out **before npm resolves**, and adds a **cooldown** that stops day-zero malware no advisory has named yet |
| **Snyk / socket.dev** | cloud service scans your manifest, dashboards + per-seat pricing, your dep graph leaves the building | **local-first, zero cloud, zero telemetry, no accounts** — state is three committed files; nothing about your repo is uploaded |
| **Lockfile pinning / `npm ci`** | reproducible installs of whatever you already trusted — including a version that was poisoned before you pinned it | re-checks the locked versions against fresh advisories on **every commit/PR**, and verifies registry signatures + lockfile integrity |
| **`--ignore-scripts` by hand** | blocks *all* lifecycle scripts; native packages break, so teams turn it back off | ignore-by-default **plus** an ask-once approval that runs the few real build scripts **boxed and syscall-traced**, so you keep the protection without the breakage |
| **OS sandboxes / per-OS jails** | contain script execution, but per-OS, escapable, complex to set up | a digest-pinned container that both **cages and observes** (strace convicts on exfil intent) — and when no runtime exists, every other layer still works |
| **Scanner-only tools** | flag suspicious *static* patterns; obfuscation hides from a code reader | pairs static signals with **dynamic syscall evidence** — you can hide a `connect()` from a reader, not from the trace |

Three structural choices nobody else combines:

- **It's a binary, not an npm package.** A security tool installed *through the
  ecosystem it protects* is itself a supply-chain target. depguard's binary lives
  on the machine; only policy lives in the repo.
- **Avoid, don't just recover.** The ephemeral proxy means the risky version is
  *invisible* to npm — there's no error to handle and no "we caught it after it
  ran" window.
- **No background process, no cloud.** Nothing daemonizes, nothing phones home.
  Protection fires only when you act, and your dependency graph never leaves your
  machine.

## Why teams pick it

- **Zero friction by default** — ~90% of packages have no scripts and install
  exactly as before; the safe version is simply the only one offered.
- **Set up once** — `guard init` per repo; policy and approvals are code-reviewed
  in PRs like everything else.
- **Honest by design** — no layer claims 100%. Each one raises attacker cost;
  together they close the gaps the others leave. Runtime malice and code you
  *deliberately* execute stay out of scope — and the docs say so.

## Get started (2 minutes)

```sh
go build -o guard . && sudo mv guard /usr/local/bin   # or grab the signed binary
cd your-project
guard init             # policy, hooks, .npmrc — done
guard install lodash   # instead of npm install
```

See it live: `node demo/run.mjs`. Full model: [DESIGN.md](DESIGN.md).
