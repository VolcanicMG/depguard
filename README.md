# depguard

Local-first supply-chain protection for npm installs. One signed binary, per-repo
policy, **nothing running in the background** — protection fires only when you act
(install, commit, PR). Full model: [DESIGN.md](DESIGN.md). New to a repo?
Step-by-step: [SETUP.md](SETUP.md).

```
 guard install lodash
       │
       ▼
 ┌─────────────────────────────┐
 │ ephemeral proxy (this cmd    │  versions younger than the cooldown are
 │ only) filters what npm SEES  │  invisible → npm picks a safe one itself
 └─────────────────────────────┘
       │  --ignore-scripts: lifecycle scripts never auto-run
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

See it live: `node demo/run.mjs` ([demo/README.md](demo/README.md)).

## Install

```sh
go build -o guard .          # Go 1.26.4, zero dependencies
sudo mv guard /usr/local/bin # or anywhere on PATH
```

End users need only the compiled binary — never Go, never npm packages.

## Use

```sh
cd your-project
guard init            # drops .guardrc, .npmrc, pre-commit/pre-push hooks (--ci adds PR gate)
#   bypass a hook once (depguard only, other hooks still run): GUARD_SKIP=1 git push
guard status          # is this repo protected? policy, hooks, sandbox, decisions (offline)
guard install <pkg>   # instead of npm install
guard ci              # instead of npm ci (lockfile-exact installs, same protections)
guard check [--all] [--json]   # advisories + cooldown + integrity (hooks run this)
guard scan <dir> [--json]      # static-scan one package dir (scripts, caps, injection)
guard approve <name@version> [--uncontained|--deny]   # script decisions
guard ignore <issue-id> [--reason ".."] [--expires 30d]  # waive a REVIEWED check finding (--list, --remove)
guard allow <pattern>...                 # add a name/scope to .guardrc allow (bypass cooldown)
guard config [get | set <k> <v>]         # show or edit .guardrc policy
guard clean           # remove the sandbox image + stray run artifacts (offline, idempotent)
guard mcp             # run as an MCP server over stdio (tools: scan_package, check_dependencies)
```

Run `guard status` anytime for an offline, instant read on whether the repo is
protected — policy, the committed files, hooks, sandbox runtime, and recorded
approvals/waivers (it flags expired ones). Output is colorized on a terminal and
respects `NO_COLOR`.

## Per-repo files (commit them)

| File | Holds |
|---|---|
| `.guardrc` | policy: cooldown, allowed scopes, fallback mode — **review changes in PRs** (it controls the filter) |
| `.guard-approvals` | ask-once script decisions — **review changes in PRs** (they're security decisions) |
| `.guard-ignores` | reviewed-finding waivers — one per issue, version-pinned + optional expiry — **review changes in PRs** |
| `.npmrc` | `ignore-scripts=true` so even raw `npm install` can't run scripts |

## Waiving a reviewed finding

`guard check` gates commit / push / PR / CI on advisories, cooldown, and lockfile
integrity. When you have **reviewed** a specific finding and accept it, waive that
one issue so it stops gating — without weakening the check for anything else:

```sh
guard check                       # prints the exact `guard ignore …` line per finding
guard ignore cooldown:lodash@4.17.21 --reason "vendored fork, vetted" --expires 90d
guard ignore --list               # every waiver, tagged active / EXPIRED
guard ignore --remove cooldown:lodash@4.17.21
```

A waiver is **purposeful, not a blanket off-switch**: it is pinned to an exact
`name@version` + finding-kind, so it lapses the moment the package moves to a new
version (which is then judged on its own). `--expires` makes it self-retiring — an
expired waiver re-gates (fail closed) and is reported. Waivers live in the
committed `.guard-ignores`, so the decision *and its reason* travel to teammates
and CI as reviewable evidence. (The install-time **name** gate — typosquat /
dependency-confusion — is escaped with `allow:` in `.guardrc`, not here.)

## What each layer stops

| Layer | Stops |
|---|---|
| Typosquat / homoglyph name gate | impostor names before any metadata is served: one-edit look-alikes (`lodahs`, `expresss`) and non-ASCII homoglyphs (`reаct`) — blocked fail-closed, cleared via `allow:` |
| Dependency-confusion gate | `internal-scopes` names blocked from resolving against the public registry |
| Cooldown (default 14d) | freshly-published malicious versions (most are yanked in days) |
| OSV at resolve time + on commit | known-bad versions dropped *before* npm resolves (not just flagged after) |
| Registry signature verification | a version whose npm ECDSA signature is present-but-invalid (registry/account tampering the integrity hash can't catch) |
| Maintainer-change (opt-in) | publisher changes / long-dormancy republishes on installed versions — the account-takeover fingerprint |
| Lockfile integrity check | entries whose tarball resolves off-registry or carry no integrity hash (poisoned lockfile) |
| Ignore-scripts (`guard` + `.npmrc`) | install-time code execution — the #1 npm attack vector — even via plain npm |
| Static scan at approval | informed yes/no: network, child_process, secret paths, eval — **plus LLM/agent-injection** (prompt-injection prose, Trojan-Source bidi chars, zero-width hiding) in README/markdown/code, for when an agent reviews your deps |
| Boxed + traced script run | exfil from approved scripts: no network, no secrets, digest-pinned image, no-new-privileges, pids-limit, **seccomp** (blocks io_uring + the kernel keyring + bpf/perf) — **and strace watches syscalls**, so a connect() to a real host or a read of `/root/.ssh` auto-convicts, discards the output, and revokes the approval. The container is named + force-removed on a timeout; `guard clean` reclaims the image |
| `guard check` on commit/PR | newly-reported advisories AND cooldown violations across **every distinct version** in the tree, entered via *any* install path; `flag: new-deps` also reports packages a change adds |

`guard check` scopes the cooldown re-check to lockfile versions **added since git
HEAD** — each version is vetted once, at the commit that introduces it. `--all`
forces a full-tree sweep.

## Tests

Black-box e2e suite in `test/` — vitest spawns the **real compiled binary**
against a mock npm registry with fabricated publish dates, so the cooldown is
tested deterministically and nothing touches registry.npmjs.org.

```sh
cd test
npm install          # vitest only; the harness itself adds zero other deps
npm test             # builds the binary (globalSetup), runs the e2e suite
```

| File | Proves |
|---|---|
| `cooldown.test.mjs` | young versions hidden, latest repointed, blocks explained, allowlist + custom cooldown, scoped names, `check` catches bypass installs, https-only registry |
| `scripts.test.mjs` | postinstall neutralized, denials honored, approvals file written, approved script runs sealed in docker (auto-skips without docker) |
| `init.test.mjs` | policy + executable hooks + `.npmrc` dropped, never clobbers existing files, clear failure outside git, `check` with no lockfile |
| `additions.test.mjs` | typosquat + dependency-confusion blocks, deprecation note, lockfile-integrity (off-registry / no-hash), fail-closed config, `scan --json` (caps + injection + bundled binary + zero-width), `mcp` stdio |

## Honest limits

- **Runtime malice is out of scope** — a dep that behaves badly when your app runs
  in production needs different tooling.
- The box needs Docker/Podman; without one, approved scripts follow the
  `no-container-fallback` policy (warn-then-approve; CI fails closed). Uncontained
  runs get a scrubbed environment (PATH/HOME/LANG only), but that's damage
  limitation, not containment.
- Static scan is signals, not proof — that's why approved scripts still run boxed
  and traced.
- Syscall observation uses `strace` inside the box (built locally from signed
  Debian packages — nothing installed on the host). It catches network reach-out,
  DNS queries, secret-path access, and process spawns. A kernel-level eBPF/Falco
  upgrade for richer detection stays future work; if the strace image can't be
  built (offline), scripts still run CAGED but UNTRACED, and guard says so.
- A `.bin` entry from a malicious package still executes when *invoked* — install
  protection can't help once you run the code on purpose.
- `guard install` is npm-shaped (it wraps npm). pnpm and yarn are covered by the
  **check** path (`guard check` reads `pnpm-lock.yaml` / `yarn.lock` for
  advisory/cooldown/integrity), not the install-time proxy.
- Signature verification **blocks only present-but-invalid** signatures; unsigned
  versions pass, because most of the ecosystem still is. Maintainer-change and the
  per-version capability diff are **opt-in** (`flag:`) — they fetch a packument per
  package, too heavy to run on every commit by default.
- The MCP server returns scan/check results wrapped as **untrusted data**; an agent
  must still be told (as the banner says) not to follow instructions embedded in a
  package's files.

Repo layout and call flows: [docs/CODEMAP.md](docs/CODEMAP.md).
