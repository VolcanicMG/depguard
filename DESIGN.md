# depguard — Design

A local-first guard against supply-chain attacks in package dependencies (npm first).
Automatic, per-repo, no background process.

---

## 1. Goal & non-goals

**Goal:** stop malicious package versions and install-time code from harming your
machine — automatically, without manual review, and without anything running in the
background.

```
 IN SCOPE                              OUT OF SCOPE
 ─────────────────────────            ────────────────────────────────
 malicious published versions          runtime malice (a dep behaving
 install-time scripts (postinstall)      badly when your APP runs in prod)
 typosquats / dependency confusion     vulnerabilities in YOUR own code
 tarball ≠ source tampering            kernel / container escapes (rare)
```

**Honest stance:** no single check certifies a package "clean." depguard is
**defense in depth** — each layer raises attacker cost; none claims 100%.

---

## 2. What the tool *is*

A single **signed standalone binary** (Go or Rust, zero package-manager deps of its
own) installed once on the machine. Per repo, a one-time `guard init` drops a small
amount of config — nothing runs in the background.

```
 ┌─────────────────────────────────────────┐
 │  guard — one signed binary on the box    │  ◄ installed once, globally
 └─────────────────────────────────────────┘
            │ guard init  (once per repo)
            ▼
 your-repo/
 ├── .guardrc            ◄ policy (committed, shared with team)
 ├── .guard-approvals    ◄ remembered "ask once" answers (committed)
 ├── .git/hooks/         ◄ tiny hooks that call the global `guard`
 └── .github/workflows/  ◄ optional CI check (PR trigger)
```

**Why a binary, not an npm dev-dependency:** a security tool must not be installed
*through the ecosystem it protects* — that would make the tool itself a supply-chain
target. Binary lives on the machine; only config lives in the repo.

---

## 3. Triggers — runs only when you act

No daemon, no cron, no polling. Protection fires on *your* actions.

```
 you install a dep ─────► filter versions + handle scripts (see §5, §6)
 you commit/push ──────► git hook re-checks lockfile vs advisory feeds
 you open a PR (CI) ───► same check, blocks merge if a dep is now flagged
 you run `guard check` ► on-demand audit, anytime
```

Both commit-hook and PR-check triggers are enabled (chosen): the hook catches your
own installs and later-flagged deps; the PR check stops a teammate's bad dep before
merge. The "a dep installed last month turns malicious next week" gap is closed at
your **next commit / PR**, not by a background watcher.

**Local escape hatch.** A commit/push hook can be bypassed for one action with
`GUARD_SKIP=1 git push`. Unlike `git --no-verify` (which skips *every* hook) this
skips depguard alone, so co-located lint/format hooks still run. The bypass lives
in the shell shim, never in the binary — the CI gate calls `guard check` directly,
so no contributor-set env var can weaken it. Local speed, unweakened merge gate.

---

## 4. Defense layers (overview)

```
 ① COOLDOWN / ALLOWLIST  → fetch fewer bad versions        (avoid)
 ② SCAN (static)         → detect bad before install        (catch)
 ③ IGNORE-SCRIPTS        → don't execute untrusted setup     (neutralize)
 ④ BOX (dynamic)         → run approved scripts watched+caged (contain+observe)
 ⑤ LOCKFILE RE-CHECK     → catch deps that go bad later       (recover)
```

Each layer is independent and pluggable (Open/Closed): adding a rule never touches
the install path.

---

## 5. Version filtering — the ephemeral proxy

depguard filters *which versions the package manager is allowed to see*, so the safe
version becomes the only choice — no error to handle.

```
 guard install lodash
   │
   ├─ spin up a proxy on a random localhost port
   ├─ point THIS command's registry at it
   ├─ run the real install (filtered)
   └─ kill the proxy
   ▲
 lives only for the duration of one command — no persistent daemon
```

Inside, per request:

```
 npm asks proxy for metadata (the "packument": all versions + time map + dist-tags)
   │
 proxy fetches upstream, then RETURNS A REWRITTEN packument:
   - versions younger than cooldown removed
   - versions on advisory/yanked feeds removed
   - `latest` repointed to newest surviving version
   - your own scope (@yourco/*) bypasses cooldown
   │
 npm resolves normally — it never sees the risky version, picks newest safe one
   │
 tarball request → proxy streams it through, runs the scan (§6), caches by hash
```

**Decision engine filters** (ordered cheap → expensive):

| Filter | Cost | Catches |
|---|---|---|
| Cooldown (age from `time` map) | metadata only | most malware (yanked within days) |
| Allowlist / scope bypass | trivial | keeps internal dev fast |
| Advisory / yank feed (OSV etc.) | feed lookup | already-reported malware |
| Tarball scan | first fetch only, cached | everything in §6 |

---

## 6. The scan (static) — judging a version

Run once per version, **cached by `name@version + integrity hash`** (computed once
ever, reused forever).

| Check | Catches |
|---|---|
| Install-script presence | the #1 attack vector |
| Capability diff vs previous version | new network / `fs` / `child_process` / env reads |
| Obfuscation signals | `eval`, base64 blobs, dynamic `require` |
| Known-bad feeds (OSV / advisories / yanked) | reported malware |
| Tarball ≠ git source (provenance) | code injected only into the publish |
| Typosquat distance / scope shadow | `lodahs`, dependency confusion |

Highest-signal cheap wins: **capability diff** (good package turning bad) and
**provenance** (publish differs from source).

---

## 7. Install scripts — neutralize by default

The strongest, most *universal* move is to not run untrusted setup code at all.

```
 OLD idea: run postinstall in an OS sandbox  → per-OS, escapable, complex
 USED:     --ignore-scripts by default        → pure config, identical everywhere,
                                                 nothing to escape
```

Effect of skipping lifecycle scripts:

```
 pure-JS packages (~90%+)  → zero difference (they have no scripts)
 native/binary packages    → need a follow-up build  (→ §8)
   e.g. better-sqlite3, bcrypt, esbuild, puppeteer
```

**The allowlist is not hand-maintained.** A package's `package.json` already
declares its scripts; depguard detects the few that want to run code and asks once:

```
 install
   │
 read each dep's package.json
   ├─ no install script (most) → installs clean, never asked
   └─ has install script (few) → "pkg X wants to run setup. Allow? [y/N]"
                                  └─ answer remembered in .guard-approvals (committed)
 + a shipped BASELINE of obvious-good build packages → rarely even asked
```

---

## 8. The box (dynamic) — run approved scripts watched + caged

Only packages with an **approved** install script ever enter the box. It is both a
**cage** (can't hurt you) and an **observation chamber** (records intent → verdict).

```
 approved build script
   │
   ▼
 guard shells out to a container runtime (does NOT reimplement isolation):

   docker run --rm \
     --network none \          # no phone line (or sinkhole mode, below)
     --read-only \             # can't modify the image
     --tmpfs /tmp \            # scratch only
     -v ./node_modules/pkg:/work:rw \   # ONLY this package dir
     -w /work \
     --cap-drop ALL \          # no special powers
     --user 1000 \             # not root
     node:20-slim  npm rebuild pkg
```

**Watched, not blindly blocked** — run instrumented so we see *intent*:

```
 ① NETWORK → sinkhole logs every connection attempt   "tried 185.x.x.x:443"
 ② FILES   → syscall trace logs reads outside /work    "opened ~/.ssh/id_rsa"
 ③ EXEC    → log every child process spawned           "ran: curl | bash"
 ④ DIFF    → project dir before/after                  "wrote outside build output"
```

Mechanism on Linux (the container is Linux): **eBPF / seccomp-log / Falco-style**
passive syscall, exec, and network tracing.

**Behavior → verdict:**

```
 ┌──────────────────────────────────────────────┐
 │ compiled + wrote .node files, no network       │ → SAFE
 │   → keep build output, remember                 │
 ├──────────────────────────────────────────────┤
 │ touched ~/.ssh / opened socket / curl|bash      │ → UNSAFE
 │   → DISCARD output, flag package, alert you      │
 └──────────────────────────────────────────────┘
```

Because the box has no real network and no secrets mounted, a malicious attempt
**fails anyway** — but we also *recorded* it, so we flag the package instead of
silently moving on. The verdict is reusable (cached by hash, shareable).

**Static + dynamic together** closes the obfuscation gap: you can hide from a code
reader, but you can't hide the `connect()` to your server when we watch syscalls.

---

## 9. Universality & the container tradeoff

There is **no zero-dependency, cross-OS way to safely execute arbitrary native
build code.** depguard resolves this by putting universality in the *default*, not
the box:

```
 DEFAULT (everyone, everywhere) → ignore-scripts  = pure config, no runtime needed
 THE BOX (rare approved build)  → container if present, else fallback
```

| Box mechanism | Universal? | Runs native builds? | Needs |
|---|---|---|---|
| Container | mostly (Win → WSL2) | yes | Docker/Podman |
| WASM | truly | no (can't compile C) | — |
| OS sandbox | no (per-OS) | yes | rejected |

No container runtime present → every other layer still works (cooldown, scan,
provenance); only the box for build scripts is unavailable.

**RESOLVED — warn-then-approve.** With no container runtime, when an approved build
script must run, depguard does *not* silently run it and does *not* just fail.
It warns loudly, then lets you explicitly approve running it **uncontained**:

```
 approved build script, but no container runtime
   │
   ▼
 WARN: "pkg X has a build script and there's no sandbox available.
        Running it will execute its code on your machine, uncontained."
   │
 interactive? ──► prompt: run uncontained? [y/N]
   │                ├─ y → run as-is + record the decision in .guard-approvals
   │                └─ N → skip-and-fail
   │
 non-interactive (CI)? ──► no human to approve:
        ├─ decision already recorded in .guard-approvals → run as-is
        └─ otherwise → skip-and-fail (never auto-run uncontained in CI)
```

The recorded approval travels with the repo, so a package you've vetted once can
build in CI without re-prompting — but an *unvetted* script can never silently run
uncontained in a non-interactive context.

---

## 10. State that lives in the repo

```
 .guardrc           policy — cooldown, allowlist scopes, fallback mode
 .guard-approvals   remembered ask-once answers + verdicts (travels with team)
 .guard-ignores     reviewed-finding waivers — one per issue, version-pinned (§13)
 package-lock.json  source of truth for what's installed (already version-controlled)
```

No external database tracks your projects. State is the lockfile plus two committed
files.

Example `.guardrc`:

```yaml
cooldown: 14d
allow: ["@yourco/*"]      # internal scopes bypass cooldown
ignore-scripts: true       # default; the few approved ones live in .guard-approvals
no-container-fallback: warn-approve  # warn + prompt; or: fail (always skip)
flag: [new-network, new-fs, new-deps]
```

---

## 11. Hardening addendum (v0.2.0 — multi-repo review)

Closed in the lockdown review before multi-repo rollout:

```
 BYPASS: plain npm / npx / npm ci skip guard entirely
   → .npmrc ignore-scripts=true written by guard init  (raw npm can't run scripts)
   → guard check now re-verifies the COOLDOWN on lockfile versions added
     since git HEAD (hooks/CI = enforcement point for any install path)
   → guard ci command wraps lockfile-exact installs

 LEAKS: uncontained runs inherited the full shell env (tokens!)
   → env scrubbed to PATH/HOME/LANG/TMPDIR

 SUPPLY CHAIN OF THE GUARD ITSELF:
   → box image pinned by sha256 digest, not tag
   → CI workflow template refuses to run until YOU pin a release URL + checksum
   → .guardrc registry must be https (loopback http allowed for tests)

 CORRECTNESS/PERF:
   → `prepare` no longer flags registry deps (npm never runs it for them);
     root project's own scripts (incl. prepare) replayed after install — trusted
   → full capability sweep only for script-bearing packages (cheap gate first)
   → box: --security-opt no-new-privileges, --pids-limit 512
```

## 11b. Observation chamber (v0.3.0 — dynamic analysis)

The box now WATCHES, not just cages (closes the §8 "eBPF is future work" line):

```
 approved script → box runs it under strace -f (network, openat, execve)
                   strace lives in a LOCALLY-built image (node@digest + apt
                   strace from signed Debian repos — nothing on the host)
        │
   trace.Parse(log) → convict ONLY on no-build-excuse behavior:
        ├─ connect()/sendto() to a non-loopback address   → network-attempt
        ├─ DNS query name decoded from the payload         → dns-query
        └─ openat() on /root/.ssh, id_rsa, /etc/shadow,
           another proc's environ (NOT the box's own mounts) → secret-access
        ·  execve()/file writes = CONTEXT only, never a conviction
        │
   UNSAFE → package dir RESTORED from a pre-run backup (output discarded);
            approval auto-flipped to Denied and committed (evidence travels)
```

Design choices:
- **Network stays `--network none`.** A sinkhole would expose a host bridge;
  "none is none." strace captures the *intent* (destination/host) with zero
  reachability — better security AND better evidence.
- **No host dependency.** strace ships inside the box image; if the image
  can't be built (offline), scripts run CAGED but UNTRACED and guard says so.
- **Conservative verdicts.** False positives would train users to disable the
  tool; `demo/demo-native-build` is the regression guard for this (a build
  that spawns/reads/writes but is correctly PASSED).

## 11c. Name + content hardening (v0.4.0 — dependency-level review)

Closed the gaps a dependency-tree review surfaced (the bad package is rarely
the one you typed — it's a transitive dep or a look-alike):

```
 NAME-LEVEL ATTACKS (were unbuilt despite §1/§6 listing them):
   → internal/typosquat: curated popular-name list + optimal-string-alignment
     (Damerau) distance-1 catches transposition ("lodahs"), insert/delete/sub;
     any non-ASCII LETTER in a name = homoglyph block ("reаct" w/ Cyrillic а).
   → wired into proxy rewrite() BEFORE version filtering: a suspect name has
     ALL versions emptied → npm "no matching version", fail closed; reason
     rides the install summary; `allow:` in .guardrc is the escape hatch.

 LLM / AGENT-REVIEWER INJECTION (new vector for the MCP future):
   → scanner now sweeps README/markdown/txt/package.json AND code for:
     · prompt-injection prose ("ignore previous instructions", "this file is
       safe, skip it", "as an AI", fake <system>/<im_start> tags)
     · bidirectional control chars (Trojan Source) in source — DANGER
     · zero-width chars hiding content — Warn (emoji ZWJ / leading BOM exempt
       so it doesn't become FP noise)
   → findings are SIGNAL for a human/agent, never auto-trust; the detector is
     ready for an MCP server to scan every package, not just script-bearing.

 TREE-COVERAGE CORRECTNESS:
   → lockfile.Installed/InstalledBytes return distinct name@version PAIRS, not
     a name-keyed map: two versions of one package are BOTH advisory- and
     cooldown-checked (the old map silently dropped every duplicate version).
   → guard check `flag: [new-deps]` (on by default) reports packages a
     lockfile change ADDS vs git HEAD — the cheap half of §6's capability diff.

 FAIL-CLOSED POLICY PARSING:
   → ignore-scripts (and any bool) errors on a typo'd value instead of
     silently falling to the unsafe side ("tru" no longer disables the guard);
     unknown .guardrc keys warn (catches a misspelled known key).
```

Reserved for the next increment: `new-network` / `new-fs` capability diffing
(needs the previous version's source to diff against); dependency-confusion by
declared-internal scope (needs a private-registry routing model).

## 11d. Dependency trust + MCP (v0.5.0)

The biggest build-out: closing the "is this dependency trustworthy?" gaps (we
were strong on containment, weak on intelligence) and exposing the scanners to
agents.

```
 DEPENDENCY-TRUST (the three gaps + neighbors):
   → maintainer/publisher change   internal/maintainer: compares the publisher
     (account-takeover signal)      of an installed version to the prior one;
                                    flags changes + long-dormancy republishes.
                                    Opt-in via flag: new-maintainer.
   → registry signature verify     internal/provenance: verifies npm's ECDSA
     (publish/registry tampering)   dist.signatures (stdlib crypto, zero-dep).
                                    Proxy BLOCKS present-but-invalid; unsigned
                                    passes (warn-not-block — most aren't signed).
   → OSV at resolve time            proxy now drops OSV-flagged versions BEFORE
     (avoid, not just recover)      npm resolves (was post-install only).
   → dependency confusion           internal-scopes: names that must come from a
                                    private registry are blocked from the public
                                    one (proxy, fail closed).
   → lockfile integrity             guard check flags entries whose tarball
                                    resolves OFF the registry or lack an
                                    integrity hash (poisoned-lockfile tells).
   → capability diff vs prev        scans the previous version's tarball and
                                    shows what THIS version added (new socket,
                                    new eval...) at approval. flag: new-network/new-fs.

 BROADER COVERAGE:
   → pnpm-lock.yaml + yarn.lock      hand-rolled zero-dep parsers; the check path
                                    (advisory/cooldown/integrity) now spans all
                                    three managers. (install stays npm-shaped.)
   → io_uring/seccomp               box runs under a seccomp profile blocking
                                    io_uring_* (else network I/O is invisible to
                                    strace) + bpf/perf/userfaultfd/kexec.
   → box resource caps              --memory/--cpus + a wall-clock kill (a miner
                                    that just spins is bounded).
   → more scan signals              wallet/clipboard paths, os.homedir, dynamic
                                    require/import, process.binding, bundled
                                    prebuilt binaries (.node/.wasm/.exe...).

 SURFACES:
   → guard scan <dir> [--json]       static-scan one package; JSON for CI/agents.
   → guard check --json              structured CheckResult.
   → guard mcp                       MCP server over stdio (hand-rolled JSON-RPC,
                                    zero-dep). Tools: scan_package, check_dependencies.
                                    EVERY result is wrapped as UNTRUSTED DATA so an
                                    agent treats a package's injection prose as data,
                                    not instructions — the same payloads the scanner
                                    itself now flags (prompt-injection, Trojan-Source
                                    bidi, zero-width). See §11c.

 FAIL-CLOSED PARSING:
   → ignore-scripts (and bools) error on a typo'd value instead of silently
     going unsafe; unknown .guardrc keys warn.
   → OSV queries fail LOUD on a non-200 (rate-limit / outage) instead of
     decoding to an empty result that reads as "no advisories" — an OSV
     hiccup can never silently turn the gate green; the body is size-capped.
```

## 13. Reviewed-finding waivers (v0.6.0 — .guard-ignores)

`guard check` is the enforcement point: advisories, cooldown, and lockfile
integrity gate commit / push / PR / CI. Sometimes a gating finding is one a human
has reviewed and consciously accepts (a vendored fork still inside the cooldown,
an internal mirror that resolves off-registry). Forcing the choice between "leave
the gate red forever" and "weaken the policy for everything" is exactly what
trains a team to disable a security tool. Waivers add the missing third option:
silence ONE finding, on purpose, with evidence.

```
 guard check ──► prints, per gating finding, the exact line that waives it:
                 "→ guard ignore cooldown:lodash@4.17.21 --reason ..."
        │
 guard ignore <id> [--reason ..] [--expires 30d|YYYY-MM-DD]
        │
        ▼
 .guard-ignores   (committed JSON, like .guard-approvals)
        │
 next guard check ─► waived findings are SHOWN (muted ⊘) but do NOT gate;
                     every other finding still gates normally
```

**Issue identity is version-pinned.** A waiver ID is `<kind>:<name>@<version>`
(advisories also carry the OSV id): `cooldown:lodash@4.17.21`,
`off-registry:evil@9.9.9`, `unhashed:bar@1.0.0`, `advisory:foo@1.2.3:GHSA-xxxx`.
Because the version is part of the ID, a waiver **lapses automatically** when the
package moves — the new version is a new finding, judged (and, if still wanted,
re-waived) on its own. A waiver can never silently cover a version nobody reviewed.

**Purposeful but low-friction.** Adding one is a single command (copy the line
`guard check` prints), but it is scoped to exactly one issue and carries an
optional `--reason` (encouraged — it is the audit trail) and `--expires`
(relative `30d`, or absolute `YYYY-MM-DD`). An **expired** waiver does not
suppress: it fails closed, re-gates the finding, and is reported loudly, so a
stale waiver cannot quietly hide a real problem.

**Scope.** Waivers cover the `guard check` gates (advisory, cooldown,
off-registry, unhashed) — the findings that hold up *events*. The install-time
**name** gate (typosquat / dependency-confusion, which fails closed before any
metadata is even served) keeps its existing escape hatch, `allow:` in `.guardrc`:
clearing a fail-closed name block is a deliberately different decision from
waiving a reviewed check finding.

The ID scheme is the single source of truth shared by the human-prose path and
the structured `--json` / MCP path (`CheckResult.waived`), so the two never
disagree about what is or isn't waived.

## 12. Open items

1. ~~§9 fallback~~ — **resolved: warn-then-approve** (run uncontained only on explicit
   approval; CI falls back to fail unless pre-approved in `.guard-approvals`).
2. Ecosystem after npm (PyPI has different registry API + script model).
3. How shared verdicts are distributed/trusted (community feed vs local-only).
4. Exact provenance method (sigstore/npm-provenance when present; diff fallback).
