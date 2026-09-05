# depguard — Design Absence is established only by a SUCCESSFUL listing of the index or tree (`ls-files` / `ls-tree`); a failed probe is an error, because `cat-file -e` fails identically for "no such path" and "cannot read the index".

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
 secrets reaching the remote (.env,
   key material) — YOUR files leaking
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
 you install a dep ─────► filter versions + gate the lockfile + handle scripts
 you commit ───────────► pre-commit: the STAGED lockfile (the index)
 you push ─────────────► pre-push:   the PUSHED commits vs what that remote has
 you open a PR (CI) ───► same check, blocks merge if a dep is now flagged
 you run `guard check` ► on-demand audit, anytime
```

The two hook phases are **not** the same check, and neither of them judges the
working tree. The shim passes `--hook=<phase>` and `--remote=$1`; at pre-push git
also hands the hook its ref lines on stdin.

**Every lockfile gate — advisories, integrity, licenses, provenance and the
cooldown's "current" side — reads the snapshot for the phase**, via
`lockfile.InstalledAt(dir, ref)`:

```
 pre-commit  →  git show :package-lock.json        the INDEX: what the commit will contain
 pre-push    →  git show <local sha>:…             the pushed COMMITS (union across refs)
 otherwise   →  the working tree
```

One exception, by necessity: the **license gate always reads the working tree**.
It opens each package's own `package.json` under `node_modules`, and node_modules
only ever reflects the tree — pairing a staged or pushed lockfile's paths with
on-disk files would report "incomplete" for every entry that differs, which is
noise, not a finding.

The working tree is not what git records or transmits. `git add` a poisoned
lockfile and edit the file back, and a tree-based gate sees nothing while the
commit carries it. After a commit the tree and HEAD agree, so a too-young version
or a secret committed anyway (`GUARD_SKIP`, a teammate without guard) is
invisible to a HEAD diff — yet it is exactly what the push transmits. The
snapshot reader dispatches on the lockfile's FILENAME, because bytes from
`git show` carry no other format hint, so pnpm and yarn snapshots work too.

Occurrence-level gates (integrity, provenance) run **per ref**, not over the
union. They judge a specific tarball at a specific path, so unioning first let a
clean branch in the same push lend its hash — or its registry host — to a bad
occurrence in another, and the finding vanished. Findings are prefixed with the
short sha when a push carries more than one ref. Name@version-only checks
(advisories, cooldown) keep using the union.

"Outgoing" is likewise scoped to the **destination**: `--not --remotes=<remote>`,
not `--remotes`. Excluding commits present on *any* remote meant a branch already
pushed to a fork looked like nothing-new when first pushed to the real upstream.
When the named remote has no tracking refs yet, `--remotes=<name>` matches
nothing and the whole branch is scanned — the conservative direction. When the
remote name is UNKNOWN (a pre-1.2.1 shim that passes no `--remote`, a push by
URL, or a hook chain that consumed `$1`) guard falls back to `--not --remotes`
(any remote). That is an explicit, accepted tradeoff — history already on some
OTHER remote can still be new to this destination — so it is routed through the
`on-check-error` policy like any check that could not complete precisely: under
`warn` (default) the check runs with the wider scope and prints the fix (re-run
`guard init`); under `fail` the push is refused with that same message. A
full-history scan was rejected as the fallback because it would turn every
not-yet-re-initialised repo's next push into a wall of historic findings — the
false-positive fatigue §11b warns against.

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
 tarball request → proxy streams it through UNMODIFIED (npm verifies the
   integrity hash itself, which doubles as the tamper check). The §6 static
   scan is not inline here — it runs at APPROVAL time on the few script-bearing
   packages (and as the capability diff against the prior version), cached by hash
```

**Decision engine filters** (ordered cheap → expensive):

| Filter | Cost | Catches |
|---|---|---|
| Cooldown (age from `time` map) | metadata only | most malware (yanked within days) |
| Allowlist / scope bypass | trivial | keeps internal dev fast |
| Name gate (typosquat / homoglyph / confusion) | metadata only | impostor + internal-scope names — fail closed |
| Advisory / yank feed (OSV etc.) | feed lookup | already-reported malware |
| Registry signature verify | per-version sig | present-but-invalid npm ECDSA signatures |

The static tarball scan (§6) is **not** a proxy filter — the proxy streams tarballs
through unmodified; the scan runs later, at script-**approval** time.

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

The tarball scanner reads under a **total decompression budget** (256 MiB) and an
entry-count cap, so a gzip bomb is *flagged*, never run unbounded. Within that
budget **every file is scanned in full**: a sliding window (1 MiB + a 64 KiB
overlap, so a match across a seam still counts) streams the whole file at constant
memory, and Go's RE2 engine keeps matching linear — full coverage is not a ReDoS
or memory-exhaustion vector. A per-file ceiling (64 MiB) backstops a pathological
input: beyond it the scan stops and says so. So a payload padded past 1 MiB is now
*found*, not an unseen blind spot.

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

**An approval is about code, not about a name.** Each recorded decision stores the
lockfile's integrity hash for that `name@version`, and a decision only applies
while the hash still matches. Re-point the lockfile at a different tarball, or
republish the version, and the entry stops counting as known: guard re-prompts
(and in a non-interactive context lists it as skipped) rather than letting new
bytes inherit a yes given to old ones. Entries written before this binding existed
carry no hash and keep applying — but only until the next run: the first time
guard executes such an entry it records the tarball's current hash into it
(bind-on-first-use), so upgrading guard actually buys the binding for packages
that were already approved, instead of leaving them permanently unbound. Such an
entry is annotated `auto-bound on first run after upgrade (integrity inferred,
not reviewed)`, because `.guard-approvals` is reviewed in PRs and an inferred
hash carries none of the assurance of one recorded while a human read the code.

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
     --user <non-root> \       # os.Getuid(), not root
     node:20@sha256:…  sh -c 'npm run preinstall install postinstall --if-present'
                               # digest-pinned image; runs the package's OWN
                               # lifecycle scripts (not `npm rebuild`). Real flags
                               # (seccomp, ro node_modules mount, etc.) in §11a–§11b.
```

**Watched, not blindly blocked** — run instrumented so we see *intent*:

```
 ① NETWORK → sinkhole logs every connection attempt   "tried 185.x.x.x:443"
 ② FILES   → syscall trace logs reads outside /work    "opened ~/.ssh/id_rsa"
 ③ EXEC    → log every child process spawned           "ran: curl | bash"
 ④ DIFF    → project dir before/after                  "wrote outside build output"
```

Mechanism on Linux (the container is Linux): passive syscall, exec, and network
tracing. **As shipped this is `strace -f` running inside the container** (see §11b);
a richer eBPF / Falco-style probe stays future work.

**The evidence path is UNREACHABLE from the tracee, and completion is PROVEN.**
strace writes the trace to the container's STDOUT and the traced script's own
output is redirected to stderr, so guard reads the trace over a pipe. An earlier
design wrote it to a bind-mounted file, which the script — running as the same
uid — could truncate or rewrite, and an unreadable trace downgraded the run to
"untraced". Both host-side buffers (script output, trace) are bounded, so a
script that prints forever cannot exhaust guard's memory.

Being a pipe is not by itself enough. The script holds no fd to it (`exec 1>&2`
replaces fd 1; strace's `-o` fd is CLOEXEC) — but `/proc/<tracer>/fd/1` would
reopen it, and a tracee knows its own pid, so it could FORGE its own completion
marker there and then kill the tracer. What closes that is the image:

```
 obsDockerfile:  RUN chmod 0111 /usr/bin/strace     ← execute-only for EVERYONE
   │
   └─ kernel marks the running strace NON-DUMPABLE
        └─ /proc/<strace>/ becomes root:root dr-x------
             └─ tracee: write EACCES, read EACCES
```

**0111, not 0711.** The box runs as the *invoking* uid, so `sudo guard` or a root
CI runner puts the tracee at uid 0 — and 0711 leaves the owner read bit, which
made strace dumpable again and the forgery worked. At 0111 nobody has the read
bit; uid 0 inside the box cannot bypass that because `--cap-drop ALL` removes
CAP_DAC_OVERRIDE, and the same cap-drop removes CAP_SYS_PTRACE, which
`ptrace_may_access` would otherwise let root use to reach a non-dumpable
process's `/proc` entries.

So the trace can be neither truncated NOR appended to. **The whole guarantee
rests on that exec-only binary** — without it the marker below is forgeable and
the observation proves nothing.

Append-only is necessary but not sufficient, because the tracee can kill its
tracer: `kill -9 $PPID` from an install script. strace dies, its pipe closes, and
what guard reads is an entirely ordinary trace — non-empty, under the cap, nothing
incriminating in it. The script is DETACHED by that kill, not stopped, so
everything it does next is unseen. Absence of evidence is therefore not evidence
of absence, and the trace must carry positive proof of a clean ending:

```
 strace -f -q   (NOT -qq — that suppresses exactly the line we need)
   │
   └─ last line of a complete run:  "<root pid> +++ exited with N +++"
                                    "<root pid> +++ killed by SIGx +++"
```

The pid must be the ROOT tracee's — the pid on the first trace line. A child's
marker will not do: a script can arrange for a child to exit before it kills the
tracer.

No marker → `Traced=false`, reported as "observer terminated by the script", and
the output is **DISCARDED under every policy** — including `untraced-boxed: run`,
where an ordinarily-unobserved run is kept. Killing your own tracer has no
build-time excuse — and neither does flooding the trace past guard's 64 MiB cap
(no real build emits that many network/exec/open syscalls), so a capped trace is
discarded the same way. It is still not an auto-conviction (the approval stands, the
package is not denied): a build we killed ourselves at the wall-clock limit looks
similar from the outside, which is exactly why a TIMED-OUT run is excluded from
"observer lost" — `Traced` is still false there, but the blame is ours.

strace is `exec`'d so it is PID 1. Without that, Debian's `dash` (which has no
single-command exec optimization) sits at PID 1, dumpable, holding the trace pipe
as its fd 1 — `/proc/1/fd/1` forgery works, verified live. As PID 1 strace also
inherits the kernel's rule that a pid-namespace init ignores signals from inside
the namespace (SIGKILL included): the tracer cannot be killed by the tracee at
all. The completion marker is therefore defense in depth, not the only line.

`kill` is deliberately NOT added to the seccomp denylist — npm legitimately
signals its own children, and blocking it would break ordinary builds to close a
hole the unreachable pipe already closes.

**Unobserved ≠ observed clean.** A trace that is missing (strace never ran) or
truncated (we stopped reading) means we did not see everything, and `Traced` is
false. Under `untraced-boxed: fail` the output of such a run is DISCARDED — the
package dir is rolled back exactly as for an unsafe verdict. That is not a
conviction and the approval is not revoked; the script may well have been fine.
The rule is only that we don't keep what we couldn't watch. Evidence captured
before a truncation still convicts.

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

**`no-container-fallback: fail` is enforced at every RUN, not just at approval.**
A recorded `approved-uncontained` entry is checked against the CURRENT policy each
time it would run: under `fail` the script is skipped (the install continues) and
`guard approve --uncontained` refuses to record a new one. Otherwise an approval
made on a Docker-less machine, or committed by a teammate, would keep running bare
in a repo that had since tightened the policy — the policy would describe the past
instead of governing the present.

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
allow: ["@yourco/*"]      # bypass cooldown + typosquat ONLY (not OSV/signature/internal)
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
   → .npmrc save-exact=true + save-prefix= written by guard init  (new deps
     pinned to the exact installed version — no ^/~ range drift when a later
     `npm install` re-resolves; bump deliberately, never silently)
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
   → `allow:` SCOPE (proxy rewrite): an allowlisted name skips the cooldown loop
     and the typosquat gate ONLY — its whole purpose ("I want this exact name,
     it may be fresh"). It still falls THROUGH to the OSV blocking-version filter
     and the registry-signature filter, and internal-scopes still outranks it: a
     known-bad or tampered version of an allowed name is still dropped. allow is
     NOT a blanket "trust everything about this package".

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
   → OSV at resolve time            proxy drops OSV-flagged versions BEFORE npm
     (avoid, not just recover)      resolves (was post-install only), tiered by
                                    advisory-threshold like the check path
                                    (§12a): only BLOCKING hits are hidden, so a
                                    moderate/low advisory with a wide range
                                    doesn't make every old version uninstallable.
   → dependency confusion           internal-scopes: names that must come from a
                                    private registry are blocked from the public
                                    one (proxy, fail closed). Outranks allow: —
                                    a name in BOTH lists is the attack shape,
                                    so the allowlist cannot unlock it.
   → lockfile integrity             guard check flags entries whose tarball
                                    resolves OFF the registry or lack an
                                    integrity hash (poisoned-lockfile tells).
                                    Covers npm, pnpm AND yarn: pnpm records no
                                    tarball URL, so its parser MARKS entries as
                                    registry deps (its keys only admit real
                                    versions) and the unhashed gate applies
                                    without a URL; a pnpm `tarball:` in the
                                    resolution block feeds the host check. npm
                                    file:/link:/git deps stay exempt — they
                                    legitimately carry neither host nor hash —
                                    and internal-scopes names are exempt from the
                                    HOST check only (they are declared to live on
                                    a private registry). `allow:` exempts nothing
                                    here: it is a cooldown/typosquat escape
                                    hatch in the proxy and buys no authority in
                                    the check path.
                                    It also flags a CONFLICT: one name@version
                                    recorded at two lockfile paths with different
                                    tarballs or hashes — or with a hash at one
                                    path and NONE at the other. A registry dep is
                                    hashed at every path, so a hashless
                                    occurrence is the unhashed finding, not a
                                    field to fill in from a sibling; filling it
                                    made the missing hash disappear. (Resolved is
                                    different: pnpm records no tarball URL at all,
                                    so empty-vs-set is no contradiction there.)
                                    BUNDLED entries stay in the INVENTORY but are
                                    not integrity OCCURRENCES: npm records a
                                    bundled copy with no resolved/integrity
                                    because the bytes ship inside the PARENT's
                                    hashed tarball. They are still installed code,
                                    so advisories, the cooldown and the SBOM see
                                    them (dropping them hid a package from every
                                    check whenever it only ever appeared bundled);
                                    the integrity gates skip them, because
                                    counting them as hashless occurrences made
                                    every bundling package look
                                    self-contradictory — and since the conflict
                                    verdict is unwaivable, and the advice ("npm
                                    install regenerates consistent entries")
                                    reproduces the same file, the repo would
                                    become un-committable. `inBundle` is
                                    attacker-writable, so the SHAPE decides: an
                                    entry claiming inBundle that still records a
                                    URL and a hash is checked like any other. LINK
                                    entries are dropped entirely — no registry
                                    identity to inventory or verify. inBundle is a field
                                    anyone can write, so the parser trusts the
                                    SHAPE, not the flag: only an entry with
                                    neither resolved nor integrity is dropped;
                                    one that claims inBundle but carries a URL
                                    or hash is checked like any other. A
                                    lockfile that EXISTS at the staged/pushed
                                    ref but cannot be parsed is a gate failure,
                                    never "no lockfile". Across a MULTI-REF
                                    push no conflicts are derived either: two
                                    branches are two lockfiles, each internally
                                    consistent, and they are allowed to differ. Dedupe has to keep one, so
                                    the disagreement would otherwise vanish
                                    silently — and there is no single truth to
                                    waive, so a conflict is not waivable. Fix the
                                    lockfile.
   → capability diff vs prev        scans the previous version's tarball and
                                    shows what THIS version added (new socket,
                                    new eval...) at approval. flag: new-network/new-fs.

 BROADER COVERAGE:
   → pnpm-lock.yaml + yarn.lock      hand-rolled zero-dep parsers covering pnpm
                                    v5 (/name/version) and v6+ (name@version)
                                    keys, and yarn classic (`version "x"`) and
                                    berry (`version: x`). A parser that reads a
                                    file but recognizes NOTHING in it returns an
                                    ERROR — "we didn't understand this" must
                                    never be reported as "no dependencies", which
                                    is exactly how a CRLF lockfile once went
                                    completely unchecked. Berry's `checksum` is
                                    yarn's cache key, not an SRI hash, so berry
                                    entries stay OUT of the integrity gates
                                    rather than being claimed as verified;
                                    check spans all
                                    three managers. As of v0.8.0 `guard install`
                                    PROXIES all three too (§11e); boxed script
                                    approval stays npm-only.
   → io_uring/seccomp               box runs under a seccomp profile blocking
                                    io_uring_* (else network I/O is invisible to
                                    strace) + the kernel keyring (keyctl/add_key/
                                    request_key — no-cap-required) + bpf/perf/
                                    userfaultfd/kexec. A DENYLIST on an allow-by-
                                    default base, NOT a brittle full allowlist:
                                    a hand-rolled allowlist breaks node-gyp (the
                                    §11b false-positive trap), and --cap-drop ALL
                                    already covers the capability-gated syscalls.
   → box resource caps              --memory/--cpus + a wall-clock kill (a miner
                                    that just spins is bounded).
   → box cleanup                    the run container is NAMED and force-removed
                                    on a wall-clock kill (--rm only fires on a
                                    clean CLI exit). `guard prewarm` (or `guard
                                    init --prebuild-box`) builds the strace image
                                    ahead of the first boxed run. `guard clean`
                                    sweeps stray containers + backup/obs leftovers
                                    and KEEPS the image (next run stays instant);
                                    `guard clean --image` also reclaims it.
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
   → OSV non-200s (rate-limit / outage) surface as an explicit lookup error
     instead of mis-decoding to an empty "no advisories". The advisory layer
     stays FAIL-OPEN for availability (an OSV outage must not block every
     commit) but no longer SILENTLY: the prose check warns, and guard check
     --json / MCP record it in CheckResult.degraded, so a green result cannot
     hide that the advisory layer did not run. Body is size-capped.
```

**Fail open vs fail closed — and who chooses.** The filter path (name gates,
confusion gate, policy parsing, proxy rewrites) fails CLOSED: those decisions are
local and cheap, so there is no excuse for guessing. The lookup path (OSV,
registry publish dates, publisher history, provenance, and the git call behind the
secret gate) fails OPEN by default: an outage on someone else's server must not
wedge every commit in every repo. That default is a availability trade, not a
claim of safety — which is why nothing is ever silent about it, and why the choice
is the repo's to make. `on-check-error: fail` in `.guardrc` flips the lookup path
closed: every check that could not COMPLETE then gates, with a message saying so,
and `guard check --json` reports `ok: false` whenever `degraded` is non-empty. One
helper (`config.Degrade`) implements it, so every fail-open site obeys the same
policy rather than each drifting on its own.

### 12a. Advisory severity tiering (v0.9.0)

The advisory layer is **graded**, not all-or-nothing. Each hit is scored against
OSV's per-vuln detail (`/v1/vulns/{id}` — the `querybatch` feed carries no
severity, so this is one extra GET per *distinct* id, only when there are hits)
and split against a configurable threshold:

```
 advisory-threshold: high   (default — npm-audit-style)

   MAL-* id ........................... BLOCK   (malicious package; never a warning)
   severity unknown / unscored ........ BLOCK   (fail closed — can't prove it's minor)
   severity >= threshold .............. BLOCK
   severity <  threshold .............. WARN    (printed, does not gate)
```

Three invariants keep this fail-closed:

- **`MAL-*` always blocks**, regardless of threshold — flagging an outright
  malicious package is the tool's whole reason to exist; it is never downgradable.
- **Unknown severity always blocks.** `SevUnknown` is the zero value, and an OSV
  detail fetch that fails or returns no machine-readable severity leaves the hit
  unscored — so a flaky fetch can only make the gate *stricter*, never leak a hit
  through as a "low".
- **Only blockers flip `CheckResult.OK`.** Warnings live in
  `CheckResult.advisoryWarnings`; they are surfaced but never gate on their own.

The **resolve-time proxy filter** applies the same tiering (`advisory.BlockingVersions`):
it hides only versions whose advisory blocks at the threshold, so a moderate/low
advisory with a wide affected range doesn't turn into a wall of "no matching
version" at install time — those versions install and `guard check` warns on them.
A version blocked here was genuinely too risky to resolve under the policy (e.g. a
HIGH advisory); the safe move is to pin a fixed version or, deliberately, lower the
threshold / waive the specific hit.

**Interactive accept-and-record (`guard check --confirm`).** The git hooks pass
`--confirm`. When the *only* findings are warn-tier and a controlling terminal
exists, `guard check` asks before letting the commit/push through; on "yes" it
records each accepted hit as a waiver in `.guard-ignores` (the audit trail of
what was waved through and when, and what suppresses the same hit next time).
No terminal (CI, a piped hook) ⇒ no prompt: warnings print, the action proceeds,
blockers still fail the gate. The prompt reads `/dev/tty`, not stdin, because a
git hook's stdin is ref data, not the keyboard. Blockers are **never** confirmable
this way — accept a specific blocker deliberately with `guard ignore`.

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

## 11e. Provenance, SBOM, licenses, why, pnpm/yarn (v0.8.0)

Five capabilities added in one pass:

```
 BUILD PROVENANCE (internal/attestation, flag: [provenance])
   → fetches npm's Sigstore attestation (/-/npm/v1/attestations/<name>@<ver>),
     verifies the DSSE signature over the in-toto SLSA statement, chains the
     leaf cert to a PINNED Fulcio root, binds the statement subject digest
     to the installed tarball hash, AND binds the signer to the claimed source:
     the leaf's SAN URI must be under github.com/<owner>/<repo> of the repo the
     statement names (host taken from a URL parse, never a substring — else any
     forge could put "github.com/<victim>" in a path). Without that step any
     Fulcio-issued identity could self-attest provenance naming someone else's
     repo and verify green — so VERIFIED now means identity-bound.
     Signer that doesn't match a GitHub source = INVALID (impersonation).
     Source on an UNSUPPORTED FORGE (npm carries GitLab-built provenance too)
     = NONE with a reason, never INVALID: we can't bind it, but calling a
     legitimate GitLab build "tampered" would gate a commit on a false
     accusation. Fails open like the layer's other degradations.
     Reports the attested source repo + builder.
     Only present-but-INVALID gates (tamper); absent/verified are informational.
     NONE vs DEGRADED: a clean 404 / empty attestations list = NONE ("nothing
     published"). A fetch failure, a non-404 HTTP status, or an unparseable
     response = DEGRADED — "verification couldn't complete", surfaced (in the
     check summary + --json Result.Reason) but NEVER gating. Splitting the two
     stops a transient or hostile failure from masquerading as "no attestation".
     LIMITS (documented, like §6 provenance candor): no Rekor inclusion / SCT /
     TUF root rotation yet — a high bar, not the full Sigstore guarantee.

 SBOM (internal/sbom, guard sbom [--spdx])
   → emits CycloneDX 1.5 (default) or SPDX 2.3 JSON straight from the lockfile,
     with purls + SRI-derived hashes. An audit artifact from existing state.

 LICENSE GATE (internal/license, .guardrc license-deny / license-allow)
   → reads each installed package's declared license (node_modules manifest),
     gates guard check on a denied (or, in allowlist mode, non-allowed) license.
     Version-pinned waivers (license:<name>@<ver>); degrades if node_modules is
     absent rather than passing silently.

 GUARD WHY (internal/lockfile graph, guard why <pkg>)
   → reconstructs the npm lockfile's parent->child graph and prints the path(s)
     from a direct dependency down to a transitive one — triage for "what pulled
     this in?". npm-only (pnpm/yarn carry no graph we parse zero-dep).

 pnpm/yarn INSTALL PROXYING (buildInstall / detectManager)
   → guard install now detects the manager from the lockfile and routes npm,
     pnpm, AND yarn through the same ephemeral cooldown proxy (registry override
     by flag for npm/pnpm, by env for yarn berry). Closes the loudest §11d gap.
     Boxed script approval stays npm-only (it enumerates from package-lock.json).
```

**v0.8.1 — feedback polish:** cooldown violations show an ETA ("clears cooldown in ~3d"); `guard check` prints a one-line rollup verdict (deps count + gating categories); the slow per-package network checks (provenance, maintainer) show `N/M` progress on a TTY; `guard status` lists the license + provenance gates and whether each is enabled; `guard init` prints numbered next steps. Output-only — no new commands, flags, or policy keys.

## 14. Secret-file gate (v1.0.0)

Every layer above guards against THIRD-PARTY code. This one guards the other
direction: the repo's own authors accidentally committing a credential. It is the
only gate that inspects *your* files, not your dependencies.

`secret-paths` in `.guardrc` lists file/dir glob patterns that must never reach
the remote (`.env`, `.env.*`, `secrets/`, `*.pem`, …). On `guard check` — which
the pre-commit and pre-push hooks run — the gate collects every file git would
upload (the union of `git ls-files` for already-tracked and `git diff --cached`
for staged) and HARD-BLOCKS, same weight as a critical advisory, when any match a
pattern. It leads the exit-code precedence: an uploaded credential is the
highest-stakes, least-recoverable miss.

Guarantees / boundaries:
- The upload surface depends on the phase. At **pre-commit** it is the working
  tree's tracked + staged set. At **pre-push** guard additionally reads the
  OUTGOING COMMITS (`git log --diff-filter=ACMR` over `<remote>..<local>`, or
  `<local> --not --remotes=<remote>` for a new branch, or `--not --remotes` when
  the destination is unknown) — because a secret committed and
  then deleted in a later commit is gone from the index yet still travels in the
  history the push carries. Those hits are labelled `[committed in outgoing
  history]`, and the advice for them is a history rewrite plus rotation: `git rm
  --cached` removes the file going forward and takes nothing back.
- An untracked / gitignored file is ignored — git won't push it, so it isn't a
  leak yet.
- Matching is repo-relative-path OR basename via `path.Match`, plus a
  trailing-'/' directory prefix. No registry, no network — pure local git state.
- Fail-open + loud on a git error (not a repo, git absent): there is no upload
  surface to assert about, so the gate stays inert rather than wedging commits.
- A deliberate match (`.env.example`, a fixture) is waived per-path with `guard
  ignore secret:<path>`, recorded in `.guard-ignores` like every other waiver.
- The pattern list is entirely user-defined (empty = gate off; no baked-in
  entries). Extend it with `guard secret-add <pattern>…` (append) or `guard config
  set secret-paths …` (replace), or by hand in `.guardrc`.

## 14b. Cooldown resolution — accept-all + auto-pin (v1.0.0)

A cooldown violation at commit/push used to be a flat hard block. On an
interactive terminal (`guard check --confirm`, which the hooks pass) it now
offers one choice over ALL violations at once:

```
 [a] accept all       record a cooldown waiver per version, then proceed
 [p] pin & reinstall  rewrite package.json's DIRECT deps to each package's
                      latest version PAST the cooldown (from the registry time
                      map), re-run the install through the ephemeral proxy,
                      then re-verify
 [N] abort
```

Pinning is a targeted string edit of package.json (not a JSON re-encode), so the
committed file's formatting and key order survive; only direct deps can be pinned
(a transitive too-fresh version is reported, and the reinstall may drop it on its
own). The pin is not trusted blindly — after reinstall the freshness check
re-runs, and a surviving violation fails the pin rather than reporting success.
CI / no-terminal keeps the strict hard block: this is an interactive convenience,
never an automatic bypass.

## 11f. Known limits (deliberate, v1.2.0)

Named here so they are choices, not oversights:

- **No host disk quota on the box's writable mount.** The package directory is
  bind-mounted read-write, and a script can fill the host filesystem through it.
  Memory, CPU, pids and wall-clock are capped; disk is not — there is no portable
  way to quota a bind mount across Docker/Podman and every filesystem. The blast
  radius is a full disk, not an escape or a leak.
- **A legacy approval (no integrity) is bound on first RUN, not on upgrade.**
  Entries written before approvals recorded a tarball hash keep applying until
  guard next executes them, at which point the current hash is recorded and
  annotated `integrity inferred, not reviewed`. Auto-binding them at upgrade time
  would pin hashes nobody ever looked at.
- **The pre-push snapshot follows the first parseable lockfile per ref.** A push
  whose commits change package manager mid-history is scanned per ref, not per
  commit.

## 12. Open items

1. ~~§9 fallback~~ — **resolved: warn-then-approve** (run uncontained only on explicit
   approval; CI falls back to fail unless pre-approved in `.guard-approvals`).
2. Ecosystem after npm (PyPI has different registry API + script model).
3. How shared verdicts are distributed/trusted (community feed vs local-only).
4. ~~Exact provenance method~~ — **partially resolved (v0.8.0, §11e)**: npm
   build-provenance (Sigstore/SLSA) attestations are fetched and verified
   (DSSE + Fulcio chain + digest binding). Rekor inclusion / SCT / TUF root
   rotation remain future work.
