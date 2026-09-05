# depguard test suite — how it works

Two layers, both zero-dependency:

- **Go unit tests** (`internal/<pkg>/*_test.go`, stdlib `testing`) pin internal
  logic in isolation — parsers, matchers, fail-closed branches, the scan/trace
  decision functions. Run with `~/.local/go/bin/go test ./...`. Fast, no registry
  or docker needed. This is the regression net for the security checks.
- **Black-box e2e** (this directory) — vitest spawns the **real compiled `guard`
  binary** and asserts on observable behavior (exit codes, stderr, what landed on
  disk). The contract under test is the same one users get.

The rest of this file documents the e2e layer (the Go unit tests are ordinary
`go test` files next to the code they cover).

## Run it

```sh
cd test
npm install     # vitest only (pinned exact); the harness itself adds zero other deps
npm test        # = vitest run
npm run test:watch
```

`globalSetup.mjs` go-builds the binary into `test/.bin/guard` before anything
runs — a compile error fails the suite immediately. Go is found at
`~/.local/go/bin/go`; override with `GUARD_GO=/path/to/go npm test`.

## The trick: a mock npm registry

The cooldown filter can't be tested against the real registry — real publish
dates drift past any cutoff over time, so assertions would rot. Instead each
test fabricates packages with **exact ages**:

```
 test file                         mock registry (helpers/registry.mjs)
 ─────────                         ────────────────────────────────────
 reg.publish('mixed-pkg','1.0.0',  serves a real packument: versions,
             { ageDays: 100 })     time map, dist-tags, tarball URLs
 reg.publish('mixed-pkg','2.0.0',
             { ageDays: 2 })       serves real .tgz tarballs with real
                                   sha512 integrity (npm verifies them)
```

```
 guard binary ──.guardrc registry:──► mock registry (127.0.0.1:random)
      ▲                                      ▲
      └── spawned by helpers/run.mjs         └── tarballs built by helpers/tar.mjs
          in a throwaway temp project            (hand-rolled USTAR+gzip)
```

Everything is hermetic: no request ever leaves localhost except `guard
check`'s OSV advisory lookup (fake package names → no hits; offline → guard
fails open by design, so tests pass either way).

## The helpers

| File | Job |
|---|---|
| `helpers/registry.mjs` | `MockRegistry` — `publish(name, version, {ageDays, scripts, files})`, serves packuments + tarballs on a random port |
| `helpers/tar.mjs` | `packTgz(files)` — minimal USTAR+gzip encoder so fabricated tarballs need no tar dependency |
| `helpers/run.mjs` | `makeProject(registryUrl, opts)` — temp dir with `package.json` + `.guardrc` pointed at the mock; `guard(dir, args)` — spawns the binary, resolves `{code, stdout, stderr}` |
| `globalSetup.mjs` | builds the binary once per suite run |

Two deliberate harness choices:

- **stdin is detached** (`execFile` default pipes; guard's termios check sees
  no terminal) → every test exercises the *non-interactive* paths, exactly
  like CI. Interactive prompting has no automated coverage — by design, it
  would need a PTY; verify it manually with `guard install` in a terminal.
- **Test files run sequentially** (`fileParallelism: false`) — each file binds
  ports and spawns npm; keeping them serial keeps failures readable.

## What each suite proves

| Suite | Tests | Ground truth used |
|---|---|---|
| `cooldown.test.mjs` | 9 | which version number landed in `node_modules/<pkg>/package.json`; stderr explanations; `guard check` exit code after a bypass-style install; https-only `.guardrc` rejection |
| `additions.test.mjs` | 9 | typosquat + homoglyph name gate, dependency-confusion (`internal-scopes`), deprecation surfacing, lockfile integrity (off-registry / no-hash), fail-closed config parsing, `guard scan --json` (capabilities + injection), `guard mcp` stdio JSON-RPC |
| `scripts.test.mjs` | 7 | `marker.txt` — the fixture's postinstall writes it, so its existence *is* "did the script run"; `.guard-approvals` content; boxed+traced run via real docker — incl. a benign script passing the syscall trace AND an exfil script convicted (output discarded, approval auto-denied); plus `guard prewarm` building the image and `guard clean [--image]` reclaiming it. Box tests auto-skip without docker |
| `init.test.mjs` | 6 | files dropped by `guard init` (.guardrc, hooks, `.npmrc`), executable bits, no-clobber on re-run, clean failure outside git |
| `secrets.test.mjs` | 6 | the secret-file gate: staged `.env` blocked, untracked file ignored, `*.pem` basename glob, `guard ignore secret:<path>` waiver clears it, `--json` flips `ok` to false, `guard secret-add` appends a pattern |

## Adding a test

1. `reg.publish('my-pkg', '1.0.0', { ageDays: ..., scripts: ..., files: ... })`
   in `beforeAll` — ages are the input to cooldown behavior.
2. `const { dir } = project(opts)` — opts: `cooldown`, `allow`, `git`.
3. `await guard(dir, ['install', 'my-pkg', ...NPM_QUIET])` and assert on
   `code` / `stderr` / files on disk.
4. Assert on **observable outcomes** (what's installed, what's written),
   not on log phrasing beyond stable keywords — keeps tests honest and
   refactor-proof.

Budget: each test costs an npm spawn (~0.5s); docker/traced tests ~3s. The
whole suite stays around ~10s — keep it that way; this runs in pre-commit
habits.

## Manual: the trace-forgery replay (needs Docker)

The box's evidence guarantee — the tracee cannot reach the trace pipe — is a
kernel property of the exec-only strace binary, so the unit suite can only pin
the recipe (`TestObsImageMakesTracerNonDumpable`). Prove the property itself
against the shipped image after any change to `obsDockerfile`, `tracedScript`,
or the `docker run` flags. Run as a non-root uid, with the same flags `box.Run`
uses:

```sh
IMG=depguard-box:2   # box.ObsImageName()
docker run --rm --read-only --network none --tmpfs /tmp:size=64m \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 512 --user 1000:1000 \
  $IMG sh -c "exec strace -f -q -e trace=%network,execve,openat -s 512 -o /dev/stdout sh -c '
    exec 1>&2
    ls -l /proc/\$\$/fd                                   # expect: 0 /dev/null, 1 and 2 the SAME pipe, nothing else
    printf \"%d    +++ exited with 0 +++\n\" \$\$ > /proc/1/fd/1 && echo FORGE-OK || echo FORGE-BLOCKED
    cat /proc/1/fd/1 || true                              # expect: Permission denied
    kill -9 1; echo still-alive; exit 5'" > trace.txt 2> out.txt
echo "exit=$?"; tail -1 trace.txt; cat out.txt
```

Expected: `cat /proc/1/comm` says `strace`; `FORGE-BLOCKED`; both `/proc/1/fd/1`
accesses denied; `kill -9 1` is silently dropped (a pid-namespace init ignores
signals from inside), so `still-alive` prints, exit is 5 and the trace's last
line is `<root pid> +++ exited with 5 +++`. Drop the `exec` before `strace` to
see the hole this guards: PID 1 becomes `sh`, `FORGE-OK`, and the kill lands
(exit 137). Killed-tracer / flooded-trace classification itself is pinned by
the unit fixtures in `internal/box/box_test.go`.

## Related: the live demo

`demo/run.mjs` (see [../demo/README.md](../demo/README.md)) reuses these same
helpers to *narrate* guard handling a cast of packages for an audience —
including `demo-native-build`, the false-positive-resistance showcase. The
demo asserts its own outcomes, so it doubles as a coarse integration check.
