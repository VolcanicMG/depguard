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
| `scripts.test.mjs` | 6 | `marker.txt` — the fixture's postinstall writes it, so its existence *is* "did the script run"; `.guard-approvals` content; boxed+traced run via real docker — incl. a benign script passing the syscall trace AND an exfil script convicted (output discarded, approval auto-denied). Box tests auto-skip without docker |
| `init.test.mjs` | 6 | files dropped by `guard init` (.guardrc, hooks, `.npmrc`), executable bits, no-clobber on re-run, clean failure outside git |

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

## Related: the live demo

`demo/run.mjs` (see [../demo/README.md](../demo/README.md)) reuses these same
helpers to *narrate* guard handling a cast of packages for an audience —
including `demo-native-build`, the false-positive-resistance showcase. The
demo asserts its own outcomes, so it doubles as a coarse integration check.
