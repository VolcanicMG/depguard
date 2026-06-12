# depguard — working rules

Zero-dependency Go guard against npm supply-chain attacks. One signed binary,
per-repo policy, nothing in the background — protection fires only when the user
acts (install, commit, PR).

## The docs are part of the contract — keep them in sync

This repo's `.md` files are not decoration; each one is the canonical source for a
specific audience. When you change behavior, you are **not done until the matching
doc reflects it in the same change**. Stale docs here are a correctness bug, not a
nicety.

### Doc map — who owns what

| File | Audience / role | Owns |
|---|---|---|
| `DESIGN.md` | **the contract** — the *why* | goals/non-goals, the layered threat model, each defense layer's guarantee, design stance |
| `README.md` | end users — the *how to use* | install steps, the command list + flags, per-repo files, the "what each layer stops" table |
| `SETUP.md` | end users — *onboarding* | step-by-step per-repo setup (binary → `init` → workflow → CI), `.guardrc` tuning, waiving findings, tips/tricks, troubleshooting |
| `docs/CODEMAP.md` | contributors — the *where* | file/dir layout, what calls what, where to make which kind of change |
| `PITCH.md` | prospective users — the *sell* | problem framing, product summary, value per layer in plain language |
| `demo/README.md` | demo runners | demo commands, scenario cast, safety guarantees of the demo |
| `test/README.md` | test authors | how the black-box suite runs, the mock-registry trick, Go-path override |

## When you change X, update Y

| You changed… | Update… |
|---|---|
| a CLI command, flag, or its output | `README.md` command list **and** `docs/CODEMAP.md` if dispatch moved |
| a defense layer's behavior or guarantee | `DESIGN.md` (the layer's promise) **and** `README.md` "what each layer stops" |
| added/removed/renamed a file or package | `docs/CODEMAP.md` layout + call graph |
| a new threat covered or a scope boundary | `DESIGN.md` goals/non-goals **and** `PITCH.md` if it changes the pitch |
| a demo scenario or its safety model | `demo/README.md` |
| how tests are built/run, or the registry mock | `test/README.md` |
| MCP tools exposed by `guard mcp` | `README.md` (the `guard mcp` line) **and** `docs/CODEMAP.md` (`mcp.go`) |
| install/onboarding steps, a setup tip, or a new per-repo file | `SETUP.md` |

Rule of thumb: `DESIGN.md` answers *why/what-guarantee*, `README.md` answers
*how-to-use*, `CODEMAP.md` answers *where-in-the-code*. A change usually touches at
least two of these — if you can only think of one, check whether you missed the
others.

## Before finishing any change

1. Re-read the doc-map row(s) for what you touched; edit the doc in the same change.
2. If the change adds/removes a defense or alters a guarantee, the `DESIGN.md`
   layer description **and** the `README.md` layer table must agree — verify both.
3. Keep the existing voice: terse, concrete, ASCII diagrams over prose, honest
   about limits ("none claims 100%"). Don't oversell.

## Engineering constraints (don't regress these)

- **Zero dependencies, on purpose.** `go.mod` stays dependency-free. Use the stdlib;
  if you reach for a third-party package, stop and reconsider — it's a design line.
- **Nothing runs in the background.** Every protection is triggered by a user action.
  Don't add daemons, watchers, or always-on processes.
- **Fail closed** on the name/confusion gates; **defense in depth** everywhere — no
  single check is claimed to certify a package clean.
- Go toolchain lives at `~/.local/go/bin/go` (not on PATH); override in tests with
  `GUARD_GO=/path/to/go`.

## Testing — required, regression-first

Security IS the product here, so we test as much as we can. **This repo OVERRIDES
the parent's "no tests unless asked" rule:** every behavior change ships with tests
in the same change. The goal is a net dense enough that a future edit cannot
silently regress a check — when we make changes, the tests are what stop us
breaking something elsewhere.

Two layers, both zero-dep:

| Layer | Tool | Covers | Lives in |
|---|---|---|---|
| **Unit** | Go stdlib `testing` | internal logic in isolation — parsers, matchers, the scan/trace/proxy decision functions, fail-closed branches | `internal/<pkg>/*_test.go` |
| **E2E** | vitest + mock registry | the real compiled binary end-to-end (install / check / scan / mcp) | `test/*.test.mjs` |

Rules:
- **Test in the same change as the behavior.** A new check, filter, parser, or
  fail-closed branch is not done until a test pins it. A bug fix gets a test that
  fails *before* the fix (see `hasPathFragment`, `Check` non-200 → error).
- **Characterize before refactoring.** Before changing a hot path (e.g. the
  scanner), land tests for the CURRENT behavior first so the refactor proves it
  preserved them.
- **Cover the negative + fail-closed cases**, not just the happy path: the
  look-alike that must NOT match, the non-200 that must fail loud, the bomb that
  must be flagged, the dedup that must collapse to one finding.
- Make an internal knob a `var` (not `const`) when a test needs to trip a bound
  cheaply (see `maxArchiveBytes`, `maxArchiveEntries`, `maxOSVResponse`).
- Before calling a change done: `~/.local/go/bin/go test ./...` (unit) **and** the
  `test/` e2e suite (per `test/README.md`) must both be green.

## Inherited rules

The parent `~/repos/CLAUDE.md` applies (SOLID, version-pegging, ask before any git
action, JSDoc/comment-the-why). **Exception: the parent's "no tests unless asked"
does NOT apply here** — see Testing above; tests are required for every change.
This file refines it for depguard; on conflict, this file wins for repo-specific points.
