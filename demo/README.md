# depguard live demo

Watch depguard handle a cast of realistic packages — clean installs, a build
that *looks* malicious but isn't, real exfil attempts caught by the box, and a
too-fresh version blocked before it runs.

```sh
node demo/run.mjs              # all scenarios
node demo/run.mjs demo-exfil   # just one
```

Needs the same setup as the tests (Go to build the binary, docker/podman for
the conviction demos). It builds `guard` on first run.

## Safety

**Nothing in this demo can harm a machine or reach the network.**

- Every "malicious" package targets **unroutable documentation IPs**
  (`203.0.113.0/24`, RFC 5737) — they go nowhere by definition.
- The box runs with `--network none`, so even a real address couldn't be
  reached. The demos prove depguard detects *intent*; no packet ever leaves.
- The packages run in throwaway temp projects that are deleted after each run.

## The cast

| Package | Outcome | Demonstrates |
|---|---|---|
| `demo-plain` | installs | the quiet baseline — no scripts, nothing to decide |
| `demo-native-build` | installs | **false-positive resistance** (see below) |
| `demo-exfil` | convicted | install-time network exfil → caught, output discarded |
| `demo-snoop` | convicted | credential theft (`/root/.ssh`, `/etc/shadow`) → caught |
| `demo-too-fresh` | blocked | cooldown stops a 1-day-old version before it runs |

## The false-positive demo package (`demo-native-build`)

This is the most important one to understand, because it's where naive tools
get it wrong. Its `build.js` deliberately does three things that **look**
dangerous and that the *static* scanner flags:

1. **Spawns a child process** (`child_process.execSync`) — like a compiler.
2. **Reads a config file** (`.npmrc` in its own dir) — looks like "secret access".
3. **Writes a binary** (`build/addon.node`) — like a native addon build.

Every real native module (`node-gyp`, `esbuild`, `sharp`, `better-sqlite3`)
does exactly these. A tool that convicted on them would cry wolf until you
turned it off.

depguard **passes it**, because the *dynamic* syscall trace tells the truth:

| Signal | Static scan | Syscall trace (the box) | Verdict |
|---|---|---|---|
| spawns child process | flagged ⚠ | child does nothing networked/secret | fine |
| reads `.npmrc` | flagged ⚠ | path is inside the box's own mounts, not a real secret | fine |
| writes files | flagged ⚠ | writes land in its own dir (the only writable mount) | fine |
| — | — | **no connect() to a real address, no read of `/root/.ssh` etc.** | **PASS** |

That's the whole thesis: **static signals raise questions; the box answers
them with what the code actually did.** `demo-native-build` is the package
that proves depguard isn't just a keyword grep.

### Why the box doesn't false-positive on these

The trace verdict (`internal/trace`) only convicts on behavior with **no
legitimate build-time explanation**:

- **network reach-out** to a non-loopback address, or a **DNS query** naming a
  host — builds shouldn't phone home;
- **secret access** — reads of credential paths (`/root/.ssh`, `id_rsa`,
  `/etc/shadow`, another process's `environ`), but **not** paths inside the
  box's own mounts (`/app`, `/home/node`, `/tmp`), which hold only data
  already in the cage.

Spawning children and writing build output are recorded as *context*, never as
convictions — they need the real signals above to matter.

## Adding a scenario

Add an entry to `demo/packages.mjs` with its `expect` outcome and a `why`
caption. The runner publishes it to the mock registry, runs guard against it,
and asserts the outcome matches — so a demo that drifts out of date fails
loudly instead of misleading an audience.
