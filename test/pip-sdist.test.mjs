// pip sdists end to end (PyPI phase 3): guard fetches the sdist, scans it,
// needs a recorded approval, TRIAL-BUILDS it in the strace box for a verdict,
// and only then lets pip build it on the host. Needs docker AND pip; offline
// apart from the one-time observation-image build. The fixtures use an in-tree
// PEP 517 backend (helpers/pypi.mjs inTreeSdist) so building needs no build
// dependencies and no network.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MockPyPI, inTreeSdist } from './helpers/pypi.mjs';
import { guard } from './helpers/run.mjs';

const ok = (cmd, args) => {
  try {
    execFileSync(cmd, args, { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
};
const hasDocker = () => ok('docker', ['version', '--format', '{{.Server.Version}}']);
const hasPip = () => ok('pip', ['--version']);

// Hermetic pip (see pip-install.test.mjs). PEP 668 is lifted because the host
// install goes to a --target dir, never the system site-packages.
const PIP_ENV = {
  PIP_CONFIG_FILE: '/dev/null',
  PIP_NO_CACHE_DIR: '1',
  PIP_DISABLE_PIP_VERSION_CHECK: '1',
  PIP_BREAK_SYSTEM_PACKAGES: '1',
  PIP_RETRIES: '0',
  PIP_TIMEOUT: '5',
};

let pypi;
const dirs = [];

beforeAll(async () => {
  pypi = await new MockPyPI().start();
  pypi.publish('sdist-clean', '1.0.0', { ageDays: 100, files: inTreeSdist('sdist-clean', '1.0.0') });
  // Newer, but no host python satisfies it: guard must pick (and pin pip to) 1.0.0.
  pypi.publish('sdist-clean', '2.0.0', { ageDays: 100, requiresPython: '>=3.99', files: inTreeSdist('sdist-clean', '2.0.0') });
  pypi.publish('sdist-evil', '1.0.0', { ageDays: 100, files: inTreeSdist('sdist-evil', '1.0.0', { evil: true }) });
});

afterAll(async () => {
  await pypi?.stop();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function pipProject() {
  const dir = mkdtempSync(join(tmpdir(), 'depguard-pips-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'requirements.txt'), '# empty\n');
  writeFileSync(join(dir, '.guardrc'), `cooldown: 14d\npypi: ${pypi.url}\n`);
  return dir;
}

const approvals = (dir) => JSON.parse(readFileSync(join(dir, '.guard-approvals'), 'utf8')).packages;

describe.skipIf(!hasDocker() || !hasPip())('guard install --allow-sdist (boxed trial build)', () => {
  it('a clean sdist: review needed, then trial-built in the box, then installed by pip', async () => {
    const dir = pipProject();
    const target = join(dir, 't');
    let res = await guard(dir, ['install', '--allow-sdist', 'sdist-clean', '--target', target], PIP_ENV);
    expect(res.code).toBe(1);
    expect(res.stdout).toContain('build backend: backend (in-tree)');
    expect(res.stderr).toContain('guard approve sdist-clean@1.0.0');

    expect((await guard(dir, ['approve', 'sdist-clean@1.0.0'])).code).toBe(0);
    const started = Date.now();
    res = await guard(dir, ['install', '--allow-sdist', 'sdist-clean', '--target', target], PIP_ENV);
    console.log(`sdist trial build + host install took ${Math.round((Date.now() - started) / 1000)}s (first run builds depguard-box:4)`);
    expect(res.code, res.stderr).toBe(0);
    expect(res.stderr).toContain('sdist-clean@1.0.0 — trial build clean');
    expect(existsSync(join(target, 'sdist_clean-1.0.0.dist-info'))).toBe(true);
    expect(existsSync(join(target, 'sdist_clean-2.0.0.dist-info'))).toBe(false);
    expect(Object.keys(approvals(dir))).toEqual(['sdist-clean@1.0.0']);
    // The unbound `guard approve` entry is now pinned to the sdist's sha256.
    expect(approvals(dir)['sdist-clean@1.0.0'].integrity).toMatch(/^sha256:[0-9a-f]{64}$/);
  }, 600_000);

  it('a malicious sdist: the box sees the connect, the approval flips to denied, nothing installs', async () => {
    const dir = pipProject();
    const target = join(dir, 't');
    expect((await guard(dir, ['approve', 'sdist-evil@1.0.0'])).code).toBe(0);
    const res = await guard(dir, ['install', '--allow-sdist', 'sdist-evil', '--target', target], PIP_ENV);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain('203.0.113.1:80');
    expect(res.stderr).toContain('attempted malicious actions during its build');
    expect(approvals(dir)['sdist-evil@1.0.0'].decision).toBe('denied');
    expect(existsSync(target)).toBe(false);
  }, 600_000);
});
