// guard install for pip (PyPI phases 2-3): pip resolves through guard's ephemeral
// PEP 691 index proxy; sdists need --allow-sdist and a review (the boxed trial
// build itself is in pip-sdist.test.mjs, gated on docker). Offline: `pypi:` points at MockPyPI, whose file URLs are
// unfetchable, so pip always fails AFTER resolving — the assertions are on what
// the proxy hid, and nothing is ever installed (`--target` a temp dir anyway).
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MockPyPI, inTreeSdist } from './helpers/pypi.mjs';
import { guard } from './helpers/run.mjs';

const hasPip = (() => {
  try {
    execFileSync('pip', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

// Hermetic pip: no user config, no cache, no version-check call home. PEP 668
// is lifted only because the download is guaranteed to fail first.
const PIP_ENV = {
  PIP_CONFIG_FILE: '/dev/null',
  PIP_NO_CACHE_DIR: '1',
  PIP_DISABLE_PIP_VERSION_CHECK: '1',
  PIP_BREAK_SYSTEM_PACKAGES: '1',
  PIP_RETRIES: '0',
  PIP_TIMEOUT: '2',
  PIP_EXTRA_INDEX_URL: 'http://127.0.0.1:9/simple/', // guard must strip this
};

let pypi;
const dirs = [];

beforeAll(async () => {
  pypi = await new MockPyPI().start();
  pypi.publish('mixed-pkg', '1.0.0', { ageDays: 100 }).publish('mixed-pkg', '2.0.0', { ageDays: 2 });
  pypi.publish('src-only', '1.0.0', { ageDays: 100, files: inTreeSdist('src-only', '1.0.0') });
  pypi.publish('reqeusts', '1.0.0', { ageDays: 400 }); // one edit from "requests"
});

afterAll(async () => {
  await pypi?.stop();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/**
 * Temp pip project whose .guardrc points pypi: at the mock.
 * @param {string} [extra] - extra .guardrc lines
 * @returns {string} project dir
 */
function pipProject(extra = '') {
  const dir = mkdtempSync(join(tmpdir(), 'depguard-pipi-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'requirements.txt'), '# empty\n');
  writeFileSync(join(dir, '.guardrc'), `cooldown: 14d\npypi: ${pypi.url}\n${extra}`);
  return dir;
}

describe.skipIf(!hasPip)('guard install (pip)', () => {
  it('hides the too-fresh version and pip resolves the old one', async () => {
    const dir = pipProject();
    const res = await guard(dir, ['install', 'mixed-pkg', '--target', join(dir, 't')], PIP_ENV);
    expect(res.code).not.toBe(0); // the mock's file URL is unfetchable
    expect(res.stderr).toContain('filtered 1 version(s)');
    expect(res.stderr).toMatch(/mixed-pkg\s+1 version\(s\), e\.g\. 2\.0\.0 \(published 2d ago, cooldown is 14d\)/);
    expect(res.stdout + res.stderr).toContain('mixed_pkg-1.0.0-py3-none-any.whl');
    expect(res.stdout + res.stderr).not.toContain('mixed_pkg-2.0.0');
    expect(res.stdout + res.stderr).not.toContain('127.0.0.1:9/simple'); // PIP_EXTRA_INDEX_URL stripped
    expect(existsSync(join(dir, 'package-lock.json'))).toBe(false); // pip path, never npm
  });

  it('sdist-only projects need --allow-sdist, which asks for a review first', async () => {
    const dir = pipProject();
    const res = await guard(dir, ['install', 'src-only', '--target', join(dir, 't')], PIP_ENV);
    expect(res.code).not.toBe(0);
    expect(res.stderr).toContain('rerun with --allow-sdist');

    // No one to answer the prompt: guard fetched + scanned the sdist, prints
    // the report, records nothing, and names the command that approves it.
    const allowed = await guard(dir, ['install', '--allow-sdist', 'src-only', '--target', join(dir, 't')], PIP_ENV);
    expect(allowed.code).toBe(1);
    expect(allowed.stdout).toContain('src-only@1.0.0 wants to run a source build');
    expect(allowed.stdout).toContain('build backend: backend (in-tree)');
    expect(allowed.stderr).toContain('guard approve src-only@1.0.0');
    expect(existsSync(join(dir, '.guard-approvals'))).toBe(false);
  });

  it('with --allow-sdist, --no-binary / --only-binary are guard\'s call', async () => {
    const dir = pipProject();
    const res = await guard(dir, ['install', '--allow-sdist', '--no-binary', ':all:', 'src-only'], PIP_ENV);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain("--no-binary is guard's call");
  });

  it('an uncontained sdist approval is refused under no-container-fallback: fail', async () => {
    const dir = pipProject('no-container-fallback: fail\n');
    expect((await guard(dir, ['approve', 'src-only@1.0.0', '--uncontained'])).code).not.toBe(0);
    // ...and one recorded elsewhere (a machine with the default policy) is not honored here.
    writeFileSync(join(dir, '.guard-approvals'), JSON.stringify({ schema: 1, packages: { 'src-only@1.0.0': { decision: 'approved-uncontained', date: '2026-01-01T00:00:00Z' } } }));
    const res = await guard(dir, ['install', '--allow-sdist', 'src-only', '--target', join(dir, 't')], PIP_ENV);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("no-container-fallback is 'fail'");
    expect(existsSync(join(dir, 't'))).toBe(false);
  });

  it('a typosquat name is hidden; allow: lets it through', async () => {
    let dir = pipProject();
    let res = await guard(dir, ['install', 'reqeusts', '--target', join(dir, 't')], PIP_ENV);
    expect(res.code).not.toBe(0);
    expect(res.stderr).toMatch(/reqeusts\s+1 version\(s\), e\.g\. \* \(one edit from popular package "requests"/);
    expect(res.stderr).toContain('No matching distribution');
    expect(res.stderr).toContain('see the hidden versions above');

    dir = pipProject('allow: [reqeusts]\n');
    res = await guard(dir, ['install', 'reqeusts', '--target', join(dir, 't')], PIP_ENV);
    expect(res.stderr).not.toContain('filtered');
    expect(res.stdout + res.stderr).toContain('reqeusts-1.0.0-py3-none-any.whl');
  });
});
