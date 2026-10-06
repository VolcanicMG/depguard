// PyPI phase 1: requirements.txt is a check-only lockfile. Offline by design —
// .guardrc points `pypi:` at a closed loopback port, so freshness lookups fail
// fast and degrade to a warning (on-check-error defaults to warn). OSV sees
// fixture names that exist nowhere: no hits online, fail-open offline.
import { describe, it, expect, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { guard } from './helpers/run.mjs';

const dirs = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const H1 = 'sha256:' + 'a'.repeat(64);
const H2 = 'sha256:' + 'b'.repeat(64);

/**
 * Temp pip project: git repo + requirements.txt (+ an offline .guardrc).
 * @param {string} requirements - requirements.txt body
 * @param {boolean} [guardrc=true] - write the offline .guardrc
 * @returns {string} project dir
 */
function pipProject(requirements, guardrc = true) {
  const dir = mkdtempSync(join(tmpdir(), 'depguard-pip-'));
  dirs.push(dir);
  execFileSync('git', ['init', '-q'], { cwd: dir });
  writeFileSync(join(dir, 'requirements.txt'), requirements);
  if (guardrc) writeFileSync(join(dir, '.guardrc'), 'cooldown: 14d\npypi: http://127.0.0.1:9\n');
  return dir;
}

describe('pip / requirements.txt', () => {
  it('guard init writes .guardrc + hooks but no .npmrc', async () => {
    const dir = pipProject(`depguard-fixture-alpha==1.0.0 --hash=${H1}\n`, false);
    const res = await guard(dir, ['init']);
    expect(res.code).toBe(0);
    expect(existsSync(join(dir, '.guardrc'))).toBe(true);
    expect(existsSync(join(dir, '.git', 'hooks', 'pre-commit'))).toBe(true);
    expect(existsSync(join(dir, '.git', 'hooks', 'pre-push'))).toBe(true);
    expect(existsSync(join(dir, '.npmrc'))).toBe(false);
  });

  it('a hashed pinned file passes guard check', async () => {
    const dir = pipProject(`depguard-fixture-alpha==1.0.0 \\\n    --hash=${H1}\n`);
    const res = await guard(dir, ['check', '--all', '--quiet']);
    expect(res.code).toBe(0);
    expect(res.stderr).not.toContain('--hash');
  });

  it('unhashed pins warn once (collapsed) and do not gate', async () => {
    const dir = pipProject('depguard-fixture-alpha==1.0.0\ndepguard-fixture-beta==2.0\n');
    const res = await guard(dir, ['check', '--all', '--quiet']);
    expect(res.code).toBe(0);
    expect(res.stderr).toContain('2 of 2 pinned requirements carry no --hash');
    expect(res.stderr.match(/carry no --hash/g)).toHaveLength(1);
    const json = await guard(dir, ['check', '--all', '--json']);
    const out = JSON.parse(json.stdout);
    expect(out.ok).toBe(true);
    expect(out.unhashedWarnings).toHaveLength(2);
  });

  it('the same pin with two different hashes gates', async () => {
    const dir = pipProject(
      `depguard-fixture-alpha==1.0.0 --hash=${H1}\ndepguard-fixture-alpha==1.0.0 --hash=${H2}\n`,
    );
    const res = await guard(dir, ['check', '--all', '--quiet']);
    expect(res.code).not.toBe(0);
    expect(res.stderr).toContain('conflicting');
  });

  it('guard install refuses with exit 2 and touches nothing', async () => {
    const dir = pipProject(`depguard-fixture-alpha==1.0.0 --hash=${H1}\n`);
    const res = await guard(dir, ['install']);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('pip projects are check-only');
    expect(existsSync(join(dir, 'node_modules'))).toBe(false);
    expect(existsSync(join(dir, 'package-lock.json'))).toBe(false);
  });
});
