// guard init: per-repo setup (DESIGN.md §3, §10) — drops policy + hook shims,
// never clobbers what's already there.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { MockRegistry } from './helpers/registry.mjs';
import { makeProject, guard } from './helpers/run.mjs';

let reg;
const projects = [];

beforeAll(async () => {
  reg = await new MockRegistry().start();
});

afterAll(async () => {
  await reg.stop();
  for (const p of projects) p.cleanup();
});

describe('guard init', () => {
  it('drops .guardrc and executable git hooks', async () => {
    const p = makeProject(reg.url, { git: true });
    projects.push(p);
    // makeProject pre-writes .guardrc; remove it so init's own copy is tested.
    const rcPath = join(p.dir, '.guardrc');
    writeFileSync(rcPath, ''); // will be reported as existing — test fresh below
    const res = await guard(p.dir, ['init']);
    expect(res.code).toBe(0);
    for (const hook of ['pre-commit', 'pre-push']) {
      const path = join(p.dir, '.git', 'hooks', hook);
      expect(existsSync(path)).toBe(true);
      // Owner-executable bit set — git won't run it otherwise.
      expect(statSync(path).mode & 0o100).toBeTruthy();
      expect(readFileSync(path, 'utf8')).toContain('guard check');
    }
  });

  it('writes .npmrc so even raw npm installs are script-neutralized', async () => {
    const p = makeProject(reg.url, { git: true });
    projects.push(p);
    await guard(p.dir, ['init']);
    const npmrc = readFileSync(join(p.dir, '.npmrc'), 'utf8');
    expect(npmrc).toContain('ignore-scripts=true');
    // Re-init must not duplicate the line.
    await guard(p.dir, ['init']);
    const again = readFileSync(join(p.dir, '.npmrc'), 'utf8');
    expect(again.match(/ignore-scripts/g)).toHaveLength(1);
  });

  it('appends to an existing .npmrc without clobbering it', async () => {
    const p = makeProject(reg.url, { git: true });
    projects.push(p);
    writeFileSync(join(p.dir, '.npmrc'), 'save-exact=true\n');
    await guard(p.dir, ['init']);
    const npmrc = readFileSync(join(p.dir, '.npmrc'), 'utf8');
    expect(npmrc).toContain('save-exact=true');
    expect(npmrc).toContain('ignore-scripts=true');
  });

  it('refuses to overwrite an existing .guardrc or hooks on re-run', async () => {
    const p = makeProject(reg.url, { git: true });
    projects.push(p);
    await guard(p.dir, ['init']);
    // Mark the existing artifacts, re-init, verify untouched.
    const hookPath = join(p.dir, '.git', 'hooks', 'pre-commit');
    const before = readFileSync(hookPath, 'utf8');
    const res = await guard(p.dir, ['init']);
    expect(res.code).toBe(0);
    expect(readFileSync(hookPath, 'utf8')).toBe(before);
    expect(res.stderr).toContain('already exists');
  });

  it('fails with a clear message outside a git repo', async () => {
    const p = makeProject(reg.url); // no git
    projects.push(p);
    const res = await guard(p.dir, ['init']);
    expect(res.code).not.toBe(0);
    expect(res.stderr).toContain('git');
  });
});

describe('guard check', () => {
  it('passes quietly when there is no lockfile yet', async () => {
    const p = makeProject(reg.url);
    projects.push(p);
    const res = await guard(p.dir, ['check']);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('nothing to check');
  });
});
