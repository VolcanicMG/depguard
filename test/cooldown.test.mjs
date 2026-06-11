// Layer 1: the cooldown filter (DESIGN.md §5).
// The proxy must hide young versions, repoint `latest` at the newest
// survivor, explain blocks, and let allowlisted packages bypass entirely.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { MockRegistry } from './helpers/registry.mjs';
import { makeProject, guard, NPM_QUIET } from './helpers/run.mjs';

let reg;
const projects = [];

beforeAll(async () => {
  reg = await new MockRegistry().start();

  // old-pkg: single version, well past the 14d cooldown.
  reg.publish('old-pkg', '1.0.0', { ageDays: 100 });

  // mixed-pkg: latest is 2 days old (inside cooldown); 1.0.0 is safe.
  reg.publish('mixed-pkg', '1.0.0', { ageDays: 100 });
  reg.publish('mixed-pkg', '2.0.0', { ageDays: 2 }); // becomes dist-tags.latest

  // fresh-pkg: every version inside the cooldown window.
  reg.publish('fresh-pkg', '1.0.0', { ageDays: 3 });
  reg.publish('fresh-pkg', '1.0.1', { ageDays: 1 });
});

afterAll(async () => {
  await reg.stop();
  for (const p of projects) p.cleanup();
});

/** Shorthand: new project on the mock registry, tracked for cleanup. */
function project(opts) {
  const p = makeProject(reg.url, opts);
  projects.push(p);
  return p;
}

/** Installed version of a package in a project, or null. */
function installedVersion(dir, name) {
  const path = join(dir, 'node_modules', name, 'package.json');
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, 'utf8')).version;
}

describe('cooldown filter', () => {
  it('installs a version older than the cooldown', async () => {
    const { dir } = project();
    const res = await guard(dir, ['install', 'old-pkg', ...NPM_QUIET]);
    expect(res.code).toBe(0);
    expect(installedVersion(dir, 'old-pkg')).toBe('1.0.0');
  });

  it('silently resolves to the newest SAFE version when latest is too young', async () => {
    const { dir } = project();
    const res = await guard(dir, ['install', 'mixed-pkg', ...NPM_QUIET]);
    // The core promise: no error, npm just never saw 2.0.0.
    expect(res.code).toBe(0);
    expect(installedVersion(dir, 'mixed-pkg')).toBe('1.0.0');
    expect(res.stderr).toContain('mixed-pkg');
    expect(res.stderr).toMatch(/cooldown/);
  });

  it('fails with an explanation when every version is inside the cooldown', async () => {
    const { dir } = project();
    const res = await guard(dir, ['install', 'fresh-pkg', ...NPM_QUIET]);
    expect(res.code).not.toBe(0);
    expect(installedVersion(dir, 'fresh-pkg')).toBeNull();
    // guard must say what it hid and why — the failure is the feature.
    expect(res.stderr).toContain('filtered');
    expect(res.stderr).toContain('fresh-pkg');
  });

  it('lets allowlisted packages bypass the cooldown', async () => {
    const { dir } = project({ allow: ['fresh-pkg'] });
    const res = await guard(dir, ['install', 'fresh-pkg', ...NPM_QUIET]);
    expect(res.code).toBe(0);
    expect(installedVersion(dir, 'fresh-pkg')).toBe('1.0.1');
  });

  it('respects a custom cooldown from .guardrc', async () => {
    // 1-day cooldown: the 2-day-old version becomes installable.
    const { dir } = project({ cooldown: '1d' });
    const res = await guard(dir, ['install', 'mixed-pkg', ...NPM_QUIET]);
    expect(res.code).toBe(0);
    expect(installedVersion(dir, 'mixed-pkg')).toBe('2.0.0');
  });
});

describe('guard check freshness (the plain-npm bypass closer)', () => {
  it('fails when the lockfile contains a version inside the cooldown', async () => {
    // Install the fresh package WITH an allowlist (simulating any bypass
    // route), then drop the allowlist — check must now flag what's locked.
    const { dir } = project({ allow: ['fresh-pkg'] });
    await guard(dir, ['install', 'fresh-pkg', ...NPM_QUIET]);
    writeFileSync(join(dir, '.guardrc'), `cooldown: 14d\nregistry: ${reg.url}\n`);
    const res = await guard(dir, ['check']);
    expect(res.code).not.toBe(0);
    expect(res.stderr).toContain('fresh-pkg@1.0.1');
    expect(res.stderr).toContain('cooldown');
  });

  it('passes when locked versions are older than the cooldown', async () => {
    const { dir } = project();
    await guard(dir, ['install', 'old-pkg', ...NPM_QUIET]);
    const res = await guard(dir, ['check']);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('all clear');
  });
});

describe('.guardrc hardening', () => {
  it('rejects a non-https registry (committed-file MITM vector)', async () => {
    const { dir } = project();
    writeFileSync(join(dir, '.guardrc'), 'registry: http://evil.example.com\n');
    const res = await guard(dir, ['install', 'old-pkg', ...NPM_QUIET]);
    expect(res.code).not.toBe(0);
    expect(res.stderr).toContain('https');
  });
});

describe('scoped packages', () => {
  it('filters and installs @scope/name through the proxy URL-encoding round-trip', async () => {
    reg.publish('@acme/widget', '3.1.4', { ageDays: 50 });
    const { dir } = project();
    const res = await guard(dir, ['install', '@acme/widget', ...NPM_QUIET]);
    expect(res.code).toBe(0);
    expect(installedVersion(dir, '@acme/widget')).toBe('3.1.4');
  });
});
