// pip repos end to end, without pip: the check path against MockPyPI's JSON API
// (hook scoping, waivers, --json, MCP), sbom, the install-flag refusals that
// fire before pip runs, `guard why`, and a mixed npm+pip repo.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MockPyPI } from './helpers/pypi.mjs';
import { guard, GUARD } from './helpers/run.mjs';

const H1 = 'sha256:' + 'a'.repeat(64);
const H2 = 'sha256:' + 'b'.repeat(64);
const GIT_ENV = { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@e', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@e' };

let pypi;
const dirs = [];

beforeAll(async () => {
  pypi = await new MockPyPI().start();
  pypi.publish('old-pkg', '1.0.0', { ageDays: 100 });
  pypi.publish('other-old', '1.0.0', { ageDays: 200 });
  pypi.publish('fresh-pkg', '2.0.0', { ageDays: 2 });
});

afterAll(async () => {
  await pypi?.stop();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/**
 * Temp pip project (git repo) pointed at the mock.
 * @param {string} requirements - requirements.txt body
 * @returns {string} project dir
 */
function project(requirements) {
  const dir = mkdtempSync(join(tmpdir(), 'depguard-pipc-'));
  dirs.push(dir);
  execFileSync('git', ['init', '-q'], { cwd: dir });
  writeFileSync(join(dir, 'requirements.txt'), requirements);
  writeFileSync(join(dir, '.guardrc'), `cooldown: 14d\npypi: ${pypi.url}\n`);
  return dir;
}

const git = (dir, ...args) => execFileSync('git', args, { cwd: dir, env: GIT_ENV });

describe('guard check on a pip repo', () => {
  it('pre-commit vets only the staged additions, and a waiver clears one', async () => {
    const dir = project('old-pkg==1.0.0\n');
    git(dir, 'add', '-A');
    git(dir, 'commit', '-qm', 'base');

    writeFileSync(join(dir, 'requirements.txt'), 'old-pkg==1.0.0\nfresh-pkg==2.0.0\n');
    git(dir, 'add', 'requirements.txt');
    let res = await guard(dir, ['check', '--hook=pre-commit']);
    expect(res.code).not.toBe(0);
    expect(res.stderr).toMatch(/fresh-pkg@2\.0\.0 — published 2d ago/);

    writeFileSync(join(dir, 'requirements.txt'), 'old-pkg==1.0.0\nother-old==1.0.0\n');
    git(dir, 'add', 'requirements.txt');
    res = await guard(dir, ['check', '--hook=pre-commit']);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('1 version(s) cooldown-checked');

    writeFileSync(join(dir, 'requirements.txt'), 'old-pkg==1.0.0\nfresh-pkg==2.0.0\n');
    git(dir, 'add', 'requirements.txt');
    expect((await guard(dir, ['ignore', 'cooldown:fresh-pkg@2.0.0', '--reason', 'reviewed'])).code).toBe(0);
    res = await guard(dir, ['check', '--hook=pre-commit']);
    expect(res.code).toBe(0);
    expect(res.stderr).toContain('cooldown waived cooldown:fresh-pkg@2.0.0');
  });

  it('--json: unhashed pins warn with ok true; a conflict flips ok', async () => {
    let out = JSON.parse((await guard(project('old-pkg==1.0.0\nother-old==1.0.0\n'), ['check', '--all', '--json'])).stdout);
    expect(out.ok).toBe(true);
    expect(out.unhashedWarnings).toEqual(['old-pkg@1.0.0', 'other-old@1.0.0']);

    const res = await guard(project(`old-pkg==1.0.0 --hash=${H1}\nold-pkg==1.0.0 --hash=${H2}\n`), ['check', '--all', '--json']);
    out = JSON.parse(res.stdout);
    expect(res.code).not.toBe(0);
    expect(out.ok).toBe(false);
    expect(out.conflicting).toEqual(['old-pkg@1.0.0']);
  });

  it('MCP check_dependencies returns the same shape for a pip dir', async () => {
    const dir = project('old-pkg==1.0.0\n');
    const out = await new Promise((resolve) => {
      const proc = spawn(GUARD, ['mcp'], { env: process.env });
      let buf = '';
      proc.stdout.on('data', (d) => { buf += d; });
      proc.on('close', () => resolve(buf));
      proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'check_dependencies', arguments: { dir } } }) + '\n');
      proc.stdin.end();
    });
    const text = JSON.parse(out.trim().split('\n')[0]).result.content[0].text;
    expect(text).toMatch(/"unhashedWarnings": \[\s*"old-pkg@1\.0\.0"/);
    expect(text).toMatch(/"ok": true/);
  });

  it('a mixed repo (package-lock.json + requirements.txt) is checked as npm', async () => {
    const dir = project('old-pkg==1.0.0\n');
    writeFileSync(join(dir, '.guardrc'), `cooldown: 14d\nregistry: http://127.0.0.1:9\npypi: ${pypi.url}\n`);
    writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: { '': { name: 'mixed' }, 'node_modules/depguard-fixture-npm': { version: '1.0.0', resolved: 'http://127.0.0.1:9/x.tgz', integrity: 'sha512-a' } },
    }));
    const res = await guard(dir, ['check', '--all']);
    expect(res.stdout).toContain('lockfile integrity ok (1 version(s)');
    expect(res.stderr).not.toContain('--hash');
  });
});

describe('other commands in a pip repo', () => {
  it('guard sbom emits pkg:pypi purls and SHA-256 (CycloneDX and SPDX)', async () => {
    const dir = project(`Old_Pkg==1.0.0 --hash=${H1}\n`);
    const cdx = JSON.parse((await guard(dir, ['sbom'])).stdout);
    expect(cdx.components[0].purl).toBe('pkg:pypi/old-pkg@1.0.0');
    expect(cdx.components[0].hashes[0]).toEqual({ alg: 'SHA-256', content: 'a'.repeat(64) });
    const spdx = JSON.parse((await guard(dir, ['sbom', '--spdx'])).stdout);
    const pkg = spdx.packages.find((p) => p.name === 'old-pkg');
    expect(pkg.externalRefs[0].referenceLocator).toBe('pkg:pypi/old-pkg@1.0.0');
    expect(pkg.checksums[0]).toEqual({ algorithm: 'SHA256', checksumValue: 'a'.repeat(64) });
  });

  it('install refuses proxy-bypassing pip flags before anything runs', async () => {
    const dir = project('old-pkg==1.0.0\n');
    let res = await guard(dir, ['install', 'old-pkg', '--extra-index-url', 'http://x']);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('--extra-index-url bypasses the guard proxy');
    res = await guard(dir, ['install', '--no-binary', ':all:', 'old-pkg']);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('--no-binary re-enables source builds');
  });

  it('guard why exits 2 in a pip repo', async () => {
    const res = await guard(project('old-pkg==1.0.0\n'), ['why', 'old-pkg']);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('not supported for requirements.txt');
  });
});
