// Layer: the secret-file gate (DESIGN.md §11). `guard check` must hard-block a
// commit/push when a file matching a secret-paths pattern is staged or already
// tracked by git — and stay quiet when the match is only an untracked file or a
// waived path. Drives the REAL guard binary, like the rest of the suite.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFileSync, appendFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
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

/** New git-backed project with a secret-paths policy line appended. */
function secretProject(patterns) {
  const p = makeProject(reg.url, { git: true });
  projects.push(p);
  appendFileSync(join(p.dir, '.guardrc'), `secret-paths: [${patterns.map((x) => `"${x}"`).join(', ')}]\n`);
  return p;
}

const gitAdd = (dir, ...files) => execFileSync('git', ['-C', dir, 'add', ...files]);

describe('secret-file gate', () => {
  it('blocks a staged .env from being committed', async () => {
    const { dir } = secretProject(['.env']);
    writeFileSync(join(dir, '.env'), 'TOKEN=shh');
    gitAdd(dir, '.env');

    const res = await guard(dir, ['check']);
    expect(res.code).not.toBe(0);
    expect(res.stderr).toMatch(/secret file/i);
    expect(res.stderr).toContain('.env');
  });

  it('ignores an UNTRACKED secret file (git would not upload it)', async () => {
    const { dir } = secretProject(['.env']);
    writeFileSync(join(dir, '.env'), 'TOKEN=shh'); // never `git add`ed

    const res = await guard(dir, ['check']);
    expect(res.code).toBe(0);
  });

  it('matches a file by basename glob (*.pem) across the tree', async () => {
    const { dir } = secretProject(['*.pem', 'secrets/']);
    writeFileSync(join(dir, 'server.pem'), 'KEY');
    gitAdd(dir, 'server.pem');
    const res = await guard(dir, ['check']);
    expect(res.code).not.toBe(0);
    expect(res.stderr).toContain('server.pem');
  });

  it('a waived path stops gating (guard ignore secret:<path>)', async () => {
    const { dir } = secretProject(['.env.*']);
    writeFileSync(join(dir, '.env.example'), 'TOKEN=example');
    gitAdd(dir, '.env.example');

    let res = await guard(dir, ['check']);
    expect(res.code).not.toBe(0); // caught first

    const ig = await guard(dir, ['ignore', 'secret:.env.example', '--reason', 'template, no real secret']);
    expect(ig.code).toBe(0);

    res = await guard(dir, ['check']);
    expect(res.code).toBe(0); // now waived
  });

  it('reports secrets in --json and flips ok=false', async () => {
    const { dir } = secretProject(['.env']);
    writeFileSync(join(dir, '.env'), 'TOKEN=shh');
    gitAdd(dir, '.env');
    const res = await guard(dir, ['check', '--json']);
    const out = JSON.parse(res.stdout);
    expect(out.ok).toBe(false);
    expect(out.secrets.map((s) => s.Path)).toContain('.env');
  });

  it('guard secret-add APPENDS a user pattern that then gates', async () => {
    const { dir } = secretProject(['.env']); // starts with just .env
    // A custom folder the user adds later — not one of the starter examples.
    const add = await guard(dir, ['secret-add', 'private/', '*.pfx']);
    expect(add.code).toBe(0);
    expect(add.stdout).toMatch(/secret-paths \+= private\//);

    // The newly-added pattern is now enforced.
    writeFileSync(join(dir, 'cert.pfx'), 'BINARY');
    gitAdd(dir, 'cert.pfx');
    const res = await guard(dir, ['check']);
    expect(res.code).not.toBe(0);
    expect(res.stderr).toContain('cert.pfx');

    // Re-adding an existing pattern is a no-op (dedup), still exit 0.
    const dup = await guard(dir, ['secret-add', '.env']);
    expect(dup.code).toBe(0);
    expect(dup.stdout).toMatch(/already a secret-path/);
  });
});
