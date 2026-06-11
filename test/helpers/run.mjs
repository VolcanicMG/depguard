// Test-project scaffolding + guard binary runner.
//
// Each test gets a throwaway project directory wired to the mock registry via
// .guardrc, then drives the REAL guard binary as a child process — black-box
// testing of the same artifact users run, not Go internals.
import { execFile, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** Path to the binary built by globalSetup. */
export const GUARD = join(import.meta.dirname, '..', '.bin', 'guard');

/**
 * Create a throwaway npm project pointed at the mock registry.
 * @param {string} registryUrl - mock registry base URL
 * @param {object} [opts]
 * @param {string} [opts.cooldown='14d'] - .guardrc cooldown
 * @param {string[]} [opts.allow] - .guardrc allow patterns
 * @param {boolean} [opts.git=false] - also git init (needed for `guard init`)
 * @returns {{ dir: string, cleanup: () => void }}
 */
export function makeProject(registryUrl, { cooldown = '14d', allow, git = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'depguard-test-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'fixture', version: '1.0.0', private: true }));
  const allowLine = allow ? `allow: [${allow.map((a) => `"${a}"`).join(', ')}]\n` : '';
  writeFileSync(join(dir, '.guardrc'), `cooldown: ${cooldown}\n${allowLine}registry: ${registryUrl}\n`);
  if (git) execFileSync('git', ['init', '-q'], { cwd: dir });
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/**
 * Run the guard binary in a project dir.
 * stdin is 'ignore' → guard's termios check correctly sees "no human here",
 * exercising the non-interactive paths the same way CI would.
 * @param {string} dir - project directory
 * @param {string[]} args - guard CLI args
 * @returns {Promise<{ code: number, stdout: string, stderr: string }>}
 */
export function guard(dir, args) {
  return new Promise((resolve) => {
    execFile(
      GUARD,
      args,
      { cwd: dir, timeout: 120_000, env: process.env },
      (err, stdout, stderr) => resolve({ code: err?.code ?? 0, stdout, stderr }),
    );
  });
}

/** npm install passthrough flags that keep test output quiet and registry-clean. */
export const NPM_QUIET = ['--no-audit', '--no-fund', '--loglevel=error'];
