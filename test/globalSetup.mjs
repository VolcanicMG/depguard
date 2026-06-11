// Builds the guard binary once before the suite — the tests exercise the
// real compiled artifact, so a build break fails the suite immediately.
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export default function setup() {
  const root = join(import.meta.dirname, '..');
  const binDir = join(root, 'test', '.bin');
  mkdirSync(binDir, { recursive: true });
  // GUARD_GO overrides for machines where Go lives elsewhere.
  const go = process.env.GUARD_GO ?? join(homedir(), '.local', 'go', 'bin', 'go');
  execFileSync(go, ['build', '-o', join(binDir, 'guard'), '.'], { cwd: root, stdio: 'inherit' });
}
