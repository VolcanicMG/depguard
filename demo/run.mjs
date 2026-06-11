// Live demo runner — watch depguard handle a cast of realistic packages.
//
//   node demo/run.mjs            run every scenario
//   node demo/run.mjs demo-exfil run one by name
//
// Hermetic and safe: a local mock registry serves the demo packages (see
// packages.mjs — all "malicious" targets are unroutable doc IPs, and the box
// has no network anyway). The real guard binary does the work; this script
// only narrates and sanity-checks the outcome.
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { MockRegistry } from '../test/helpers/registry.mjs';
import { makeProject, guard, GUARD, NPM_QUIET } from '../test/helpers/run.mjs';
import { DEMO_PACKAGES } from './packages.mjs';

const C = { dim: '\x1b[2m', red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', bold: '\x1b[1m', reset: '\x1b[0m' };
const has = (bin) => { try { execFileSync(bin, ['--version'], { stdio: 'ignore' }); return true; } catch { return false; } };

async function main() {
  // Build the binary if it isn't there yet (mirrors the test globalSetup).
  if (!existsSync(GUARD)) {
    console.log(`${C.dim}building guard binary...${C.reset}`);
    const go = process.env.GUARD_GO ?? join(process.env.HOME, '.local', 'go', 'bin', 'go');
    execFileSync(go, ['build', '-o', GUARD, '.'], { cwd: join(import.meta.dirname, '..'), stdio: 'inherit' });
  }
  if (!has('docker') && !has('podman')) {
    console.log(`${C.yellow}Note: no container runtime — conviction demos need docker/podman to run the box.${C.reset}\n`);
  }

  const only = process.argv[2];
  const cast = only ? DEMO_PACKAGES.filter((p) => p.name === only) : DEMO_PACKAGES;
  if (cast.length === 0) {
    console.error(`No demo package named "${only}". Options: ${DEMO_PACKAGES.map((p) => p.name).join(', ')}`);
    process.exit(1);
  }

  const reg = await new MockRegistry().start();
  for (const p of DEMO_PACKAGES) {
    reg.publish(p.name, p.version, { ageDays: p.ageDays, scripts: p.scripts, files: p.files });
  }

  let failures = 0;
  for (const p of cast) {
    failures += await runScenario(reg, p);
  }
  await reg.stop();

  console.log(`\n${C.bold}${failures === 0 ? C.green + '✓ all demos behaved as documented' : C.red + `✗ ${failures} demo(s) did not match expectations`}${C.reset}`);
  process.exit(failures === 0 ? 0 : 1);
}

/**
 * Run one demo package through guard and narrate + verify the outcome.
 * @returns {Promise<number>} 1 if the outcome didn't match expect, else 0
 */
async function runScenario(reg, p) {
  console.log(`\n${C.bold}── ${p.title ?? p.name} ──${C.reset}`);
  console.log(`${C.dim}${p.why}${C.reset}`);

  const { dir, cleanup } = makeProject(reg.url);
  // Pre-approve script-bearing packages so the demo shows the BOX verdict,
  // not the approval prompt (which needs a TTY).
  if (p.scripts) await guard(dir, ['approve', `${p.name}@${p.version}`]);

  const res = await guard(dir, ['install', p.name, ...NPM_QUIET]);
  const installed = existsSync(join(dir, 'node_modules', p.name, 'package.json'));
  const convicted = /MALICIOUSLY/.test(res.stderr);

  let outcome, ok;
  if (convicted) {
    outcome = 'convicted';
    // Show the evidence lines — the money shot of the demo.
    res.stderr.split('\n').filter((l) => /\[(network-attempt|dns-query|secret-access)\]/.test(l))
      .forEach((l) => console.log(`   ${C.red}${l.trim()}${C.reset}`));
  } else if (!installed && res.code !== 0) {
    outcome = 'blocked';
    const why = res.stderr.split('\n').find((l) => /cooldown/.test(l));
    if (why) console.log(`   ${C.yellow}${why.trim()}${C.reset}`);
  } else if (installed && res.code === 0) {
    outcome = 'installs';
    console.log(`   ${C.green}installed cleanly${p.scripts ? ' (script passed the trace)' : ''}${C.reset}`);
  } else {
    outcome = `unexpected (code ${res.code})`;
  }

  ok = outcome === p.expect;
  console.log(`   ${ok ? C.green + '✓' : C.red + '✗'} outcome: ${outcome} (expected ${p.expect})${C.reset}`);
  cleanup();
  return ok ? 0 : 1;
}

main().catch((e) => { console.error(e); process.exit(1); });
