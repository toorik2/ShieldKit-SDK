#!/usr/bin/env node
/**
 * Emit external release gate boundaries for the ShieldKit-Groth-54KB (pf6)
 * product, using the authoritative gate module from the ShieldKit-Groth
 * product tree (read-only reference; no writes outside this tree).
 *
 * PLAN.md WP-8: "external-release-gate.mjs --gate bchn|chipnet|
 * final-ceremony-and-audits boundaries emitted (status blocked until evidence
 * lands)". The gate module is fail-closed by design: it always exits 1 and
 * prints the boundary object (status blocked-external-evidence-required) to
 * stderr. We record exactly what it emits.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const GATE_MODULE = path.resolve(repositoryRoot, '../shieldkit-groth/scripts/external-release-gate.mjs');
const GATES = ['bchn', 'chipnet', 'final-ceremony-and-audits'];

function sha256File(p) {
  return createHash('sha256').update(readFileSync(p)).digest('hex');
}

export function emitExternalGateBoundaries({ output = path.join(repositoryRoot, 'evidence/08-release/external-gate-boundaries.json') } = {}) {
  const boundaries = [];
  for (const gate of GATES) {
    const run = spawnSync(process.execPath, [GATE_MODULE, '--gate', gate], { encoding: 'utf8' });
    let boundary = null;
    try { boundary = JSON.parse(run.stderr.trim()); } catch { /* fallthrough */ }
    if (!boundary) {
      throw new Error(`external gate ${gate}: module produced no boundary JSON (status ${run.status}); stderr: ${run.stderr}`);
    }
    if (run.status === 0) {
      throw new Error(`external gate ${gate}: module exited 0 but fail-closed boundary emission must exit 1`);
    }
    boundaries.push({ gate, boundary });
  }

  const record = {
    schema: 'shieldkit-54kb/evidence/release-scans/external-gate-boundaries/v1',
    generated: new Date().toISOString(),
    status: 'boundaries-emitted-fail-closed',
    gateModule: {
      path: 'shieldkit-groth/scripts/external-release-gate.mjs (read-only reference)',
      sha256: `sha256:${sha256File(GATE_MODULE)}`,
    },
    command: GATES.map((gate) => `node shieldkit-groth/scripts/external-release-gate.mjs --gate ${gate}`),
    boundaries,
  };
  writeFileSync(output, `${JSON.stringify(record, null, 2)}\n`);
  return record;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const record = emitExternalGateBoundaries();
  process.stdout.write(`${JSON.stringify(record, null, 2)}\n`);
}
