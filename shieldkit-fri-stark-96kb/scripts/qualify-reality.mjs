#!/usr/bin/env node
/** Alias: P1 reality measurements already in qualify:security; re-assert settlement size ceilings */
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { ROOT, writeJson } from './lib/evidence.mjs';
import { buildSignedSettlement, MAX_TX_BYTES, MAX_UNLOCK_BYTES, VERIFIER_ROLES } from '../packages/settlement/settlement.mjs';

const outDir = path.join(ROOT, 'evidence/p1');
mkdirSync(outDir, { recursive: true });
// Product path: re-assert ceilings against the REAL materialized sound assembly
// (produced by the python assembler with the Rust worker; pure-JS re-prove at
// depth 20 is not the product path and would hang).
const art = path.join(ROOT, 'evidence/production/assemble-state0/assemble-withdrawal-d20-b2048-n7-g30-base1.materialized.json');
const tx = buildSignedSettlement({ statement: { kind: 'withdrawal' }, assemblyArtifact: art });
const report = {
  gate: 'P1-reality',
  ok:
    tx.fullySigned
    && VERIFIER_ROLES.length === 17
    && tx.roleLayout.inputCount === 18
    && tx.sizes.maxUnlockBytes <= MAX_UNLOCK_BYTES
    && tx.sizes.estimatedTxBytes <= MAX_TX_BYTES
    // Fail-closed: placeholder tag-hash redeems are not production FRI one-tx reality
    && tx.productionVerifiers === true
    && tx.placeholder !== true,
  topology: tx.roleLayout,
  sizes: tx.sizes,
  ceilings: { MAX_TX_BYTES, MAX_UNLOCK_BYTES },
  productionVerifiers: tx.productionVerifiers,
  placeholder: tx.placeholder,
  timestamp: new Date().toISOString(),
};
writeJson(path.join(outDir, 'P1_REALITY.json'), report);
console.log(JSON.stringify(report, null, 2));
process.exit(report.ok ? 0 : 1);
