import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { describe, it } from 'node:test';
import { LIMITS } from '../constants.mjs';
import {
  densfuelRollingPlan,
  inspectDensfuelCandidateTx,
  loadDensfuelArtifacts,
  measureDensfuelFoundation,
} from './densfuel-settle.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const UNLOCK = path.join(ROOT, '.cache/v2-direct-unlocks');

describe('densfuel settle wiring', () => {
  it('measures foundation and builds rolling plan from densFuel dump', () => {
    if (!existsSync(path.join(UNLOCK, 'unlocks/build/result.json'))) {
      console.log('SKIP: densFuel artifacts missing');
      return;
    }
    const art = loadDensfuelArtifacts(UNLOCK);
    const m = measureDensfuelFoundation(art);
    assert.equal(m.gateOk, true);
    // Full VM power — never enforce plan soft 90kB / 9500B / 90%.
    assert.ok(m.maxUnlock <= LIMITS.maxUnlockBytes, `maxUnlock ${m.maxUnlock}`);
    assert.ok(m.wire <= LIMITS.maxTransactionBytes, `wire ${m.wire}`);
    assert.equal(m.packetBytes, 552);

    const plan = densfuelRollingPlan(art, {
      stateCommitment: Buffer.alloc(128, 1),
      instanceIdCategory: 'ab'.repeat(32),
      postReserveSats: 10_000_000n,
    });
    assert.equal(plan.carrierCount, 7);
    assert.equal(plan.carriers[0].unlockLen, 8177);
    assert.equal(plan.binding.unlockLen, 555);
    assert.equal(plan.state.value, 1000n + 10_000_000n);

    const tx = inspectDensfuelCandidateTx(art);
    assert.ok(tx);
    assert.equal(tx.underLimit, true);
    assert.equal(tx.txBytes, m.wire);
  });
});
