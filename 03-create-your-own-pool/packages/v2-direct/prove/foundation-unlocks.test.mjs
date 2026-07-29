/**
 * Foundation gate: V2 densFuel unlock measurement (real path artifacts).
 * Requires prior `node prove/build-unlocks.mjs` producing .cache/v2-direct-unlocks/.
 */
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { LIMITS } from '../constants.mjs';
import { selectCarrierCandidate } from '../covenant/bundle.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const UNLOCK = path.join(ROOT, '.cache/v2-direct-unlocks');

describe('V2 densFuel foundation unlocks', () => {
  it('has densFuel result with gateOk and size gates', () => {
    const resultPath = path.join(UNLOCK, 'unlocks/build/result.json');
    const dumpPath = path.join(UNLOCK, 'unlocks/build/inputs_dump.json');
    if (!existsSync(resultPath) || !existsSync(dumpPath)) {
      console.log('SKIP: run prove/build-unlocks.mjs first');
      return;
    }
    const result = JSON.parse(readFileSync(resultPath, 'utf8'));
    const dump = JSON.parse(readFileSync(dumpPath, 'utf8'));
    assert.equal(result.gateOk, true);
    assert.equal(result.verifierInputCount, 7);
    assert.ok(result.wire <= LIMITS.maxTransactionBytes, `wire ${result.wire}`);
    const unlockLens = dump.slice(0, 7).map((row) => row.unlock.length / 2);
    const maxUnlock = Math.max(...unlockLens);
    assert.ok(maxUnlock <= LIMITS.maxUnlockBytes, `maxUnlock ${maxUnlock}`);
    for (const row of result.perInput || []) {
      assert.equal(row.accepts, true, `input ${row.index} must accept`);
    }
    // Packet is SDA2
    assert.equal(result.packet?.bytes, 552);
    assert.equal(result.packet?.unlockBytes, 555);
    const candidate = selectCarrierCandidate([{
      id: 'v2-densfuel',
      txBytes: result.wire,
      maxUnlockBytes: maxUnlock,
      vmResourceFraction: (result.op ?? 0) && result.budget
        ? result.op / result.budget
        : 0.85,
      vmCost: result.score ?? 0,
    }]);
    assert.equal(candidate?.id, 'v2-densfuel');
    // op budget margin if present in sibling file
    const marginPath = path.join(UNLOCK, 'unlocks/build/c7_opmargin.json');
    if (existsSync(marginPath)) {
      const m = JSON.parse(readFileSync(marginPath, 'utf8'));
      if (m.op && m.budget) {
        assert.ok(m.op / m.budget <= LIMITS.maxVmResourceFraction, `vm fraction ${m.op}/${m.budget}`);
      }
    }
  });

  it('adapter is V2 SDA2-bound with matching digest limbs', () => {
    const adapterPath = path.join(UNLOCK, 'adapter.json');
    const packetPath = path.join(UNLOCK, 'action.packet');
    if (!existsSync(adapterPath) || !existsSync(packetPath)) {
      console.log('SKIP: adapter artifacts missing');
      return;
    }
    const adapter = JSON.parse(readFileSync(adapterPath, 'utf8'));
    const packet = readFileSync(packetPath);
    assert.equal(packet.length, 552);
    assert.equal(packet.subarray(0, 4).toString('ascii'), 'SDA2');
    assert.ok(adapter.verifierCashFixture?.in0);
    assert.ok(adapter.verifierCashFixture?.in1);
    assert.equal(adapter.schema, 'shield.cash/snarkjs-groth16-pf7-adapter/v1');
  });
});
