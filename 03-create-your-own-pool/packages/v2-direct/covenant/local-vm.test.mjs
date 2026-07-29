import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { LIMITS } from '../constants.mjs';
import {
  executeDigestBinding,
  executeDigestBindingAttack,
  measureCandidate,
} from './local-vm.mjs';

describe('local VM foundation scaffold', () => {
  it('measures candidates against full-VM LIMITS (soft plan caps waived)', () => {
    const ok = measureCandidate({
      txBytes: 40_000,
      unlockBytesList: [4_000, 5_000],
      vmOpsUsed: 50,
      vmOpsLimit: 100,
    });
    assert.equal(ok.passes, true);
    // Above plan soft 90kB but under full-VM maxTransactionBytes — must pass.
    const softPlanOk = measureCandidate({
      txBytes: 100_000,
      unlockBytesList: [100],
      vmOpsUsed: 1,
      vmOpsLimit: 100,
    });
    assert.equal(softPlanOk.passes, true);
    const bad = measureCandidate({
      txBytes: LIMITS.maxTransactionBytes + 1,
      unlockBytesList: [100],
      vmOpsUsed: 1,
      vmOpsLimit: 100,
    });
    assert.equal(bad.passes, false);
  });

  it('accepts matching digest unlock and rejects forged digest', async () => {
    const digest = createHash('sha256').update('v2-direct-digest').digest();
    const good = await executeDigestBinding({ digest });
    // Libauth verify may return true or an error string depending on version API
    assert.ok(good.measurement.passes);
    assert.ok(good.txBytes <= LIMITS.maxTransactionBytes);
    assert.ok(good.unlockBytes <= LIMITS.maxUnlockBytes);

    const forged = createHash('sha256').update('forged').digest();
    const attack = await executeDigestBindingAttack({
      honestDigest: digest,
      forgedDigest: forged,
    });
    assert.equal(attack.failedClosed, true);
  });
});
