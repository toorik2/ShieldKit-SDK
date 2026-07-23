import assert from 'node:assert/strict';
import test from 'node:test';
import {
  classifyCompleteG2Vm,
  G2CompleteAssemblerError,
  planCompleteG2Settlement,
  verifyCompleteG2Vm,
} from './g2-complete-assembler.mjs';

function trivialTenInputCandidate() {
  const inputs = Array.from({ length: 10 }, (_, index) => ({
    outpointTransactionHash: Uint8Array.from({ length: 32 }, () => index + 1),
    outpointIndex: index,
    sequenceNumber: 0,
    unlockingBytecode: Uint8Array.of(),
  }));
  return {
    transaction: {
      version: 2,
      locktime: 0,
      inputs,
      outputs: [{ valueSatoshis: 10_000n, lockingBytecode: Uint8Array.of(0x51) }],
    },
    sourceOutputs: Array.from({ length: 10 }, () => ({
      valueSatoshis: 1_000n,
      lockingBytecode: Uint8Array.of(0x51),
    })),
  };
}

test('classifies all ten BCH-2026 role evaluations and names a failing role', () => {
  const candidate = trivialTenInputCandidate();
  const raw = verifyCompleteG2Vm(candidate, true);
  assert.equal(raw.length, 10);
  const accepted = classifyCompleteG2Vm(candidate, true);
  assert.equal(accepted.inputCount, 10);
  assert.equal(accepted.accepted, true);
  assert.deepEqual(accepted.failedInputIndexes, []);

  candidate.sourceOutputs[4].lockingBytecode = Uint8Array.of(0x00);
  const rejected = classifyCompleteG2Vm(candidate, true);
  assert.equal(rejected.accepted, false);
  assert.deepEqual(rejected.failedInputIndexes, [4]);
});

test('plan API rejects a raw forged manifest before PF7 material can be accepted', async () => {
  await assert.rejects(
    () => planCompleteG2Settlement({
      kind: 'deposit',
      minimumFeeRateSatoshisPerByte: 1n,
      profileManifest: { genesis: {} },
    }),
    G2CompleteAssemblerError,
  );
});
