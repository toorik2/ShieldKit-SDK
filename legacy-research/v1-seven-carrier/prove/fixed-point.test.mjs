import assert from 'node:assert/strict';
import test from 'node:test';
import { encodeTransaction } from '@bitauth/libauth';
import { encodeActionPacket, OUTPUT_RECORD_BYTES } from '../action/packet.mjs';
import { encodeSettlementContext } from '../action/context.mjs';
import {
  enumeratePf7FixedPointCandidates,
  measurePf7FixedPointCandidate,
  Pf7FixedPointError,
  verifyPf7FixedPointCandidate,
} from './fixed-point.mjs';

const hex = (byte, length = 32) => byte.toString(16).padStart(2, '0').repeat(length);
const state = (sequence, reserve, commitment) => ({
  profileId: hex(0x11), instanceId: hex(0x22), noteRoot: hex(0x33), nullifierRoot: hex(0x44),
  nextLeafIndex: '1', actionSequence: sequence, liveNoteCount: reserve === '0' ? '0' : '1',
  reserveSats: reserve, maximumReserve: '30000000', stateCommitment: hex(commitment),
});
const packet = (contextDigest) => encodeActionPacket({
  kind: 'deposit', networkId: 2, preState: state('0', '0', 0x55), postState: state('1', '10000000', 0x66),
  inputCommitment: hex(0), inputNullifier: hex(0), outputCommitment: hex(0x77), outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES, 0x88),
  boundaryAmount: '10000000', withdrawalScriptHash: hex(0), transactionContextDigest: contextDigest,
});

function input(index, unlockingBytecode) {
  return {
    outpointTransactionHash: Uint8Array.from({ length: 32 }, () => index + 1),
    outpointIndex: index,
    sequenceNumber: 0,
    unlockingBytecode,
  };
}

function contextMaterials(inputs, outputs) {
  return {
    kind: 'deposit', profileId: hex(0x11), instanceId: hex(0x22),
    sourceOutputs: inputs.map((_, index) => ({ valueSatoshis: '100000', lockingBytecode: `51${hex(index, 1)}`, token: null })),
    transaction: {
      version: '2', locktime: '0',
      inputs: inputs.map((entry) => ({
        outpointTransactionHashWire: Buffer.from(entry.outpointTransactionHash).reverse().toString('hex'),
        outpointIndex: String(entry.outpointIndex), sequenceNumber: String(entry.sequenceNumber),
      })),
      outputs: outputs.map((output) => ({ valueSatoshis: output.valueSatoshis.toString(), lockingBytecode: Buffer.from(output.lockingBytecode).toString('hex'), token: null })),
    },
  };
}

/** Structural fixture only: no row in this test is a PF7 proof claim. */
function exactFixture() {
  const preliminaryPacket = packet(hex(0));
  const pf7Unlocks = Array.from({ length: 7 }, (_, index) => Uint8Array.of(0x51, index));
  const inputs = [
    ...pf7Unlocks.map((unlock, index) => input(index, unlock)),
    input(7, preliminaryPacket), input(8, Uint8Array.of(0x51)), input(9, Uint8Array.of(0x51, 0x51)),
  ];
  const stateOutput = { valueSatoshis: 5_000n, lockingBytecode: Uint8Array.of(0x51) };
  const draft = { version: 2, locktime: 0, inputs, outputs: [stateOutput, { valueSatoshis: 1n, lockingBytecode: Uint8Array.of(0x51) }] };
  const wireBytes = encodeTransaction(draft).length;
  const outputs = [stateOutput, { valueSatoshis: 1_000_000n - stateOutput.valueSatoshis - BigInt(wireBytes), lockingBytecode: Uint8Array.of(0x51) }];
  const materials = contextMaterials(inputs, outputs);
  // SCCT excludes unlocking bytecode, so this direct preliminary encoding is
  // the non-circular context pass used before the final packet/PF7 build.
  const actionPacket = packet(encodeSettlementContext(materials).digestHex);
  inputs[7].unlockingBytecode = actionPacket;
  const encodedTransaction = encodeTransaction({ version: 2, locktime: 0, inputs, outputs });
  const actualPf7UnlockRows = pf7Unlocks.map((unlockingBytecode, inputIndex) => ({ inputIndex, unlockingBytecode }));
  return { actionPacket, actualPf7UnlockRows, encodedTransaction, settlementContextMaterials: materials };
}

function plannedFor(value) {
  const measured = measurePf7FixedPointCandidate(value);
  return {
    expectedWireBytes: measured.measurements.wireBytes,
    expectedFeeSatoshis: measured.measurements.feeSatoshis.toString(),
    expectedPf7UnlockingByteLengths: [...measured.measurements.pf7UnlockingByteLengths],
    expectedPf7UnlockingBytes: measured.measurements.pf7UnlockingBytes,
    transactionContext: {
      digestHex: measured.context.digestHex,
      preimageHex: measured.context.preimageHex,
      publicInputLimbs: [...measured.context.publicInputLimbs],
    },
  };
}

test('measures and closes an exact packet/context/fee/PF7-byte fixed point', async () => {
  const candidate = exactFixture();
  const measured = measurePf7FixedPointCandidate(candidate);
  assert.equal(measured.measurements.feeSatoshis, BigInt(measured.measurements.wireBytes));
  assert.deepEqual(measured.measurements.pf7UnlockingByteLengths, [2, 2, 2, 2, 2, 2, 2]);
  const closed = await verifyPf7FixedPointCandidate({
    ...candidate,
    planned: plannedFor(candidate),
    packetPublicInputLimbs: [...measured.packetPublicInputLimbs],
    pf7Compatibility: (publicCandidate) => (
      publicCandidate.transactionContext.digestHex === measured.context.digestHex
      && publicCandidate.pf7UnlockRows.length === 7
      && publicCandidate.transactionHex === Buffer.from(candidate.encodedTransaction).toString('hex')
    ),
  });
  assert.equal(closed.fixedPoint, true);
  assert.match(closed.qualification, /not.*proof|Groth16/i);
});

test('fails closed on post-build PF7 length drift, packet-limb drift, and a false compatibility predicate', async () => {
  const candidate = exactFixture();
  const measured = measurePf7FixedPointCandidate(candidate);
  const planned = plannedFor(candidate);
  await assert.rejects(() => verifyPf7FixedPointCandidate({
    ...candidate,
    planned: { ...planned, expectedPf7UnlockingBytes: planned.expectedPf7UnlockingBytes + 1 },
    packetPublicInputLimbs: [...measured.packetPublicInputLimbs], pf7Compatibility: () => true,
  }), Pf7FixedPointError);
  await assert.rejects(() => verifyPf7FixedPointCandidate({
    ...candidate, planned, packetPublicInputLimbs: ['0', '0'], pf7Compatibility: () => true,
  }), /packetPublicInputLimbs/);
  await assert.rejects(() => verifyPf7FixedPointCandidate({
    ...candidate, planned, packetPublicInputLimbs: [...measured.packetPublicInputLimbs], pf7Compatibility: () => false,
  }), /pf7Compatibility/);
});

test('deterministically enumerates seeds and never promotes a rejected closure', async () => {
  const good = exactFixture();
  const goodMeasured = measurePf7FixedPointCandidate(good);
  const calls = [];
  const seeds = [hex(1), hex(2)];
  const enumerated = await enumeratePf7FixedPointCandidates({
    seedCandidates: seeds,
    evaluatePacketPublicInputs: ({ seedHex }) => {
      calls.push(`packet:${seedHex}`);
      return { actionPacket: good.actionPacket, packetPublicInputLimbs: [...goodMeasured.packetPublicInputLimbs] };
    },
    buildCandidate: ({ seedHex }) => {
      calls.push(`build:${seedHex}`);
      const plan = plannedFor(good);
      return {
        actualPf7UnlockRows: good.actualPf7UnlockRows,
        encodedTransaction: good.encodedTransaction,
        settlementContextMaterials: good.settlementContextMaterials,
        planned: seedHex === seeds[0] ? { ...plan, expectedWireBytes: plan.expectedWireBytes + 1 } : plan,
      };
    },
    pf7Compatibility: ({ seedHex, transactionContext }) => seedHex === seeds[1] && transactionContext.digestHex === goodMeasured.context.digestHex,
  });
  assert.deepEqual(calls, [`packet:${seeds[0]}`, `build:${seeds[0]}`, `packet:${seeds[1]}`, `build:${seeds[1]}`]);
  assert.deepEqual(enumerated.accepted.map((entry) => entry.seedHex), [seeds[1]]);
  assert.deepEqual(enumerated.rejected.map((entry) => entry.seedHex), [seeds[0]]);
});

test('rejects PF7 rows that differ from the decoded final transaction', () => {
  const candidate = exactFixture();
  candidate.actualPf7UnlockRows[0] = { inputIndex: 0, unlockingBytecode: Uint8Array.of(0x51) };
  assert.throws(() => measurePf7FixedPointCandidate(candidate), /does not match the decoded complete transaction/);
});

test('rejects a context-material transaction drift and any synthetic proof-validity flag', async () => {
  const candidate = exactFixture();
  const drifted = {
    ...candidate,
    settlementContextMaterials: JSON.parse(JSON.stringify(candidate.settlementContextMaterials)),
  };
  drifted.settlementContextMaterials.transaction.outputs[1].valueSatoshis = '1';
  assert.throws(() => measurePf7FixedPointCandidate(drifted), /do not reconstruct the exact complete transaction/);
  const measured = measurePf7FixedPointCandidate(candidate);
  await assert.rejects(() => verifyPf7FixedPointCandidate({
    ...candidate,
    planned: plannedFor(candidate),
    packetPublicInputLimbs: [...measured.packetPublicInputLimbs],
    pf7Compatibility: () => true,
    proofValid: true,
  }), /missing or unknown properties/);
});
